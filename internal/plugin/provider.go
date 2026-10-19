package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
)

// Guest ports. Kandev fixes the control port; the instance range is ours to
// choose and is published at create time, three wide because agentctl skips
// a port that is still bound after a restart.
const (
	controlPort       = 8765
	instancePortFirst = 41001
	instancePortLast  = 41003
)

// stateVersion matches supported_state_versions in the manifest.
const stateVersion = 1

// maxArtifactBytes matches the SDK's own cap on the runtime artifact.
const maxArtifactBytes = 512 << 20

// resourceState is the descriptor's state_json: what routes every call
// after provision. It is closed by the manifest's resource_state_schema and
// never carries a secret.
type resourceState struct {
	Host        string `json:"host"`
	SandboxName string `json:"sandbox_name"`
	Env         string `json:"env"`
	Image       string `json:"image,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

func descriptorFor(host string, rec msbctl.Record) *pluginsdk.ExecutorResourceDescriptor {
	state, _ := json.Marshal(resourceState{
		Host: host, SandboxName: rec.Name, Env: rec.Env, Image: rec.Image, CreatedAt: rec.CreatedAt,
	})
	return &pluginsdk.ExecutorResourceDescriptor{
		ResourceHandle: "msb:" + host + "/" + rec.Name,
		StateJson:      string(state),
		Platform:       rec.Platform,
		Capabilities:   capabilities(),
		ExpiresAt:      rec.ExpiresAt,
		Retention:      "bounded",
		StateVersion:   stateVersion,
	}
}

var errNoState = errors.New("resource has no usable state")

func stateOf(d *pluginsdk.ExecutorResourceDescriptor) (resourceState, error) {
	if d == nil || d.GetStateJson() == "" {
		return resourceState{}, errNoState
	}
	var s resourceState
	if err := json.Unmarshal([]byte(d.GetStateJson()), &s); err != nil || s.Host == "" || s.Env == "" || s.SandboxName == "" {
		return resourceState{}, errNoState
	}
	return s, nil
}

// bootstrap is Kandev's bootstrap_json. It is transient: never logged,
// stored, checkpointed or put in argv.
type bootstrap struct {
	Nonce       string `json:"nonce"`
	RuntimePort int    `json:"runtime_port"`
	APIURL      string `json:"api_url"`
	ArtifactID  string `json:"artifact_id"`
}

func parseBootstrap(raw string) (bootstrap, msbctl.KandevAPI, error) {
	var b bootstrap
	if err := json.Unmarshal([]byte(raw), &b); err != nil || b.Nonce == "" {
		return b, msbctl.KandevAPI{}, errors.New("bootstrap descriptor is unreadable")
	}
	if b.RuntimePort == 0 {
		b.RuntimePort = controlPort
	}
	if b.RuntimePort != controlPort {
		return b, msbctl.KandevAPI{}, errors.New("bootstrap runtime port is not the published control port")
	}
	if b.ArtifactID == "" {
		b.ArtifactID = "agentctl"
	}
	u, err := url.Parse(b.APIURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return b, msbctl.KandevAPI{}, errors.New("bootstrap api_url is unusable")
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return b, msbctl.KandevAPI{}, errors.New("bootstrap api_url has an invalid port")
		}
	}
	return b, msbctl.KandevAPI{Host: u.Hostname(), Port: port}, nil
}

// providerFailure turns an msbctl or transport error into a provider error.
// The host's message text is never used.
func providerFailure(err error, messageID string) *pluginsdk.ExecutorProviderError {
	var e *msbctl.Error
	if errors.As(err, &e) {
		out := providerError(e.Code, messageID)
		if e.Code == msbctl.CodeRateLimited {
			out.RetryAfterSeconds = uint32(e.RetryAfterSeconds)
		}
		return out
	}
	return providerError(msbctl.CodeUnavailable, messageID)
}

func requireIdentity(c *pluginsdk.ExecutorProviderRequestContext) bool {
	return c.GetOperationId() != "" && c.GetEnvironmentId() != "" && c.GetInputDigest() != ""
}

// providerHost returns the operation-bound callbacks.
func (r *Runtime) providerHost() (pluginsdk.ExecutorProviderHostAPI, error) {
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	p, ok := h.(pluginsdk.ExecutorProviderHost)
	if !ok {
		return nil, errors.New("kandev host does not offer executor provider callbacks")
	}
	return p.ExecutorProvider(), nil
}

// progress reports a stage; failures are logged, never fatal.
func progress(ctx context.Context, api pluginsdk.ExecutorProviderHostAPI, rc *pluginsdk.ExecutorProviderRequestContext, stage string, done uint32) {
	if _, err := api.ReportExecutorProgress(ctx, &pluginsdk.ReportExecutorProgressRequest{
		Context: rc, Stage: stage, Completed: done, Total: 1,
	}); err != nil {
		log.Printf("progress %s: %v", stage, err)
	}
}

// ProvisionExecutorEnvironment places a sandbox, creates it, checkpoints it
// with Kandev before anything else can fail, then installs and starts
// agentctl with the bootstrap nonce.
func (r *Runtime) ProvisionExecutorEnvironment(ctx context.Context, req *pluginsdk.ProvisionExecutorEnvironmentRequest) (*pluginsdk.ProvisionExecutorEnvironmentResponse, error) {
	rc := req.GetContext()
	fail := func(e *pluginsdk.ExecutorProviderError) (*pluginsdk.ProvisionExecutorEnvironmentResponse, error) {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: e}, nil
	}
	if !requireIdentity(rc) {
		return fail(providerError(msbctl.CodeInvalidConfig, "identityIncomplete"))
	}
	spec, problems := profile.Parse(req.GetProfile().GetConfig(), req.GetProfile().GetSecretValues())
	if len(problems) > 0 {
		return fail(providerError(msbctl.CodeInvalidConfig, "profileInvalid"))
	}
	boot, api, err := parseBootstrap(req.GetBootstrapJson())
	if err != nil {
		log.Printf("provision %s: %v", rc.GetEnvironmentId(), err)
		return fail(providerError(msbctl.CodeInvalidConfig, "bootstrapInvalid"))
	}
	callbacks, err := r.providerHost()
	if err != nil {
		return fail(providerError(msbctl.CodeUnavailable, "hostUnavailable"))
	}
	client, err := r.client(ctx)
	if err != nil {
		return fail(providerError(msbctl.CodeUnavailable, "hostUnavailable"))
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return fail(providerError(msbctl.CodeUnavailable, "registryUnavailable"))
	}
	if spec.EgressAllow, err = r.sandboxEgress(ctx, spec); err != nil {
		log.Printf("provision %s: %v", rc.GetEnvironmentId(), err)
		if errors.Is(err, egress.ErrUnknown) || errors.Is(err, egress.ErrPolicy) {
			return fail(providerError(msbctl.CodeInvalidConfig, "egressInvalid"))
		}
		return fail(providerError(msbctl.CodeUnavailable, "egressUnavailable"))
	}

	progress(ctx, callbacks, rc, "provision", 0)
	host, perr := r.placeOrReuse(ctx, client, registry, spec, rc)
	if perr != nil {
		return fail(perr)
	}
	rec, err := client.Provision(ctx, host, rc.GetEnvironmentId(), provisionRequest(spec, rc, api, r.now()))
	if err != nil {
		log.Printf("provision %s on %s: %v", rc.GetEnvironmentId(), host.Name, err)
		if errors.Is(err, msbctl.ErrTooLarge) {
			return fail(providerError(msbctl.CodeInvalidConfig, "requestTooLarge"))
		}
		return fail(providerFailure(err, "provisionFailed"))
	}
	resource := descriptorFor(host.Name, rec)
	if _, err := callbacks.CheckpointExecutorResource(ctx, &pluginsdk.CheckpointExecutorResourceRequest{
		Context: rc, Resource: resource, Phase: "provisioned",
	}); err != nil {
		// Kandev now drives cleanup by operation id, which Destroy and
		// Recover resolve through `find`.
		log.Printf("provision %s: checkpoint: %v", rc.GetEnvironmentId(), err)
		return fail(providerError(msbctl.CodeUnavailable, "checkpointFailed"))
	}
	progress(ctx, callbacks, rc, "provision", 1)

	progress(ctx, callbacks, rc, "artifact", 0)
	binary, digest, version, err := readArtifact(ctx, callbacks, rc, boot.ArtifactID, rec.Platform)
	if err != nil {
		log.Printf("provision %s: agentctl artifact: %v", rc.GetEnvironmentId(), err)
		return fail(providerError(msbctl.CodeUnavailable, "artifactUnavailable"))
	}
	progress(ctx, callbacks, rc, "artifact", 1)

	progress(ctx, callbacks, rc, "bootstrap", 0)
	rec, err = client.Agentctl(ctx, host, rc.GetEnvironmentId(), msbctl.AgentctlRequest{
		SHA256: digest, Size: int64(len(binary)), Version: version, Nonce: boot.Nonce,
		RuntimePort: controlPort, Args: []string{"-port=" + strconv.Itoa(controlPort)},
		Env: map[string]string{
			// msb publishes ports by connecting to the guest's own address,
			// so a server bound to loopback inside the guest is never reached.
			"AGENTCTL_LISTEN_HOST":        "0.0.0.0",
			"AGENTCTL_INSTANCE_PORT_BASE": strconv.Itoa(instancePortFirst),
			"AGENTCTL_INSTANCE_PORT_MAX":  strconv.Itoa(instancePortLast),
		},
	}, bytes.NewReader(binary))
	if err != nil {
		log.Printf("provision %s: agentctl: %v", rc.GetEnvironmentId(), err)
		return fail(providerFailure(err, "agentctlFailed"))
	}
	progress(ctx, callbacks, rc, "bootstrap", 1)
	progress(ctx, callbacks, rc, "readiness", 1)
	return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptorFor(host.Name, rec)}, nil
}

func provisionRequest(spec profile.Spec, rc *pluginsdk.ExecutorProviderRequestContext, api msbctl.KandevAPI, now time.Time) msbctl.ProvisionRequest {
	out := msbctl.ProvisionRequest{
		OperationID: rc.GetOperationId(), InputDigest: rc.GetInputDigest(),
		Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, DiskGiB: spec.DiskGiB, WorkspaceGiB: spec.WorkspaceGiB,
		ExpiresAt:   now.UTC().Add(time.Duration(spec.MaxLifetimeHours) * time.Hour).Format(time.RFC3339),
		KandevAPI:   api,
		EgressAllow: spec.EgressAllow,
	}
	for _, e := range spec.Env {
		out.Env = append(out.Env, msbctl.EnvVar{Name: e.Name, Value: e.Value})
	}
	for _, s := range spec.Secrets {
		out.Secrets = append(out.Secrets, msbctl.Secret{Name: s.Name, Value: s.Value, Hosts: s.Hosts})
	}
	if spec.RegistryUsername != "" {
		out.Registry = &msbctl.Registry{Username: spec.RegistryUsername, Password: spec.RegistryPassword}
	}
	return out
}

// placeOrReuse returns the host that already holds this operation, if any
// candidate does, so a retried provision never lands on a second host;
// otherwise it places a new sandbox.
func (r *Runtime) placeOrReuse(ctx context.Context, client *msbctl.Client, registry hosts.Registry, spec profile.Spec, rc *pluginsdk.ExecutorProviderRequestContext) (hosts.Host, *pluginsdk.ExecutorProviderError) {
	candidates := registry.Candidates(spec.Placement)
	if found := findOperation(ctx, client, candidates, rc.GetOperationId()); found.ok {
		return found.host, nil
	}
	host, err := hosts.Place(ctx, candidates, placementProber{r: r, client: client}, hosts.Demand{CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB})
	switch {
	case err == nil:
		return host, nil
	case errors.Is(err, hosts.ErrAllFull):
		e := providerError(msbctl.CodeRateLimited, "hostsFull")
		e.RetryAfterSeconds = 30
		return hosts.Host{}, e
	case errors.Is(err, hosts.ErrNoCandidates):
		return hosts.Host{}, providerError(msbctl.CodeInvalidConfig, "placementUnresolved")
	default:
		return hosts.Host{}, providerError(msbctl.CodeUnavailable, "hostsUnreachable")
	}
}

// placementProber heals a proxy host's certificate before it is counted as
// a candidate, so a host whose certificate lapsed takes sessions again as
// soon as it is asked to.
type placementProber struct {
	r      *Runtime
	client *msbctl.Client
}

func (p placementProber) Capacity(ctx context.Context, h hosts.Host) (hosts.Capacity, error) {
	health, err := p.client.Health(ctx, h)
	if err != nil {
		return hosts.Capacity{}, err
	}
	if health.Serve.Mode == msbctl.ServeProxy && !health.Serve.OK {
		if outcome := p.r.healTLS(ctx, p.client, h, health); outcome.State == tlsRenewed {
			if health, err = p.client.Health(ctx, h); err != nil {
				return hosts.Capacity{}, err
			}
		}
	}
	if !health.Usable() {
		return hosts.Capacity{}, &msbctl.Error{Code: msbctl.CodeUnavailable}
	}
	return health.Capacity, nil
}

type foundOperation struct {
	ok      bool
	host    hosts.Host
	record  msbctl.Record
	unknown bool // some host could not answer
}

// findOperation asks each host for the operation, in parallel.
func findOperation(ctx context.Context, client *msbctl.Client, candidates []hosts.Host, operationID string) foundOperation {
	type answer struct {
		host hosts.Host
		rec  msbctl.Record
		err  error
	}
	answers := make(chan answer, len(candidates))
	for _, h := range candidates {
		go func() {
			findCtx, cancel := context.WithTimeout(ctx, hosts.ProbeTimeout)
			defer cancel()
			rec, ok, err := client.FindOperation(findCtx, h, operationID)
			if err == nil && !ok {
				err = &msbctl.Error{Code: msbctl.CodeNotFound}
			}
			answers <- answer{h, rec, err}
		}()
	}
	var out foundOperation
	for range candidates {
		a := <-answers
		switch {
		case a.err == nil && !out.ok:
			out.ok, out.host, out.record = true, a.host, a.rec
		case a.err != nil && msbctl.CodeOf(a.err) != msbctl.CodeNotFound:
			out.unknown = true
		}
	}
	return out
}

// readArtifact streams agentctl from Kandev and verifies it before anything
// is sent to a host.
func readArtifact(ctx context.Context, api pluginsdk.ExecutorProviderHostAPI, rc *pluginsdk.ExecutorProviderRequestContext, artifactID, platform string) ([]byte, string, string, error) {
	var buf bytes.Buffer
	var want, version string
	hash := sha256.New()
	err := api.ReadExecutorRuntimeArtifact(ctx, &pluginsdk.ReadExecutorRuntimeArtifactRequest{
		Context: rc, ArtifactId: artifactID, Platform: platform,
	}, func(chunk *pluginsdk.ExecutorRuntimeArtifactChunk) error {
		if want == "" {
			want, version = chunk.GetSha256(), chunk.GetVersion()
			if chunk.GetTotalSizeBytes() > maxArtifactBytes {
				return errors.New("artifact exceeds the size limit")
			}
		}
		if buf.Len()+len(chunk.GetData()) > maxArtifactBytes {
			return errors.New("artifact exceeds the size limit")
		}
		buf.Write(chunk.GetData())
		hash.Write(chunk.GetData())
		return nil
	})
	if err != nil {
		return nil, "", "", err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); want == "" || !strings.EqualFold(got, want) {
		return nil, "", "", errors.New("artifact digest does not match")
	}
	return buf.Bytes(), strings.ToLower(want), version, nil
}

// hostFor resolves the host a resource's state names. A host removed from
// the registry is reported, never guessed.
func (r *Runtime) hostFor(ctx context.Context, s resourceState) (hosts.Host, error) {
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return hosts.Host{}, err
	}
	h, ok := registry.Find(s.Host)
	if !ok {
		return hosts.Host{}, fmt.Errorf("host %q is no longer registered", s.Host)
	}
	return h, nil
}

// sandboxEgress is what a new sandbox may reach beyond the host's own rule
// groups: the policy's default groups, the profile's groups, then the
// profile's own entries.
func (r *Runtime) sandboxEgress(ctx context.Context, spec profile.Spec) ([]string, error) {
	policy, err := r.loadEgress(ctx)
	if err != nil {
		return nil, err
	}
	return policy.Expand(spec.EgressGroups, spec.EgressAllow)
}
