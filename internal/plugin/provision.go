package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
	"kandev-plugin-microsandbox/internal/sandbox"
	"kandev-plugin-microsandbox/internal/secrets"
)

// maxArtifactBytes matches the SDK's own cap on the runtime artifact.
const maxArtifactBytes = 512 << 20

// descriptorFor is the resource Kandev records for the sandbox rec on host.
func descriptorFor(host string, rec msbctl.Record) *pluginsdk.ExecutorResourceDescriptor {
	state := sandbox.StateOf(host, rec)
	return &pluginsdk.ExecutorResourceDescriptor{
		ResourceHandle: state.Handle(),
		StateJson:      state.JSON(),
		Platform:       rec.Platform,
		Capabilities:   capabilities(),
		ExpiresAt:      rec.ExpiresAt,
		Retention:      "bounded",
		StateVersion:   sandbox.StateVersion,
	}
}

func operationOf(rc *pluginsdk.ExecutorProviderRequestContext) sandbox.Operation {
	return sandbox.Operation{ID: rc.GetOperationId(), Environment: rc.GetEnvironmentId(), InputDigest: rc.GetInputDigest()}
}

// providerHost returns the operation-bound callbacks.
func (p *provider) providerHost() (pluginsdk.ExecutorProviderHostAPI, error) {
	h, err := p.host.Get()
	if err != nil {
		return nil, err
	}
	callbacks, ok := h.(pluginsdk.ExecutorProviderHost)
	if !ok {
		return nil, errors.New("kandev host does not offer executor provider callbacks")
	}
	return callbacks.ExecutorProvider(), nil
}

// provisioning is one provision, step by step. A step returns the failure
// to report, or nil to go on.
type provisioning struct {
	p         *provider
	rc        *pluginsdk.ExecutorProviderRequestContext
	op        sandbox.Operation
	spec      profile.Spec
	boot      sandbox.Bootstrap
	api       msbctl.KandevAPI
	callbacks pluginsdk.ExecutorProviderHostAPI
	client    *msbctl.Client
	registry  hosts.Registry
	host      hosts.Host
	record    msbctl.Record
}

// provision places a sandbox, creates it, checkpoints it with Kandev before
// anything else can fail, then installs and starts agentctl with the
// bootstrap nonce.
func (p *provider) provision(ctx context.Context, req *pluginsdk.ProvisionExecutorEnvironmentRequest) *pluginsdk.ProvisionExecutorEnvironmentResponse {
	run := &provisioning{p: p, rc: req.GetContext(), op: operationOf(req.GetContext())}
	if !run.op.Complete() {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError(msbctl.CodeInvalidConfig, "identityIncomplete")}
	}
	steps := []func(context.Context) *sandbox.Failure{
		func(ctx context.Context) *sandbox.Failure { return run.read(ctx, req) },
		run.connect,
		run.resolve,
		run.create,
		run.bootstrap,
	}
	for _, step := range steps {
		if f := step(ctx); f != nil {
			return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: sdkError(f)}
		}
	}
	return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptorFor(run.host.Name, run.record)}
}

// read parses the profile and the bootstrap.
func (r *provisioning) read(ctx context.Context, req *pluginsdk.ProvisionExecutorEnvironmentRequest) *sandbox.Failure {
	spec, problems := profile.Parse(req.GetProfile().GetConfig(), req.GetProfile().GetSecretValues())
	if len(problems) > 0 {
		return sandbox.Fail(msbctl.CodeInvalidConfig, "profileInvalid")
	}
	boot, api, err := sandbox.ParseBootstrap(req.GetBootstrapJson())
	if err != nil {
		log.Printf("provision %s: %v", r.op.Environment, err)
		return sandbox.Fail(msbctl.CodeInvalidConfig, "bootstrapInvalid")
	}
	r.spec, r.boot, r.api = spec, boot, api
	r.p.apiURL.Note(ctx, boot.APIURL)
	return nil
}

// connect gets Kandev's callbacks, the hosts and the registry.
func (r *provisioning) connect(ctx context.Context) *sandbox.Failure {
	var err error
	if r.callbacks, err = r.p.providerHost(); err != nil {
		return sandbox.Fail(msbctl.CodeUnavailable, "hostUnavailable")
	}
	if r.client, err = r.p.connect(ctx); err != nil {
		return sandbox.Fail(msbctl.CodeUnavailable, "hostUnavailable")
	}
	if r.registry, err = r.p.registry.Load(ctx); err != nil {
		return sandbox.Fail(msbctl.CodeUnavailable, "registryUnavailable")
	}
	return nil
}

// resolve fills in what the profile names: its egress, from the plugin's
// policy, and its secrets' values.
func (r *provisioning) resolve(ctx context.Context) *sandbox.Failure {
	var err error
	if r.spec.EgressAllow, err = r.p.sandboxEgress(ctx, r.spec); err != nil {
		log.Printf("provision %s: %v", r.op.Environment, err)
		if errors.Is(err, egress.ErrUnknown) || errors.Is(err, egress.ErrPolicy) {
			return sandbox.Fail(msbctl.CodeInvalidConfig, "egressInvalid")
		}
		return sandbox.Fail(msbctl.CodeUnavailable, "egressUnavailable")
	}
	if r.spec.Secrets, err = r.p.secrets.Resolve(ctx, r.spec.SecretNames); err != nil {
		log.Printf("provision %s: %v", r.op.Environment, err)
		if errors.Is(err, secrets.ErrUnknown) {
			return sandbox.Fail(msbctl.CodeInvalidConfig, "secretUnresolved")
		}
		return sandbox.Fail(msbctl.CodeUnavailable, "secretsUnavailable")
	}
	return nil
}

// sandboxEgress is what a new sandbox may reach beyond the host's own rule
// groups: the policy's default groups, the profile's groups, then the
// profile's own entries.
func (p *provider) sandboxEgress(ctx context.Context, spec profile.Spec) ([]string, error) {
	policy, err := p.policy.Load(ctx)
	if err != nil {
		return nil, err
	}
	return policy.Expand(spec.EgressGroups, spec.EgressAllow)
}

// create places the sandbox, creates it and checkpoints it.
func (r *provisioning) create(ctx context.Context) *sandbox.Failure {
	r.progress(ctx, "provision", 0)
	host, f := sandbox.PlaceOrReuse(ctx, r.client, r.p.healer, r.registry.Candidates(r.spec.Placement), r.spec, r.op.ID)
	if f != nil {
		return f
	}
	r.host = host
	rec, err := r.client.Provision(ctx, host, r.op.Environment, sandbox.ProvisionRequest(r.spec, r.op, r.api, r.p.now()))
	if err != nil {
		log.Printf("provision %s on %s: %v", r.op.Environment, host.Name, err)
		if errors.Is(err, msbctl.ErrTooLarge) {
			return sandbox.Fail(msbctl.CodeInvalidConfig, "requestTooLarge")
		}
		return sandbox.FailureOf(err, "provisionFailed")
	}
	r.record = rec
	if _, err := r.callbacks.CheckpointExecutorResource(ctx, &pluginsdk.CheckpointExecutorResourceRequest{
		Context: r.rc, Resource: descriptorFor(host.Name, rec), Phase: "provisioned",
	}); err != nil {
		// Kandev now drives cleanup by operation id, which Destroy and
		// Recover resolve through `find`.
		log.Printf("provision %s: checkpoint: %v", r.op.Environment, err)
		return sandbox.Fail(msbctl.CodeUnavailable, "checkpointFailed")
	}
	r.progress(ctx, "provision", 1)
	return nil
}

// bootstrap streams agentctl from Kandev and starts it in the sandbox.
func (r *provisioning) bootstrap(ctx context.Context) *sandbox.Failure {
	r.progress(ctx, "artifact", 0)
	artifact, err := readArtifact(ctx, r.callbacks, r.rc, r.boot.ArtifactID, r.record.Platform)
	if err != nil {
		log.Printf("provision %s: agentctl artifact: %v", r.op.Environment, err)
		return sandbox.Fail(msbctl.CodeUnavailable, "artifactUnavailable")
	}
	r.progress(ctx, "artifact", 1)

	r.progress(ctx, "bootstrap", 0)
	rec, err := r.client.Agentctl(ctx, r.host, r.op.Environment, sandbox.AgentctlRequest(artifact, r.boot.Nonce), bytes.NewReader(artifact.Binary))
	if err != nil {
		log.Printf("provision %s: agentctl: %v", r.op.Environment, err)
		return sandbox.FailureOf(err, "agentctlFailed")
	}
	r.record = rec
	r.progress(ctx, "bootstrap", 1)
	r.progress(ctx, "readiness", 1)
	return nil
}

// progress reports a stage; failures are logged, never fatal.
func (r *provisioning) progress(ctx context.Context, stage string, done uint32) {
	if _, err := r.callbacks.ReportExecutorProgress(ctx, &pluginsdk.ReportExecutorProgressRequest{
		Context: r.rc, Stage: stage, Completed: done, Total: 1,
	}); err != nil {
		log.Printf("progress %s: %v", stage, err)
	}
}

// readArtifact streams agentctl from Kandev and verifies it before anything
// is sent to a host.
func readArtifact(ctx context.Context, api pluginsdk.ExecutorProviderHostAPI, rc *pluginsdk.ExecutorProviderRequestContext, artifactID, platform string) (sandbox.Artifact, error) {
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
		return sandbox.Artifact{}, err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); want == "" || !strings.EqualFold(got, want) {
		return sandbox.Artifact{}, errors.New("artifact digest does not match")
	}
	return sandbox.Artifact{Binary: buf.Bytes(), SHA256: strings.ToLower(want), Version: version}, nil
}
