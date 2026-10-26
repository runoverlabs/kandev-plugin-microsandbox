package sandbox

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"time"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
)

// Bootstrap is Kandev's bootstrap_json. It is transient: never logged,
// stored, checkpointed or put in argv. The one exception is api_url,
// Kandev's public address, which the readiness view keeps.
type Bootstrap struct {
	Nonce       string `json:"nonce"`
	RuntimePort int    `json:"runtime_port"`
	APIURL      string `json:"api_url"`
	ArtifactID  string `json:"artifact_id"`
}

// ParseBootstrap reads bootstrap_json, filling its defaults, and the address
// a sandbox reaches Kandev's API at.
func ParseBootstrap(raw string) (Bootstrap, msbctl.KandevAPI, error) {
	var b Bootstrap
	if err := json.Unmarshal([]byte(raw), &b); err != nil || b.Nonce == "" {
		return b, msbctl.KandevAPI{}, errors.New("bootstrap descriptor is unreadable")
	}
	if b.RuntimePort == 0 {
		b.RuntimePort = ControlPort
	}
	if b.RuntimePort != ControlPort {
		return b, msbctl.KandevAPI{}, errors.New("bootstrap runtime port is not the published control port")
	}
	if b.ArtifactID == "" {
		b.ArtifactID = "agentctl"
	}
	api, err := kandevAPI(b.APIURL)
	return b, api, err
}

func kandevAPI(raw string) (msbctl.KandevAPI, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return msbctl.KandevAPI{}, errors.New("bootstrap api_url is unusable")
	}
	port := map[string]int{"https": 443, "http": 80}[u.Scheme]
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return msbctl.KandevAPI{}, errors.New("bootstrap api_url has an invalid port")
		}
	}
	return msbctl.KandevAPI{Host: u.Hostname(), Port: port}, nil
}

// Operation is Kandev's identity for one provision.
type Operation struct {
	ID          string
	Environment string
	InputDigest string
}

// Complete reports whether every part of the identity is set.
func (o Operation) Complete() bool { return o.ID != "" && o.Environment != "" && o.InputDigest != "" }

// ProvisionRequest is what msbctl is asked to create for spec. It carries
// secret values, so it is never logged.
func ProvisionRequest(spec profile.Spec, op Operation, api msbctl.KandevAPI, now time.Time) msbctl.ProvisionRequest {
	out := msbctl.ProvisionRequest{
		OperationID: op.ID, InputDigest: op.InputDigest,
		Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, DiskGiB: spec.DiskGiB, WorkspaceGiB: spec.WorkspaceGiB,
		ExpiresAt:    now.UTC().Add(time.Duration(spec.MaxLifetimeHours) * time.Hour).Format(time.RFC3339),
		KandevAPI:    api,
		EgressAllow:  spec.EgressAllow,
		PrivateNames: spec.PrivateNames,
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

// Artifact is a verified agentctl binary.
type Artifact struct {
	Binary  []byte
	SHA256  string
	Version string
}

// AgentctlRequest installs and starts agentctl with the bootstrap nonce.
func AgentctlRequest(a Artifact, nonce string) msbctl.AgentctlRequest {
	return msbctl.AgentctlRequest{
		SHA256: a.SHA256, Size: int64(len(a.Binary)), Version: a.Version, Nonce: nonce,
		RuntimePort: ControlPort, Args: []string{"-port=" + strconv.Itoa(ControlPort)},
		Env: map[string]string{
			// msb publishes ports by connecting to the guest's own address,
			// so a server bound to loopback inside the guest is never reached.
			"AGENTCTL_LISTEN_HOST":        "0.0.0.0",
			"AGENTCTL_INSTANCE_PORT_BASE": strconv.Itoa(InstancePortFirst),
			"AGENTCTL_INSTANCE_PORT_MAX":  strconv.Itoa(InstancePortLast),
		},
	}
}
