package msbctl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"kandev-plugin-microsandbox/internal/hosts"
)

// Record is the document provision, inspect, find, start, stop and expiry
// return. It carries names, ports and timestamps only, never a secret.
type Record struct {
	Env         string         `json:"env"`
	Name        string         `json:"name"`
	OperationID string         `json:"operation_id"`
	InputDigest string         `json:"input_digest"`
	State       string         `json:"state"` // creating | running | stopped | absent
	Platform    string         `json:"platform"`
	Image       string         `json:"image"`
	CreatedAt   string         `json:"created_at"`
	ExpiresAt   string         `json:"expires_at"`
	MaxExpires  string         `json:"max_expires_at"`
	Generation  int            `json:"generation"`
	Ports       map[string]int `json:"ports"`
	Agentctl    struct {
		Running bool   `json:"running"`
		SHA256  string `json:"sha256"`
	} `json:"agentctl"`
}

// Record states.
const (
	StateCreating = "creating"
	StateRunning  = "running"
	StateStopped  = "stopped"
	StateAbsent   = "absent"
)

// EnvVar is one non-secret guest variable.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Secret is a host-bound secret. Value is secret; Hosts may be omitted on
// start, where the sandbox already knows them.
type Secret struct {
	Name  string   `json:"name"`
	Value string   `json:"value"`
	Hosts []string `json:"hosts,omitempty"`
}

// Registry is a private image's pull credentials.
type Registry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KandevAPI is the Kandev API endpoint the sandbox must reach.
type KandevAPI struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ProvisionRequest is provision's stdin header. It holds secret values.
type ProvisionRequest struct {
	OperationID string    `json:"operation_id"`
	InputDigest string    `json:"input_digest"`
	Image       string    `json:"image"`
	CPUs        int       `json:"cpus"`
	MemoryMiB   int       `json:"memory_mib"`
	DiskGiB     int       `json:"disk_gib"`
	ExpiresAt   string    `json:"expires_at"`
	KandevAPI   KandevAPI `json:"kandev_api"`
	EgressAllow []string  `json:"egress_allow,omitempty"`
	Env         []EnvVar  `json:"env,omitempty"`
	Secrets     []Secret  `json:"secrets,omitempty"`
	Registry    *Registry `json:"registry,omitempty"`
}

// AgentctlRequest is agentctl's stdin header. Nonce is secret.
type AgentctlRequest struct {
	SHA256      string            `json:"sha256"`
	Size        int64             `json:"size"`
	Version     string            `json:"version"`
	Nonce       string            `json:"nonce"`
	RuntimePort int               `json:"runtime_port"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
}

// Lease is lease's answer. Headers may carry a token: treat it as secret.
type Lease struct {
	BaseURL    string            `json:"base_url"`
	ExpiresAt  string            `json:"expires_at"`
	Generation string            `json:"generation"`
	Headers    map[string]string `json:"headers,omitempty"`
}

func header(v any) (io.Reader, error) {
	line, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(append(line, '\n')), nil
}

func (c *Client) record(ctx context.Context, h hosts.Host, args []string, stdin io.Reader) (Record, error) {
	var out struct {
		Record *Record `json:"record"`
	}
	if err := c.call(ctx, h, args, stdin, &out); err != nil {
		return Record{}, err
	}
	if out.Record == nil || out.Record.Name == "" {
		return Record{}, &Error{Code: CodeUnavailable}
	}
	return *out.Record, nil
}

// Provision runs `msbctl kandev provision ENV` with req on stdin. It is
// idempotent on the host by operation id and input digest.
func (c *Client) Provision(ctx context.Context, h hosts.Host, env string, req ProvisionRequest) (Record, error) {
	stdin, err := header(req)
	if err != nil {
		return Record{}, err
	}
	return c.record(ctx, h, []string{"provision", env}, stdin)
}

// Agentctl runs `msbctl kandev agentctl ENV`: the header line, then exactly
// req.Size bytes of the binary.
func (c *Client) Agentctl(ctx context.Context, h hosts.Host, env string, req AgentctlRequest, binary io.Reader) (Record, error) {
	head, err := header(req)
	if err != nil {
		return Record{}, err
	}
	return c.record(ctx, h, []string{"agentctl", env}, io.MultiReader(head, io.LimitReader(binary, req.Size)))
}

// Inspect runs `msbctl kandev inspect ENV`, which checks agentctl live.
func (c *Client) Inspect(ctx context.Context, h hosts.Host, env string) (Record, error) {
	return c.record(ctx, h, []string{"inspect", env}, nil)
}

// Find runs `msbctl kandev find --operation OP`.
func (c *Client) Find(ctx context.Context, h hosts.Host, operationID string) (Record, error) {
	return c.record(ctx, h, []string{"find", "--operation", operationID}, nil)
}

// Start runs `msbctl kandev start ENV` with exactly the secrets the sandbox
// binds on stdin.
func (c *Client) Start(ctx context.Context, h hosts.Host, env string, secrets []Secret) (Record, error) {
	if secrets == nil {
		secrets = []Secret{}
	}
	stdin, err := header(map[string]any{"secrets": secrets})
	if err != nil {
		return Record{}, err
	}
	return c.record(ctx, h, []string{"start", env}, stdin)
}

// Lease runs `msbctl kandev lease ENV PORT`.
func (c *Client) Lease(ctx context.Context, h hosts.Host, env string, port int) (Lease, error) {
	var out struct {
		Lease *Lease `json:"lease"`
	}
	if err := c.call(ctx, h, []string{"lease", env, strconv.Itoa(port)}, nil, &out); err != nil {
		return Lease{}, err
	}
	if out.Lease == nil || out.Lease.BaseURL == "" {
		return Lease{}, &Error{Code: CodeUnavailable}
	}
	return *out.Lease, nil
}

// Destroy runs `msbctl kandev destroy ENV`. Success includes "was already
// gone".
func (c *Client) Destroy(ctx context.Context, h hosts.Host, env string) error {
	var out struct {
		Destroyed bool `json:"destroyed"`
	}
	if err := c.call(ctx, h, []string{"destroy", env}, nil, &out); err != nil {
		return err
	}
	if !out.Destroyed {
		return &Error{Code: CodeUnavailable}
	}
	return nil
}
