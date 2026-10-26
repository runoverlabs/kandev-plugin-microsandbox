package sandbox

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"kandev-plugin-microsandbox/internal/msbctl"
)

// Guest ports. Kandev fixes the control port; the instance range is ours to
// choose and is published at create time, three wide because agentctl skips
// a port that is still bound after a restart.
const (
	ControlPort       = 8765
	InstancePortFirst = 41001
	InstancePortLast  = 41003
)

// StateVersion matches supported_state_versions in the manifest.
const StateVersion = 1

// ErrNoState means a resource carries no usable state.
var ErrNoState = errors.New("resource has no usable state")

// State is the descriptor's state_json: what routes every call after
// provision. It is closed by the manifest's resource_state_schema and never
// carries a secret.
type State struct {
	Host        string `json:"host"`
	SandboxName string `json:"sandbox_name"`
	Env         string `json:"env"`
	Image       string `json:"image,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// StateOf is the state of the sandbox rec on host.
func StateOf(host string, rec msbctl.Record) State {
	return State{Host: host, SandboxName: rec.Name, Env: rec.Env, Image: rec.Image, CreatedAt: rec.CreatedAt}
}

// Handle is the resource handle Kandev shows for the state.
func (s State) Handle() string { return "msb:" + s.Host + "/" + s.SandboxName }

// JSON is the state as state_json.
func (s State) JSON() string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// ParseState reads state_json; ErrNoState unless it names a host, an env
// and a sandbox.
func ParseState(raw string) (State, error) {
	if raw == "" {
		return State{}, ErrNoState
	}
	var s State
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.Host == "" || s.Env == "" || s.SandboxName == "" {
		return State{}, ErrNoState
	}
	return s, nil
}

// Kandev's environment states.
const (
	StateRunning    = "running"
	StateSuspended  = "suspended"
	StateTerminated = "terminated"
	StateAbsent     = "absent"
	StateUnknown    = "unknown"
)

var kandevStates = map[string]string{
	msbctl.StateRunning: StateRunning,
	msbctl.StateStopped: StateSuspended,
	msbctl.StateAbsent:  StateAbsent,
}

// KandevState maps the host's view of a sandbox onto Kandev's states. A
// sandbox past its expiry is terminated whatever the host says.
func KandevState(rec msbctl.Record, now time.Time) string {
	if expires, err := time.Parse(time.RFC3339, rec.ExpiresAt); err == nil && !now.Before(expires) {
		return StateTerminated
	}
	if state, found := kandevStates[rec.State]; found {
		return state
	}
	return StateUnknown
}

// LeasablePort reports whether a lease may be resolved for port: the control
// port or an instance port.
func LeasablePort(port int) bool {
	return port == ControlPort || port >= InstancePortFirst && port <= InstancePortLast
}

// ForbiddenLeaseHeader reports the names Kandev refuses in a lease
// (normalizeLeaseHeaders, v0.97.0). A host that sends one would make the
// launch fail later with a generic error; the transport fails it clearly.
func ForbiddenLeaseHeader(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "x-instance-id", "host", "cookie", "set-cookie", "sec-websocket-protocol",
		"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
		"transfer-encoding", "upgrade":
		return true
	}
	return strings.HasPrefix(lower, "proxy-")
}
