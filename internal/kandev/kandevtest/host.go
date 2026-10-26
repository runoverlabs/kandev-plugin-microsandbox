// Package kandevtest is an in-memory Kandev host for tests: plugin state and
// the plugin secret store, with the same JSON round trip and secret key rule
// the real host applies.
package kandevtest

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"sync"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// Host keeps state and secrets in memory. State values go through JSON, as
// they do over the wire, so numbers come back as float64. Every method it
// does not implement panics through the embedded UnimplementedHostData, which
// names the missing call.
type Host struct {
	pluginsdk.UnimplementedHostData

	mu      sync.Mutex
	state   map[string]map[string]any
	secrets map[string]string

	// StateErr, when set, fails every state read and write.
	StateErr error
}

// NewHost returns a host with no state and no secrets.
func NewHost() *Host {
	return &Host{state: map[string]map[string]any{}, secrets: map[string]string{}}
}

func stateKey(scope, scopeID, key string) string { return scope + "/" + scopeID + "/" + key }

func (h *Host) GetState(_ context.Context, scope, scopeID, key string) (map[string]any, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.StateErr != nil {
		return nil, false, h.StateErr
	}
	v, ok := h.state[stateKey(scope, scopeID, key)]
	return v, ok, nil
}

func (h *Host) SetState(_ context.Context, scope, scopeID, key string, value map[string]any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var copied map[string]any
	if err := json.Unmarshal(raw, &copied); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.StateErr != nil {
		return h.StateErr
	}
	h.state[stateKey(scope, scopeID, key)] = copied
	return nil
}

func (h *Host) DeleteState(_ context.Context, scope, scopeID, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.state, stateKey(scope, scopeID, key))
	return nil
}

func (h *Host) ListState(context.Context, string, string) ([]pluginsdk.StateEntry, error) {
	return nil, nil
}

func (h *Host) GetConfig(context.Context) (map[string]any, error) { return map[string]any{}, nil }

func (h *Host) RevealSecret(context.Context, string) (string, error) { return "", nil }

func (h *Host) GetSecret(_ context.Context, key string) (string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.secrets[key]
	return v, ok, nil
}

// secretKeyPattern is Kandev's rule for plugin secret keys (pluginSecretKeyPattern).
var secretKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func (h *Host) SetSecret(_ context.Context, key, value string) error {
	if !secretKeyPattern.MatchString(key) {
		return fmt.Errorf("invalid secret key %q", key)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets[key] = value
	return nil
}

func (h *Host) DeleteSecret(_ context.Context, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.secrets, key)
	return nil
}

func (h *Host) EmitEvent(context.Context, string, map[string]any) error { return nil }

// Secret returns a stored secret, for a test to check what was written.
func (h *Host) Secret(key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.secrets[key]
}

// State returns a copy of every state document, by scope/scope id/key, for a
// test to check what was written.
func (h *Host) State() map[string]map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, _ := json.Marshal(h.state)
	var out map[string]map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// Secrets returns a copy of the secret store.
func (h *Host) Secrets() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]string, len(h.secrets))
	maps.Copy(out, h.secrets)
	return out
}
