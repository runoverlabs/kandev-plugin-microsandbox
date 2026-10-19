package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/sshx"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

// fakeHost keeps state and secrets in memory. State values go through JSON,
// as they do over the wire, so numbers come back as float64.
type fakeHost struct {
	pluginsdk.UnimplementedHostData

	mu       sync.Mutex
	state    map[string]map[string]any
	secrets  map[string]string
	stateErr error
}

func newFakeHost() *fakeHost {
	return &fakeHost{state: map[string]map[string]any{}, secrets: map[string]string{}}
}

func stateKey(scope, scopeID, key string) string { return scope + "/" + scopeID + "/" + key }

func (h *fakeHost) GetState(_ context.Context, scope, scopeID, key string) (map[string]any, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stateErr != nil {
		return nil, false, h.stateErr
	}
	v, ok := h.state[stateKey(scope, scopeID, key)]
	return v, ok, nil
}

func (h *fakeHost) SetState(_ context.Context, scope, scopeID, key string, value map[string]any) error {
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
	if h.stateErr != nil {
		return h.stateErr
	}
	h.state[stateKey(scope, scopeID, key)] = copied
	return nil
}

func (h *fakeHost) DeleteState(_ context.Context, scope, scopeID, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.state, stateKey(scope, scopeID, key))
	return nil
}

func (h *fakeHost) ListState(context.Context, string, string) ([]pluginsdk.StateEntry, error) {
	return nil, nil
}

func (h *fakeHost) GetConfig(context.Context) (map[string]any, error) { return map[string]any{}, nil }
func (h *fakeHost) RevealSecret(context.Context, string) (string, error) {
	return "", nil
}

func (h *fakeHost) GetSecret(_ context.Context, key string) (string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.secrets[key]
	return v, ok, nil
}

func (h *fakeHost) SetSecret(_ context.Context, key, value string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets[key] = value
	return nil
}

func (h *fakeHost) DeleteSecret(_ context.Context, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.secrets, key)
	return nil
}

func (h *fakeHost) EmitEvent(context.Context, string, map[string]any) error { return nil }

func newRuntime(t *testing.T, host pluginsdk.Host) *Runtime {
	t.Helper()
	r := NewRuntime()
	r.maintEvery = 0 // tests drive maintainHosts directly
	if host != nil {
		r.SetHost(host)
	}
	t.Cleanup(r.Close)
	return r
}

// call runs one action and decodes its JSON body.
func call(t *testing.T, r *Runtime, action string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	res, err := r.HandleAction(context.Background(), &pluginsdk.PluginActionRequest{ActionKey: action, Body: raw})
	require.NoError(t, err, "actions must never return a Go error")
	var out map[string]any
	require.NoError(t, json.Unmarshal(res.Body, &out), string(res.Body))
	return res.Status, out
}

// pluginKey returns the runtime's public key, generating it.
func pluginKey(t *testing.T, r *Runtime) ssh.PublicKey {
	t.Helper()
	status, body := call(t, r, ActionHostsList, map[string]any{})
	require.Equal(t, 200, status, body)
	key, err := sshx.ParseHostKey(body["public_key"].(string))
	require.NoError(t, err)
	return key
}

// msbctlHost answers `msbctl kandev <verb>` and the generic verbs
// (`msbctl ls --json`, …) by verb.
func msbctlHost(replies map[string]sshtest.Reply) sshtest.Handler {
	return func(command string, _ []byte) sshtest.Reply {
		fields := strings.Fields(command)
		if len(fields) < 2 || fields[0] != "msbctl" {
			return sshtest.Reply{Status: 126}
		}
		verb := fields[1]
		if verb == "kandev" && len(fields) > 2 {
			verb = fields[2]
		}
		if reply, ok := replies[verb]; ok {
			return reply
		}
		return sshtest.Reply{Status: 126}
	}
}

const healthyJSON = `{"protocol":1,"msbctl_version":"0.4.0","msb_version":"0.7.7","kvm":true,"enabled":true,
 "platform":"linux-amd64","base_url":"https://sbx-01.tailnet.ts.net",
 "capacity":{"max_sandboxes":12,"sandboxes":0,"max_cpus":32,"cpus":0,"max_memory_mib":98304,"memory_mib":0},
 "serve":{"ok":true,"mode":"tailscale"},"tls":{"installed":false}}`

func hostBody(name, dest, hostKey string, labels ...string) map[string]any {
	if labels == nil {
		labels = []string{}
	}
	return map[string]any{
		"name": name, "ssh": dest, "host_key": hostKey,
		"base_url": "https://" + name + ".tailnet.ts.net", "labels": labels,
	}
}

// Any syntactically valid ed25519 key line, for hosts never dialed.
const unusedHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0lGH0Mvc2PwPW7y5mHLUVHMwBNN1k6d0jP2iTgNPg"
