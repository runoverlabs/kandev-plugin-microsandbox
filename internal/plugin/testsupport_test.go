package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/kandev/kandevtest"
	"kandev-plugin-microsandbox/internal/sshx"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

// fakeHost is the in-memory Kandev host the tests drive the runtime with.
type fakeHost = kandevtest.Host

func newFakeHost() *fakeHost { return kandevtest.NewHost() }

// Where the plugin keeps its keys and secret values in the secret store.
const (
	sshKeySecret      = "ssh-key"
	caKeySecret       = "ca-key"
	secretValuePrefix = "secret."
)

func newRuntime(t *testing.T, host pluginsdk.Host) *Runtime {
	t.Helper()
	r := NewRuntime()
	r.maintEvery = 0 // tests drive maintainHosts directly
	r.getenv = func(string) string { return "" }
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
 "serve":{"ok":true,"mode":"tailscale"},"tls":{"installed":false},"features":["workspace_disk"]}`

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
