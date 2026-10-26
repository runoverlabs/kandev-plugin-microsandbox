package plugin

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/profile"
	"kandev-plugin-microsandbox/internal/sandbox"
	"kandev-plugin-microsandbox/internal/sshx"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func TestListGeneratesOneKeyAndKeepsIt(t *testing.T) {
	host := newFakeHost()
	r := newRuntime(t, host)
	status, body := call(t, r, ActionHostsList, nil)
	require.Equal(t, 200, status)
	publicKey := body["public_key"].(string)
	assert.True(t, strings.HasPrefix(publicKey, "ssh-ed25519 "))
	assert.Equal(t, "msbctl host authorize '"+publicKey+"' --kandev", body["authorize"])
	assert.Equal(t, []any{}, body["hosts"])
	private := host.Secret(sshKeySecret)
	require.NotEmpty(t, private)

	// A restarted plugin process reads the same key back.
	again := newRuntime(t, host)
	_, body = call(t, again, ActionHostsList, nil)
	assert.Equal(t, publicKey, body["public_key"])
	assert.Equal(t, private, host.Secret(sshKeySecret))
	assert.NotContains(t, body, "private", "the private key never leaves the secret store")
}

func TestAddUpdateDrainRoundTrip(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	status, body := call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey, "Default"))
	require.Equal(t, 201, status, body)
	saved := body["host"].(map[string]any)
	assert.Equal(t, []any{"default"}, saved["labels"])
	assert.True(t, strings.HasPrefix(saved["fingerprint"].(string), "SHA256:"))

	status, body = call(t, r, ActionHostsDrain, map[string]any{"name": "sbx-01", "draining": true})
	require.Equal(t, 200, status, body)
	assert.Equal(t, true, body["host"].(map[string]any)["draining"])

	status, body = call(t, r, ActionHostsUpdate, hostBody("sbx-01", "msb@sbx-01:2222", unusedHostKey, "gpu"))
	require.Equal(t, 200, status, body)
	updated := body["host"].(map[string]any)
	assert.Equal(t, "msb@sbx-01:2222", updated["ssh"])
	assert.Equal(t, true, updated["draining"], "update keeps the draining flag")

	_, body = call(t, r, ActionHostsList, nil)
	list := body["hosts"].([]any)
	require.Len(t, list, 1)
	assert.Equal(t, []any{"gpu"}, list[0].(map[string]any)["labels"])
}

// Without a root there is no certificate to issue, so a write never reaches
// for the plugin's key, let alone generates one.
func TestAddWithoutARootLeavesTheKeyAlone(t *testing.T) {
	host := newFakeHost()
	r := newRuntime(t, host)
	status, body := call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey))
	require.Equal(t, 201, status, body)
	assert.NotContains(t, body, "tls")
	assert.Empty(t, host.Secret(sshKeySecret))
}

func TestAddRejectsBadInput(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	status, body := call(t, r, ActionHostsAdd, hostBody("Bad Name", "sbx-01", "ssh-ed25519 AAAA", ""))
	assert.Equal(t, 422, status)
	assert.NotEmpty(t, body["fields"])

	status, _ = call(t, r, ActionHostsAdd, map[string]any{"name": "sbx-01", "surprise": true})
	assert.Equal(t, 422, status, "unknown fields are refused")

	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey))))
	assert.Equal(t, 409, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey))))
	assert.Equal(t, 404, first(call(t, r, ActionHostsUpdate, hostBody("sbx-02", "msb@sbx-02", unusedHostKey))))
	assert.Equal(t, 404, first(call(t, r, ActionHostsDrain, map[string]any{"name": "sbx-02", "draining": true})))
	assert.Equal(t, 422, first(call(t, r, ActionHostsDrain, map[string]any{"name": "sbx-01"})))
}

func TestAddRejectsAKeyThatDoesNotParse(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	// Base64 of the right shape that is not an ed25519 key.
	status, body := call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", "ssh-ed25519 AAAAB3NzaC1yc2E="))
	assert.Equal(t, 422, status, body)
}

func TestActionsWithoutHostAreUnavailable(t *testing.T) {
	r := newRuntime(t, nil)
	status, body := call(t, r, ActionHostsList, nil)
	assert.Equal(t, 503, status)
	assert.Contains(t, body["error"], "starting")
}

func TestRegistryFailureDoesNotLeakTheCause(t *testing.T) {
	host := newFakeHost()
	host.StateErr = errors.New("sqlite: disk I/O error at /home/op/.kandev/data/kandev.db")
	r := newRuntime(t, host)
	status, body := call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey))
	assert.Equal(t, 500, status)
	assert.NotContains(t, body["error"], "sqlite")
}

func TestUnknownAction(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	assert.Equal(t, 404, first(call(t, r, "hosts.nope", nil)))
}

func TestScanReturnsTheHostKeyWithoutSavingIt(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, nil, msbctlHost(nil))
	status, body := call(t, r, ActionHostsScan, map[string]any{"ssh": server.Dest("msb")})
	require.Equal(t, 200, status, body)
	assert.Equal(t, server.HostKey, body["host_key"])
	assert.True(t, strings.HasPrefix(body["fingerprint"].(string), "SHA256:"))
	_, list := call(t, r, ActionHostsList, nil)
	assert.Empty(t, list["hosts"])

	assert.Equal(t, 422, first(call(t, r, ActionHostsScan, map[string]any{"ssh": "nouser"})))
	assert.Equal(t, 502, first(call(t, r, ActionHostsScan, map[string]any{"ssh": "msb@" + closedAddress(t)})))
}

func TestTestReportsHealthyHost(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: healthyJSON}}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))

	status, body := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	require.Equal(t, 200, status, body)
	assert.Equal(t, true, body["ok"], body)
	assert.Equal(t, "0.7.7", body["health"].(map[string]any)["msb_version"])
	assert.Equal(t, "msbctl kandev health", server.Execs()[0].Command)
	assert.NotContains(t, body, "warning")
}

func TestTestWarnsWhenTheHostReportsAnotherBaseURL(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	other := strings.Replace(healthyJSON, "https://sbx-01.tailnet.ts.net", "https://sbx-07.tailnet.ts.net", 1)
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: other}}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	_, body := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, true, body["ok"])
	assert.Contains(t, body["warning"], "https://sbx-07.tailnet.ts.net")
}

func TestTestDiagnoses(t *testing.T) {
	cases := []struct {
		label   string
		replies map[string]sshtest.Reply
		problem string
	}{
		{"refused by forced command", map[string]sshtest.Reply{}, "refused"},
		{"disabled", map[string]sshtest.Reply{"health": {Stdout: strings.Replace(healthyJSON, `"enabled":true`, `"enabled":false`, 1)}}, "disabled"},
		{"no kvm", map[string]sshtest.Reply{"health": {Stdout: strings.Replace(healthyJSON, `"kvm":true`, `"kvm":false`, 1)}}, "no_kvm"},
		{"no data path", map[string]sshtest.Reply{"health": {Stdout: strings.Replace(healthyJSON, `"serve":{"ok":true,`, `"serve":{"ok":false,`, 1)}}, "no_data_path"},
		{"protocol", map[string]sshtest.Reply{"health": {Stdout: strings.Replace(healthyJSON, `"protocol":1`, `"protocol":2`, 1)}}, "protocol"},
		{"broken msbctl", map[string]sshtest.Reply{"health": {Stdout: "boom", Status: 1}}, "unavailable"},
	}
	for _, c := range cases {
		r := newRuntime(t, newFakeHost())
		server := sshtest.Start(t, pluginKey(t, r), msbctlHost(c.replies))
		require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
		_, body := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
		assert.Equal(t, false, body["ok"], c.label)
		assert.Equal(t, c.problem, body["problem"], c.label)
	}
}

func TestTestDiagnosesKeyProblems(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	key := pluginKey(t, r)
	authorized := sshtest.Start(t, key, msbctlHost(map[string]sshtest.Reply{"health": {Stdout: healthyJSON}}))
	stranger := sshtest.Start(t, nil, msbctlHost(nil))

	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("pinned-wrong", authorized.Dest("msb"), stranger.HostKey))))
	_, body := call(t, r, ActionHostsTest, map[string]any{"name": "pinned-wrong"})
	assert.Equal(t, "host_key_mismatch", body["problem"])
	assert.Empty(t, authorized.Execs(), "nothing runs on a host whose key does not match")

	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("not-authorized", stranger.Dest("msb"), stranger.HostKey))))
	_, body = call(t, r, ActionHostsTest, map[string]any{"name": "not-authorized"})
	assert.Equal(t, "not_authorized", body["problem"])
	assert.Contains(t, body["hint"], "msbctl host authorize '"+sshx.AuthorizedLine(key)+"' --kandev")

	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("gone", "msb@"+closedAddress(t), stranger.HostKey))))
	_, body = call(t, r, ActionHostsTest, map[string]any{"name": "gone"})
	assert.Equal(t, "unreachable", body["problem"])
}

func TestRemove(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	key := pluginKey(t, r)
	busy := sshtest.Start(t, key, msbctlHost(map[string]sshtest.Reply{"ls": {Stdout: `{"msbctl":"0.3.0","sandboxes":[{"name":"k-e1","source":"kandev","state":"running","kandev":{"env":"e1","name":"k-e1","state":"running"}}]}`}}))
	idle := sshtest.Start(t, key, msbctlHost(map[string]sshtest.Reply{"ls": {Stdout: `{"msbctl":"0.3.0","sandboxes":[]}`}}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("busy", busy.Dest("msb"), busy.HostKey))))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("idle", idle.Dest("msb"), idle.HostKey))))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("gone", "msb@"+closedAddress(t), idle.HostKey))))

	status, body := call(t, r, ActionHostsRemove, map[string]any{"name": "busy"})
	assert.Equal(t, 409, status)
	assert.Equal(t, float64(1), body["sandboxes"])

	assert.Equal(t, 200, first(call(t, r, ActionHostsRemove, map[string]any{"name": "idle"})))
	assert.Equal(t, 502, first(call(t, r, ActionHostsRemove, map[string]any{"name": "gone"})))
	assert.Equal(t, 200, first(call(t, r, ActionHostsRemove, map[string]any{"name": "gone", "force": true})))
	assert.Equal(t, 404, first(call(t, r, ActionHostsRemove, map[string]any{"name": "idle"})))

	_, list := call(t, r, ActionHostsList, nil)
	names := []string{}
	for _, h := range list["hosts"].([]any) {
		names = append(names, h.(map[string]any)["name"].(string))
	}
	assert.Equal(t, []string{"busy"}, names)
}

func TestActionResponsesAreJSON(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	res, err := r.HandleAction(context.Background(), &pluginsdk.PluginActionRequest{ActionKey: ActionHostsList})
	require.NoError(t, err)
	assert.Equal(t, "application/json", res.Headers["Content-Type"])
}

func first(status int, _ map[string]any) int { return status }

// closedAddress returns a loopback address nothing listens on.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

// A protocol-1 host without the workspace disk (msb-manager 0.4.0) would run
// sandboxes with no /workspace: Test names the fix, and placement skips it.
func TestOutdatedHostIsDiagnosedAndNeverPlaced(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	old := strings.Replace(healthyJSON, `,"features":["workspace_disk"]`, ``, 1)
	require.NotEqual(t, healthyJSON, old)
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: old}}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey, "default"))))
	_, body := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "outdated", body["problem"])
	assert.Contains(t, body["hint"], "workspace_disk")

	client, err := r.connect(t.Context())
	require.NoError(t, err)
	registry, err := r.registry.Load(t.Context())
	require.NoError(t, err)
	_, failure := sandbox.PlaceOrReuse(t.Context(), client, r.provider.healer, registry.Hosts, profile.Spec{CPUs: 1, MemoryMiB: 512}, "op-1")
	require.NotNil(t, failure)
	assert.Equal(t, "hostsUnreachable", failure.MessageID, "an outdated host is not a candidate")
}
