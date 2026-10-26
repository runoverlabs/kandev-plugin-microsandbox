package plugin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/readiness"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func readinessItems(t *testing.T, r *Runtime) (bool, map[string]map[string]any) {
	t.Helper()
	status, body := call(t, r, ActionSetupStatus, map[string]any{})
	require.Equal(t, 200, status, body)
	items := map[string]map[string]any{}
	for _, i := range body["items"].([]any) {
		item := i.(map[string]any)
		items[item["key"].(string)] = item
	}
	return body["ready"].(bool), items
}

func TestSetupStatusOnAFreshInstall(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	ready, items := readinessItems(t, r)
	assert.False(t, ready)
	assert.Equal(t, readiness.Missing, items["root"]["state"])
	assert.Equal(t, readiness.Unknown, items["api_url"]["state"], "nothing in the environment, no launch yet")
	assert.NotEmpty(t, items["api_url"]["fix"])
	assert.Equal(t, readiness.Missing, items["hosts"]["state"])
}

func TestSetupStatusReadsTheAPIURLFromKandevsEnvironment(t *testing.T) {
	for raw, want := range map[string]string{
		"https://kandev.vild.party":   readiness.OK,
		"https://kandev.example.com/": readiness.OK,
		"http://kandev.example.com":   readiness.Invalid,
		"https://localhost:8080":      readiness.Invalid,
		"https://192.168.2.6":         readiness.Invalid,
		"https://127.0.0.1":           readiness.Invalid,
		"https://[fe80::1]":           readiness.Invalid,
		"https://u:p@kandev.example":  readiness.Invalid,
		"https://kandev.example?x=1":  readiness.Invalid,
		"kandev.example.com":          readiness.Invalid,
	} {
		r := newRuntime(t, newFakeHost())
		r.getenv = func(name string) string {
			if name == readiness.APIURLEnv {
				return raw
			}
			return ""
		}
		_, items := readinessItems(t, r)
		assert.Equal(t, want, items["api_url"]["state"], raw)
	}
}

// A URL set in Kandev's config file never reaches the plugin's environment,
// but every launch carries it.
func TestSetupStatusFallsBackToTheLastLaunch(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	f.r.getenv = func(string) string { return "" }
	f.r.now = func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }
	require.Nil(t, f.provision(t, "env-1", "op-1", fullProfile()).Error)
	_, items := readinessItems(t, f.r)
	assert.Equal(t, readiness.OK, items["api_url"]["state"])
	assert.Contains(t, items["api_url"]["detail"], "https://kandev.tailnet.ts.net/api/v1")
	assert.Contains(t, items["api_url"]["detail"], "2026-10-19T12:00:00Z")
}

func TestSetupStatusReadyWhenEverythingIs(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	f.r.getenv = func(string) string { return "https://kandev.example.com" }
	_, items := readinessItems(t, f.r)
	assert.Equal(t, readiness.Untrusted, items["root"]["state"], "the system roots do not hold it")

	f.trustRoot(t)
	p := newProxyHost()
	f.addProxyHost(t, "sbx-01", p)
	_, items = readinessItems(t, f.r)
	assert.Equal(t, readiness.Unchecked, items["hosts"]["state"])

	f.r.maintainHosts(t.Context())
	ready, items := readinessItems(t, f.r)
	assert.Equal(t, readiness.OK, items["root"]["state"])
	assert.Equal(t, readiness.OK, items["hosts"]["state"], items["hosts"])
	assert.True(t, ready, items)
}

func TestSetupStatusNamesFailingHosts(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: healthyJSON[:10]}}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	r.maintainHosts(t.Context())
	_, items := readinessItems(t, r)
	assert.Equal(t, readiness.Failing, items["hosts"]["state"])
	assert.Contains(t, items["hosts"]["detail"], "sbx-01: unavailable")
}
