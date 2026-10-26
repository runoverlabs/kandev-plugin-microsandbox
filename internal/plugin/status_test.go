package plugin

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func listedStatus(t *testing.T, r *Runtime, name string) map[string]any {
	t.Helper()
	status, body := call(t, r, ActionHostsList, map[string]any{})
	require.Equal(t, 200, status)
	for _, h := range body["hosts"].([]any) {
		host := h.(map[string]any)
		if host["name"] == name {
			s, _ := host["status"].(map[string]any)
			return s
		}
	}
	t.Fatalf("host %s not listed", name)
	return nil
}

// The list shows each host's last check without contacting any host: Test
// and the maintainer record it.
func TestHostListShowsTheLastCheck(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return at }
	withFacts := strings.Replace(healthyJSON, `"features":`, `"host":{"os":"Debian GNU/Linux 13 (trixie)","cpus":16,"memory_total_mib":64000},"features":`, 1)
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{
		"health": {Stdout: withFacts}, "ls": {Stdout: `{"sandboxes":[]}`},
	}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	assert.Nil(t, listedStatus(t, r, "sbx-01"), "never checked")

	require.Equal(t, 200, first(call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})))
	execs := len(server.Execs())
	s := listedStatus(t, r, "sbx-01")
	require.NotNil(t, s)
	assert.Equal(t, "2026-10-19T12:00:00Z", s["checked_at"])
	assert.Equal(t, true, s["ok"])
	facts := s["health"].(map[string]any)["host"].(map[string]any)
	assert.Equal(t, "Debian GNU/Linux 13 (trixie)", facts["os"])
	assert.Equal(t, float64(16), facts["cpus"])
	assert.Equal(t, execs, len(server.Execs()), "listing contacts no host")

	at = at.Add(time.Hour)
	r.maintainHosts(t.Context())
	assert.Equal(t, "2026-10-19T13:00:00Z", listedStatus(t, r, "sbx-01")["checked_at"], "the maintainer refreshes it")

	require.Equal(t, 200, first(call(t, r, ActionHostsRemove, map[string]any{"name": "sbx-01"})))
	statuses, err := r.status.Load(t.Context())
	require.NoError(t, err)
	assert.NotContains(t, statuses, "sbx-01", "a removed host's status goes with it")
}

func TestHostListShowsAFailingCheck(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{
		"health": {Stdout: strings.Replace(healthyJSON, `"kvm":true`, `"kvm":false`, 1)},
	}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	r.maintainHosts(t.Context())
	s := listedStatus(t, r, "sbx-01")
	assert.Equal(t, false, s["ok"])
	assert.Equal(t, "no_kvm", s["problem"])
}
