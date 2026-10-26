package plugin

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func upgradeHost(t *testing.T, version string, selfUpdate sshtest.Reply) (*Runtime, *sshtest.Server) {
	t.Helper()
	r := newRuntime(t, newFakeHost())
	health := strings.Replace(healthyJSON, `"msbctl_version":"0.4.0"`, `"msbctl_version":"`+version+`"`, 1)
	server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: health}, "self-update": selfUpdate}))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	return r, server
}

func runUpgrade(t *testing.T, r *Runtime) map[string]any {
	t.Helper()
	status, started := call(t, r, ActionHostsUpgrade, map[string]any{"name": "sbx-01"})
	require.Equal(t, 202, status, started)
	return waitForJob(t, r, started["id"].(string))
}

func withUpgradeTarget(t *testing.T, version string) {
	old := hostsetup.UpgradeTarget
	hostsetup.UpgradeTarget = version
	t.Cleanup(func() { hostsetup.UpgradeTarget = old })
}

func TestUpgradeUpdatesThroughThePluginsKey(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	r, server := upgradeHost(t, "0.6.0", sshtest.Reply{Stdout: `{"msbctl_version": "0.7.0", "updated": true}`})
	job := runUpgrade(t, r)
	steps := jobSteps(job)
	assert.Equal(t, hostsetup.JobDone, job["state"], steps)
	assert.Equal(t, hostsetup.StateChanged, steps[hostsetup.StepUpgrade]["state"])
	assert.Equal(t, "Updated msbctl from 0.6.0 to 0.7.0.", steps[hostsetup.StepUpgrade]["detail"])
	assert.Equal(t, hostsetup.StateOK, steps[hostsetup.StepProxy]["state"], "a tailscale host has no proxy to restart")
	var commands []string
	for _, e := range server.Execs() {
		commands = append(commands, e.Command)
	}
	assert.Contains(t, commands, "msbctl self-update --json --version v0.7.0", "pinned, so never a release the plugin has not seen")
	assert.NotNil(t, listedStatus(t, r, "sbx-01"), "Test ran after")
}

func TestUpgradeLeavesACurrentHostAlone(t *testing.T) {
	withUpgradeTarget(t, "0.6.0")
	r, server := upgradeHost(t, "0.6.1", sshtest.Reply{Status: 126})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.JobDone, job["state"])
	assert.Equal(t, hostsetup.StateOK, jobSteps(job)[hostsetup.StepUpgrade]["state"])
	for _, e := range server.Execs() {
		assert.NotContains(t, e.Command, "self-update")
	}
}

func TestUpgradeNeedsAHostThatTakesIt(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	r, server := upgradeHost(t, "0.5.1", sshtest.Reply{Status: 126})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.JobFailed, job["state"])
	assert.Equal(t, hostsetup.StateManual, jobSteps(job)[hostsetup.StepUpgradeCheck]["state"])
	assert.Contains(t, jobSteps(job)[hostsetup.StepUpgradeCheck]["detail"], "hosts.setup")
	for _, e := range server.Execs() {
		assert.NotContains(t, e.Command, "self-update", "0.5.1's forced command would refuse it")
	}
}

func TestUpgradeSaysWhyTheHostRefused(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	for reply, want := range map[string]string{
		`{"error": {"code": "unsupported", "message": "git checkout"}}`: "git pull",
		`{"error": {"code": "denied", "message": "kandev off"}}`:        "Kandev is turned off",
	} {
		r, _ := upgradeHost(t, "0.6.0", sshtest.Reply{Stdout: reply, Status: 3})
		job := runUpgrade(t, r)
		assert.Equal(t, hostsetup.JobFailed, job["state"])
		assert.Contains(t, jobSteps(job)[hostsetup.StepUpgrade]["detail"], want)
	}
}

func TestUpgradeOneJobPerHost(t *testing.T) {
	r, _ := upgradeHost(t, "0.6.0", sshtest.Reply{})
	assert.Equal(t, 404, first(call(t, r, ActionHostsUpgrade, map[string]any{"name": "nope"})))
	assert.Equal(t, 422, first(call(t, r, ActionHostsUpgrade, map[string]any{})))
}

// A proxy-mode host whose proxy runs proxyVersion ("" for one older than
// 0.6.1, which reports none).
func proxyUpgradeHost(t *testing.T, version, proxyVersion string, replies map[string]sshtest.Reply) (*Runtime, *sshtest.Server) {
	t.Helper()
	r := newRuntime(t, newFakeHost())
	serve := `"serve":{"ok":true,"mode":"proxy","listen":"10.0.1.23","running":true`
	if proxyVersion != "" {
		serve += `,"version":"` + proxyVersion + `"`
	}
	health := strings.Replace(healthyJSON, `"msbctl_version":"0.4.0"`, `"msbctl_version":"`+version+`"`, 1)
	health = strings.Replace(health, `"serve":{"ok":true,"mode":"tailscale"`, serve, 1)
	require.NotEqual(t, healthyJSON, health)
	replies["health"] = sshtest.Reply{Stdout: health}
	// After an update the host answers health as the new release.
	updated := false
	base := msbctlHost(replies)
	server := sshtest.Start(t, pluginKey(t, r), func(command string, stdin []byte) sshtest.Reply {
		if strings.Contains(command, "self-update") {
			reply := base(command, stdin)
			if v := regexp.MustCompile(`"msbctl_version": "([^"]+)"`).FindStringSubmatch(reply.Stdout); v != nil {
				health = strings.Replace(health, `"msbctl_version":"`+version+`"`, `"msbctl_version":"`+v[1]+`"`, 1)
				updated = true
			}
			return reply
		}
		if strings.HasSuffix(command, "kandev health") && updated {
			return sshtest.Reply{Stdout: health}
		}
		return base(command, stdin)
	})
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	return r, server
}

func commandsOf(server *sshtest.Server) []string {
	var out []string
	for _, e := range server.Execs() {
		out = append(out, e.Command)
	}
	return out
}

// 0.6.1 and later restart the proxy during the update itself.
func TestUpgradeTrustsTheUpdatesOwnProxyRestart(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	r, server := proxyUpgradeHost(t, "0.6.1", "0.6.1", map[string]sshtest.Reply{
		"self-update": {Stdout: `{"msbctl_version": "0.7.0", "updated": true, "proxy": {"state": "restarted", "version": "0.7.0"}}`},
	})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.StateChanged, jobSteps(job)[hostsetup.StepProxy]["state"])
	assert.Nil(t, job["manual"])
	assert.NotContains(t, commandsOf(server), "msbctl kandev restart-proxy")
}

// An update run by 0.6.0 never restarts the proxy: the new release does.
func TestUpgradeFinishesWhatAnOlderUpdateLeft(t *testing.T) {
	withUpgradeTarget(t, "0.6.1")
	r, server := proxyUpgradeHost(t, "0.6.0", "", map[string]sshtest.Reply{
		"self-update":   {Stdout: `{"msbctl_version": "0.6.1", "updated": true}`},
		"restart-proxy": {Stdout: `{"proxy": {"state": "restarted", "version": "0.6.1"}}`},
	})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.JobDone, job["state"], jobSteps(job))
	assert.Equal(t, hostsetup.StateChanged, jobSteps(job)[hostsetup.StepProxy]["state"])
	assert.Contains(t, commandsOf(server), "msbctl kandev restart-proxy")
}

// A current host whose proxy missed a restart gets one, and only that.
func TestUpgradeRestartsAStaleProxyOnACurrentHost(t *testing.T) {
	withUpgradeTarget(t, "0.6.1")
	r, server := proxyUpgradeHost(t, "0.6.1", "", map[string]sshtest.Reply{
		"restart-proxy": {Stdout: `{"proxy": {"state": "restarted", "version": "0.6.1"}}`},
	})
	_, test := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Contains(t, test["warning"], "older release than msbctl 0.6.1")
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.StateChanged, jobSteps(job)[hostsetup.StepProxy]["state"])
	commands := commandsOf(server)
	assert.Contains(t, commands, "msbctl kandev restart-proxy")
	assert.NotContains(t, strings.Join(commands, "\n"), "self-update")
}

// A proxy on the current release is left alone: a restart cuts connections.
func TestUpgradeLeavesACurrentProxyAlone(t *testing.T) {
	withUpgradeTarget(t, "0.6.1")
	r, server := proxyUpgradeHost(t, "0.6.1", "0.6.1", map[string]sshtest.Reply{})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.StateOK, jobSteps(job)[hostsetup.StepProxy]["state"])
	assert.NotContains(t, commandsOf(server), "msbctl kandev restart-proxy")
}

func TestUpgradeSaysHowToRestartWhenMsbctlCannot(t *testing.T) {
	withUpgradeTarget(t, "0.6.1")
	r, _ := proxyUpgradeHost(t, "0.6.1", "", map[string]sshtest.Reply{
		"restart-proxy": {Stdout: `{"error": {"code": "unavailable", "message": "systemctl failed"}}`, Status: 3},
	})
	job := runUpgrade(t, r)
	assert.Equal(t, hostsetup.StateFailed, jobSteps(job)[hostsetup.StepProxy]["state"])
	assert.Contains(t, job["manual"].([]any)[0], "systemctl --user restart msb-kandev-proxy.service")
}
