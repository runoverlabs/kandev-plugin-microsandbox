package plugin

import (
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
	old := upgradeTarget
	upgradeTarget = version
	t.Cleanup(func() { upgradeTarget = old })
}

func TestUpgradeUpdatesThroughThePluginsKey(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	r, server := upgradeHost(t, "0.6.0", sshtest.Reply{Stdout: `{"msbctl_version": "0.7.0", "updated": true}`})
	job := runUpgrade(t, r)
	steps := jobSteps(job)
	assert.Equal(t, jobDone, job["state"], steps)
	assert.Equal(t, hostsetup.StateChanged, steps[stepUpgrade]["state"])
	assert.Equal(t, "Updated msbctl from 0.6.0 to 0.7.0.", steps[stepUpgrade]["detail"])
	assert.Contains(t, job["manual"].([]any)[0], "systemctl --user restart msb-kandev-proxy.service", "the proxy keeps the old release")
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
	assert.Equal(t, jobDone, job["state"])
	assert.Equal(t, hostsetup.StateOK, jobSteps(job)[stepUpgrade]["state"])
	for _, e := range server.Execs() {
		assert.NotContains(t, e.Command, "self-update")
	}
}

func TestUpgradeNeedsAHostThatTakesIt(t *testing.T) {
	withUpgradeTarget(t, "0.7.0")
	r, server := upgradeHost(t, "0.5.1", sshtest.Reply{Status: 126})
	job := runUpgrade(t, r)
	assert.Equal(t, jobFailed, job["state"])
	assert.Equal(t, hostsetup.StateManual, jobSteps(job)[stepUpgradeCheck]["state"])
	assert.Contains(t, jobSteps(job)[stepUpgradeCheck]["detail"], "hosts.setup")
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
		assert.Equal(t, jobFailed, job["state"])
		assert.Contains(t, jobSteps(job)[stepUpgrade]["detail"], want)
	}
}

func TestUpgradeOneJobPerHost(t *testing.T) {
	r, _ := upgradeHost(t, "0.6.0", sshtest.Reply{})
	assert.Equal(t, 404, first(call(t, r, ActionHostsUpgrade, map[string]any{"name": "nope"})))
	assert.Equal(t, 422, first(call(t, r, ActionHostsUpgrade, map[string]any{})))
}
