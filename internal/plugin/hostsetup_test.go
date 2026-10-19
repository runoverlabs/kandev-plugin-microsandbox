package plugin

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

const plantedAdminPassword = "planted-admin-pw-5e7a"

// setupHealth is what a freshly set-up host reports: the proxy is
// configured and waits for its certificate.
const setupHealth = `{"protocol":1,"msbctl_version":"0.5.1","msb_version":"0.7.7","kvm":true,"enabled":true,
"platform":"linux-amd64","base_url":"https://sbx-01.tailnet.ts.net",
"capacity":{"max_sandboxes":12,"sandboxes":0,"max_cpus":32,"cpus":0,"max_memory_mib":98304,"memory_mib":0},
"serve":{"ok":false,"mode":"proxy","listen":"10.0.1.23","running":true},"tls":{"installed":false},
"features":["workspace_disk"],"egress":{"allow_extra":["*"]}}`

// setUpMachine answers as a machine where everything is already in place:
// the admin login (by password) runs scripts, the plugin's key runs
// msbctl kandev verbs.
func setUpMachine(command string, stdin []byte) sshtest.Reply {
	script := string(stdin)
	switch {
	case command == "msbctl kandev health":
		return sshtest.Reply{Stdout: setupHealth}
	case strings.Contains(script, "kvm=present"):
		return sshtest.Reply{Stdout: "kernel=Linux\narch=x86_64\nos=Debian GNU/Linux 13\nuser=admin\nuid=1000\nsudo=yes\nkvm=present\npython=3.13\n" +
			"has_git=1\nhas_curl=1\nhas_tar=1\nhas_sha256sum=1\nhas_systemctl=1\nhas_loginctl=1\nhas_apt-get=1\n" +
			"ssh_connection=203.0.113.9 50022 10.0.1.23 22\n"}
	case strings.Contains(script, msbctl.VersionsScript()):
		return sshtest.Reply{Stdout: "msb=msb 0.7.7\nmsbctl=msbctl 0.5.1\n"}
	case strings.Contains(script, "[kandev]"):
		return sshtest.Reply{Stdout: "present\n"}
	case strings.Contains(script, "msbctl kandev health"):
		return sshtest.Reply{Stdout: setupHealth}
	}
	return sshtest.Reply{}
}

func setupBody(server *sshtest.Server) map[string]any {
	return map[string]any{
		"name": "sbx-01", "ssh": server.Dest("admin"), "host_key": server.HostKey,
		"admin_password": plantedAdminPassword, "base_url": "https://sbx-01.tailnet.ts.net",
		"labels": []string{"default"}, "egress_from_plugin": true,
	}
}

func waitForJob(t *testing.T, r *Runtime, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, job := call(t, r, ActionHostsSetupStatus, map[string]any{"id": id})
		require.Equal(t, 200, status, job)
		if job["state"] != jobRunning {
			return job
		}
		require.True(t, time.Now().Before(deadline), "setup did not finish")
		time.Sleep(10 * time.Millisecond)
	}
}

func jobSteps(job map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, s := range job["steps"].([]any) {
		step := s.(map[string]any)
		out[step["key"].(string)] = step
	}
	return out
}

func TestSetupRegistersAndTestsTheHost(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, pluginKey(t, r), setUpMachine, sshtest.WithPassword(plantedAdminPassword))
	status, started := call(t, r, ActionHostsSetup, setupBody(server))
	require.Equal(t, 202, status, started)
	assert.Equal(t, jobRunning, started["state"])

	job := waitForJob(t, r, started["id"].(string))
	steps := jobSteps(job)
	assert.Equal(t, jobDone, job["state"], steps)
	for _, key := range []string{hostsetup.StepProbe, hostsetup.StepMsb, hostsetup.StepVerify} {
		assert.Equal(t, hostsetup.StateOK, steps[key]["state"], key)
	}
	assert.Equal(t, hostsetup.StateChanged, steps[stepRegister]["state"])
	// No root yet, so Test says what is missing; the setup itself is done.
	assert.Equal(t, hostsetup.StateManual, steps[stepTest]["state"])
	assert.Equal(t, "no_root", job["test"].(map[string]any)["problem"])

	registry, err := r.loadRegistry(t.Context())
	require.NoError(t, err)
	h, found := registry.Find("sbx-01")
	require.True(t, found)
	assert.Equal(t, "msb@"+server.Addr, h.SSH, "the plugin's key reaches the msb account, not the admin login")
	assert.Equal(t, server.HostKey, h.HostKey)
	assert.Equal(t, []string{"default"}, h.Labels)
	assert.NotNil(t, listedStatus(t, r, "sbx-01"), "the test result is the host's status")

	var users []string
	for _, e := range server.Execs() {
		users = append(users, e.User)
	}
	assert.Contains(t, users, "admin")
	assert.Equal(t, "msb", users[len(users)-1], "Test runs with the plugin's key")

	// Running it again repairs, rather than refusing the registered name.
	status, again := call(t, r, ActionHostsSetup, setupBody(server))
	require.Equal(t, 202, status, again)
	assert.Equal(t, jobDone, waitForJob(t, r, again["id"].(string))["state"])
}

func TestSetupNeverKeepsOrShowsTheAdminLogin(t *testing.T) {
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	host := newFakeHost()
	r := newRuntime(t, host)
	server := sshtest.Start(t, pluginKey(t, r), setUpMachine, sshtest.WithPassword(plantedAdminPassword))
	body := setupBody(server)
	_, started := call(t, r, ActionHostsSetup, body)
	job := waitForJob(t, r, started["id"].(string))

	// A wrong login too, so error paths are covered.
	body["admin_password"] = plantedAdminPassword + "-wrong"
	body["name"] = "sbx-02"
	_, failedStart := call(t, r, ActionHostsSetup, body)
	failed := waitForJob(t, r, failedStart["id"].(string))
	assert.Equal(t, jobFailed, failed["state"])
	assert.Equal(t, "The machine refused the admin login.", jobSteps(failed)[hostsetup.StepProbe]["detail"])

	everything, _ := json.Marshal([]any{started, job, failedStart, failed, host.state, host.secrets})
	for _, e := range server.Execs() {
		everything = append(everything, e.Command...)
		everything = append(everything, e.Stdin...)
	}
	everything = append(everything, logs.Bytes()...)
	assert.NotContains(t, string(everything), plantedAdminPassword)
}

func TestSetupRefusesBadInput(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	server := sshtest.Start(t, pluginKey(t, r), setUpMachine, sshtest.WithPassword(plantedAdminPassword))
	for name, change := range map[string]func(map[string]any){
		"no login":         func(b map[string]any) { delete(b, "admin_password") },
		"bad ssh":          func(b map[string]any) { b["ssh"] = "nouser" },
		"bad name":         func(b map[string]any) { b["name"] = "Bad Name" },
		"loopback default": func(b map[string]any) { delete(b, "base_url") },
		"no host key":      func(b map[string]any) { b["host_key"] = "" },
		"unknown field":    func(b map[string]any) { b["sudo_password"] = "x" },
	} {
		body := setupBody(server)
		change(body)
		status, res := call(t, r, ActionHostsSetup, body)
		assert.Equal(t, 422, status, "%s: %v", name, res)
		assert.NotContains(t, res, "id", name)
	}
	assert.Empty(t, server.Execs(), "nothing reached the machine")

	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-09.example.com", server.HostKey, "default"))))
	status, _ := call(t, r, ActionHostsSetup, setupBody(server))
	assert.Equal(t, 409, status, "a registered name at another address is not taken over")
}

func TestSetupStatusOfAnUnknownJob(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	assert.Equal(t, 404, first(call(t, r, ActionHostsSetupStatus, map[string]any{"id": "nope"})))
	assert.Equal(t, 422, first(call(t, r, ActionHostsSetupStatus, map[string]any{})))
}
