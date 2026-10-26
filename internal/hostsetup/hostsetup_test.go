package hostsetup

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
)

const pluginKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPluginKeyForTests kandev-plugin"

// machine is a fake Linux host: it keeps the state bootstrap changes and
// answers each script the way the real one would.
type machine struct {
	user, uid, sudo string
	kvm             bool
	kvmUsable       bool
	python          string
	missing         map[string]bool
	accountExists   bool
	linger          bool
	msb, manager    string
	config          string
	servicesActive  bool
	firewalld       bool
	firewallRules   []string
	authorized      []string
	failInstall     string
	failAuthorize   bool

	execs []exec
}

type exec struct {
	command, script string
}

func ubuntu() *machine {
	return &machine{user: "ubuntu", uid: "1000", sudo: "yes", kvm: true, kvmUsable: true, python: "3.12",
		missing: map[string]bool{"git": true}}
}

func (m *machine) has(c string) bool { return !m.missing[c] }

func (m *machine) Exec(_ context.Context, command string, stdin []byte) (remote.Output, error) {
	script := string(stdin)
	m.execs = append(m.execs, exec{command, script})
	ok := func(stdout string) (remote.Output, error) { return remote.Output{Stdout: []byte(stdout)}, nil }
	exit := func(code int, stderr string) (remote.Output, error) {
		return remote.Output{Stderr: []byte(stderr), Exit: code}, nil
	}
	switch {
	case script == probeScript:
		var b strings.Builder
		fmt.Fprintf(&b, "kernel=Linux\narch=x86_64\nos=Ubuntu 24.04.1 LTS\nuser=%s\nuid=%s\nsudo=%s\n", m.user, m.uid, m.sudo)
		if m.kvm {
			b.WriteString("kvm=present\n")
		} else {
			b.WriteString("kvm=missing\n")
		}
		if m.has("python3") {
			fmt.Fprintf(&b, "python=%s\n", m.python)
		} else {
			b.WriteString("python=\n")
		}
		for _, c := range []string{"git", "curl", "tar", "sha256sum", "systemctl", "loginctl", "apt-get", "runuser"} {
			if m.has(c) {
				fmt.Fprintf(&b, "has_%s=1\n", c)
			}
		}
		if m.firewalld {
			b.WriteString("firewalld=active\n")
		}
		b.WriteString("ssh_connection=203.0.113.9 50022 10.0.1.23 22\n")
		return ok(b.String())
	case strings.Contains(script, "apt-get install"):
		for _, c := range []string{"python3", "git", "curl", "tar"} {
			if strings.Contains(script, " "+c) {
				delete(m.missing, c)
			}
		}
		return ok("")
	case strings.HasPrefix(script, "python3 -c"):
		return ok(m.python + "\n")
	case strings.Contains(script, "useradd"):
		var changes []string
		if !m.accountExists {
			m.accountExists = true
			changes = append(changes, "created")
		}
		if !m.kvmUsable {
			m.kvmUsable = true
			changes = append(changes, "kvm group kvm")
		}
		if !m.linger {
			m.linger = true
			changes = append(changes, "linger")
		}
		return ok(strings.Join(changes, "\n"))
	case strings.HasSuffix(script, "[ -r /dev/kvm ] && [ -w /dev/kvm ]\n"):
		if m.kvmUsable {
			return ok("")
		}
		return exit(1, "")
	case strings.Contains(script, "echo kvm=rw"):
		var b strings.Builder
		if m.kvmUsable {
			b.WriteString("kvm=rw\n")
		}
		if m.linger {
			b.WriteString("linger=yes\n")
		}
		return ok(b.String())
	case strings.Contains(script, msbctl.VersionsScript()):
		return ok(fmt.Sprintf("msb=%s\nmsbctl=%s\n", versionLine("msb", m.msb), versionLine("msbctl", m.manager)))
	case strings.Contains(script, msbctl.MsbPin.SHA256):
		if m.failInstall == "msb" {
			return exit(1, "\x1b[31merror\x1b[0m: Checksum verification failed")
		}
		m.msb = msbctl.MsbPin.Version
		return ok("")
	case strings.Contains(script, msbctl.ManagerPin.SHA256):
		m.manager = msbctl.ManagerPin.Version
		return ok("")
	case strings.Contains(script, "'configure'"):
		return ok(m.configure(script))
	case strings.Contains(script, "is-active --quiet msb-kandev-proxy"):
		if m.servicesActive {
			return ok("")
		}
		return exit(3, "")
	case strings.Contains(script, "msbctl host kandev install"):
		m.servicesActive = true
		return ok("")
	case strings.Contains(script, "firewall-cmd"):
		for _, r := range m.firewallRules {
			if strings.Contains(script, r) {
				return ok("")
			}
		}
		m.firewallRules = append(m.firewallRules, "203.0.113.9")
		return ok("firewalld\n")
	case strings.Contains(script, "msbctl host authorize"):
		if m.failAuthorize {
			return exit(1, "msbctl: not on PATH")
		}
		m.authorized = append(m.authorized, script)
		return ok("")
	case strings.Contains(script, "msbctl kandev health"):
		return ok(m.health())
	}
	return exit(127, "unexpected script: "+script)
}

// configure applies `host kandev configure` flags to the fake's [kandev]
// lines and answers as msbctl does: the keys it changed.
func (m *machine) configure(script string) string {
	var tokens []string
	for _, match := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(script, -1) {
		tokens = append(tokens, match[1])
	}
	current := map[string]string{}
	var order []string
	for _, line := range strings.Split(m.config, "\n") {
		if k, v, found := strings.Cut(line, " = "); found {
			current[k] = v
			order = append(order, k)
		}
	}
	want := map[string]string{}
	var extra []string
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "--enabled":
			want["enabled"] = "true"
		case "--serve":
			want["serve"] = strconv.Quote(tokens[i+1])
			i++
		case "--proxy-listen":
			want["proxy_listen"] = strconv.Quote(tokens[i+1])
			i++
		case "--base-url":
			want["base_url"] = strconv.Quote(tokens[i+1])
			i++
		case "--allow-extra":
			extra = append(extra, strconv.Quote(tokens[i+1]))
			i++
		}
	}
	if extra != nil {
		want["allow_extra"] = "[" + strings.Join(extra, ", ") + "]"
	}
	var changed []string
	for _, k := range []string{"enabled", "serve", "proxy_listen", "base_url", "allow_extra"} {
		v, given := want[k]
		if !given || current[k] == v {
			continue
		}
		if _, had := current[k]; !had {
			order = append(order, k)
		}
		current[k] = v
		changed = append(changed, strconv.Quote(k))
	}
	var b strings.Builder
	b.WriteString("[kandev]\n")
	for _, k := range order {
		fmt.Fprintf(&b, "%s = %s\n", k, current[k])
	}
	m.config = b.String()
	return `{"changed": [` + strings.Join(changed, ", ") + `], "kandev": {}}`
}

func versionLine(name, v string) string {
	if v == "" {
		return ""
	}
	return name + " " + v
}

func (m *machine) health() string {
	value := func(key string) string {
		for _, line := range strings.Split(m.config, "\n") {
			if k, v, found := strings.Cut(line, " = "); found && k == key {
				return strings.Trim(v, `"`)
			}
		}
		return ""
	}
	allow := "[]"
	if strings.Contains(m.config, `allow_extra = ["*"]`) {
		allow = `["*"]`
	}
	return fmt.Sprintf(`{"protocol":1,"msbctl_version":%q,"msb_version":%q,"kvm":%t,"enabled":%t,"platform":"linux-amd64",
"base_url":%q,"capacity":{"max_sandboxes":12},"serve":{"ok":false,"mode":%q,"listen":%q},
"features":["workspace_disk"],"egress":{"allow_extra":%s}}`,
		m.manager, m.msb, m.kvmUsable, value("enabled") == "true", value("base_url"), value("serve"), value("proxy_listen"), allow)
}

func (m *machine) ran(substr string) []exec {
	var out []exec
	for _, e := range m.execs {
		if e.script != probeScript && strings.Contains(e.script, substr) {
			out = append(out, e)
		}
	}
	return out
}

func states(res Result) map[string]string {
	out := map[string]string{}
	for _, s := range res.Steps {
		out[s.Key] = s.State
	}
	return out
}

func input() Input {
	return Input{PublicKey: pluginKey, SSHHost: "sbx-01.example.com", SSHPort: 22, EgressFromPlugin: true}
}

func TestBootstrapSetsUpAFreshMachine(t *testing.T) {
	m := ubuntu()
	var reports int
	res := Run(t.Context(), m, input(), func([]Step) { reports++ })
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, map[string]string{
		StepProbe: StateOK, StepPackages: StateChanged, StepAccount: StateChanged, StepMsb: StateChanged,
		StepManager: StateChanged, StepConfig: StateChanged, StepServices: StateChanged, StepFirewall: StateOK,
		StepAuthorize: StateChanged, StepVerify: StateOK,
	}, states(res))
	assert.Equal(t, len(res.Steps), reports, "one report per step")
	assert.Equal(t, "msb@sbx-01.example.com", res.SSH, "the dedicated account, not the admin login")
	assert.Equal(t, "https://sbx-01.example.com", res.BaseURL)
	assert.Equal(t, "203.0.113.9", res.KandevAddress, "the address the admin connection came from")
	assert.Contains(t, res.Manual[0], "security group")
	assert.Contains(t, res.Manual[0], "203.0.113.9")

	assert.Contains(t, m.config, `proxy_listen = "10.0.1.23"`, "the machine's own address, as it sees the connection")
	assert.Contains(t, m.config, `base_url = "https://sbx-01.example.com"`)
	assert.Contains(t, m.config, `allow_extra = ["*"]`)
	assert.Equal(t, "sudo -n sh -s", m.ran("useradd")[0].command, "root's part goes through sudo")
	for _, marker := range []string{msbctl.MsbPin.SHA256, msbctl.ManagerPin.SHA256, "'configure'", "msbctl host authorize"} {
		assert.Equal(t, "sudo -n -iu msb sh -s", m.ran(marker)[0].command, "%s runs as the account", marker)
	}
	require.Len(t, m.authorized, 1)
	assert.Contains(t, m.authorized[0], "'"+pluginKey+"' --kandev --replace")
}

func TestBootstrapAgainChangesNothing(t *testing.T) {
	m := ubuntu()
	require.True(t, Run(t.Context(), m, input(), nil).OK)
	before := len(m.ran("msbctl host kandev install"))
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	for _, key := range []string{StepPackages, StepAccount, StepMsb, StepManager, StepConfig, StepServices, StepFirewall, StepVerify} {
		assert.Equal(t, StateOK, states(res)[key], key)
	}
	assert.Equal(t, before, len(m.ran("msbctl host kandev install")), "the running proxy is not restarted")
	assert.Len(t, m.ran(msbctl.MsbPin.SHA256), 1, "nothing is reinstalled")
}

func TestBootstrapRepairsStoppedServicesAndKeepsNewerVersions(t *testing.T) {
	m := ubuntu()
	require.True(t, Run(t.Context(), m, input(), nil).OK)
	m.servicesActive = false
	m.manager = "0.9.0"
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, StateChanged, states(res)[StepServices])
	assert.Equal(t, StateOK, states(res)[StepManager])
	assert.Equal(t, "0.9.0", m.manager, "never downgraded")
}

func TestBootstrapStopsWithoutKVM(t *testing.T) {
	m := ubuntu()
	m.kvm = false
	res := Run(t.Context(), m, input(), nil)
	assert.False(t, res.OK)
	assert.Equal(t, StateFailed, states(res)[StepProbe])
	assert.Contains(t, res.Steps[0].Detail, ".metal")
	assert.Len(t, m.execs, 1, "nothing is changed on a machine that cannot run sandboxes")
	assert.Equal(t, StateSkipped, states(res)[StepPackages])
}

func TestBootstrapRefusesAnOldPython(t *testing.T) {
	m := ubuntu()
	m.python = "3.9"
	res := Run(t.Context(), m, input(), nil)
	assert.Equal(t, StateFailed, states(res)[StepPackages])
	assert.Contains(t, res.Steps[1].Detail, "3.11")
}

func TestBootstrapWithoutSudoListsRootsPart(t *testing.T) {
	m := ubuntu()
	m.sudo, m.kvmUsable, m.missing = "no", false, map[string]bool{}
	res := Run(t.Context(), m, input(), nil)
	assert.False(t, res.OK)
	assert.Equal(t, StateManual, states(res)[StepAccount])
	assert.Equal(t, []string{`usermod -aG "$(stat -c %G /dev/kvm)" ubuntu`, "loginctl enable-linger ubuntu"}, res.Steps[2].Commands)
	assert.Equal(t, "ubuntu@sbx-01.example.com", res.SSH, "without sudo msb-manager runs as the login")
	for _, e := range m.execs {
		assert.NotContains(t, e.command, "sudo", "no sudo is attempted")
	}

	m.missing = map[string]bool{"git": true}
	res = Run(t.Context(), m, input(), nil)
	assert.Equal(t, StateManual, states(res)[StepPackages])
	assert.Contains(t, res.Steps[1].Commands[0], "apt-get install -y -qq git")
}

// configure (F23) changes only what setup sets, so an existing section is
// repaired rather than reported.
func TestBootstrapRepairsAnExistingSection(t *testing.T) {
	m := ubuntu()
	m.config = "[kandev]\nenabled = true\nserve = \"tailscale\"\nbase_url = \"https://old.example.com\"\nmax_sandboxes = 4\n"
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, StateChanged, states(res)[StepConfig])
	assert.Contains(t, res.Steps[5].Detail, "serve, proxy_listen, base_url, allow_extra")
	assert.Contains(t, m.config, `base_url = "https://sbx-01.example.com"`)
	assert.Contains(t, m.config, "max_sandboxes = 4", "keys setup does not set are kept")
}

// Without egress_from_plugin, setup leaves the host's allow_extra alone.
func TestBootstrapLeavesAllowExtraUnlessAsked(t *testing.T) {
	m := ubuntu()
	m.config = "[kandev]\nallow_extra = [\"pypi.org\"]\n"
	in := input()
	in.EgressFromPlugin = false
	require.True(t, Run(t.Context(), m, in, nil).OK)
	assert.Contains(t, m.config, `allow_extra = ["pypi.org"]`)
	assert.NotContains(t, m.ran("'configure'")[0].script, "--allow-extra")
}

func TestBootstrapShowsWhyAnInstallFailed(t *testing.T) {
	m := ubuntu()
	m.failInstall = "msb"
	res := Run(t.Context(), m, input(), nil)
	assert.False(t, res.OK)
	assert.Equal(t, StateFailed, states(res)[StepMsb])
	assert.Equal(t, "[31merror[0m: Checksum verification failed", res.Steps[3].Output, "the tail, printable only")
	assert.Equal(t, StateSkipped, states(res)[StepManager])
	assert.Empty(t, m.authorized, "the key is not authorized on a half-set-up host")
}

func TestBootstrapOpensFirewalld(t *testing.T) {
	m := ubuntu()
	m.firewalld = true
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, StateChanged, states(res)[StepFirewall])
	rule := m.ran("firewall-cmd")[0]
	assert.Equal(t, "sudo -n sh -s", rule.command)
	assert.Contains(t, rule.script, `source address="203.0.113.9" port port="30000-39999" protocol="tcp" accept`)
	assert.Equal(t, StateOK, states(Run(t.Context(), m, input(), nil))[StepFirewall], "added once")
}

func TestBootstrapAsRootUsesRunuser(t *testing.T) {
	m := ubuntu()
	m.user, m.uid, m.sudo = "root", "0", "root"
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, "sh -s", m.ran("useradd")[0].command)
	assert.Equal(t, "runuser -l msb -c 'sh -s'", m.ran(msbctl.ManagerPin.SHA256)[0].command)
}

func TestBootstrapKeepsTheSSHPort(t *testing.T) {
	in := input()
	in.SSHPort = 2222
	res := Run(t.Context(), ubuntu(), in, nil)
	assert.Equal(t, "msb@sbx-01.example.com:2222", res.SSH)
}

// An upgrade restarts the services, so the proxy runs the new msbctl.
func TestBootstrapRestartsServicesAfterAnUpgrade(t *testing.T) {
	m := ubuntu()
	require.True(t, Run(t.Context(), m, input(), nil).OK)
	m.manager = "0.4.0"
	res := Run(t.Context(), m, input(), nil)
	require.True(t, res.OK, "%+v", res.Steps)
	assert.Equal(t, StateChanged, states(res)[StepManager])
	assert.Contains(t, res.Steps[4].Detail, "from 0.4.0 to "+msbctl.ManagerPin.Version)
	assert.Equal(t, StateChanged, states(res)[StepServices])
	assert.Len(t, m.ran("msbctl host kandev install"), 2)
}

func TestBootstrapStopsWhenTheKeyCannotBeAuthorized(t *testing.T) {
	m := ubuntu()
	m.failAuthorize = true
	res := Run(t.Context(), m, input(), nil)
	assert.False(t, res.OK)
	assert.Equal(t, StateFailed, states(res)[StepAuthorize])
	assert.Equal(t, "msbctl: not on PATH", res.Steps[8].Output)
	assert.Equal(t, StateSkipped, states(res)[StepVerify])
}
