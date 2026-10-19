// Package hostsetup turns a bare Linux machine into a sandbox host over an
// operator's admin SSH login: it checks the machine, installs what
// msb-manager needs, creates the account it runs under, installs msb and
// msb-manager at pinned versions, writes the [kandev] section, starts the
// services, opens the host firewall to the Kandev server, and authorizes
// the plugin's key.
//
// Every step is idempotent, so running it again on a set-up host repairs
// drift and changes nothing else. A step that needs root and has no
// passwordless sudo is reported as manual, with the commands to run. The
// package owns the machine side (accounts, packages, firewalls); everything
// msb-manager-specific comes from internal/msbctl.
package hostsetup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx"
)

// Shell runs one command line on the machine with stdin, as the admin login.
type Shell interface {
	Exec(ctx context.Context, command string, stdin []byte) (sshx.Output, error)
}

// accountPattern is a portable account name (useradd's default rule).
var accountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// DefaultAccount is the account created for msb-manager when the login may
// use sudo: no sudo of its own and a 0700 home, as msb-manager recommends.
const DefaultAccount = "msb"

// Input is what the operator chose.
type Input struct {
	// PublicKey is the plugin's authorized_keys line.
	PublicKey string
	// SSHHost and SSHPort are the admin destination's; Kandev reaches the
	// machine at SSHHost, and the plugin's key at both.
	SSHHost string
	SSHPort int
	// BaseURL is https://<name> for the data path; empty means
	// https://<SSHHost>.
	BaseURL string
	// Account is the account msb-manager runs under when the login may use
	// sudo; empty means DefaultAccount. Without sudo it is the login itself.
	Account string
	// EgressFromPlugin writes allow_extra = ["*"]: this Kandev server's
	// egress policy decides what sandboxes reach.
	EgressFromPlugin bool
	// KandevAddress is the address the host firewall admits; empty means
	// the address this SSH connection comes from, which is the Kandev
	// server's as the machine sees it.
	KandevAddress string
}

// Step states.
const (
	StateOK      = "ok"      // already as wanted
	StateChanged = "changed" // done now
	StateManual  = "manual"  // the operator must run Commands
	StateFailed  = "failed"
	StateSkipped = "skipped" // not reached, or not applicable
)

// Step is one stage, as the operator sees it.
type Step struct {
	Key      string   `json:"key"`
	Title    string   `json:"title"`
	State    string   `json:"state"`
	Detail   string   `json:"detail,omitempty"`
	Commands []string `json:"commands,omitempty"`
	// Output is the tail of a failed command's output, printable only.
	Output string `json:"output,omitempty"`
}

// Result is the whole run.
type Result struct {
	Steps []Step `json:"steps"`
	// OK means every step is ok or changed and the host can be registered.
	OK bool `json:"ok"`
	// SSH is the destination the plugin's key uses: the account at the
	// machine.
	SSH           string `json:"ssh,omitempty"`
	BaseURL       string `json:"base_url,omitempty"`
	KandevAddress string `json:"kandev_address,omitempty"`
	// Manual are steps outside the machine the operator must still take.
	Manual []string `json:"manual,omitempty"`
}

// Step keys, in order.
const (
	StepProbe     = "probe"
	StepPackages  = "packages"
	StepAccount   = "account"
	StepMsb       = "msb"
	StepManager   = "msb-manager"
	StepConfig    = "config"
	StepServices  = "services"
	StepFirewall  = "firewall"
	StepAuthorize = "authorize"
	StepVerify    = "verify"
)

// Steps lists every step with its title, in order, all skipped: what a run
// reports before it starts.
func Steps() []Step {
	return []Step{
		{Key: StepProbe, Title: "Check the machine: Linux, KVM, sudo"},
		{Key: StepPackages, Title: "Install python3 (3.11+), git, curl and tar"},
		{Key: StepAccount, Title: "Prepare the account msb-manager runs under: KVM access, lingering user services"},
		{Key: StepMsb, Title: "Install msb " + msbctl.MsbPin.Version},
		{Key: StepManager, Title: "Install msb-manager " + msbctl.ManagerPin.Version},
		{Key: StepConfig, Title: "Set msbctl's [kandev] section"},
		{Key: StepServices, Title: "Run the TLS proxy and the reaper"},
		{Key: StepFirewall, Title: "Open the proxy ports " + msbctl.ProxyPorts + " to the Kandev server"},
		{Key: StepAuthorize, Title: "Authorize the plugin's SSH key for msbctl kandev only"},
		{Key: StepVerify, Title: "Check the host's own health report"},
	}
}

// facts is what the probe found.
type facts struct {
	values map[string]string
}

func (f facts) get(key string) string { return f.values[key] }

// privileged: root, or passwordless sudo.
func (f facts) privileged() bool { return f.get("sudo") == "root" || f.get("sudo") == "yes" }

func parseFacts(stdout []byte) facts {
	f := facts{values: map[string]string{}}
	for _, line := range strings.Split(string(stdout), "\n") {
		if key, value, found := strings.Cut(line, "="); found {
			f.values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return f
}

const probeScript = `kernel=$(uname -s); echo "kernel=$kernel"
echo "arch=$(uname -m)"
if [ -r /etc/os-release ]; then . /etc/os-release; fi
echo "os=${PRETTY_NAME:-}"
echo "user=$(id -un)"
echo "uid=$(id -u)"
if [ "$(id -u)" = 0 ]; then echo sudo=root; elif sudo -n true 2>/dev/null; then echo sudo=yes; else echo sudo=no; fi
if [ -c /dev/kvm ]; then echo kvm=present; else echo kvm=missing; fi
echo "python=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
for c in git curl tar sha256sum systemctl loginctl apt-get dnf ufw firewall-cmd runuser; do
  command -v "$c" >/dev/null 2>&1 && echo "has_$c=1"
done
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld=active; fi
echo "ssh_connection=${SSH_CONNECTION:-}"
`

// run is one bootstrap.
type run struct {
	sh       Shell
	in       Input
	facts    facts
	account  string
	steps    []Step
	progress func([]Step)
	result   Result
}

// Run sets the machine up, reporting the steps after each one.
func Run(ctx context.Context, sh Shell, in Input, progress func([]Step)) Result {
	r := &run{sh: sh, in: in, steps: Steps(), progress: progress}
	for i := range r.steps {
		r.steps[i].State = StateSkipped
	}
	r.do(ctx)
	r.result.Steps = r.steps
	r.result.OK = true
	for _, s := range r.steps {
		if s.State != StateOK && s.State != StateChanged {
			r.result.OK = false
		}
	}
	return r.result
}

func (r *run) step(key string) *Step {
	for i := range r.steps {
		if r.steps[i].Key == key {
			return &r.steps[i]
		}
	}
	panic("hostsetup: unknown step " + key)
}

func (r *run) set(key, state, detail string, commands ...string) {
	s := r.step(key)
	s.State, s.Detail, s.Commands = state, detail, commands
	if r.progress != nil {
		r.progress(append([]Step(nil), r.steps...))
	}
}

// failed records a failed command with the tail of its output.
func (r *run) failed(key, detail string, out sshx.Output, err error) {
	if err != nil {
		detail += " (the command did not complete)"
	}
	r.step(key).Output = tail(out)
	r.set(key, StateFailed, detail)
}

func (r *run) do(ctx context.Context) {
	if !r.probe(ctx) {
		return
	}
	if !r.packages(ctx) {
		return
	}
	if !r.prepareAccount(ctx) {
		return
	}
	msbChanged, ok := r.install(ctx, StepMsb, msbctl.MsbPin, true, msbctl.InstallMsbScript())
	if !ok {
		return
	}
	managerChanged, ok := r.install(ctx, StepManager, msbctl.ManagerPin, false, msbctl.InstallManagerScript())
	if !ok {
		return
	}
	configChanged, ok := r.configure(ctx)
	if !ok {
		return
	}
	if !r.services(ctx, msbChanged || managerChanged || configChanged) {
		return
	}
	r.firewall(ctx)
	if !r.authorize(ctx) {
		return
	}
	r.verify(ctx)
}

func (r *run) probe(ctx context.Context) bool {
	out, err := r.sh.Exec(ctx, "sh -s", []byte(probeScript))
	if err != nil || out.Exit != 0 {
		r.failed(StepProbe, "The machine did not answer the probe.", out, err)
		return false
	}
	r.facts = parseFacts(out.Stdout)
	f := r.facts
	switch {
	case f.get("kernel") != "Linux":
		r.set(StepProbe, StateFailed, "msb needs Linux; this is "+f.get("kernel")+".")
		return false
	case f.get("arch") != "x86_64" && f.get("arch") != "aarch64":
		r.set(StepProbe, StateFailed, "msb runs on x86_64 and aarch64; this is "+f.get("arch")+".")
		return false
	case f.get("kvm") != "present":
		r.set(StepProbe, StateFailed, "This machine has no /dev/kvm, and nothing in software adds it. "+
			"It needs hardware virtualization: on EC2 a bare-metal (.metal) instance type or one with nested virtualization; "+
			"elsewhere, VT-x or AMD-V enabled in firmware, or nested virtualization on the hypervisor.")
		return false
	}
	if f.get("uid") == "0" && f.get("has_runuser") == "" {
		r.set(StepProbe, StateFailed, "Logged in as root without runuser, so commands cannot run as the msb-manager account.")
		return false
	}
	r.account = f.get("user")
	if f.privileged() {
		r.account = r.in.Account
		if r.account == "" {
			r.account = DefaultAccount
		}
	}
	if !accountPattern.MatchString(r.account) {
		r.set(StepProbe, StateFailed, "The account name "+r.account+" is not usable.")
		return false
	}
	r.result.KandevAddress = r.in.KandevAddress
	sshConn := strings.Fields(f.get("ssh_connection"))
	if r.result.KandevAddress == "" && len(sshConn) == 4 {
		r.result.KandevAddress = sshConn[0]
	}
	r.result.BaseURL = r.in.BaseURL
	if r.result.BaseURL == "" {
		r.result.BaseURL = "https://" + bracket(r.in.SSHHost)
	}
	r.result.SSH = r.account + "@" + bracket(r.in.SSHHost)
	if r.in.SSHPort != 0 && r.in.SSHPort != 22 {
		r.result.SSH = r.account + "@" + net.JoinHostPort(r.in.SSHHost, strconv.Itoa(r.in.SSHPort))
	}
	detail := fmt.Sprintf("%s, %s; /dev/kvm present; msb-manager will run as %s.", orUnknown(f.get("os")), f.get("arch"), r.account)
	switch {
	case f.get("sudo") == "root":
		detail += " Logged in as root."
	case f.privileged():
		detail += " Passwordless sudo is available."
	default:
		detail += " No passwordless sudo: steps that need root are listed for you to run."
	}
	r.set(StepProbe, StateOK, detail)
	return true
}

func bracket(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return "[" + host + "]"
	}
	return host
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown distribution"
	}
	return s
}

// pythonOK reports whether version is 3.11 or newer, as msb-manager needs.
func pythonOK(version string) bool {
	major, minor, found := strings.Cut(version, ".")
	if !found {
		return false
	}
	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	return err1 == nil && err2 == nil && (ma > 3 || (ma == 3 && mi >= 11))
}

func (r *run) packages(ctx context.Context) bool {
	f := r.facts
	var missing []string
	if f.get("python") == "" {
		missing = append(missing, "python3")
	}
	for _, c := range []string{"git", "curl", "tar"} {
		if f.get("has_"+c) == "" {
			missing = append(missing, c)
		}
	}
	if f.get("has_sha256sum") == "" {
		missing = append(missing, "coreutils")
	}
	tooOld := f.get("python") != "" && !pythonOK(f.get("python"))
	if tooOld {
		r.set(StepPackages, StateFailed, "python3 here is "+f.get("python")+"; msb-manager needs 3.11 or newer as python3. "+
			"Use a newer distribution (Debian 12, Ubuntu 24.04, Fedora 40 or later).")
		return false
	}
	if len(missing) == 0 {
		r.set(StepPackages, StateOK, "python3 "+f.get("python")+", git, curl and tar are installed.")
		return true
	}
	var install string
	switch {
	case f.get("has_apt-get") != "":
		// dbus-user-session gives the account a user bus, which
		// `systemctl --user` needs on Debian and Ubuntu.
		install = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " +
			strings.Join(append(missing, "dbus-user-session"), " ")
	case f.get("has_dnf") != "":
		install = "dnf install -y -q " + strings.Join(missing, " ")
	default:
		r.set(StepPackages, StateManual, "Missing: "+strings.Join(missing, ", ")+". Install them with the distribution's package manager, then run setup again.")
		return false
	}
	if !f.privileged() {
		r.set(StepPackages, StateManual, "Missing: "+strings.Join(missing, ", ")+". Run this as root, then run setup again.", install)
		return false
	}
	out, err := r.root(ctx, "set -eu\n"+install+"\n")
	if err != nil || out.Exit != 0 {
		r.failed(StepPackages, "Installing "+strings.Join(missing, ", ")+" failed.", out, err)
		return false
	}
	check, err := r.sh.Exec(ctx, "sh -s", []byte(`python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'`))
	if err != nil || !pythonOK(strings.TrimSpace(string(check.Stdout))) {
		r.set(StepPackages, StateFailed, "python3 is still missing or older than 3.11 after installing it. Use a newer distribution (Debian 12, Ubuntu 24.04, Fedora 40 or later).")
		return false
	}
	r.set(StepPackages, StateChanged, "Installed "+strings.Join(missing, ", ")+".")
	return true
}

// root runs script as root: directly when logged in as root, else through
// passwordless sudo.
func (r *run) root(ctx context.Context, script string) (sshx.Output, error) {
	command := "sudo -n sh -s"
	if r.facts.get("uid") == "0" {
		command = "sh -s"
	}
	return r.sh.Exec(ctx, command, []byte(script))
}

// accountPreamble gives a script run as the account the environment
// msb-manager's tools expect: their commands on PATH, and the user bus that
// `systemctl --user` talks to, which a sudo or runuser login does not set.
const accountPreamble = `export PATH="$HOME/.local/bin:$PATH"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
if [ -S "$XDG_RUNTIME_DIR/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"; fi
`

// asAccount runs script as the msb-manager account, in its home.
func (r *run) asAccount(ctx context.Context, script string) (sshx.Output, error) {
	command := "sh -s"
	switch {
	case r.account == r.facts.get("user"):
	case r.facts.get("uid") == "0":
		command = "runuser -l " + sshx.Quote(r.account) + " -c 'sh -s'"
	default:
		command = "sudo -n -iu " + sshx.Quote(r.account) + " sh -s"
	}
	return r.sh.Exec(ctx, command, []byte(accountPreamble+"cd\n"+script))
}

func (r *run) prepareAccount(ctx context.Context) bool {
	u := sshx.Quote(r.account)
	if r.facts.privileged() {
		script := fmt.Sprintf(`set -eu
u=%[1]s
if ! id -u "$u" >/dev/null 2>&1; then useradd -m -s /bin/bash "$u"; echo created; fi
home=$(getent passwd "$u" | cut -d: -f6)
chmod 700 "$home"
group=$(stat -c %%G /dev/kvm)
regrouped=
if [ "$group" != root ] && ! id -nG "$u" | tr ' ' '\n' | grep -qx "$group"; then usermod -aG "$group" "$u"; regrouped=1; echo "kvm group $group"; fi
uid=$(id -u "$u")
if [ ! -e "/var/lib/systemd/linger/$u" ]; then loginctl enable-linger "$u"; echo linger; fi
# A user manager already running keeps the groups it started with.
if [ -n "$regrouped" ]; then systemctl restart "user@$uid.service" 2>/dev/null || true; fi
i=0
while [ ! -S "/run/user/$uid/bus" ] && [ $i -lt 40 ]; do sleep 0.25; i=$((i+1)); done
[ -S "/run/user/$uid/bus" ] || { echo "the account's user services did not start (is dbus-user-session installed?)" >&2; exit 1; }
`, u)
		out, err := r.root(ctx, script)
		if err != nil || out.Exit != 0 {
			r.failed(StepAccount, "Preparing the account "+r.account+" failed.", out, err)
			return false
		}
		changes := strings.Fields(string(out.Stdout))
		kvm, err := r.asAccount(ctx, "[ -r /dev/kvm ] && [ -w /dev/kvm ]\n")
		if err != nil || kvm.Exit != 0 {
			r.set(StepAccount, StateFailed, "The account "+r.account+" still cannot open /dev/kvm for reading and writing. Check its owner and mode (ls -l /dev/kvm): it should be group-writable by its group.")
			return false
		}
		if len(changes) == 0 {
			r.set(StepAccount, StateOK, "The account "+r.account+" exists, can use /dev/kvm, and its user services run without a login.")
		} else {
			r.set(StepAccount, StateChanged, "The account "+r.account+" can use /dev/kvm and runs user services without a login ("+strings.Join(changes, ", ")+").")
		}
		return true
	}
	// No sudo: msb-manager runs as the login, and root's part is the
	// operator's to do.
	out, err := r.asAccount(ctx, `if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then echo kvm=rw; fi
if [ -e "/var/lib/systemd/linger/$(id -un)" ]; then echo linger=yes; fi
`)
	if err != nil || out.Exit != 0 {
		r.failed(StepAccount, "Checking the account failed.", out, err)
		return false
	}
	got := parseFacts(out.Stdout)
	var commands []string
	if got.get("kvm") != "rw" {
		commands = append(commands, "usermod -aG \"$(stat -c %G /dev/kvm)\" "+u)
	}
	if got.get("linger") != "yes" {
		commands = append(commands, "loginctl enable-linger "+u)
	}
	if len(commands) > 0 {
		r.set(StepAccount, StateManual, "Run these as root, log in again, then run setup again.", commands...)
		return false
	}
	r.set(StepAccount, StateOK, r.account+" can use /dev/kvm, and its user services run without a login.")
	return true
}

// install brings one tool to its pin unless a version at least as new is
// there; it reports whether it installed.
func (r *run) install(ctx context.Context, key string, pin msbctl.Pin, isMsb bool, script string) (bool, bool) {
	name := map[bool]string{true: "msb", false: "msb-manager"}[isMsb]
	have, err := r.versions(ctx, isMsb)
	if err != nil {
		r.set(key, StateFailed, "Reading the installed version failed.")
		return false, false
	}
	if have != "" && !msbctl.Older(have, pin.Version) {
		r.set(key, StateOK, name+" "+have+" is installed.")
		return false, true
	}
	out, err := r.asAccount(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(key, "Installing "+name+" "+pin.Version+" failed.", out, err)
		return false, false
	}
	now, err := r.versions(ctx, isMsb)
	if err != nil || now == "" || msbctl.Older(now, pin.Version) {
		r.set(key, StateFailed, name+" "+pin.Version+" was installed but does not answer --version on the account's PATH.")
		return false, false
	}
	detail := "Installed " + name + " " + now + "."
	if have != "" {
		detail = "Upgraded " + name + " from " + have + " to " + now + "."
	}
	r.set(key, StateChanged, detail)
	return true, true
}

func (r *run) versions(ctx context.Context, isMsb bool) (string, error) {
	out, err := r.asAccount(ctx, msbctl.VersionsScript())
	if err != nil {
		return "", err
	}
	msb, manager := msbctl.ParseVersions(out.Stdout)
	if isMsb {
		return msb, nil
	}
	return manager, nil
}

func (r *run) desired() (msbctl.KandevConfig, error) {
	sshConn := strings.Fields(r.facts.get("ssh_connection"))
	if len(sshConn) != 4 {
		return msbctl.KandevConfig{}, fmt.Errorf("the login's SSH_CONNECTION is not set, so the machine's own address is unknown")
	}
	c := msbctl.KandevConfig{ProxyListen: sshConn[2], BaseURL: r.result.BaseURL}
	if r.in.EgressFromPlugin {
		c.AllowExtra = []string{"*"}
	}
	return c, nil
}

func (r *run) configure(ctx context.Context) (bool, bool) {
	c, err := r.desired()
	if err != nil {
		r.set(StepConfig, StateFailed, err.Error()+".")
		return false, false
	}
	script, err := msbctl.ConfigureScript(c)
	if err != nil {
		r.set(StepConfig, StateFailed, err.Error()+".")
		return false, false
	}
	out, err := r.asAccount(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(StepConfig, "msbctl refused the [kandev] settings; config.toml is unchanged.", out, err)
		return false, false
	}
	changed, err := msbctl.ParseConfigure(out.Stdout)
	if err != nil {
		r.set(StepConfig, StateFailed, "msbctl host kandev configure gave no answer it could read.")
		return false, false
	}
	if len(changed) == 0 {
		r.set(StepConfig, StateOK, "[kandev] already has the TLS proxy on "+c.ProxyListen+" and base URL "+c.BaseURL+".")
		return false, true
	}
	r.set(StepConfig, StateChanged, "Set "+strings.Join(changed, ", ")+" under [kandev]: the TLS proxy on "+c.ProxyListen+", base URL "+c.BaseURL+".")
	return true, true
}

func (r *run) services(ctx context.Context, changed bool) bool {
	if !changed {
		if out, err := r.asAccount(ctx, msbctl.ServicesActiveScript()); err == nil && out.Exit == 0 {
			r.set(StepServices, StateOK, "The TLS proxy and the reaper are running.")
			return true
		}
	}
	out, err := r.asAccount(ctx, msbctl.ServicesScript())
	if err != nil || out.Exit != 0 {
		r.failed(StepServices, "Installing the proxy and reaper services failed.", out, err)
		return false
	}
	r.set(StepServices, StateChanged, "Installed and started the TLS proxy and the reaper.")
	return true
}

func (r *run) firewall(ctx context.Context) {
	ports := msbctl.ProxyPorts
	cloud := "If the machine is behind a cloud firewall (an EC2 security group, say), allow TCP " + ports + " to it from the Kandev server"
	addr, err := netip.ParseAddr(r.result.KandevAddress)
	if err != nil {
		r.result.Manual = append(r.result.Manual, cloud+".")
		r.set(StepFirewall, StateManual, "The Kandev server's address is unknown, so nothing was opened. Allow TCP "+ports+" from it on the host firewall, if there is one.")
		return
	}
	r.result.Manual = append(r.result.Manual, cloud+" ("+addr.String()+").")
	family := "ipv4"
	if addr.Is6() {
		family = "ipv6"
	}
	rich := fmt.Sprintf(`rule family="%s" source address="%s" port port="%s" protocol="tcp" accept`, family, addr, ports)
	firewalld := fmt.Sprintf("firewall-cmd --permanent --query-rich-rule=%[1]s >/dev/null || { firewall-cmd --permanent --add-rich-rule=%[1]s && firewall-cmd --reload >/dev/null && echo firewalld; }", sshx.Quote(rich))
	ufw := fmt.Sprintf("ufw allow proto tcp from %s to any port %s", addr, strings.Replace(ports, "-", ":", 1))
	switch {
	case r.facts.get("firewalld") == "active" && !r.facts.privileged():
		r.set(StepFirewall, StateManual, "firewalld is active. Run this as root:", firewalld)
		return
	case r.facts.get("has_ufw") != "" && !r.facts.privileged():
		r.set(StepFirewall, StateManual, "If ufw is active, run this as root:", ufw)
		return
	case !r.facts.privileged():
		r.set(StepFirewall, StateOK, "No firewalld here; if the host filters traffic otherwise, allow TCP "+ports+" from "+addr.String()+".")
		return
	}
	if r.facts.get("firewalld") != "active" && r.facts.get("has_ufw") == "" {
		r.set(StepFirewall, StateOK, "No host firewall is active (firewalld, ufw); if the host filters traffic otherwise, allow TCP "+ports+" from "+addr.String()+".")
		return
	}
	script := "set -eu\n"
	if r.facts.get("firewalld") == "active" {
		script += firewalld + "\n"
	}
	if r.facts.get("has_ufw") != "" {
		script += "if ufw status | grep -q '^Status: active'; then " + ufw + " >/dev/null && echo ufw; fi\n"
	}
	out, err := r.root(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(StepFirewall, "Opening the host firewall failed.", out, err)
		return
	}
	if opened := strings.Fields(string(out.Stdout)); len(opened) > 0 {
		r.set(StepFirewall, StateChanged, "Opened TCP "+ports+" from "+addr.String()+" in "+strings.Join(opened, " and ")+".")
		return
	}
	r.set(StepFirewall, StateOK, "The host firewall already admits "+addr.String()+", or none is active (firewalld, ufw).")
}

func (r *run) authorize(ctx context.Context) bool {
	out, err := r.asAccount(ctx, msbctl.AuthorizeScript(r.in.PublicKey))
	if err != nil || out.Exit != 0 {
		r.failed(StepAuthorize, "Authorizing the plugin's key failed.", out, err)
		return false
	}
	r.set(StepAuthorize, StateChanged, "The plugin's key may run msbctl kandev verbs as "+r.account+", and nothing else.")
	return true
}

// verify reads the host's health as the account and compares it with what
// this setup set. The data path may still be down: the plugin
// issues the proxy's certificate after registering the host.
func (r *run) verify(ctx context.Context) {
	health, err := msbctl.New(accountRunner{r}).Health(ctx, hosts.Host{})
	if err != nil {
		r.set(StepVerify, StateFailed, "msbctl kandev health did not answer as expected: "+describe(err)+".")
		return
	}
	want, _ := r.desired()
	var drift []string
	if !health.Enabled {
		drift = append(drift, "enabled = true")
	}
	if health.Serve.Mode != msbctl.ServeProxy {
		drift = append(drift, `serve = "proxy"`)
	}
	if strings.TrimRight(health.BaseURL, "/") != want.BaseURL {
		drift = append(drift, fmt.Sprintf("base_url = %q", want.BaseURL))
	}
	if health.Serve.Listen != "" && !strings.HasPrefix(health.Serve.Listen, want.ProxyListen) && !strings.HasPrefix(health.Serve.Listen, "["+want.ProxyListen+"]") {
		drift = append(drift, fmt.Sprintf("proxy_listen = %q", want.ProxyListen))
	}
	if r.in.EgressFromPlugin && (health.Egress == nil || !contains(health.Egress.AllowExtra, "*")) {
		drift = append(drift, `allow_extra = ["*"]`)
	}
	if !health.KVM {
		r.set(StepVerify, StateFailed, "msbctl reports no usable /dev/kvm for "+r.account+".")
		return
	}
	if len(drift) > 0 {
		r.set(StepVerify, StateManual, "The host's health report disagrees with what setup set. Check these under [kandev] in ~"+r.account+"/.config/msb/config.toml:", drift...)
		return
	}
	r.set(StepVerify, StateOK, "msbctl "+health.MsbctlVersion+" and msb "+health.MsbVersion+" report this host ready for Kandev.")
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func describe(err error) string {
	var e *msbctl.Error
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return "it lacks a feature or protocol version the plugin needs"
	case errors.As(err, &e):
		return e.Code
	default:
		return "no answer"
	}
}

// accountRunner runs msbctl commands as the account over the admin login,
// so msbctl's own client reads the host's health before the plugin's key is
// in use.
type accountRunner struct{ r *run }

func (a accountRunner) Run(ctx context.Context, _ hosts.Host, args []string, stdin io.Reader) ([]byte, int, error) {
	var extra []byte
	if stdin != nil {
		var err error
		if extra, err = io.ReadAll(stdin); err != nil {
			return nil, 0, err
		}
	}
	if len(extra) > 0 {
		return nil, 0, fmt.Errorf("host setup runs msbctl without stdin")
	}
	out, err := a.r.asAccount(ctx, sshx.Join(args)+" </dev/null\n")
	if err != nil {
		return nil, 0, err
	}
	return out.Stdout, out.Exit, nil
}

// maxOutputTail bounds the output a failed step shows.
const maxOutputTail = 2000

// tail is the end of a failed command's stderr, then stdout, printable only.
func tail(out sshx.Output) string {
	text := bytes.TrimSpace(out.Stderr)
	if len(text) == 0 {
		text = bytes.TrimSpace(out.Stdout)
	}
	if len(text) > maxOutputTail {
		text = text[len(text)-maxOutputTail:]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(text))
}
