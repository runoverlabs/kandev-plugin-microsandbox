package hostsetup

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

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

func (r *run) probe(ctx context.Context) bool {
	out, err := r.sh.Exec(ctx, "sh -s", []byte(probeScript))
	if err != nil || out.Exit != 0 {
		r.failed(StepProbe, "The machine did not answer the probe.", out, err)
		return false
	}
	r.facts = parseFacts(out.Stdout)
	if problem := machineProblem(r.facts); problem != "" {
		r.set(StepProbe, StateFailed, problem)
		return false
	}
	r.account = r.facts.get("user")
	if r.facts.privileged() {
		r.account = cmp.Or(r.in.Account, DefaultAccount)
	}
	if !accountPattern.MatchString(r.account) {
		r.set(StepProbe, StateFailed, "The account name "+r.account+" is not usable.")
		return false
	}
	r.planResult()
	r.set(StepProbe, StateOK, r.probeDetail())
	return true
}

// machineProblem is why the machine cannot be a sandbox host, or "".
func machineProblem(f facts) string {
	switch {
	case f.get("kernel") != "Linux":
		return "msb needs Linux; this is " + f.get("kernel") + "."
	case f.get("arch") != "x86_64" && f.get("arch") != "aarch64":
		return "msb runs on x86_64 and aarch64; this is " + f.get("arch") + "."
	case f.get("kvm") != "present":
		return "This machine has no /dev/kvm, and nothing in software adds it. " +
			"It needs hardware virtualization: on EC2 a bare-metal (.metal) instance type or one with nested virtualization; " +
			"elsewhere, VT-x or AMD-V enabled in firmware, or nested virtualization on the hypervisor."
	case f.get("uid") == "0" && f.get("has_runuser") == "":
		return "Logged in as root without runuser, so commands cannot run as the msb-manager account."
	}
	return ""
}

// planResult fills in how the host will be registered: the address the
// firewall admits, its base URL and the plugin's SSH destination.
func (r *run) planResult() {
	r.result.KandevAddress = r.in.KandevAddress
	sshConn := strings.Fields(r.facts.get("ssh_connection"))
	if r.result.KandevAddress == "" && len(sshConn) == 4 {
		r.result.KandevAddress = sshConn[0]
	}
	r.result.BaseURL = cmp.Or(r.in.BaseURL, "https://"+bracket(r.in.SSHHost))
	r.result.SSH = r.account + "@" + bracketHost(r.in.SSHHost, r.in.SSHPort)
}

func (r *run) probeDetail() string {
	f := r.facts
	detail := fmt.Sprintf("%s, %s; /dev/kvm present; msb-manager will run as %s.", orUnknown(f.get("os")), f.get("arch"), r.account)
	switch {
	case f.get("sudo") == "root":
		return detail + " Logged in as root."
	case f.privileged():
		return detail + " Passwordless sudo is available."
	default:
		return detail + " No passwordless sudo: steps that need root are listed for you to run."
	}
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
