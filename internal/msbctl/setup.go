package msbctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"kandev-plugin-microsandbox/internal/hosts"
)

// Host setup: how msb-manager and msb are installed and configured on a
// machine, as shell scripts for internal/bootstrap to run as the account
// msb-manager runs under. That account's PATH must include ~/.local/bin,
// where both installers link their commands. No script carries a secret.

// Pin is one installer at a fixed version, verified by its own sha256
// before it runs. Each installer then verifies what it downloads against
// its release's checksums.
type Pin struct {
	Version string
	URL     string
	SHA256  string
}

// The versions bootstrap installs. msb-manager is developed and checked
// against msb 0.7.7. Moving a pin means re-reading both installers and
// taking their sha256 from the release's checksums.sha256.
var (
	MsbPin = Pin{
		Version: "0.7.7",
		URL:     "https://github.com/superradcompany/microsandbox/releases/download/v0.7.7/install.sh",
		SHA256:  "767df6954e09fec9bf8276cc2858fc9038024b3a22fa4740572620370eb719f4",
	}
	// 0.6.0 is the first with `host kandev configure` (F23), which setup
	// writes [kandev] with. Its get.sh is byte-identical to 0.5.1's.
	ManagerPin = Pin{
		Version: "0.6.0",
		URL:     "https://github.com/runoverlabs/sandbox-manager/releases/download/v0.6.0/get.sh",
		SHA256:  "a676bee14708d60a48f337602608674986cdb4da11c2494ac4e758130894151d",
	}
)

// ProxyPorts is msb-manager's default [kandev] proxy_port_pool, the range
// Kandev must reach on a proxy host. Bootstrap leaves the pool at its
// default, so it is the range to open.
const ProxyPorts = "30000-39999"

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// VersionsScript prints the installed versions, one `name=version` line
// each, empty when not installed.
func VersionsScript() string {
	return `printf 'msb=%s\n' "$(msb --version 2>/dev/null | head -n1)"
printf 'msbctl=%s\n' "$(msbctl --version 2>/dev/null | head -n1)"
`
}

// ParseVersions reads VersionsScript's output: the first x.y.z of each.
func ParseVersions(stdout []byte) (msb, msbctl string) {
	for _, line := range strings.Split(string(stdout), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v := versionPattern.FindString(value)
		switch key {
		case "msb":
			msb = v
		case "msbctl":
			msbctl = v
		}
	}
	return msb, msbctl
}

// Older reports whether version have is older than want; an unreadable or
// empty have is older than anything.
func Older(have, want string) bool {
	h, okH := splitVersion(have)
	w, okW := splitVersion(want)
	if !okH || !okW {
		return okW
	}
	for i := range 3 {
		if h[i] != w[i] {
			return h[i] < w[i]
		}
	}
	return false
}

func splitVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(versionPattern.FindString(v), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// fetchVerified downloads a pinned installer to "$tmp/<name>" and checks its
// sha256, in a temporary directory removed on exit.
func fetchVerified(p Pin, name string) string {
	return fmt.Sprintf(`tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' -o "$tmp/%[1]s" %[2]s
echo '%[3]s  '"$tmp/%[1]s" | sha256sum -c --quiet - || { echo "the installer does not match its pinned sha256" >&2; exit 1; }
`, name, shellQuote(p.URL), p.SHA256)
}

// InstallMsbScript installs msb at MsbPin. microsandbox's installer has no
// version flag, so its one call to get_latest_version is replaced with the
// pinned version, as msb-manager's own `remote setup` does; an installer
// that does not have exactly that line is refused rather than guessed at.
func InstallMsbScript() string {
	return "set -eu\n" + fetchVerified(MsbPin, "install.sh") + fmt.Sprintf(`[ "$(grep -c '^    get_latest_version$' "$tmp/install.sh")" = 1 ] || { echo "unexpected installer layout" >&2; exit 1; }
sed -i 's/^    get_latest_version$/    VERSION="v%s"/' "$tmp/install.sh"
sh "$tmp/install.sh" </dev/null
`, MsbPin.Version)
}

// InstallManagerScript installs msb-manager at ManagerPin through its get.sh,
// which verifies the release tarball (and its attestation when gh is there).
func InstallManagerScript() string {
	return "set -eu\n" + fetchVerified(ManagerPin, "get.sh") +
		fmt.Sprintf("bash \"$tmp/get.sh\" --version v%s --no-desktop </dev/null\n", ManagerPin.Version)
}

// KandevConfig is the [kandev] section bootstrap writes.
type KandevConfig struct {
	// ProxyListen is the host's own address the TLS proxy binds.
	ProxyListen string
	// BaseURL is https://<name>, the name Kandev connects to and the host's
	// certificate carries.
	BaseURL string
	// AllowExtra is [kandev] allow_extra; nil leaves msbctl's default.
	AllowExtra []string
}

// ErrConfig is a KandevConfig msbctl would refuse.
var ErrConfig = errors.New("invalid [kandev] config")

func (c KandevConfig) check() error {
	addr, err := netip.ParseAddr(c.ProxyListen)
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("%w: proxy_listen must be an IP address", ErrConfig)
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: base_url must be https://host[:port]", ErrConfig)
	}
	for _, e := range c.AllowExtra {
		if e == "" || strings.ContainsAny(e, "\"\\\n'") {
			return fmt.Errorf("%w: allow_extra entry %q", ErrConfig, e)
		}
	}
	return nil
}

// ConfigureScript sets the [kandev] keys in c with `msbctl host kandev
// configure` (msb-manager 0.6.0, F23), which edits config.toml in place,
// keeps every other key and comment, checks the result as every verb does at
// load, and writes nothing when it would be refused. Keys c does not name
// are left as they are; AllowExtra nil leaves allow_extra alone.
func ConfigureScript(c KandevConfig) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	args := []string{"msbctl", "host", "kandev", "configure", "--enabled", "--serve", "proxy",
		"--proxy-listen", c.ProxyListen, "--base-url", c.BaseURL}
	for _, e := range c.AllowExtra {
		args = append(args, "--allow-extra", e)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	return "set -eu\n" + strings.Join(quoted, " ") + " --json </dev/null\n", nil
}

// ParseConfigure reads configure's answer: the keys it changed.
func ParseConfigure(stdout []byte) ([]string, error) {
	var out struct {
		Changed []string        `json:"changed"`
		Kandev  json.RawMessage `json:"kandev"`
	}
	if err := json.Unmarshal(stdout, &out); err != nil || out.Kandev == nil {
		return nil, ErrConfig
	}
	return out.Changed, nil
}

// ServicesScript installs the proxy and reaper user services. It restarts
// the proxy, so it is run only when something changed or a service is down.
func ServicesScript() string {
	return "set -eu\nmsbctl host kandev install </dev/null\n"
}

// ServicesActiveScript exits 0 when the proxy and the reaper's timer, as
// `host kandev install` names them, are both running.
func ServicesActiveScript() string {
	// One unit per call: is-active succeeds when any one named unit is.
	return "systemctl --user is-active --quiet msb-kandev-proxy.service && systemctl --user is-active --quiet msb-kandev-reap.timer\n"
}

// AuthorizeScript authorizes the plugin's key with the kandev forced
// command, replacing any line for the same key.
func AuthorizeScript(publicKey string) string {
	return "set -eu\nmsbctl host authorize " + shellQuote(publicKey) + " --kandev --replace </dev/null\n"
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// SelfUpdateVersion is the first msb-manager whose `self-update --json` the
// plugin's key may run (F24). Its health lists no feature for it, so the
// version tells.
const SelfUpdateVersion = "0.6.0"

// CanSelfUpdate reports whether the host's msbctl takes self-update from the
// plugin's key.
func (h Health) CanSelfUpdate() bool {
	return h.MsbctlVersion != "" && !Older(h.MsbctlVersion, SelfUpdateVersion)
}

// Updated is self-update's answer.
type Updated struct {
	MsbctlVersion string `json:"msbctl_version"`
	Updated       bool   `json:"updated"`
}

// SelfUpdate runs `msbctl self-update --json --version V` through the
// plugin's key. msbctl refuses a V older than the running release (denied,
// or the forced command's refusal), answers unsupported on a git checkout,
// and denied when Kandev is turned off. The installer's output goes to
// stderr, which is never read.
func (c *Client) SelfUpdate(ctx context.Context, h hosts.Host, version string) (Updated, error) {
	var out Updated
	// As a tag: get.sh puts the version into the release URL unchanged, and
	// releases are tagged v0.6.0. msbctl's own check takes either form.
	tag := "v" + strings.TrimPrefix(version, "v")
	if err := c.generic(ctx, h, []string{"self-update", "--json", "--version", tag}, &out); err != nil {
		return Updated{}, err
	}
	if out.MsbctlVersion == "" {
		return Updated{}, &Error{Code: CodeUnavailable}
	}
	out.MsbctlVersion = reportedText(out.MsbctlVersion)
	return out, nil
}
