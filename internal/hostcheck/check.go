// Package hostcheck is what the plugin concludes about one sandbox host: Test's
// diagnosis, run by the operator, by the maintainer and after a setup or an
// upgrade, and certificate care, which gives a proxy host a valid certificate
// from the plugin's root before anything is reported. It reaches the host,
// the root and the egress policy only through the ports below.
package hostcheck

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/pki"
	"kandev-plugin-microsandbox/internal/remote"
)

// Host is the sandbox host as the check reaches it: msbctl kandev's health and
// tls-install verbs.
type Host interface {
	Health(ctx context.Context, h hosts.Host) (msbctl.Health, error)
	TLSInstall(ctx context.Context, h hosts.Host, chainPEM, keyPEM string) (msbctl.TLSStatus, error)
}

// Roots is the plugin's certificate authority; pki.ErrNoRoot until one is
// created.
type Roots interface {
	Root(ctx context.Context) (*pki.Root, error)
}

// Policies is the plugin-wide egress policy.
type Policies interface {
	Load(ctx context.Context) (egress.Policy, error)
}

// Checker diagnoses hosts. Every field is required.
type Checker struct {
	Roots  Roots
	Egress Policies
	// PublicKey is the plugin's SSH key line, for the authorize hint.
	PublicKey func(ctx context.Context) string
	// Trusted reports whether the Kandev server trusts root: nil when it
	// does. Kandev verifies leases against the system roots.
	Trusted func(root *pki.Root) error
	Now     func() time.Time
}

// Result is the diagnostic hosts.test returns. It is always a 200 with a
// problem code, because a failing host is the answer, not an error.
type Result struct {
	OK      bool           `json:"ok"`
	Problem string         `json:"problem,omitempty"`
	Hint    string         `json:"hint,omitempty"`
	Warning string         `json:"warning,omitempty"`
	Health  *msbctl.Health `json:"health,omitempty"`
	TLS     *TLSOutcome    `json:"tls,omitempty"`
	// EgressRefused are default-group entries the host's allow_extra would
	// refuse, which fails every provision there.
	EgressRefused []string `json:"egress_refused,omitempty"`
	// outcome is what certificate care did, for the maintainer; TLS
	// carries it to the operator for proxy hosts only.
	outcome TLSOutcome
}

// Outcome is what certificate care did during the check, proxy host or not.
func (r Result) Outcome() TLSOutcome { return r.outcome }

// Status is a host's last check, as hosts.list shows it.
type Status struct {
	CheckedAt string `json:"checked_at"`
	Result
}

// AuthorizeCommand is what the operator runs on each sandbox host.
func AuthorizeCommand(publicKey string) string {
	return "msbctl host authorize " + remote.Quote(publicKey) + " --kandev"
}

// Check is Test's diagnosis: health, then certificate care, then what the
// host's answer says about TLS, its base URL and egress.
func (c *Checker) Check(ctx context.Context, api Host, h hosts.Host) Result {
	health, err := api.Health(ctx, h)
	var outcome TLSOutcome
	if err == nil {
		// Test heals before it reports: a host that only needed a new
		// certificate passes rather than telling the operator to wait for
		// the maintainer.
		outcome = c.Heal(ctx, api, h, health)
		if outcome.State == TLSRenewed {
			health, err = api.Health(ctx, h)
		}
	} else {
		outcome = TLSOutcome{State: TLSFailed, Reason: "unreachable"}
	}
	result := diagnose(health, err, c.PublicKey(ctx))
	result.outcome = outcome
	if err != nil {
		return result
	}
	if health.Serve.Mode == msbctl.ServeProxy {
		result.TLS = &outcome
		c.diagnoseTLS(ctx, &result, outcome)
	}
	// Leases are built on the host's own base URL; one that differs from
	// the registered URL means the operator's picture of the host is stale.
	if health.BaseURL != "" && strings.TrimRight(health.BaseURL, "/") != h.BaseURL {
		result.Warning = "The host reports base_url " + health.BaseURL + ", not the registered " + h.BaseURL + "."
	}
	if health.Egress != nil {
		c.diagnoseEgress(ctx, &result, health.Egress.AllowExtra)
	}
	// A proxy on an older release than msbctl missed a restart after an
	// update: it still serves, with the old code.
	if health.ProxyStale() && result.Warning == "" {
		result.Warning = "The TLS proxy runs an older release than msbctl " + health.MsbctlVersion + ". Update the host to restart it onto the new one."
	}
	return result
}

// diagnoseEgress checks the policy's default groups against the host's
// allow_extra. msbctl refuses a whole provision over one entry, so a refused
// default makes the host unusable for every profile.
func (c *Checker) diagnoseEgress(ctx context.Context, result *Result, allowExtra []string) {
	policy, err := c.Egress.Load(ctx)
	if err != nil {
		return
	}
	entries, err := policy.Expand(nil, nil)
	if err != nil {
		return
	}
	refused := egress.Refused(entries, allowExtra)
	if len(refused) == 0 {
		return
	}
	result.EgressRefused = refused
	result.OK = false
	if result.Problem == "" {
		result.Problem = "egress_refused"
		result.Hint = "The host's [kandev] allow_extra does not admit every default egress entry, so it refuses every provision. " +
			"Set exactly one allow_extra line under [kandev] in the host's msbctl config: " + allowExtraLine(append(slices.Clone(allowExtra), refused...)) +
			` to admit these, or allow_extra = ["*"] to let this Kandev server decide.`
	}
}

// allowExtraLine is a TOML allow_extra line for entries, as msbctl reads it.
func allowExtraLine(entries []string) string {
	quoted := make([]string, len(entries))
	for i, e := range entries {
		quoted[i] = strconv.Quote(e)
	}
	return "allow_extra = [" + strings.Join(quoted, ", ") + "]"
}

// unreachable maps a failure to get a health report onto a problem and its
// hint, in the order they are checked.
func unreachable(err error, health msbctl.Health, publicKey string) Result {
	switch {
	case errors.Is(err, remote.ErrHostKeyMismatch):
		return Result{Problem: "host_key_mismatch", Hint: "The host presented a different SSH host key than the pinned one. Verify it on the host before updating the pin."}
	case errors.Is(err, remote.ErrNotAuthorized):
		return Result{Problem: "not_authorized", Hint: "Authorize the plugin's key on the host: " + AuthorizeCommand(publicKey)}
	case errors.Is(err, msbctl.ErrUnreachable):
		return Result{Problem: "unreachable", Hint: "The host's SSH server did not answer."}
	case msbctl.CodeOf(err) == msbctl.CodeDenied:
		return Result{Problem: "refused", Hint: "The host refused `msbctl kandev`: authorize the key with --kandev, and check msbctl on the host is recent enough."}
	case isOutdated(err):
		return Result{Problem: "outdated", Hint: "msbctl on the host lacks features this plugin needs (" + strings.Join(health.Missing(), ", ") + "). Update msb-manager on the host.", Health: &health}
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return Result{Problem: "protocol", Hint: "The host's msbctl speaks a different kandev protocol version than this plugin.", Health: &health}
	default:
		return Result{Problem: "unavailable", Hint: "msbctl on the host did not return a health report. Run `msbctl kandev health` on the host to see why: a config.toml it cannot load, for one."}
	}
}

func diagnose(health msbctl.Health, err error, publicKey string) Result {
	if err != nil {
		return unreachable(err, health, publicKey)
	}
	result := Result{OK: health.Usable(), Health: &health}
	switch {
	case !health.Enabled:
		result.Problem, result.Hint = "disabled", "Set enabled = true under [kandev] in the host's msbctl config."
	case !health.KVM:
		result.Problem, result.Hint = "no_kvm", "/dev/kvm is not available on the host."
	case !health.Serve.OK && health.Serve.Mode == msbctl.ServeProxy:
		result.Problem, result.Hint = "no_data_path", "The host's TLS proxy is not running, has no certificate, or has no proxy_listen address in [kandev]."
	case !health.Serve.OK:
		result.Problem, result.Hint = "no_data_path", "Tailscale is not running with a DNS name on the host, so tailscale serve cannot publish sandboxes to Kandev."
	}
	return result
}

func isOutdated(err error) bool {
	var e *msbctl.Error
	return errors.As(err, &e) && e.Reason == msbctl.ReasonOutdated
}

// tlsProblems are the outcomes that are a problem in themselves.
var tlsProblems = map[string][2]string{
	TLSNoRoot:       {"no_root", "Create the plugin's root certificate (ca.create), then install it on the Kandev server (ca.get)."},
	TLSNotPermitted: {"not_permitted", "The host's base_url is outside the names the root may certify. Register it under a permitted name, or create a new root that covers it."},
	TLSFailed:       {"tls_install_failed", "The host refused or did not accept a new certificate; it is retried automatically."},
}

// diagnoseTLS adds what certificate care found to a proxy-mode result. A
// host-side problem already found is kept, except no_data_path: a proxy
// without a certificate reports exactly that, and the certificate problem
// is its cause and the more useful thing to say.
func (c *Checker) diagnoseTLS(ctx context.Context, result *Result, outcome TLSOutcome) {
	set := func(problem, hint string) {
		result.OK = false
		if result.Problem == "" || result.Problem == "no_data_path" {
			result.Problem, result.Hint = problem, hint
		}
	}
	if problem, found := tlsProblems[outcome.State]; found {
		set(problem[0], problem[1])
		return
	}
	root, err := c.Roots.Root(ctx)
	if err != nil {
		return
	}
	if c.Trusted(root) != nil {
		set("root_not_trusted", "The Kandev server does not trust the plugin's root yet. Install it (ca.get lists the steps) and restart Kandev.")
	}
}
