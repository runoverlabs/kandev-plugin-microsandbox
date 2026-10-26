package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
	"kandev-plugin-microsandbox/internal/sshx"
)

// Action keys, matching manifest.yaml.
const (
	ActionHostsList   = "hosts.list"
	ActionHostsScan   = "hosts.scan"
	ActionHostsAdd    = "hosts.add"
	ActionHostsUpdate = "hosts.update"
	ActionHostsDrain  = "hosts.drain"
	ActionHostsRemove = "hosts.remove"
	ActionHostsTest   = "hosts.test"
)

// actionTimeout bounds one action, which may make one SSH round trip.
const actionTimeout = 20 * time.Second

// HandleAction serves the Sandbox Hosts page. Every action is admin-only in
// the manifest: the registry decides where every workspace's sandboxes run.
//
// Kandev masks any Go error from an action as a 503, so every failure the
// operator can act on is returned as a response with its own status.
func (r *Runtime) HandleAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	var handler func(context.Context, []byte) response
	switch req.ActionKey {
	case ActionHostsList:
		handler = r.actionList
	case ActionHostsScan:
		handler = r.actionScan
	case ActionHostsAdd:
		handler = r.actionAdd
	case ActionHostsUpdate:
		handler = r.actionUpdate
	case ActionHostsDrain:
		handler = r.actionDrain
	case ActionHostsRemove:
		handler = r.actionRemove
	case ActionHostsTest:
		handler = r.actionTest
	case ActionCAGet:
		handler = r.actionCAGet
	case ActionCACreate:
		handler = r.actionCACreate
	case ActionHostsSetup:
		handler = r.actionSetup
	case ActionHostsUpgrade:
		handler = r.actionUpgrade
	case ActionHostsSetupStatus:
		handler = r.actionSetupJobStatus
	case ActionSecretsList:
		handler = r.actionSecretsList
	case ActionSecretsPut:
		handler = r.actionSecretsPut
	case ActionSecretsRemove:
		handler = r.actionSecretsRemove
	case ActionSetupStatus:
		handler = r.actionSetupStatus
	case ActionEgressList:
		handler = r.actionEgressList
	case ActionEgressPut:
		handler = r.actionEgressPut
	case ActionEgressRemove:
		handler = r.actionEgressRemove
	case ActionEgressDefaults:
		handler = r.actionEgressDefaults
	default:
		return respond(fail(http.StatusNotFound, "unknown action")), nil
	}
	return respond(handler(ctx, req.Body)), nil
}

type response struct {
	status int
	body   any
}

func ok(body any) response { return response{http.StatusOK, body} }

func fail(status int, message string) response {
	return response{status, map[string]any{"error": message}}
}

func respond(res response) *pluginsdk.PluginActionResponse {
	body, err := json.Marshal(res.body)
	if err != nil {
		res.status, body = http.StatusInternalServerError, []byte(`{"error":"response encoding failed"}`)
	}
	return &pluginsdk.PluginActionResponse{
		Status: res.status, Body: body, Headers: map[string]string{"Content-Type": "application/json"},
	}
}

// internalFailure logs the cause and returns a fixed message: Host errors
// can carry details that do not belong in a browser response.
func internalFailure(action string, err error) response {
	if errors.Is(err, ErrNoHost) {
		return fail(http.StatusServiceUnavailable, "the plugin is still starting; try again")
	}
	log.Printf("%s: %v", action, err)
	return fail(http.StatusInternalServerError, "the host registry could not be read or saved")
}

func decode(body []byte, into any) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		body = []byte("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

// hostView is a host as the page shows it, with its key fingerprint and,
// in the list, its last check.
type hostView struct {
	hosts.Host
	Fingerprint string      `json:"fingerprint"`
	Status      *hostStatus `json:"status,omitempty"`
}

func viewOf(h hosts.Host) hostView {
	if h.Labels == nil {
		h.Labels = []string{}
	}
	fingerprint, _ := sshx.Fingerprint(h.HostKey)
	return hostView{Host: h, Fingerprint: fingerprint}
}

func (r *Runtime) actionList(ctx context.Context, body []byte) response {
	if err := decode(body, &struct{}{}); err != nil {
		return fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	_, publicKey, err := r.key(ctx)
	if err != nil {
		return internalFailure(ActionHostsList, err)
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return internalFailure(ActionHostsList, err)
	}
	status, err := r.loadStatus(ctx)
	if err != nil {
		return internalFailure(ActionHostsList, err)
	}
	views := make([]hostView, 0, len(registry.Hosts))
	for _, h := range registry.Hosts {
		view := viewOf(h)
		if s, found := status[h.Name]; found {
			view.Status = &s
		}
		views = append(views, view)
	}
	return ok(map[string]any{
		// The release hosts.setup installs and hosts.upgrade brings a host to.
		"msbctl_release": msbctl.ManagerPin.Version,
		"public_key":     publicKey,
		"authorize":      authorizeCommand(publicKey),
		"hosts":          views,
	})
}

// authorizeCommand is what the operator runs on each sandbox host.
func authorizeCommand(publicKey string) string {
	return "msbctl host authorize " + remote.Quote(publicKey) + " --kandev"
}

// actionScan fetches the key a host presents, for the operator to confirm
// before it is pinned by hosts.add. Nothing is stored.
func (r *Runtime) actionScan(ctx context.Context, body []byte) response {
	var in struct {
		SSH string `json:"ssh"`
	}
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, "expected {\"ssh\": \"user@host[:port]\"}")
	}
	dest := strings.TrimSpace(in.SSH)
	if _, _, _, err := hosts.ParseSSH(dest); err != nil {
		return fail(http.StatusUnprocessableEntity, "ssh: "+err.Error())
	}
	key, err := sshx.ScanHostKey(ctx, dest, r.dialer)
	if err != nil {
		log.Printf("%s %s: %v", ActionHostsScan, dest, err)
		return fail(http.StatusBadGateway, "could not reach the host's SSH server")
	}
	fingerprint, _ := sshx.Fingerprint(key)
	return ok(map[string]any{"host_key": key, "fingerprint": fingerprint})
}

func (r *Runtime) actionAdd(ctx context.Context, body []byte) response {
	var in hosts.Host
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, "expected a host: name, ssh, host_key, base_url, labels")
	}
	if res, refused := r.refuseOutsideRoot(ctx, in); refused {
		return res
	}
	return r.writeHost(ctx, ActionHostsAdd, in, func(reg hosts.Registry, h hosts.Host) (hosts.Registry, error) {
		h.Draining = false
		return reg.Add(h)
	})
}

func (r *Runtime) actionUpdate(ctx context.Context, body []byte) response {
	var in hosts.Host
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, "expected a host: name, ssh, host_key, base_url, labels")
	}
	if res, refused := r.refuseOutsideRoot(ctx, in); refused {
		return res
	}
	return r.writeHost(ctx, ActionHostsUpdate, in, hosts.Registry.Update)
}

func (r *Runtime) writeHost(ctx context.Context, action string, in hosts.Host, change func(hosts.Registry, hosts.Host) (hosts.Registry, error)) response {
	if _, err := sshx.ParseHostKey(in.HostKey); err != nil && strings.TrimSpace(in.HostKey) != "" {
		return validationFailure(&hosts.ValidationError{Fields: []hosts.FieldError{{Field: "host_key", Message: err.Error()}}})
	}
	registry, err := r.mutateRegistry(ctx, func(reg hosts.Registry) (hosts.Registry, error) { return change(reg, in) })
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return internalFailure(action, err)
	}
	saved, _ := registry.Find(strings.TrimSpace(in.Name))
	status := http.StatusOK
	if action == ActionHostsAdd {
		status = http.StatusCreated
	}
	out := map[string]any{"host": viewOf(saved)}
	if outcome, tried := r.healAfterWrite(ctx, saved); tried {
		out["tls"] = outcome
	}
	return response{status, out}
}

// refuseOutsideRoot refuses a base URL no certificate from the root could
// cover. Without a root there is nothing to check yet.
func (r *Runtime) refuseOutsideRoot(ctx context.Context, in hosts.Host) (response, bool) {
	root, err := r.root(ctx)
	if err != nil {
		return response{}, false
	}
	name := hostName(hosts.Normalize(in))
	if name == "" || root.Permits(name) {
		return response{}, false
	}
	return validationFailure(&hosts.ValidationError{Fields: []hosts.FieldError{{
		Field:   "base_url",
		Message: "outside the names the plugin's root may certify (" + strings.Join(root.Constraints().DNSSuffixes, ", ") + ")",
	}}}), true
}

// healAfterWrite issues a certificate for a newly added or changed host,
// best effort: the host is saved either way, and the maintainer retries.
func (r *Runtime) healAfterWrite(ctx context.Context, h hosts.Host) (tlsOutcome, bool) {
	if _, err := r.root(ctx); err != nil {
		return tlsOutcome{}, false
	}
	client, err := r.client(ctx)
	if err != nil {
		return tlsOutcome{}, false
	}
	health, err := client.Health(ctx, h)
	if err != nil {
		return tlsOutcome{State: tlsFailed, Reason: "unreachable"}, true
	}
	return r.healTLS(ctx, client, h, health), true
}

func validationFailure(v *hosts.ValidationError) response {
	return response{http.StatusUnprocessableEntity, map[string]any{"error": "the host is invalid", "fields": v.Fields}}
}

// registryFailure maps the registry's own errors to responses.
func registryFailure(err error) (response, bool) {
	var invalid *hosts.ValidationError
	switch {
	case err == nil:
		return response{}, false
	case errors.As(err, &invalid):
		return validationFailure(invalid), true
	case errors.Is(err, hosts.ErrNotFound):
		return fail(http.StatusNotFound, err.Error()), true
	case errors.Is(err, hosts.ErrExists):
		return fail(http.StatusConflict, err.Error()), true
	case errors.Is(err, hosts.ErrTooMany):
		return fail(http.StatusConflict, err.Error()), true
	default:
		return response{}, false
	}
}

func (r *Runtime) actionDrain(ctx context.Context, body []byte) response {
	var in struct {
		Name     string `json:"name"`
		Draining *bool  `json:"draining"`
	}
	if err := decode(body, &in); err != nil || in.Draining == nil {
		return fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\", \"draining\": true|false}")
	}
	registry, err := r.mutateRegistry(ctx, func(reg hosts.Registry) (hosts.Registry, error) {
		return reg.SetDraining(in.Name, *in.Draining)
	})
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return internalFailure(ActionHostsDrain, err)
	}
	saved, _ := registry.Find(in.Name)
	return ok(map[string]any{"host": viewOf(saved)})
}

// actionRemove refuses to forget a host that still owns kandev sandboxes:
// every later call for them routes by the host name in their resource
// state, so removing it would strand them. Only the host knows its
// inventory, so it is asked; `force` removes an unreachable host anyway.
func (r *Runtime) actionRemove(ctx context.Context, body []byte) response {
	var in struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := decode(body, &in); err != nil || in.Name == "" {
		return fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\", \"force\": false}")
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return internalFailure(ActionHostsRemove, err)
	}
	h, found := registry.Find(in.Name)
	if !found {
		return fail(http.StatusNotFound, hosts.ErrNotFound.Error())
	}
	client, err := r.client(ctx)
	if err != nil {
		return internalFailure(ActionHostsRemove, err)
	}
	sandboxes, err := client.List(ctx, h)
	switch {
	case err == nil && len(sandboxes) > 0:
		return response{http.StatusConflict, map[string]any{
			"error": "the host still has kandev sandboxes; drain it and wait for them to be destroyed", "sandboxes": len(sandboxes),
		}}
	case err != nil && !in.Force:
		log.Printf("%s %s: %v", ActionHostsRemove, h.Name, err)
		return fail(http.StatusBadGateway, "could not confirm the host has no sandboxes; retry, or remove with force")
	}
	_, err = r.mutateRegistry(ctx, func(reg hosts.Registry) (hosts.Registry, error) { return reg.Remove(in.Name) })
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return internalFailure(ActionHostsRemove, err)
	}
	r.forgetStatus(ctx, in.Name)
	return ok(map[string]any{"removed": in.Name})
}

// testResult is the diagnostic hosts.test returns. It is always a 200 with
// a problem code, because a failing host is the answer, not an error.
type testResult struct {
	OK      bool           `json:"ok"`
	Problem string         `json:"problem,omitempty"`
	Hint    string         `json:"hint,omitempty"`
	Warning string         `json:"warning,omitempty"`
	Health  *msbctl.Health `json:"health,omitempty"`
	TLS     *tlsOutcome    `json:"tls,omitempty"`
	// EgressRefused are default-group entries the host's allow_extra would
	// refuse, which fails every provision there.
	EgressRefused []string `json:"egress_refused,omitempty"`
	// outcome is what certificate care did, for the maintainer; TLS
	// carries it to the operator for proxy hosts only.
	outcome tlsOutcome
}

func (r *Runtime) actionTest(ctx context.Context, body []byte) response {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(body, &in); err != nil || in.Name == "" {
		return fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\"}")
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return internalFailure(ActionHostsTest, err)
	}
	h, found := registry.Find(in.Name)
	if !found {
		return fail(http.StatusNotFound, hosts.ErrNotFound.Error())
	}
	client, err := r.client(ctx)
	if err != nil {
		return internalFailure(ActionHostsTest, err)
	}
	result := r.checkHost(ctx, client, h)
	r.recordStatus(ctx, h.Name, result)
	return ok(result)
}

// checkHost is Test's diagnosis, also run by the maintainer: health, then
// certificate care, then what the host's answer says about TLS, its base URL
// and egress.
func (r *Runtime) checkHost(ctx context.Context, client *msbctl.Client, h hosts.Host) testResult {
	_, publicKey, _ := r.key(ctx)
	health, err := client.Health(ctx, h)
	var outcome tlsOutcome
	if err == nil {
		// Test heals before it reports: a host that only needed a new
		// certificate passes rather than telling the operator to wait for
		// the maintainer.
		outcome = r.healTLS(ctx, client, h, health)
		if outcome.State == tlsRenewed {
			health, err = client.Health(ctx, h)
		}
	} else {
		outcome = tlsOutcome{State: tlsFailed, Reason: "unreachable"}
	}
	result := diagnose(health, err, publicKey)
	if err == nil && health.Serve.Mode == msbctl.ServeProxy {
		result.TLS = &outcome
		r.diagnoseTLS(ctx, &result, outcome)
	}
	// Leases are built on the host's own base URL; one that differs from
	// the registered URL means the operator's picture of the host is stale.
	if err == nil && health.BaseURL != "" && strings.TrimRight(health.BaseURL, "/") != h.BaseURL {
		result.Warning = "The host reports base_url " + health.BaseURL + ", not the registered " + h.BaseURL + "."
	}
	if err == nil && health.Egress != nil {
		r.diagnoseEgress(ctx, &result, health.Egress.AllowExtra)
	}
	// A proxy on an older release than msbctl missed a restart after an
	// update: it still serves, with the old code.
	if err == nil && health.ProxyStale() && result.Warning == "" {
		result.Warning = "The TLS proxy runs an older release than msbctl " + health.MsbctlVersion + ". Update the host to restart it onto the new one."
	}
	result.outcome = outcome
	return result
}

// diagnoseEgress checks the policy's default groups against the host's
// allow_extra. msbctl refuses a whole provision over one entry, so a refused
// default makes the host unusable for every profile.
func (r *Runtime) diagnoseEgress(ctx context.Context, result *testResult, allowExtra []string) {
	policy, err := r.loadEgress(ctx)
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

func diagnose(health msbctl.Health, err error, publicKey string) testResult {
	switch {
	case errors.Is(err, remote.ErrHostKeyMismatch):
		return testResult{Problem: "host_key_mismatch", Hint: "The host presented a different SSH host key than the pinned one. Verify it on the host before updating the pin."}
	case errors.Is(err, remote.ErrNotAuthorized):
		return testResult{Problem: "not_authorized", Hint: "Authorize the plugin's key on the host: " + authorizeCommand(publicKey)}
	case errors.Is(err, msbctl.ErrUnreachable):
		return testResult{Problem: "unreachable", Hint: "The host's SSH server did not answer."}
	case msbctl.CodeOf(err) == msbctl.CodeDenied:
		return testResult{Problem: "refused", Hint: "The host refused `msbctl kandev`: authorize the key with --kandev, and check msbctl on the host is recent enough."}
	case isOutdated(err):
		return testResult{Problem: "outdated", Hint: "msbctl on the host lacks features this plugin needs (" + strings.Join(health.Missing(), ", ") + "). Update msb-manager on the host.", Health: &health}
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return testResult{Problem: "protocol", Hint: "The host's msbctl speaks a different kandev protocol version than this plugin.", Health: &health}
	case err != nil:
		return testResult{Problem: "unavailable", Hint: "msbctl on the host did not return a health report. Run `msbctl kandev health` on the host to see why: a config.toml it cannot load, for one."}
	}
	result := testResult{OK: health.Usable(), Health: &health}
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

// diagnoseTLS adds what certificate care found to a proxy-mode result. A
// host-side problem already found is kept, except no_data_path: a proxy
// without a certificate reports exactly that, and the certificate problem
// is its cause and the more useful thing to say.
func (r *Runtime) diagnoseTLS(ctx context.Context, result *testResult, outcome tlsOutcome) {
	set := func(problem, hint string) {
		result.OK = false
		if result.Problem == "" || result.Problem == "no_data_path" {
			result.Problem, result.Hint = problem, hint
		}
	}
	switch outcome.State {
	case tlsNoRoot:
		set("no_root", "Create the plugin's root certificate (ca.create), then install it on the Kandev server (ca.get).")
		return
	case tlsNotPermitted:
		set("not_permitted", "The host's base_url is outside the names the root may certify. Register it under a permitted name, or create a new root that covers it.")
		return
	case tlsFailed:
		set("tls_install_failed", "The host refused or did not accept a new certificate; it is retried automatically.")
		return
	}
	root, err := r.root(ctx)
	if err != nil {
		return
	}
	if r.rootTrusted(root) != nil {
		set("root_not_trusted", "The Kandev server does not trust the plugin's root yet. Install it (ca.get lists the steps) and restart Kandev.")
	}
}

func isOutdated(err error) bool {
	var e *msbctl.Error
	return errors.As(err, &e) && e.Reason == msbctl.ReasonOutdated
}
