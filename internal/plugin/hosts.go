package plugin

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/msbctl"
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

const registryWhat = "the host registry"

// hostActions serve the Sandbox Hosts page. Every action is admin-only in
// the manifest: the registry decides where every workspace's sandboxes run.
type hostActions struct {
	registry registryWriter
	status   statusReader
	keys     publicKeys
	connect  connector
	tester   hostTester
	healer   *healAfterWrite
	scope    *rootScope
	dialer   sshx.Dialer
}

func (a *hostActions) routes() map[string]actionFunc {
	return map[string]actionFunc{
		ActionHostsList:   a.list,
		ActionHostsScan:   a.scan,
		ActionHostsAdd:    a.add,
		ActionHostsUpdate: a.update,
		ActionHostsDrain:  a.drain,
		ActionHostsRemove: a.remove,
		ActionHostsTest:   a.test,
	}
}

// hostView is a host as the page shows it, with its key fingerprint and,
// in the list, its last check.
type hostView struct {
	hosts.Host
	Fingerprint string            `json:"fingerprint"`
	Status      *hostcheck.Status `json:"status,omitempty"`
}

func viewOf(h hosts.Host) hostView {
	if h.Labels == nil {
		h.Labels = []string{}
	}
	fingerprint, _ := sshx.Fingerprint(h.HostKey)
	return hostView{Host: h, Fingerprint: fingerprint}
}

func (a *hostActions) list(ctx context.Context, body []byte) kandev.Response {
	if err := kandev.Decode(body, &struct{}{}); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	publicKey, err := a.keys.PublicKey(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsList, registryWhat, err)
	}
	registry, err := a.registry.Load(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsList, registryWhat, err)
	}
	status, err := a.status.Load(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsList, registryWhat, err)
	}
	views := make([]hostView, 0, len(registry.Hosts))
	for _, h := range registry.Hosts {
		view := viewOf(h)
		if s, found := status[h.Name]; found {
			view.Status = &s
		}
		views = append(views, view)
	}
	return kandev.OK(map[string]any{
		// The release hosts.setup installs and hosts.upgrade brings a host to.
		"msbctl_release": msbctl.ManagerPin.Version,
		"public_key":     publicKey,
		"authorize":      hostcheck.AuthorizeCommand(publicKey),
		"hosts":          views,
	})
}

// scan fetches the key a host presents, for the operator to confirm before
// it is pinned by hosts.add. Nothing is stored.
func (a *hostActions) scan(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		SSH string `json:"ssh"`
	}
	if err := kandev.Decode(body, &in); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected {\"ssh\": \"user@host[:port]\"}")
	}
	dest := strings.TrimSpace(in.SSH)
	if _, _, _, err := hosts.ParseSSH(dest); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "ssh: "+err.Error())
	}
	key, err := sshx.ScanHostKey(ctx, dest, a.dialer)
	if err != nil {
		log.Printf("%s %s: %v", ActionHostsScan, dest, err)
		return kandev.Fail(http.StatusBadGateway, "could not reach the host's SSH server")
	}
	fingerprint, _ := sshx.Fingerprint(key)
	return kandev.OK(map[string]any{"host_key": key, "fingerprint": fingerprint})
}

func (a *hostActions) add(ctx context.Context, body []byte) kandev.Response {
	return a.write(ctx, body, ActionHostsAdd, func(reg hosts.Registry, h hosts.Host) (hosts.Registry, error) {
		h.Draining = false
		return reg.Add(h)
	})
}

func (a *hostActions) update(ctx context.Context, body []byte) kandev.Response {
	return a.write(ctx, body, ActionHostsUpdate, hosts.Registry.Update)
}

// write saves a host given whole, then gives it a certificate.
func (a *hostActions) write(ctx context.Context, body []byte, action string, change func(hosts.Registry, hosts.Host) (hosts.Registry, error)) kandev.Response {
	var in hosts.Host
	if err := kandev.Decode(body, &in); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected a host: name, ssh, host_key, base_url, labels")
	}
	if res, refused := a.scope.refuse(ctx, in); refused {
		return res
	}
	if _, err := sshx.ParseHostKey(in.HostKey); err != nil && strings.TrimSpace(in.HostKey) != "" {
		return validationFailure(&hosts.ValidationError{Fields: []hosts.FieldError{{Field: "host_key", Message: err.Error()}}})
	}
	registry, err := a.registry.Mutate(ctx, func(reg hosts.Registry) (hosts.Registry, error) { return change(reg, in) })
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return kandev.Internal(action, registryWhat, err)
	}
	saved, _ := registry.Find(strings.TrimSpace(in.Name))
	status := http.StatusOK
	if action == ActionHostsAdd {
		status = http.StatusCreated
	}
	out := map[string]any{"host": viewOf(saved)}
	if outcome, tried := a.healer.heal(ctx, saved); tried {
		out["tls"] = outcome
	}
	return kandev.Response{Status: status, Body: out}
}

func (a *hostActions) drain(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name     string `json:"name"`
		Draining *bool  `json:"draining"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Draining == nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\", \"draining\": true|false}")
	}
	registry, err := a.registry.Mutate(ctx, func(reg hosts.Registry) (hosts.Registry, error) {
		return reg.SetDraining(in.Name, *in.Draining)
	})
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return kandev.Internal(ActionHostsDrain, registryWhat, err)
	}
	saved, _ := registry.Find(in.Name)
	return kandev.OK(map[string]any{"host": viewOf(saved)})
}

// remove refuses to forget a host that still owns kandev sandboxes: every
// later call for them routes by the host name in their resource state, so
// removing it would strand them. Only the host knows its inventory, so it is
// asked; `force` removes an unreachable host anyway.
func (a *hostActions) remove(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Name == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\", \"force\": false}")
	}
	h, res, found := findHost(ctx, a.registry, ActionHostsRemove, in.Name)
	if !found {
		return res
	}
	if res, refused := a.refuseOccupied(ctx, h, in.Force); refused {
		return res
	}
	_, err := a.registry.Mutate(ctx, func(reg hosts.Registry) (hosts.Registry, error) { return reg.Remove(in.Name) })
	if res, handled := registryFailure(err); handled {
		return res
	}
	if err != nil {
		return kandev.Internal(ActionHostsRemove, registryWhat, err)
	}
	a.tester.Forget(ctx, in.Name)
	return kandev.OK(map[string]any{"removed": in.Name})
}

// refuseOccupied refuses to remove a host that reports sandboxes, or that
// cannot say, unless forced.
func (a *hostActions) refuseOccupied(ctx context.Context, h hosts.Host, force bool) (kandev.Response, bool) {
	client, err := a.connect(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsRemove, registryWhat, err), true
	}
	sandboxes, err := client.List(ctx, h)
	switch {
	case err == nil && len(sandboxes) > 0:
		return kandev.Response{Status: http.StatusConflict, Body: map[string]any{
			"error": "the host still has kandev sandboxes; drain it and wait for them to be destroyed", "sandboxes": len(sandboxes),
		}}, true
	case err != nil && !force:
		log.Printf("%s %s: %v", ActionHostsRemove, h.Name, err)
		return kandev.Fail(http.StatusBadGateway, "could not confirm the host has no sandboxes; retry, or remove with force"), true
	}
	return kandev.Response{}, false
}

func (a *hostActions) test(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name string `json:"name"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Name == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected {\"name\": \"...\"}")
	}
	h, res, found := findHost(ctx, a.registry, ActionHostsTest, in.Name)
	if !found {
		return res
	}
	result, err := a.tester.Test(ctx, h)
	if err != nil {
		return kandev.Internal(ActionHostsTest, registryWhat, err)
	}
	return kandev.OK(result)
}

// findHost returns a registered host, or the response refusing the action.
func findHost(ctx context.Context, registry registryReader, action, name string) (hosts.Host, kandev.Response, bool) {
	reg, err := registry.Load(ctx)
	if err != nil {
		return hosts.Host{}, kandev.Internal(action, registryWhat, err), false
	}
	h, found := reg.Find(name)
	if !found {
		return hosts.Host{}, kandev.Fail(http.StatusNotFound, hosts.ErrNotFound.Error()), false
	}
	return h, kandev.Response{}, true
}

func validationFailure(v *hosts.ValidationError) kandev.Response {
	return kandev.Response{Status: http.StatusUnprocessableEntity, Body: map[string]any{"error": "the host is invalid", "fields": v.Fields}}
}

// registryFailures map the registry's own errors to statuses.
var registryFailures = []struct {
	err    error
	status int
}{
	{hosts.ErrNotFound, http.StatusNotFound},
	{hosts.ErrExists, http.StatusConflict},
	{hosts.ErrTooMany, http.StatusConflict},
}

// registryFailure maps the registry's own errors to responses.
func registryFailure(err error) (kandev.Response, bool) {
	if err == nil {
		return kandev.Response{}, false
	}
	var invalid *hosts.ValidationError
	if errors.As(err, &invalid) {
		return validationFailure(invalid), true
	}
	for _, f := range registryFailures {
		if errors.Is(err, f.err) {
			return kandev.Fail(f.status, err.Error()), true
		}
	}
	return kandev.Response{}, false
}

// rootScope refuses a base URL no certificate from the root could cover.
// Without a root there is nothing to check yet.
type rootScope struct{ roots rootReader }

func (s *rootScope) refuse(ctx context.Context, in hosts.Host) (kandev.Response, bool) {
	root, err := s.roots.Root(ctx)
	if err != nil {
		return kandev.Response{}, false
	}
	name := hostcheck.HostName(hosts.Normalize(in))
	if name == "" || root.Permits(name) {
		return kandev.Response{}, false
	}
	return validationFailure(&hosts.ValidationError{Fields: []hosts.FieldError{{
		Field:   "base_url",
		Message: "outside the names the plugin's root may certify (" + strings.Join(root.Constraints().DNSSuffixes, ", ") + ")",
	}}}), true
}

// healAfterWrite issues a certificate for a newly added or changed host,
// best effort: the host is saved either way, and the maintainer retries.
type healAfterWrite struct {
	roots   rootReader
	connect connector
	checker *hostcheck.Checker
}

func (h *healAfterWrite) heal(ctx context.Context, saved hosts.Host) (hostcheck.TLSOutcome, bool) {
	if _, err := h.roots.Root(ctx); err != nil {
		return hostcheck.TLSOutcome{}, false
	}
	client, err := h.connect(ctx)
	if err != nil {
		return hostcheck.TLSOutcome{}, false
	}
	health, err := client.Health(ctx, saved)
	if err != nil {
		return hostcheck.TLSOutcome{State: hostcheck.TLSFailed, Reason: "unreachable"}, true
	}
	return h.checker.Heal(ctx, client, saved, health), true
}
