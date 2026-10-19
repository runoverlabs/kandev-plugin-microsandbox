package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"

	"kandev-plugin-microsandbox/internal/egress"
)

// The plugin-wide egress policy: named groups of destinations, and the
// groups every sandbox gets. Kept in Host state, like the host registry, so
// one admin change reaches every new sandbox on every host.
const egressStateKey = "egress"

// Egress action keys, matching manifest.yaml.
const (
	ActionEgressList     = "egress.list"
	ActionEgressPut      = "egress.put"
	ActionEgressRemove   = "egress.remove"
	ActionEgressDefaults = "egress.defaults"
)

func (r *Runtime) loadEgress(ctx context.Context) (egress.Policy, error) {
	h, err := r.host()
	if err != nil {
		return egress.Policy{}, err
	}
	value, found, err := h.GetState(ctx, stateScope, "", egressStateKey)
	if err != nil {
		return egress.Policy{}, fmt.Errorf("read egress policy: %w", err)
	}
	if !found {
		return egress.Policy{Version: egress.PolicyVersion}, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return egress.Policy{}, errors.New("egress policy is unreadable")
	}
	var policy egress.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return egress.Policy{}, errors.New("egress policy is unreadable")
	}
	if err := policy.Check(); err != nil {
		return egress.Policy{}, err
	}
	return policy, nil
}

// mutateEgress applies change to the stored policy under the registry lock,
// which also serializes egress edits against each other.
func (r *Runtime) mutateEgress(ctx context.Context, change func(egress.Policy) (egress.Policy, error)) (egress.Policy, error) {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	policy, err := r.loadEgress(ctx)
	if err != nil {
		return egress.Policy{}, err
	}
	next, err := change(policy)
	if err != nil {
		return egress.Policy{}, err
	}
	next.Version = egress.PolicyVersion
	if next.Groups == nil {
		next.Groups = []egress.Group{}
	}
	if next.Defaults == nil {
		next.Defaults = []string{}
	}
	if err := next.Check(); err != nil {
		return egress.Policy{}, err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return egress.Policy{}, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return egress.Policy{}, err
	}
	h, err := r.host()
	if err != nil {
		return egress.Policy{}, err
	}
	if err := h.SetState(ctx, stateScope, "", egressStateKey, value); err != nil {
		return egress.Policy{}, fmt.Errorf("write egress policy: %w", err)
	}
	return next, nil
}

// egressView is the policy as the admin sees it: every group, built-in ones
// included, each marked when it is a default.
type egressView struct {
	Groups   []egressGroupView `json:"groups"`
	Defaults []string          `json:"defaults"`
}

type egressGroupView struct {
	egress.Group
	Default bool `json:"default"`
}

func viewEgress(p egress.Policy) egressView {
	view := egressView{Groups: []egressGroupView{}, Defaults: slices.Clone(p.Defaults)}
	if view.Defaults == nil {
		view.Defaults = []string{}
	}
	for _, g := range p.All() {
		view.Groups = append(view.Groups, egressGroupView{Group: g, Default: slices.Contains(p.Defaults, g.Name)})
	}
	return view
}

// egressFailure turns a policy error into a response the admin can act on.
func egressFailure(action string, err error) response {
	switch {
	case errors.Is(err, egress.ErrEntry), errors.Is(err, egress.ErrPolicy), errors.Is(err, egress.ErrUnknown):
		return fail(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, ErrNoHost):
		return fail(http.StatusServiceUnavailable, "the plugin is still starting; try again")
	}
	log.Printf("%s: %v", action, err)
	return fail(http.StatusInternalServerError, "the egress policy could not be read or saved")
}

func (r *Runtime) actionEgressList(ctx context.Context, body []byte) response {
	if err := decode(body, &struct{}{}); err != nil {
		return fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	policy, err := r.loadEgress(ctx)
	if err != nil {
		return egressFailure(ActionEgressList, err)
	}
	return ok(viewEgress(policy))
}

// actionEgressPut creates or replaces a custom group. It applies to sandboxes
// provisioned from now on; existing ones keep the rules they were made with.
func (r *Runtime) actionEgressPut(ctx context.Context, body []byte) response {
	var in egress.Group
	if err := decode(body, &in); err != nil || in.Builtin {
		return fail(http.StatusUnprocessableEntity, `expected {"name": "...", "description": "...", "entries": ["host", "host:port", "address:port"]}`)
	}
	group, err := egress.CheckGroup(in)
	if err != nil {
		return egressFailure(ActionEgressPut, err)
	}
	created := false
	policy, err := r.mutateEgress(ctx, func(p egress.Policy) (egress.Policy, error) {
		i := slices.IndexFunc(p.Groups, func(g egress.Group) bool { return g.Name == group.Name })
		if i < 0 {
			if len(p.Groups) >= egress.MaxGroups {
				return p, fmt.Errorf("%w: at most %d groups", egress.ErrPolicy, egress.MaxGroups)
			}
			created = true
			p.Groups = append(p.Groups, group)
		} else {
			p.Groups[i] = group
		}
		return p, nil
	})
	if err != nil {
		return egressFailure(ActionEgressPut, err)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return response{status, viewEgress(policy)}
}

// actionEgressRemove deletes a custom group and drops it from the defaults.
// Profiles that still name it fail validation until they are edited.
func (r *Runtime) actionEgressRemove(ctx context.Context, body []byte) response {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(body, &in); err != nil || in.Name == "" {
		return fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	missing := false
	policy, err := r.mutateEgress(ctx, func(p egress.Policy) (egress.Policy, error) {
		if g, found := p.Lookup(in.Name); found && g.Builtin {
			return p, fmt.Errorf("%w: %q is a built-in group", egress.ErrPolicy, in.Name)
		}
		before := len(p.Groups)
		p.Groups = slices.DeleteFunc(p.Groups, func(g egress.Group) bool { return g.Name == in.Name })
		missing = len(p.Groups) == before
		p.Defaults = slices.DeleteFunc(p.Defaults, func(n string) bool { return n == in.Name })
		return p, nil
	})
	if err != nil {
		return egressFailure(ActionEgressRemove, err)
	}
	if missing {
		return fail(http.StatusNotFound, "no such egress group")
	}
	return ok(viewEgress(policy))
}

// actionEgressDefaults sets the groups every sandbox gets, built-in or custom.
func (r *Runtime) actionEgressDefaults(ctx context.Context, body []byte) response {
	var in struct {
		Groups []string `json:"groups"`
	}
	if err := decode(body, &in); err != nil || in.Groups == nil {
		return fail(http.StatusUnprocessableEntity, `expected {"groups": ["openrouter", "lan-llm"]}`)
	}
	var names []string
	for _, n := range in.Groups {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	policy, err := r.mutateEgress(ctx, func(p egress.Policy) (egress.Policy, error) {
		p.Defaults = names
		return p, nil
	})
	if err != nil {
		return egressFailure(ActionEgressDefaults, err)
	}
	return ok(viewEgress(policy))
}
