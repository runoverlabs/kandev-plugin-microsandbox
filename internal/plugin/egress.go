package plugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/kandev"
)

// Egress action keys, matching manifest.yaml.
const (
	ActionEgressList     = "egress.list"
	ActionEgressPut      = "egress.put"
	ActionEgressRemove   = "egress.remove"
	ActionEgressDefaults = "egress.defaults"
)

// policyStore changes the egress policy under its lock.
type policyStore interface {
	policyReader
	Mutate(ctx context.Context, change func(egress.Policy) (egress.Policy, error)) (egress.Policy, error)
}

// egressActions serve the Egress page. A change applies to sandboxes
// provisioned from then on; existing ones keep the rules they were made with.
type egressActions struct{ policy policyStore }

func (a *egressActions) routes() map[string]actionFunc {
	return map[string]actionFunc{
		ActionEgressList: a.list, ActionEgressPut: a.put, ActionEgressRemove: a.remove, ActionEgressDefaults: a.defaults,
	}
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
func egressFailure(action string, err error) kandev.Response {
	if errors.Is(err, egress.ErrEntry) || errors.Is(err, egress.ErrPolicy) || errors.Is(err, egress.ErrUnknown) {
		return kandev.Fail(http.StatusUnprocessableEntity, err.Error())
	}
	return kandev.Internal(action, "the egress policy", err)
}

func (a *egressActions) list(ctx context.Context, body []byte) kandev.Response {
	if err := kandev.Decode(body, &struct{}{}); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	policy, err := a.policy.Load(ctx)
	if err != nil {
		return egressFailure(ActionEgressList, err)
	}
	return kandev.OK(viewEgress(policy))
}

// put creates or replaces a custom group.
func (a *egressActions) put(ctx context.Context, body []byte) kandev.Response {
	var in egress.Group
	if err := kandev.Decode(body, &in); err != nil || in.Builtin {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name": "...", "description": "...", "entries": ["host", "host:port", "address:port"]}`)
	}
	group, err := egress.CheckGroup(in)
	if err != nil {
		return egressFailure(ActionEgressPut, err)
	}
	created := false
	policy, err := a.policy.Mutate(ctx, func(p egress.Policy) (egress.Policy, error) {
		i := slices.IndexFunc(p.Groups, func(g egress.Group) bool { return g.Name == group.Name })
		if i < 0 {
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
	return kandev.Response{Status: status, Body: viewEgress(policy)}
}

// remove deletes a custom group and drops it from the defaults. Profiles
// that still name it fail validation until they are edited.
func (a *egressActions) remove(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name string `json:"name"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Name == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	missing := false
	policy, err := a.policy.Mutate(ctx, func(p egress.Policy) (egress.Policy, error) {
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
		return kandev.Fail(http.StatusNotFound, "no such egress group")
	}
	return kandev.OK(viewEgress(policy))
}

// defaults sets the groups every sandbox gets, built-in or custom.
func (a *egressActions) defaults(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Groups []string `json:"groups"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Groups == nil {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"groups": ["openrouter", "lan-llm"]}`)
	}
	var names []string
	for _, n := range in.Groups {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	policy, err := a.policy.Mutate(ctx, func(p egress.Policy) (egress.Policy, error) {
		p.Defaults = names
		return p, nil
	})
	if err != nil {
		return egressFailure(ActionEgressDefaults, err)
	}
	return kandev.OK(viewEgress(policy))
}
