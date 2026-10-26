package plugin

import (
	"context"
	"errors"
	"net/http"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/kandev"
)

// Host job action keys, matching manifest.yaml. hosts.setup and
// hosts.upgrade start a job, since an action has 15 seconds; the page
// follows it with hosts.setup.status.
const (
	ActionHostsSetup       = "hosts.setup"
	ActionHostsUpgrade     = "hosts.upgrade"
	ActionHostsSetupStatus = "hosts.setup.status"
)

// jobActions start and follow host setup and upgrade jobs.
type jobActions struct {
	manager  *hostsetup.Manager
	jobs     *hostsetup.Jobs
	registry registryReader
	keys     publicKeys
	connect  connector
	scope    *rootScope
	hostKeys hostKeys
}

func (a *jobActions) routes() map[string]actionFunc {
	return map[string]actionFunc{ActionHostsSetup: a.setup, ActionHostsUpgrade: a.upgrade, ActionHostsSetupStatus: a.status}
}

// jobView is a job as the page shows it, its host with the fingerprint.
type jobView struct {
	hostsetup.Job
	Host *hostView `json:"host,omitempty"`
}

func viewJob(keys hostKeys, job hostsetup.Job) jobView {
	view := jobView{Job: job}
	if job.Host != nil {
		host := viewOf(keys, *job.Host)
		view.Host = &host
	}
	return view
}

// started answers a job start: the job, or why it was refused.
func (a *jobActions) started(id string, err error) kandev.Response {
	var busy *hostsetup.BusyError
	switch {
	case errors.As(err, &busy):
		return kandev.Fail(http.StatusConflict, err.Error())
	case errors.Is(err, hostsetup.ErrStopping):
		return kandev.Fail(http.StatusServiceUnavailable, err.Error())
	}
	job, _ := a.jobs.Snapshot(id)
	return kandev.Response{Status: http.StatusAccepted, Body: viewJob(a.hostKeys, job)}
}

func (a *jobActions) setup(ctx context.Context, body []byte) kandev.Response {
	var in hostsetup.Request
	if err := kandev.Decode(body, &in); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name", "ssh": "admin@host[:port]", "host_key", "admin_key" or "admin_password", "base_url", "labels", "account", "egress_from_plugin"}`)
	}
	plan, err := in.Plan()
	var invalid *hosts.ValidationError
	switch {
	case errors.As(err, &invalid):
		return validationFailure(invalid)
	case err != nil:
		return kandev.Fail(http.StatusUnprocessableEntity, err.Error())
	}
	if res, refused := a.scope.refuse(ctx, plan.Host); refused {
		return res
	}
	if res, refused := a.refuseOtherMachine(ctx, plan); refused {
		return res
	}
	publicKey, err := a.keys.PublicKey(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsSetup, keyWhat, err)
	}
	plan.Input.PublicKey = publicKey
	return a.started(a.manager.StartSetup(plan))
}

// refuseOtherMachine refuses to set up a machine under the name of another.
func (a *jobActions) refuseOtherMachine(ctx context.Context, plan hostsetup.Plan) (kandev.Response, bool) {
	registry, err := a.registry.Load(ctx)
	if err != nil {
		return kandev.Internal(ActionHostsSetup, registryWhat, err), true
	}
	if existing, found := registry.Find(plan.Host.Name); found && !plan.SameMachine(existing) {
		return kandev.Fail(http.StatusConflict, "a host named "+plan.Host.Name+" is registered at another address"), true
	}
	return kandev.Response{}, false
}

func (a *jobActions) upgrade(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name string `json:"name"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Name == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	h, res, found := findHost(ctx, a.registry, ActionHostsUpgrade, in.Name)
	if !found {
		return res
	}
	if _, err := a.connect(ctx); err != nil {
		return kandev.Internal(ActionHostsUpgrade, keyWhat, err)
	}
	return a.started(a.manager.StartUpgrade(h))
}

func (a *jobActions) status(_ context.Context, body []byte) kandev.Response {
	var in struct {
		ID string `json:"id"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.ID == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"id": "..."}`)
	}
	job, found := a.jobs.Snapshot(in.ID)
	if !found {
		return kandev.Fail(http.StatusNotFound, "no such setup job; finished jobs are kept for an hour, and none survives a plugin restart")
	}
	return kandev.OK(viewJob(a.hostKeys, job))
}
