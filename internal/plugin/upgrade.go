package plugin

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx"
)

// ActionHostsUpgrade brings a host's msb-manager to the release host setup
// installs (msbctl.ManagerPin), through the plugin's own key (F24). It runs
// as a job, followed with hosts.setup.status, since an install outlasts an
// action's 15 seconds.
const ActionHostsUpgrade = "hosts.upgrade"

const upgradeTimeout = 10 * time.Minute

// upgradeTarget is the release hosts.upgrade installs; a variable so tests
// can ask for one newer than the hosts they fake.
var upgradeTarget = msbctl.ManagerPin.Version

// Upgrade job steps.
const (
	stepUpgradeCheck = "check"
	stepUpgrade      = "upgrade"
)

func (r *Runtime) actionUpgrade(ctx context.Context, body []byte) response {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(body, &in); err != nil || in.Name == "" {
		return fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return internalFailure(ActionHostsUpgrade, err)
	}
	h, found := registry.Find(in.Name)
	if !found {
		return fail(http.StatusNotFound, hosts.ErrNotFound.Error())
	}
	if _, err := r.client(ctx); err != nil {
		return internalFailure(ActionHostsUpgrade, err)
	}
	steps := []hostsetup.Step{
		{Key: stepUpgradeCheck, Title: "Read the host's msbctl version", State: hostsetup.StateSkipped},
		{Key: stepUpgrade, Title: "Update msb-manager to " + upgradeTarget, State: hostsetup.StateSkipped},
		{Key: stepTest, Title: "Run Test", State: hostsetup.StateSkipped},
	}
	id, res := r.startJob(h.Name, steps, upgradeTimeout, func(ctx context.Context, id string) {
		r.runUpgrade(ctx, id, h)
	})
	if id == "" {
		return res
	}
	snapshot, _ := r.jobs.snapshot(id)
	return response{http.StatusAccepted, snapshot}
}

func (r *Runtime) runUpgrade(ctx context.Context, id string, h hosts.Host) {
	client, err := r.client(ctx)
	if err != nil {
		r.setJobStep(id, stepUpgradeCheck, hostsetup.StateFailed, "The plugin's key is unavailable.")
		r.finishJob(id, jobFailed, nil)
		return
	}
	health, err := client.Health(ctx, h)
	// An outdated host still reports its version, which is all this needs.
	if err != nil && health.MsbctlVersion == "" {
		log.Printf("%s %s: %v", ActionHostsUpgrade, h.Name, err)
		r.setJobStep(id, stepUpgradeCheck, hostsetup.StateFailed, "The host did not answer health; run Test for why.")
		r.finishJob(id, jobFailed, nil)
		return
	}
	have := health.MsbctlVersion
	switch {
	case !msbctl.Older(have, upgradeTarget):
		r.setJobStep(id, stepUpgradeCheck, hostsetup.StateOK, "msbctl "+have+" is not older than "+upgradeTarget+": nothing to update.")
		r.setJobStep(id, stepUpgrade, hostsetup.StateOK, "Already current.")
		r.finishUpgrade(ctx, id, client, h, nil)
		return
	case !health.CanSelfUpdate():
		r.setJobStep(id, stepUpgradeCheck, hostsetup.StateManual,
			"msbctl "+have+" does not take self-update from the plugin's key (msb-manager "+msbctl.SelfUpdateVersion+" does). Run hosts.setup with an admin login, or `msbctl self-update` on the host.")
		r.finishJob(id, jobFailed, nil)
		return
	}
	r.setJobStep(id, stepUpgradeCheck, hostsetup.StateOK, "msbctl "+have+".")
	got, err := client.SelfUpdate(ctx, h, upgradeTarget)
	if err != nil {
		log.Printf("%s %s: %v", ActionHostsUpgrade, h.Name, err)
		r.setJobStep(id, stepUpgrade, hostsetup.StateFailed, upgradeFailure(err))
		r.finishJob(id, jobFailed, nil)
		return
	}
	detail := "msbctl " + got.MsbctlVersion + " was already installed."
	if got.Updated {
		detail = "Updated msbctl from " + have + " to " + got.MsbctlVersion + "."
	}
	r.setJobStep(id, stepUpgrade, map[bool]string{true: hostsetup.StateChanged, false: hostsetup.StateOK}[got.Updated], detail)
	var manual []string
	if got.Updated {
		// The proxy is a long-running service: it keeps the release it
		// started with until restarted, which the plugin's key cannot do.
		manual = append(manual, "The TLS proxy keeps running msbctl "+have+" until it restarts. On the host, when no session needs it: systemctl --user restart msb-kandev-proxy.service")
	}
	r.finishUpgrade(ctx, id, client, h, manual)
}

func (r *Runtime) finishUpgrade(ctx context.Context, id string, client *msbctl.Client, h hosts.Host, manual []string) {
	test := r.checkHost(ctx, client, h)
	r.recordStatus(ctx, h.Name, test)
	state, detail := hostsetup.StateOK, "Test passes."
	if !test.OK {
		state, detail = hostsetup.StateManual, "Test reports "+test.Problem+": "+test.Hint
	}
	r.setJobStep(id, stepTest, state, detail)
	view := viewOf(h)
	r.finishJob(id, jobDone, func(j *setupJob) { j.Host, j.Test, j.Manual = &view, &test, manual })
}

func upgradeFailure(err error) string {
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return "The host runs msb-manager from a git checkout: update it there with git pull."
	case msbctl.CodeOf(err) == msbctl.CodeDenied:
		return "The host refused: Kandev is turned off in its [kandev] section, or the release would be older than the one it runs."
	case errors.Is(err, msbctl.ErrUnreachable), errors.Is(err, sshx.ErrNotAuthorized), errors.Is(err, sshx.ErrHostKeyMismatch):
		return "The host could not be reached with the plugin's key; run Test for why."
	default:
		return "The update failed on the host; its installer's output is on the host only (run `msbctl self-update` there to see it)."
	}
}
