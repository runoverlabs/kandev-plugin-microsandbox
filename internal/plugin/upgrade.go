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
	stepProxy        = "proxy"
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
		{Key: stepProxy, Title: "Run the TLS proxy on that release", State: hostsetup.StateSkipped},
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
		r.setJobStep(id, stepUpgradeCheck, hostsetup.StateOK, "msbctl "+have+" is not older than "+upgradeTarget+".")
		r.setJobStep(id, stepUpgrade, hostsetup.StateOK, "Already current.")
		r.finishUpgrade(ctx, id, client, h, r.settleProxy(ctx, id, client, h, health))
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
	if got.Proxy != nil && (got.Proxy.State == msbctl.ProxyRestarted || got.Proxy.State == msbctl.ProxyCurrent || got.Proxy.State == msbctl.ProxyNotRunning) {
		r.setJobStep(id, stepProxy, proxyState(got.Proxy.State), proxyDetail(*got.Proxy))
		r.finishUpgrade(ctx, id, client, h, nil)
		return
	}
	// The release that ran the update predates 0.6.1, which never restarts
	// the proxy, or its restart failed: the new release finishes it.
	after, err := client.Health(ctx, h)
	if err != nil && after.MsbctlVersion == "" {
		r.setJobStep(id, stepProxy, hostsetup.StateFailed, "The host did not answer health after the update; run Test for why.")
		r.finishJob(id, jobFailed, nil)
		return
	}
	r.finishUpgrade(ctx, id, client, h, r.settleProxy(ctx, id, client, h, after))
}

// settleProxy makes a proxy that missed an update run the host's msbctl
// release, and returns what the operator still has to do, if anything.
func (r *Runtime) settleProxy(ctx context.Context, id string, client *msbctl.Client, h hosts.Host, health msbctl.Health) []string {
	switch {
	case health.Serve.Mode != msbctl.ServeProxy || !health.Serve.Running:
		r.setJobStep(id, stepProxy, hostsetup.StateOK, "No TLS proxy runs on this host.")
		return nil
	case !health.ProxyStale():
		r.setJobStep(id, stepProxy, hostsetup.StateOK, "The proxy runs msbctl "+health.Serve.Version+".")
		return nil
	case msbctl.Older(health.MsbctlVersion, msbctl.RestartProxyVersion):
		r.setJobStep(id, stepProxy, hostsetup.StateManual, "The proxy runs an older release than msbctl "+health.MsbctlVersion+".")
		return []string{restartProxyByHand}
	}
	got, err := client.RestartProxy(ctx, h)
	if err != nil {
		log.Printf("%s %s: restart-proxy: %v", ActionHostsUpgrade, h.Name, err)
		r.setJobStep(id, stepProxy, hostsetup.StateFailed, "msbctl could not restart the proxy onto the new release.")
		return []string{restartProxyByHand}
	}
	r.setJobStep(id, stepProxy, proxyState(got.State), proxyDetail(got))
	return nil
}

const restartProxyByHand = "On the host, when no session needs it: systemctl --user restart msb-kandev-proxy.service (or msbctl host kandev install, if its unit runs an old path)."

func proxyState(state string) string {
	if state == msbctl.ProxyRestarted {
		return hostsetup.StateChanged
	}
	return hostsetup.StateOK
}

func proxyDetail(p msbctl.ProxyRestart) string {
	switch p.State {
	case msbctl.ProxyRestarted:
		return "Restarted the proxy onto msbctl " + p.Version + "; Kandev reconnects its sessions."
	case msbctl.ProxyNotRunning:
		return "No TLS proxy runs on this host."
	default:
		return "The proxy already runs msbctl " + p.Version + "."
	}
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
