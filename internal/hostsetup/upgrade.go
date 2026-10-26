package hostsetup

import (
	"context"
	"errors"
	"log"
	"time"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
)

const upgradeTimeout = 10 * time.Minute

// UpgradeTarget is the release an upgrade installs: the one setup installs.
// A variable so tests can ask for one newer than the hosts they fake.
var UpgradeTarget = msbctl.ManagerPin.Version

// Upgrade job steps.
const (
	StepUpgradeCheck = "check"
	StepUpgrade      = "upgrade"
	StepProxy        = "proxy"
)

const restartProxyByHand = "On the host, when no session needs it: systemctl --user restart msb-kandev-proxy.service (or msbctl host kandev install, if its unit runs an old path)."

// StartUpgrade brings a host's msb-manager to UpgradeTarget through the
// plugin's own key (msbctl F24), as a job: an install outlasts an action.
func (m *Manager) StartUpgrade(h hosts.Host) (string, error) {
	steps := []Step{
		{Key: StepUpgradeCheck, Title: "Read the host's msbctl version", State: StateSkipped},
		{Key: StepUpgrade, Title: "Update msb-manager to " + UpgradeTarget, State: StateSkipped},
		{Key: StepProxy, Title: "Run the TLS proxy on that release", State: StateSkipped},
		{Key: StepTest, Title: "Run Test", State: StateSkipped},
	}
	return m.Jobs.Start(h.Name, steps, upgradeTimeout, func(ctx context.Context, id string) {
		m.runUpgrade(ctx, id, h)
	})
}

// upgrade is one upgrade job's state.
type upgrade struct {
	m   *Manager
	id  string
	h   hosts.Host
	api HostAPI
}

func (u *upgrade) step(key, state, detail string) { u.m.Jobs.setStep(u.id, key, state, detail) }

func (u *upgrade) fail(key, detail string) {
	u.step(key, StateFailed, detail)
	u.m.Jobs.finish(u.id, JobFailed, nil)
}

func (m *Manager) runUpgrade(ctx context.Context, id string, h hosts.Host) {
	api, err := m.Connect(ctx)
	u := &upgrade{m: m, id: id, h: h, api: api}
	if err != nil {
		u.fail(StepUpgradeCheck, "The plugin's key is unavailable.")
		return
	}
	health, err := api.Health(ctx, h)
	// An outdated host still reports its version, which is all this needs.
	if err != nil && health.MsbctlVersion == "" {
		log.Printf("hosts.upgrade %s: %v", h.Name, err)
		u.fail(StepUpgradeCheck, "The host did not answer health; run Test for why.")
		return
	}
	have := health.MsbctlVersion
	switch {
	case !msbctl.Older(have, UpgradeTarget):
		u.step(StepUpgradeCheck, StateOK, "msbctl "+have+" is not older than "+UpgradeTarget+".")
		u.step(StepUpgrade, StateOK, "Already current.")
		u.finish(ctx, u.settleProxy(ctx, health))
	case !health.CanSelfUpdate():
		u.step(StepUpgradeCheck, StateManual,
			"msbctl "+have+" does not take self-update from the plugin's key (msb-manager "+msbctl.SelfUpdateVersion+" does). Run hosts.setup with an admin login, or `msbctl self-update` on the host.")
		u.m.Jobs.finish(id, JobFailed, nil)
	default:
		u.step(StepUpgradeCheck, StateOK, "msbctl "+have+".")
		u.update(ctx, have)
	}
}

// update runs self-update, then makes sure the proxy follows.
func (u *upgrade) update(ctx context.Context, have string) {
	got, err := u.api.SelfUpdate(ctx, u.h, UpgradeTarget)
	if err != nil {
		log.Printf("hosts.upgrade %s: %v", u.h.Name, err)
		u.fail(StepUpgrade, upgradeFailure(err))
		return
	}
	detail, state := "msbctl "+got.MsbctlVersion+" was already installed.", StateOK
	if got.Updated {
		detail, state = "Updated msbctl from "+have+" to "+got.MsbctlVersion+".", StateChanged
	}
	u.step(StepUpgrade, state, detail)
	if got.Proxy != nil && proxySettled(got.Proxy.State) {
		u.step(StepProxy, proxyState(got.Proxy.State), proxyDetail(*got.Proxy))
		u.finish(ctx, nil)
		return
	}
	// The release that ran the update predates 0.6.1, which never restarts
	// the proxy, or its restart failed: the new release finishes it.
	after, err := u.api.Health(ctx, u.h)
	if err != nil && after.MsbctlVersion == "" {
		u.fail(StepProxy, "The host did not answer health after the update; run Test for why.")
		return
	}
	u.finish(ctx, u.settleProxy(ctx, after))
}

func proxySettled(state string) bool {
	return state == msbctl.ProxyRestarted || state == msbctl.ProxyCurrent || state == msbctl.ProxyNotRunning
}

// settleProxy makes a proxy that missed an update run the host's msbctl
// release, and returns what the operator still has to do, if anything.
func (u *upgrade) settleProxy(ctx context.Context, health msbctl.Health) []string {
	switch {
	case health.Serve.Mode != msbctl.ServeProxy || !health.Serve.Running:
		u.step(StepProxy, StateOK, "No TLS proxy runs on this host.")
		return nil
	case !health.ProxyStale():
		u.step(StepProxy, StateOK, "The proxy runs msbctl "+health.Serve.Version+".")
		return nil
	case msbctl.Older(health.MsbctlVersion, msbctl.RestartProxyVersion):
		u.step(StepProxy, StateManual, "The proxy runs an older release than msbctl "+health.MsbctlVersion+".")
		return []string{restartProxyByHand}
	}
	got, err := u.api.RestartProxy(ctx, u.h)
	if err != nil {
		log.Printf("hosts.upgrade %s: restart-proxy: %v", u.h.Name, err)
		u.step(StepProxy, StateFailed, "msbctl could not restart the proxy onto the new release.")
		return []string{restartProxyByHand}
	}
	u.step(StepProxy, proxyState(got.State), proxyDetail(got))
	return nil
}

func (u *upgrade) finish(ctx context.Context, manual []string) {
	u.m.finishWithTest(ctx, u.id, u.h, manual, "Test passes.")
}

func proxyState(state string) string {
	if state == msbctl.ProxyRestarted {
		return StateChanged
	}
	return StateOK
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

func upgradeFailure(err error) string {
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return "The host runs msb-manager from a git checkout: update it there with git pull."
	case msbctl.CodeOf(err) == msbctl.CodeDenied:
		return "The host refused: Kandev is turned off in its [kandev] section, or the release would be older than the one it runs."
	case errors.Is(err, msbctl.ErrUnreachable), errors.Is(err, remote.ErrNotAuthorized), errors.Is(err, remote.ErrHostKeyMismatch):
		return "The host could not be reached with the plugin's key; run Test for why."
	default:
		return "The update failed on the host; its installer's output is on the host only (run `msbctl self-update` there to see it)."
	}
}
