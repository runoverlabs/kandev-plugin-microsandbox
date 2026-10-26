package hostsetup

import (
	"context"
	"fmt"
	"strings"

	"kandev-plugin-microsandbox/internal/msbctl"
)

func (r *run) desired() (msbctl.KandevConfig, error) {
	sshConn := strings.Fields(r.facts.get("ssh_connection"))
	if len(sshConn) != 4 {
		return msbctl.KandevConfig{}, fmt.Errorf("the login's SSH_CONNECTION is not set, so the machine's own address is unknown")
	}
	c := msbctl.KandevConfig{ProxyListen: sshConn[2], BaseURL: r.result.BaseURL}
	if r.in.EgressFromPlugin {
		c.AllowExtra = []string{"*"}
	}
	return c, nil
}

func (r *run) configure(ctx context.Context) (bool, bool) {
	c, err := r.desired()
	if err != nil {
		r.set(StepConfig, StateFailed, err.Error()+".")
		return false, false
	}
	script, err := msbctl.ConfigureScript(c)
	if err != nil {
		r.set(StepConfig, StateFailed, err.Error()+".")
		return false, false
	}
	out, err := r.asAccount(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(StepConfig, "msbctl refused the [kandev] settings; config.toml is unchanged.", out, err)
		return false, false
	}
	changed, err := msbctl.ParseConfigure(out.Stdout)
	if err != nil {
		r.set(StepConfig, StateFailed, "msbctl host kandev configure gave no answer it could read.")
		return false, false
	}
	if len(changed) == 0 {
		r.set(StepConfig, StateOK, "[kandev] already has the TLS proxy on "+c.ProxyListen+" and base URL "+c.BaseURL+".")
		return false, true
	}
	r.set(StepConfig, StateChanged, "Set "+strings.Join(changed, ", ")+" under [kandev]: the TLS proxy on "+c.ProxyListen+", base URL "+c.BaseURL+".")
	return true, true
}

func (r *run) services(ctx context.Context, changed bool) bool {
	if !changed {
		if out, err := r.asAccount(ctx, msbctl.ServicesActiveScript()); err == nil && out.Exit == 0 {
			r.set(StepServices, StateOK, "The TLS proxy and the reaper are running.")
			return true
		}
	}
	out, err := r.asAccount(ctx, msbctl.ServicesScript())
	if err != nil || out.Exit != 0 {
		r.failed(StepServices, "Installing the proxy and reaper services failed.", out, err)
		return false
	}
	r.set(StepServices, StateChanged, "Installed and started the TLS proxy and the reaper.")
	return true
}
