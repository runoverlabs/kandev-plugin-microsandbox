package hostsetup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
)

func (r *run) authorize(ctx context.Context) bool {
	out, err := r.asAccount(ctx, msbctl.AuthorizeScript(r.in.PublicKey))
	if err != nil || out.Exit != 0 {
		r.failed(StepAuthorize, "Authorizing the plugin's key failed.", out, err)
		return false
	}
	r.set(StepAuthorize, StateChanged, "The plugin's key may run msbctl kandev verbs as "+r.account+", and nothing else.")
	return true
}

// verify reads the host's health as the account and compares it with what
// this setup set. The data path may still be down: the plugin
// issues the proxy's certificate after registering the host.
func (r *run) verify(ctx context.Context) {
	health, err := msbctl.New(accountRunner{r}).Health(ctx, hosts.Host{})
	if err != nil {
		r.set(StepVerify, StateFailed, "msbctl kandev health did not answer as expected: "+describe(err)+".")
		return
	}
	want, _ := r.desired()
	var drift []string
	if !health.Enabled {
		drift = append(drift, "enabled = true")
	}
	if health.Serve.Mode != msbctl.ServeProxy {
		drift = append(drift, `serve = "proxy"`)
	}
	if strings.TrimRight(health.BaseURL, "/") != want.BaseURL {
		drift = append(drift, fmt.Sprintf("base_url = %q", want.BaseURL))
	}
	if health.Serve.Listen != "" && !strings.HasPrefix(health.Serve.Listen, want.ProxyListen) && !strings.HasPrefix(health.Serve.Listen, "["+want.ProxyListen+"]") {
		drift = append(drift, fmt.Sprintf("proxy_listen = %q", want.ProxyListen))
	}
	if r.in.EgressFromPlugin && (health.Egress == nil || !contains(health.Egress.AllowExtra, "*")) {
		drift = append(drift, `allow_extra = ["*"]`)
	}
	if !health.KVM {
		r.set(StepVerify, StateFailed, "msbctl reports no usable /dev/kvm for "+r.account+".")
		return
	}
	if len(drift) > 0 {
		r.set(StepVerify, StateManual, "The host's health report disagrees with what setup set. Check these under [kandev] in ~"+r.account+"/.config/msb/config.toml:", drift...)
		return
	}
	r.set(StepVerify, StateOK, "msbctl "+health.MsbctlVersion+" and msb "+health.MsbVersion+" report this host ready for Kandev.")
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func describe(err error) string {
	var e *msbctl.Error
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeUnsupported:
		return "it lacks a feature or protocol version the plugin needs"
	case errors.As(err, &e):
		return e.Code
	default:
		return "no answer"
	}
}
