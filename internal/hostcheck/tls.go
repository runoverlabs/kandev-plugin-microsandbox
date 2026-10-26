package hostcheck

import (
	"context"
	"errors"
	"log"
	"net/url"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/pki"
)

// TLSOutcome reports what certificate care did for one host.
type TLSOutcome struct {
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	NotAfter string `json:"not_after,omitempty"`
}

// TLS outcome states.
const (
	TLSNotProxy     = "not_proxy"     // the host terminates TLS some other way
	TLSNoRoot       = "no_root"       // nothing to issue from yet
	TLSNotPermitted = "not_permitted" // the host's name is outside the root
	TLSOK           = "ok"
	TLSRenewed      = "renewed"
	TLSFailed       = "failed"
)

// HostName is the name a host's certificate must carry: the host part of its
// registered base URL.
func HostName(h hosts.Host) string {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Heal gives a proxy-mode host a valid certificate from the current root if
// it lacks one: missing, expiring, for another name, or from a replaced root.
// It never asks first. Certificates are replaceable, and one that lapses
// breaks every session on the host.
func (c *Checker) Heal(ctx context.Context, api Host, h hosts.Host, health msbctl.Health) TLSOutcome {
	if health.Serve.Mode != msbctl.ServeProxy {
		return TLSOutcome{State: TLSNotProxy}
	}
	root, err := c.Roots.Root(ctx)
	if errors.Is(err, pki.ErrNoRoot) {
		return TLSOutcome{State: TLSNoRoot}
	}
	if err != nil {
		log.Printf("tls %s: %v", h.Name, err)
		return TLSOutcome{State: TLSFailed, Reason: msbctl.CodeUnavailable}
	}
	name := HostName(h)
	if !root.Permits(name) {
		return TLSOutcome{State: TLSNotPermitted}
	}
	var current pki.HostTLS
	if health.TLS != nil {
		current = pki.HostTLS(*health.TLS)
	}
	reason := root.RenewReason(current, name, c.Now())
	if reason == "" {
		return TLSOutcome{State: TLSOK, NotAfter: current.NotAfter}
	}
	issued, err := root.IssueHost(name, c.Now())
	if err != nil {
		log.Printf("tls %s: issue: %v", h.Name, err)
		return TLSOutcome{State: TLSFailed, Reason: reason}
	}
	installed, err := api.TLSInstall(ctx, h, issued.ChainPEM, issued.KeyPEM)
	if err != nil {
		log.Printf("tls %s: install (%s): %v", h.Name, reason, err)
		return TLSOutcome{State: TLSFailed, Reason: msbctl.CodeOf(err)}
	}
	log.Printf("tls %s: installed a new certificate (%s), valid until %s", h.Name, reason, installed.NotAfter)
	return TLSOutcome{State: TLSRenewed, Reason: reason, NotAfter: installed.NotAfter}
}
