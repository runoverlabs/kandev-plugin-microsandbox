package plugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/pki"
)

// The root's certificate is public and lives in Host state; its key lives
// only in the plugin secret store.
const (
	caStateKey  = "ca"
	caKeySecret = "ca-key"
)

const (
	ActionCAGet    = "ca.get"
	ActionCACreate = "ca.create"
)

// errNoRoot means no root has been created yet.
var errNoRoot = errors.New("no root certificate has been created")

// root returns the plugin's certificate authority, loading it once.
func (r *Runtime) root(ctx context.Context) (*pki.Root, error) {
	r.caMu.Lock()
	defer r.caMu.Unlock()
	if r.ca != nil {
		return r.ca, nil
	}
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	value, found, err := h.GetState(ctx, stateScope, "", caStateKey)
	if err != nil {
		return nil, fmt.Errorf("read root certificate: %w", err)
	}
	if !found {
		return nil, errNoRoot
	}
	certPEM, _ := value["cert_pem"].(string)
	keyPEM, found, err := h.GetSecret(ctx, caKeySecret)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	if !found {
		return nil, errors.New("the root's key is missing from the secret store")
	}
	root, err := pki.LoadRoot(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	r.ca = root
	return root, nil
}

// createRoot generates and stores a new root. The key is written before the
// certificate, so a half-finished create leaves no certificate without its
// key.
func (r *Runtime) createRoot(ctx context.Context, c pki.Constraints) (*pki.Root, error) {
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	root, keyPEM, certPEM, err := pki.NewRoot(c, r.now())
	if err != nil {
		return nil, err
	}
	r.caMu.Lock()
	defer r.caMu.Unlock()
	if err := h.SetSecret(ctx, caKeySecret, keyPEM); err != nil {
		return nil, fmt.Errorf("store root key: %w", err)
	}
	if err := h.SetState(ctx, stateScope, "", caStateKey, map[string]any{
		"cert_pem": certPEM, "created_at": r.now().UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, fmt.Errorf("store root certificate: %w", err)
	}
	r.ca = root
	return root, nil
}

// installSteps tell the operator how to make the Kandev server trust the
// root. Only that machine needs it: it is the only client of the data path.
var installSteps = []string{
	"Save the root as kandev-sandbox-root.crt on the Kandev server.",
	"Debian/Ubuntu host: copy it to /usr/local/share/ca-certificates/ and run update-ca-certificates.",
	"Fedora/RHEL host: copy it to /etc/pki/ca-trust/source/anchors/ and run update-ca-trust.",
	"Container: mount it in a directory such as /kandev-ca and set SSL_CERT_DIR=/etc/ssl/certs:/kandev-ca for Kandev. Do not use SSL_CERT_FILE: it replaces the system bundle.",
	"Restart Kandev. It reads system roots once, at start.",
	"Run Test on a sandbox host: it reports whether the root is trusted.",
}

func (r *Runtime) actionCAGet(ctx context.Context, body []byte) response {
	if err := decode(body, &struct{}{}); err != nil {
		return fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	root, err := r.root(ctx)
	if errors.Is(err, errNoRoot) {
		return ok(map[string]any{"exists": false, "install": installSteps})
	}
	if err != nil {
		return caFailure(ActionCAGet, err)
	}
	return ok(rootView(root, r.rootTrusted(root)))
}

func rootView(root *pki.Root, trusted error) map[string]any {
	return map[string]any{
		"exists":      true,
		"cert_pem":    root.PEM(),
		"sha256":      root.Fingerprint(),
		"constraints": root.Constraints(),
		"not_after":   root.Cert.NotAfter.UTC().Format(time.RFC3339),
		"trusted":     trusted == nil,
		"install":     installSteps,
	}
}

func (r *Runtime) actionCACreate(ctx context.Context, body []byte) response {
	var in struct {
		pki.Constraints
		Replace bool `json:"replace"`
	}
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, "expected {\"dns_suffixes\": [...], \"cidrs\": [...], \"replace\": false}")
	}
	c := in.Constraints.Normalize()
	if err := c.Validate(); err != nil {
		return fail(http.StatusUnprocessableEntity, err.Error())
	}
	if _, err := r.root(ctx); err == nil && !in.Replace {
		return fail(http.StatusConflict, "a root already exists; replacing it means reinstalling it on the Kandev server, so pass replace: true")
	} else if err != nil && !errors.Is(err, errNoRoot) {
		return caFailure(ActionCACreate, err)
	}
	root, err := r.createRoot(ctx, c)
	if err != nil {
		return caFailure(ActionCACreate, err)
	}
	// Hosts carrying a certificate from a replaced root are re-issued by
	// the maintainer and by Test, which see the issuer fingerprint change.
	return response{http.StatusCreated, rootView(root, r.rootTrusted(root))}
}

func caFailure(action string, err error) response {
	if errors.Is(err, ErrNoHost) {
		return fail(http.StatusServiceUnavailable, "the plugin is still starting; try again")
	}
	log.Printf("%s: %v", action, err)
	return fail(http.StatusInternalServerError, "the root certificate could not be read or saved")
}

func (r *Runtime) rootTrusted(root *pki.Root) error {
	return root.Trusted(r.trustPool, r.now())
}

// hostName is the name a host's certificate must carry: the host part of
// its registered base URL.
func hostName(h hosts.Host) string {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// tlsOutcome reports what certificate care did for one host.
type tlsOutcome struct {
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	NotAfter string `json:"not_after,omitempty"`
}

// TLS outcome states.
const (
	tlsNotProxy     = "not_proxy"     // the host terminates TLS some other way
	tlsNoRoot       = "no_root"       // nothing to issue from yet
	tlsNotPermitted = "not_permitted" // the host's name is outside the root
	tlsOK           = "ok"
	tlsRenewed      = "renewed"
	tlsFailed       = "failed"
)

// healTLS gives a proxy-mode host a valid certificate from the current root
// if it lacks one: missing, expiring, for another name, or from a replaced
// root. It never asks first. Certificates are replaceable, and one that
// lapses breaks every session on the host.
func (r *Runtime) healTLS(ctx context.Context, client *msbctl.Client, h hosts.Host, health msbctl.Health) tlsOutcome {
	if health.Serve.Mode != msbctl.ServeProxy {
		return tlsOutcome{State: tlsNotProxy}
	}
	root, err := r.root(ctx)
	if errors.Is(err, errNoRoot) {
		return tlsOutcome{State: tlsNoRoot}
	}
	if err != nil {
		log.Printf("tls %s: %v", h.Name, err)
		return tlsOutcome{State: tlsFailed, Reason: msbctl.CodeUnavailable}
	}
	name := hostName(h)
	if !root.Permits(name) {
		return tlsOutcome{State: tlsNotPermitted}
	}
	var current pki.HostTLS
	if health.TLS != nil {
		current = pki.HostTLS(*health.TLS)
	}
	reason := root.RenewReason(current, name, r.now())
	if reason == "" {
		return tlsOutcome{State: tlsOK, NotAfter: current.NotAfter}
	}
	issued, err := root.IssueHost(name, r.now())
	if err != nil {
		log.Printf("tls %s: issue: %v", h.Name, err)
		return tlsOutcome{State: tlsFailed, Reason: reason}
	}
	installed, err := client.TLSInstall(ctx, h, issued.ChainPEM, issued.KeyPEM)
	if err != nil {
		log.Printf("tls %s: install (%s): %v", h.Name, reason, err)
		return tlsOutcome{State: tlsFailed, Reason: msbctl.CodeOf(err)}
	}
	log.Printf("tls %s: installed a new certificate (%s), valid until %s", h.Name, reason, installed.NotAfter)
	return tlsOutcome{State: tlsRenewed, Reason: reason, NotAfter: installed.NotAfter}
}
