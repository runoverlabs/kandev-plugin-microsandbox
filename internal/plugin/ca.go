package plugin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/pki"
	"kandev-plugin-microsandbox/internal/readiness"
)

// CA action keys, matching manifest.yaml.
const (
	ActionCAGet    = "ca.get"
	ActionCACreate = "ca.create"
)

const caWhat = "the root certificate"

// rootStore is the plugin's root, created or replaced by ca.create.
type rootStore interface {
	rootReader
	Create(ctx context.Context, c pki.Constraints) (*pki.Root, error)
}

// caActions show and create the plugin's root certificate authority.
type caActions struct {
	roots   rootStore
	trusted func(*pki.Root) error
}

func (a *caActions) routes() map[string]actionFunc {
	return map[string]actionFunc{ActionCAGet: a.get, ActionCACreate: a.create}
}

func (a *caActions) get(ctx context.Context, body []byte) kandev.Response {
	if err := kandev.Decode(body, &struct{}{}); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	root, err := a.roots.Root(ctx)
	if errors.Is(err, pki.ErrNoRoot) {
		return kandev.OK(map[string]any{"exists": false, "install": readiness.RootInstallSteps})
	}
	if err != nil {
		return kandev.Internal(ActionCAGet, caWhat, err)
	}
	return kandev.OK(a.view(root))
}

func (a *caActions) view(root *pki.Root) map[string]any {
	return map[string]any{
		"exists":      true,
		"cert_pem":    root.PEM(),
		"sha256":      root.Fingerprint(),
		"constraints": root.Constraints(),
		"not_after":   root.Cert.NotAfter.UTC().Format(time.RFC3339),
		"trusted":     a.trusted(root) == nil,
		"install":     readiness.RootInstallSteps,
	}
}

// refuseReplace refuses to replace a root unless asked to. A root that
// cannot be used is replaced too: that is the way out of a lost key. A
// failure to read the store replaces nothing, as it says nothing of the root.
func (a *caActions) refuseReplace(ctx context.Context, replace bool) (kandev.Response, bool) {
	const pass = "; replacing it means reinstalling it on the Kandev server, so pass replace: true"
	_, err := a.roots.Root(ctx)
	switch {
	case errors.Is(err, pki.ErrNoRoot):
		return kandev.Response{}, false
	case err != nil && !errors.Is(err, pki.ErrRootUnusable):
		return kandev.Internal(ActionCACreate, caWhat, err), true
	case replace:
		return kandev.Response{}, false
	case err != nil:
		return kandev.Fail(http.StatusConflict, "a root exists but cannot be used ("+err.Error()+")"+pass), true
	default:
		return kandev.Fail(http.StatusConflict, "a root already exists"+pass), true
	}
}

func (a *caActions) create(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		pki.Constraints
		Replace bool `json:"replace"`
	}
	if err := kandev.Decode(body, &in); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "expected {\"dns_suffixes\": [...], \"cidrs\": [...], \"replace\": false}")
	}
	c := in.Constraints.Normalize()
	if err := c.Validate(); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, err.Error())
	}
	if res, refused := a.refuseReplace(ctx, in.Replace); refused {
		return res
	}
	root, err := a.roots.Create(ctx, c)
	if err != nil {
		return kandev.Internal(ActionCACreate, caWhat, err)
	}
	// Hosts carrying a certificate from a replaced root are re-issued by
	// the maintainer and by Test, which see the issuer fingerprint change.
	return kandev.Response{Status: http.StatusCreated, Body: a.view(root)}
}
