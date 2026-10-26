package plugin

import (
	"context"
	"errors"
	"net/http"

	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/secrets"
)

// Secret action keys, matching manifest.yaml.
const (
	ActionSecretsList   = "secrets.list"
	ActionSecretsPut    = "secrets.put"
	ActionSecretsRemove = "secrets.remove"
)

const secretsWhat = "the secrets"

// secretStore keeps the secret index and the values.
type secretStore interface {
	Load(ctx context.Context) (secrets.Index, error)
	Put(ctx context.Context, meta secrets.Meta, value *string) (secrets.Meta, bool, error)
	Remove(ctx context.Context, name string) error
}

// secretActions serve the Secrets page. A value goes in and is never
// returned.
type secretActions struct{ secrets secretStore }

func (a *secretActions) routes() map[string]actionFunc {
	return map[string]actionFunc{ActionSecretsList: a.list, ActionSecretsPut: a.put, ActionSecretsRemove: a.remove}
}

func (a *secretActions) list(ctx context.Context, body []byte) kandev.Response {
	if err := kandev.Decode(body, &struct{}{}); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	index, err := a.secrets.Load(ctx)
	if err != nil {
		return kandev.Internal(ActionSecretsList, secretsWhat, err)
	}
	return kandev.OK(map[string]any{"secrets": index.Secrets})
}

func invalidSecret(fields map[string]string) kandev.Response {
	return kandev.Response{Status: http.StatusUnprocessableEntity, Body: map[string]any{"error": "the secret is invalid", "fields": fields}}
}

// put creates a secret or changes one. A value is required to create;
// leaving it out of a change keeps the stored one.
func (a *secretActions) put(ctx context.Context, body []byte) kandev.Response {
	var in secrets.Put
	if err := kandev.Decode(body, &in); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name": "NPM_TOKEN", "description": "...", "hosts": "registry.npmjs.org", "value": "..."}`)
	}
	meta, fields := in.Check()
	if len(fields) > 0 {
		return invalidSecret(fields)
	}
	saved, created, err := a.secrets.Put(ctx, meta, in.Value)
	switch {
	case errors.Is(err, secrets.ErrNeedsValue):
		return invalidSecret(map[string]string{"value": err.Error()})
	case errors.Is(err, secrets.ErrTooMany):
		return kandev.Fail(http.StatusConflict, err.Error())
	case err != nil:
		return kandev.Internal(ActionSecretsPut, secretsWhat, err)
	case created:
		return kandev.Response{Status: http.StatusCreated, Body: map[string]any{"secret": saved}}
	default:
		return kandev.OK(map[string]any{"secret": saved})
	}
}

// remove deletes a secret. Profiles still naming it fail validation, and
// their launches fail, until they are edited.
func (a *secretActions) remove(ctx context.Context, body []byte) kandev.Response {
	var in struct {
		Name string `json:"name"`
	}
	if err := kandev.Decode(body, &in); err != nil || in.Name == "" {
		return kandev.Fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	err := a.secrets.Remove(ctx, in.Name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return kandev.Fail(http.StatusNotFound, err.Error())
	case err != nil:
		return kandev.Internal(ActionSecretsRemove, secretsWhat, err)
	}
	return kandev.OK(map[string]any{"removed": in.Name})
}
