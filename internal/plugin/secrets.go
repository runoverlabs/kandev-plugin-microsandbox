package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"kandev-plugin-microsandbox/internal/profile"
)

// Secrets a profile can name: each a value, kept in the plugin's secret
// store, and the hosts it may be sent to, set by an admin. A profile only
// names them (its `secrets` field), so whoever edits a profile can use a
// secret but never read it or send it anywhere new. The guest sees a
// placeholder; the sandbox host substitutes the value into request headers
// bound for those hosts only.
const (
	secretsStateKey = "secrets"
	// secretValuePrefix keys each value in the plugin's secret store.
	secretValuePrefix = "secret/"
	secretsVersion    = 1
	maxSecrets        = 100
	maxSecretValue    = 16 << 10
)

// Secret action keys, matching manifest.yaml.
const (
	ActionSecretsList   = "secrets.list"
	ActionSecretsPut    = "secrets.put"
	ActionSecretsRemove = "secrets.remove"
)

// ErrUnknownSecret is a profile naming a secret the plugin does not hold.
var ErrUnknownSecret = errors.New("unknown secret")

// secretMeta is what state keeps about a secret: never its value.
type secretMeta struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Hosts       []string `json:"hosts"`
	UpdatedAt   string   `json:"updated_at"`
}

type secretIndex struct {
	Version int          `json:"version"`
	Secrets []secretMeta `json:"secrets"`
}

func (r *Runtime) loadSecrets(ctx context.Context) (secretIndex, error) {
	h, err := r.host()
	if err != nil {
		return secretIndex{}, err
	}
	value, found, err := h.GetState(ctx, stateScope, "", secretsStateKey)
	if err != nil {
		return secretIndex{}, fmt.Errorf("read secrets: %w", err)
	}
	if !found {
		return secretIndex{Version: secretsVersion, Secrets: []secretMeta{}}, nil
	}
	raw, _ := json.Marshal(value)
	var index secretIndex
	if err := json.Unmarshal(raw, &index); err != nil || index.Version != secretsVersion {
		return secretIndex{}, errors.New("the secret index is unreadable")
	}
	if index.Secrets == nil {
		index.Secrets = []secretMeta{}
	}
	return index, nil
}

func (r *Runtime) saveSecrets(ctx context.Context, index secretIndex) error {
	h, err := r.host()
	if err != nil {
		return err
	}
	index.Version = secretsVersion
	slices.SortFunc(index.Secrets, func(a, b secretMeta) int { return strings.Compare(a.Name, b.Name) })
	raw, err := json.Marshal(index)
	if err != nil {
		return err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if err := h.SetState(ctx, stateScope, "", secretsStateKey, value); err != nil {
		return fmt.Errorf("write secrets: %w", err)
	}
	return nil
}

func secretsFailure(action string, err error) response {
	if errors.Is(err, ErrNoHost) {
		return fail(http.StatusServiceUnavailable, "the plugin is still starting; try again")
	}
	log.Printf("%s: %v", action, err)
	return fail(http.StatusInternalServerError, "the secrets could not be read or saved")
}

func (r *Runtime) actionSecretsList(ctx context.Context, body []byte) response {
	if err := decode(body, &struct{}{}); err != nil {
		return fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	index, err := r.loadSecrets(ctx)
	if err != nil {
		return secretsFailure(ActionSecretsList, err)
	}
	return ok(map[string]any{"secrets": index.Secrets})
}

// actionSecretsPut creates a secret or changes one. A value is required to
// create; leaving it out of a change keeps the stored one, so editing hosts
// never needs the value retyped. The value is never returned.
func (r *Runtime) actionSecretsPut(ctx context.Context, body []byte) response {
	var in struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Hosts       string  `json:"hosts"`
		Value       *string `json:"value"`
	}
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, `expected {"name": "NPM_TOKEN", "description": "...", "hosts": "registry.npmjs.org", "value": "..."}`)
	}
	name := strings.TrimSpace(in.Name)
	fields := map[string]string{}
	if code := profile.CheckSecretName(name); code != "" {
		fields["name"] = map[string]string{
			profile.CodeRequired: "a name is required",
			profile.CodeInvalid:  "uppercase letters, digits and _, starting with a letter or _",
			profile.CodeReserved: "reserved: Kandev or the sandbox sets this variable",
		}[code]
	}
	hosts, okHosts := profile.ParseSecretHosts(in.Hosts)
	if !okHosts {
		fields["hosts"] = "at least one host or host:port, comma-separated, no wildcards"
	}
	if in.Value != nil && (*in.Value == "" || len(*in.Value) > maxSecretValue) {
		fields["value"] = fmt.Sprintf("1 to %d bytes", maxSecretValue)
	}
	if len(strings.TrimSpace(in.Description)) > 200 {
		fields["description"] = "at most 200 characters"
	}
	if len(fields) > 0 {
		return response{http.StatusUnprocessableEntity, map[string]any{"error": "the secret is invalid", "fields": fields}}
	}
	h, err := r.host()
	if err != nil {
		return secretsFailure(ActionSecretsPut, err)
	}

	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	index, err := r.loadSecrets(ctx)
	if err != nil {
		return secretsFailure(ActionSecretsPut, err)
	}
	i := slices.IndexFunc(index.Secrets, func(m secretMeta) bool { return m.Name == name })
	switch {
	case i < 0 && in.Value == nil:
		return response{http.StatusUnprocessableEntity, map[string]any{"error": "the secret is invalid", "fields": map[string]string{"value": "a new secret needs its value"}}}
	case i < 0 && len(index.Secrets) >= maxSecrets:
		return fail(http.StatusConflict, fmt.Sprintf("at most %d secrets", maxSecrets))
	}
	// The value goes first: an index entry never points at a missing value.
	if in.Value != nil {
		if err := h.SetSecret(ctx, secretValuePrefix+name, *in.Value); err != nil {
			return secretsFailure(ActionSecretsPut, err)
		}
	}
	meta := secretMeta{Name: name, Description: strings.TrimSpace(in.Description), Hosts: hosts, UpdatedAt: r.now().UTC().Format(time.RFC3339)}
	status := http.StatusOK
	if i < 0 {
		index.Secrets = append(index.Secrets, meta)
		status = http.StatusCreated
	} else {
		index.Secrets[i] = meta
	}
	if err := r.saveSecrets(ctx, index); err != nil {
		return secretsFailure(ActionSecretsPut, err)
	}
	return response{status, map[string]any{"secret": meta}}
}

// actionSecretsRemove deletes a secret. Profiles still naming it fail
// validation, and their launches fail, until they are edited.
func (r *Runtime) actionSecretsRemove(ctx context.Context, body []byte) response {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(body, &in); err != nil || in.Name == "" {
		return fail(http.StatusUnprocessableEntity, `expected {"name": "..."}`)
	}
	h, err := r.host()
	if err != nil {
		return secretsFailure(ActionSecretsRemove, err)
	}
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	index, err := r.loadSecrets(ctx)
	if err != nil {
		return secretsFailure(ActionSecretsRemove, err)
	}
	before := len(index.Secrets)
	index.Secrets = slices.DeleteFunc(index.Secrets, func(m secretMeta) bool { return m.Name == in.Name })
	if len(index.Secrets) == before {
		return fail(http.StatusNotFound, "no such secret")
	}
	// The index goes first: a value without an entry is unreachable.
	if err := r.saveSecrets(ctx, index); err != nil {
		return secretsFailure(ActionSecretsRemove, err)
	}
	if err := h.DeleteSecret(ctx, secretValuePrefix+in.Name); err != nil {
		log.Printf("%s %s: delete value: %v", ActionSecretsRemove, in.Name, err)
	}
	return ok(map[string]any{"removed": in.Name})
}

// unknownSecrets returns the names the plugin holds no secret for.
func (r *Runtime) unknownSecrets(ctx context.Context, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	index, err := r.loadSecrets(ctx)
	if err != nil {
		return nil, err
	}
	var unknown []string
	for _, name := range names {
		if !slices.ContainsFunc(index.Secrets, func(m secretMeta) bool { return m.Name == name }) {
			unknown = append(unknown, name)
		}
	}
	return unknown, nil
}

// resolveSecrets reads the named secrets' hosts and values for one
// provision. The values stay in memory, in the profile.Spec.
func (r *Runtime) resolveSecrets(ctx context.Context, names []string) ([]profile.Secret, error) {
	if len(names) == 0 {
		return nil, nil
	}
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	index, err := r.loadSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]profile.Secret, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(index.Secrets, func(m secretMeta) bool { return m.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnknownSecret, name)
		}
		value, found, err := h.GetSecret(ctx, secretValuePrefix+name)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", name, err)
		}
		if !found || value == "" {
			return nil, fmt.Errorf("%w: %s has no value", ErrUnknownSecret, name)
		}
		out = append(out, profile.Secret{Name: name, Value: value, Hosts: slices.Clone(index.Secrets[i].Hosts)})
	}
	return out, nil
}
