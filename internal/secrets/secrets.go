// Package secrets is the model of the secrets a profile can name: each a
// value, kept in the plugin's secret store, and the hosts it may be sent to,
// set by an admin. A profile only names them (its `secrets` field), so
// whoever edits a profile can use a secret but never read it or send it
// anywhere new. The guest sees a placeholder; the sandbox host substitutes
// the value into request headers bound for those hosts only.
//
// Pure: where the index and the values are stored is internal/store's.
package secrets

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"kandev-plugin-microsandbox/internal/profile"
)

// Limits on the index and on one secret.
const (
	Version        = 1
	MaxSecrets     = 100
	MaxValue       = 16 << 10
	maxDescription = 200
)

var (
	// ErrUnknown is a profile naming a secret the plugin does not hold.
	ErrUnknown = errors.New("unknown secret")
	// ErrNotFound is a change to a secret that does not exist.
	ErrNotFound = errors.New("no such secret")
	// ErrNeedsValue is a new secret without its value.
	ErrNeedsValue = errors.New("a new secret needs its value")
	// ErrTooMany is a new secret past MaxSecrets.
	ErrTooMany = fmt.Errorf("at most %d secrets", MaxSecrets)
)

// Meta is what state keeps about a secret: never its value.
type Meta struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Hosts       []string `json:"hosts"`
	UpdatedAt   string   `json:"updated_at"`
}

// Index is the stored list of secrets, sorted by name.
type Index struct {
	Version int    `json:"version"`
	Secrets []Meta `json:"secrets"`
}

// Find returns the named secret's position, or -1.
func (i Index) Find(name string) int {
	return slices.IndexFunc(i.Secrets, func(m Meta) bool { return m.Name == name })
}

// Unknown returns the names the index holds no secret for.
func (i Index) Unknown(names []string) []string {
	var unknown []string
	for _, name := range names {
		if i.Find(name) < 0 {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// Put creates or changes a secret, as the admin sends it. A nil Value keeps
// the stored one, so editing hosts never needs the value retyped.
type Put struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Hosts       string  `json:"hosts"`
	Value       *string `json:"value"`
}

var nameProblems = map[string]string{
	profile.CodeRequired: "a name is required",
	profile.CodeInvalid:  "uppercase letters, digits and _, starting with a letter or _",
	profile.CodeReserved: "reserved: Kandev or the sandbox sets this variable",
}

// Check normalizes a put into the secret's metadata, or returns what is wrong
// with it by field. UpdatedAt is left to the caller.
func (p Put) Check() (Meta, map[string]string) {
	meta := Meta{Name: strings.TrimSpace(p.Name), Description: strings.TrimSpace(p.Description)}
	fields := map[string]string{}
	if code := profile.CheckSecretName(meta.Name); code != "" {
		fields["name"] = nameProblems[code]
	}
	hosts, ok := profile.ParseSecretHosts(p.Hosts)
	if !ok {
		fields["hosts"] = "at least one host or host:port, comma-separated, no wildcards"
	}
	meta.Hosts = hosts
	if p.Value != nil && (*p.Value == "" || len(*p.Value) > MaxValue) {
		fields["value"] = fmt.Sprintf("1 to %d bytes", MaxValue)
	}
	if len(meta.Description) > maxDescription {
		fields["description"] = fmt.Sprintf("at most %d characters", maxDescription)
	}
	return meta, fields
}

// Upsert puts meta into the index, refusing a new secret without its value
// or past the limit. created reports a new entry.
func (i Index) Upsert(meta Meta, hasValue bool) (next Index, created bool, err error) {
	at := i.Find(meta.Name)
	switch {
	case at < 0 && !hasValue:
		return i, false, ErrNeedsValue
	case at < 0 && len(i.Secrets) >= MaxSecrets:
		return i, false, ErrTooMany
	}
	next = Index{Version: Version, Secrets: slices.Clone(i.Secrets)}
	if at < 0 {
		next.Secrets = append(next.Secrets, meta)
	} else {
		next.Secrets[at] = meta
	}
	next.Sort()
	return next, at < 0, nil
}

// Remove drops the named secret.
func (i Index) Remove(name string) (Index, error) {
	next := Index{Version: Version, Secrets: slices.DeleteFunc(slices.Clone(i.Secrets), func(m Meta) bool { return m.Name == name })}
	if len(next.Secrets) == len(i.Secrets) {
		return i, ErrNotFound
	}
	return next, nil
}

// Sort orders the secrets by name, as they are stored.
func (i Index) Sort() {
	slices.SortFunc(i.Secrets, func(a, b Meta) int { return strings.Compare(a.Name, b.Name) })
}
