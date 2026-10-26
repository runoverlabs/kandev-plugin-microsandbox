package store

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/profile"
	"kandev-plugin-microsandbox/internal/secrets"
)

const (
	secretsKey = "secrets"
	// SecretValuePrefix keys each value in the plugin's secret store, whose
	// keys Kandev limits to [a-zA-Z0-9][a-zA-Z0-9._-]{0,127}.
	SecretValuePrefix = "secret."
)

// Secrets keeps the secret index in Host state and each value in the
// plugin's secret store. A value is never returned to anyone but a
// provision.
type Secrets struct {
	host kandev.Provider
	now  func() time.Time
	mu   sync.Mutex
}

// NewSecrets returns the secrets store over host.
func NewSecrets(host kandev.Provider, now func() time.Time) *Secrets {
	return &Secrets{host: host, now: now}
}

// Load reads the index; with none stored, it is empty.
func (s *Secrets) Load(ctx context.Context) (secrets.Index, error) {
	h, err := s.host.Get()
	if err != nil {
		return secrets.Index{}, err
	}
	var index secrets.Index
	found, err := kandev.LoadDocument(ctx, h, secretsKey, &index)
	switch {
	case errors.Is(err, kandev.ErrUnreadable) || found && index.Version != secrets.Version:
		return secrets.Index{}, errors.New("the secret index is unreadable")
	case err != nil:
		return secrets.Index{}, fmt.Errorf("read secrets: %w", err)
	case !found:
		return secrets.Index{Version: secrets.Version, Secrets: []secrets.Meta{}}, nil
	}
	if index.Secrets == nil {
		index.Secrets = []secrets.Meta{}
	}
	return index, nil
}

func (s *Secrets) save(ctx context.Context, index secrets.Index) error {
	h, err := s.host.Get()
	if err != nil {
		return err
	}
	index.Version = secrets.Version
	index.Sort()
	if err := kandev.SaveDocument(ctx, h, secretsKey, index); err != nil {
		return fmt.Errorf("write secrets: %w", err)
	}
	return nil
}

// Put creates or changes a secret; a nil value keeps the stored one. The
// value is written first, so an index entry never points at a missing value.
func (s *Secrets) Put(ctx context.Context, meta secrets.Meta, value *string) (saved secrets.Meta, created bool, err error) {
	h, err := s.host.Get()
	if err != nil {
		return secrets.Meta{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.Load(ctx)
	if err != nil {
		return secrets.Meta{}, false, err
	}
	meta.UpdatedAt = s.now().UTC().Format(time.RFC3339)
	next, created, err := index.Upsert(meta, value != nil)
	if err != nil {
		return secrets.Meta{}, false, err
	}
	if value != nil {
		if err := h.SetSecret(ctx, SecretValuePrefix+meta.Name, *value); err != nil {
			return secrets.Meta{}, false, err
		}
	}
	if err := s.save(ctx, next); err != nil {
		return secrets.Meta{}, false, err
	}
	return meta, created, nil
}

// Remove deletes a secret. The index goes first: a value without an entry
// is unreachable, and failing to delete it is only logged.
func (s *Secrets) Remove(ctx context.Context, name string) error {
	h, err := s.host.Get()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.Load(ctx)
	if err != nil {
		return err
	}
	next, err := index.Remove(name)
	if err != nil {
		return err
	}
	if err := s.save(ctx, next); err != nil {
		return err
	}
	if err := h.DeleteSecret(ctx, SecretValuePrefix+name); err != nil {
		log.Printf("secrets.remove %s: delete value: %v", name, err)
	}
	return nil
}

// Unknown returns the names the plugin holds no secret for.
func (s *Secrets) Unknown(ctx context.Context, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	index, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	return index.Unknown(names), nil
}

// Resolve reads the named secrets' hosts and values for one provision. The
// values stay in memory, in the profile.Spec.
func (s *Secrets) Resolve(ctx context.Context, names []string) ([]profile.Secret, error) {
	if len(names) == 0 {
		return nil, nil
	}
	h, err := s.host.Get()
	if err != nil {
		return nil, err
	}
	index, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]profile.Secret, 0, len(names))
	for _, name := range names {
		at := index.Find(name)
		if at < 0 {
			return nil, fmt.Errorf("%w: %s", secrets.ErrUnknown, name)
		}
		value, found, err := h.GetSecret(ctx, SecretValuePrefix+name)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", name, err)
		}
		if !found || value == "" {
			return nil, fmt.Errorf("%w: %s has no value", secrets.ErrUnknown, name)
		}
		out = append(out, profile.Secret{Name: name, Value: value, Hosts: slices.Clone(index.Secrets[at].Hosts)})
	}
	return out, nil
}
