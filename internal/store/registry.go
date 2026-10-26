package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/kandev"
)

const registryKey = "hosts"

// Registry keeps the host registry as one Host state document.
type Registry struct {
	host kandev.Provider
	mu   sync.Mutex
}

var _ hosts.Store = (*Registry)(nil)

// NewRegistry returns the registry store over host.
func NewRegistry(host kandev.Provider) *Registry { return &Registry{host: host} }

// Load reads the registry without taking the lock: a read never needs to
// wait for a mutation in progress.
func (s *Registry) Load(ctx context.Context) (hosts.Registry, error) {
	h, err := s.host.Get()
	if err != nil {
		return hosts.Registry{}, err
	}
	var registry hosts.Registry
	found, err := kandev.LoadDocument(ctx, h, registryKey, &registry)
	switch {
	case errors.Is(err, kandev.ErrUnreadable):
		return hosts.Registry{}, errors.New("host registry is unreadable")
	case err != nil:
		return hosts.Registry{}, fmt.Errorf("read host registry: %w", err)
	case !found:
		return hosts.Registry{Version: hosts.RegistryVersion}, nil
	}
	if err := registry.Check(); err != nil {
		return hosts.Registry{}, err
	}
	return registry, nil
}

// Save replaces the registry.
func (s *Registry) Save(ctx context.Context, registry hosts.Registry) error {
	h, err := s.host.Get()
	if err != nil {
		return err
	}
	registry.Version = hosts.RegistryVersion
	if err := kandev.SaveDocument(ctx, h, registryKey, registry); err != nil {
		return fmt.Errorf("write host registry: %w", err)
	}
	return nil
}

// Mutate applies change under the lock and saves the result.
func (s *Registry) Mutate(ctx context.Context, change func(hosts.Registry) (hosts.Registry, error)) (hosts.Registry, error) {
	if _, err := s.host.Get(); err != nil {
		return hosts.Registry{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.Load(ctx)
	if err != nil {
		return hosts.Registry{}, err
	}
	next, err := change(current)
	if err != nil {
		return hosts.Registry{}, err
	}
	if err := s.Save(ctx, next); err != nil {
		return hosts.Registry{}, err
	}
	return next, nil
}
