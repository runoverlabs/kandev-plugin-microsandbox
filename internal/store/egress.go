package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/kandev"
)

// The plugin-wide egress policy: named groups of destinations, and the
// groups every sandbox gets. One admin change reaches every new sandbox on
// every host.
const egressKey = "egress"

// Egress keeps the egress policy as one Host state document.
type Egress struct {
	host kandev.Provider
	mu   sync.Mutex
}

// NewEgress returns the egress policy store over host.
func NewEgress(host kandev.Provider) *Egress { return &Egress{host: host} }

// Load reads the policy; with none stored, it is the empty policy.
func (s *Egress) Load(ctx context.Context) (egress.Policy, error) {
	h, err := s.host.Get()
	if err != nil {
		return egress.Policy{}, err
	}
	var policy egress.Policy
	found, err := kandev.LoadDocument(ctx, h, egressKey, &policy)
	switch {
	case errors.Is(err, kandev.ErrUnreadable):
		return egress.Policy{}, errors.New("egress policy is unreadable")
	case err != nil:
		return egress.Policy{}, fmt.Errorf("read egress policy: %w", err)
	case !found:
		return egress.Policy{Version: egress.PolicyVersion}, nil
	}
	if err := policy.Check(); err != nil {
		return egress.Policy{}, err
	}
	return policy, nil
}

// Mutate applies change to the stored policy under the lock, checks the
// result and saves it.
func (s *Egress) Mutate(ctx context.Context, change func(egress.Policy) (egress.Policy, error)) (egress.Policy, error) {
	h, err := s.host.Get()
	if err != nil {
		return egress.Policy{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, err := s.Load(ctx)
	if err != nil {
		return egress.Policy{}, err
	}
	next, err := change(policy)
	if err != nil {
		return egress.Policy{}, err
	}
	next.Version = egress.PolicyVersion
	if next.Groups == nil {
		next.Groups = []egress.Group{}
	}
	if next.Defaults == nil {
		next.Defaults = []string{}
	}
	if err := next.Check(); err != nil {
		return egress.Policy{}, err
	}
	if err := kandev.SaveDocument(ctx, h, egressKey, next); err != nil {
		return egress.Policy{}, fmt.Errorf("write egress policy: %w", err)
	}
	return next, nil
}
