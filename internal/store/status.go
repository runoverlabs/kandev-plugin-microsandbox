package store

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/kandev"
)

// The last check of each host, by name, so the host list shows it without an
// SSH round trip per host. It is written by Test and by every maintainer
// pass, and holds nothing secret: a health report, the diagnosis and when it
// was made.
const StatusKey = "status"

// Status keeps the hosts' last checks as one Host state document. It is a
// cache: an unreadable one is replaced, and a failed write is only logged.
type Status struct {
	host kandev.Provider
	now  func() time.Time
	mu   sync.Mutex
}

// NewStatus returns the status store over host.
func NewStatus(host kandev.Provider, now func() time.Time) *Status {
	return &Status{host: host, now: now}
}

// Load reads every host's last check.
func (s *Status) Load(ctx context.Context) (map[string]hostcheck.Status, error) {
	h, err := s.host.Get()
	if err != nil {
		return nil, err
	}
	out := map[string]hostcheck.Status{}
	_, err = kandev.LoadDocument(ctx, h, StatusKey, &out)
	switch {
	case errors.Is(err, kandev.ErrUnreadable):
		return map[string]hostcheck.Status{}, nil
	case err != nil:
		return map[string]hostcheck.Status{}, err
	}
	return out, nil
}

// Record keeps result as the host's last check, made now.
func (s *Status) Record(ctx context.Context, name string, result hostcheck.Result) {
	s.mutate(ctx, func(all map[string]hostcheck.Status) {
		all[name] = hostcheck.Status{CheckedAt: s.now().UTC().Format(time.RFC3339), Result: result}
	})
}

// Forget drops a removed host's last check.
func (s *Status) Forget(ctx context.Context, name string) {
	s.mutate(ctx, func(all map[string]hostcheck.Status) { delete(all, name) })
}

func (s *Status) mutate(ctx context.Context, change func(map[string]hostcheck.Status)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.Load(ctx)
	if err != nil {
		log.Printf("status: %v", err)
		return
	}
	change(all)
	h, err := s.host.Get()
	if err != nil {
		return
	}
	if err := kandev.SaveDocument(ctx, h, StatusKey, all); err != nil {
		log.Printf("status: %v", err)
	}
}
