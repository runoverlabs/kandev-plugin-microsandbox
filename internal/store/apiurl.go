package store

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/kandev"
)

// apiURLKey keeps the API URL the last launch carried: Kandev's public
// address, which is not secret.
const apiURLKey = "kandev"

// SeenAPI is the API URL a launch carried, and when.
type SeenAPI struct {
	URL    string `json:"url"`
	SeenAt string `json:"seen_at"`
}

// APIURL keeps the API URL launches carry: the readiness view's evidence
// when Kandev's environment does not show it.
type APIURL struct {
	host kandev.Provider
	now  func() time.Time

	mu   sync.Mutex
	seen string // the URL last written, to skip rewriting it every launch
}

// NewAPIURL returns the API URL store over host.
func NewAPIURL(host kandev.Provider, now func() time.Time) *APIURL {
	return &APIURL{host: host, now: now}
}

// Load reads the URL last seen; zero when none was, or when it is unreadable.
func (s *APIURL) Load(ctx context.Context) (SeenAPI, error) {
	h, err := s.host.Get()
	if err != nil {
		return SeenAPI{}, err
	}
	var seen SeenAPI
	if _, err := kandev.LoadDocument(ctx, h, apiURLKey, &seen); err != nil && !errors.Is(err, kandev.ErrUnreadable) {
		return SeenAPI{}, err
	}
	return seen, nil
}

// Note keeps the URL a launch carried, when it changed. Failures are logged:
// the URL is only evidence for the readiness view.
func (s *APIURL) Note(ctx context.Context, apiURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if apiURL == "" || apiURL == s.seen {
		return
	}
	h, err := s.host.Get()
	if err != nil {
		return
	}
	seen := SeenAPI{URL: apiURL, SeenAt: s.now().UTC().Format(time.RFC3339)}
	if err := kandev.SaveDocument(ctx, h, apiURLKey, seen); err != nil {
		log.Printf("note api url: %v", err)
		return
	}
	s.seen = apiURL
}
