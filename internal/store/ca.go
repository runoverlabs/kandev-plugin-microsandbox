package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/pki"
)

// The root's certificate is public and lives in Host state; its key lives
// only in the plugin secret store.
const (
	caKey       = "ca"
	CAKeySecret = "ca-key"
)

// CA keeps the plugin's root certificate authority, loaded once.
type CA struct {
	host kandev.Provider
	now  func() time.Time

	mu   sync.Mutex
	root *pki.Root
}

// NewCA returns the root store over host.
func NewCA(host kandev.Provider, now func() time.Time) *CA { return &CA{host: host, now: now} }

type rootDocument struct {
	CertPEM   string `json:"cert_pem"`
	CreatedAt string `json:"created_at"`
}

// Root returns the plugin's certificate authority, or pki.ErrNoRoot when
// none has been created.
func (s *CA) Root(ctx context.Context) (*pki.Root, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root != nil {
		return s.root, nil
	}
	h, err := s.host.Get()
	if err != nil {
		return nil, err
	}
	var doc rootDocument
	found, err := kandev.LoadDocument(ctx, h, caKey, &doc)
	if err != nil && !errors.Is(err, kandev.ErrUnreadable) {
		return nil, fmt.Errorf("read root certificate: %w", err)
	}
	if !found {
		return nil, pki.ErrNoRoot
	}
	keyPEM, found, err := h.GetSecret(ctx, CAKeySecret)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	if !found {
		return nil, errors.New("the root's key is missing from the secret store")
	}
	root, err := pki.LoadRoot(doc.CertPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	s.root = root
	return root, nil
}

// Create generates and stores a new root, replacing any other. The key is
// written before the certificate, so a half-finished create leaves no
// certificate without its key.
func (s *CA) Create(ctx context.Context, c pki.Constraints) (*pki.Root, error) {
	h, err := s.host.Get()
	if err != nil {
		return nil, err
	}
	root, keyPEM, certPEM, err := pki.NewRoot(c, s.now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := h.SetSecret(ctx, CAKeySecret, keyPEM); err != nil {
		return nil, fmt.Errorf("store root key: %w", err)
	}
	doc := rootDocument{CertPEM: certPEM, CreatedAt: s.now().UTC().Format(time.RFC3339)}
	if err := kandev.SaveDocument(ctx, h, caKey, doc); err != nil {
		return nil, fmt.Errorf("store root certificate: %w", err)
	}
	s.root = root
	return root, nil
}
