package sshx

import (
	"context"
	"fmt"
	"sync"
)

// KeyStore is where the plugin's private key is kept.
type KeyStore interface {
	Load(ctx context.Context) (privatePEM string, found bool, err error)
	Store(ctx context.Context, privatePEM string) error
}

// Keyring is the plugin's SSH key and the connection pool that uses it. The
// key is generated and stored on first use; one key serves every host, and
// the operator authorizes its public half on each with
// `msbctl host authorize --kandev`.
type Keyring struct {
	store  KeyStore
	dialer Dialer

	mu        sync.Mutex
	publicKey string
	pool      *Pool
}

// NewKeyring returns a keyring over store, dialing with dialer.
func NewKeyring(store KeyStore, dialer Dialer) *Keyring {
	return &Keyring{store: store, dialer: dialer}
}

// PublicKey is the key's authorized_keys line.
func (k *Keyring) PublicKey(ctx context.Context) (string, error) {
	if err := k.load(ctx); err != nil {
		return "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.publicKey, nil
}

// Pool is the shared connection pool, signing with the plugin's key.
func (k *Keyring) Pool(ctx context.Context) (*Pool, error) {
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.pool, nil
}

// Close drops every pooled connection.
func (k *Keyring) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pool != nil {
		k.pool.Close()
	}
}

func (k *Keyring) load(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pool != nil {
		return nil
	}
	private, found, err := k.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("read ssh key: %w", err)
	}
	if !found {
		generated, _, genErr := GenerateKey()
		if genErr != nil {
			return genErr
		}
		if err := k.store.Store(ctx, generated); err != nil {
			return fmt.Errorf("store ssh key: %w", err)
		}
		private = generated
	}
	signer, err := ParseSigner(private)
	if err != nil {
		return err
	}
	k.publicKey = AuthorizedLine(signer.PublicKey())
	k.pool = NewPool(signer, k.dialer)
	return nil
}
