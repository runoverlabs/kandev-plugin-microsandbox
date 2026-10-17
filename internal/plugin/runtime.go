// Package plugin wires the neutral packages and the msbctl/SSH adapters to
// the Kandev SDK. It owns the browser actions and the executor provider RPCs.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx"
)

// Host state and secret keys. State is plugin-wide ("instance" scope with an
// empty scope id): sandbox hosts are not owned by any one workspace.
const (
	stateScope       = "instance"
	registryStateKey = "hosts"
	sshKeySecret     = "ssh-key"
)

// ErrNoHost means the Host broker connection is not up yet.
var ErrNoHost = errors.New("kandev host is not connected yet")

// Runtime is the plugin value pluginsdk.Serve runs.
type Runtime struct {
	pluginsdk.UnimplementedPlugin

	dialer sshx.Dialer

	// registryMu serializes registry read-modify-write cycles; Host state
	// has no compare-and-swap.
	registryMu sync.Mutex

	keyMu     sync.Mutex
	signer    ssh.Signer
	publicKey string
	pool      *sshx.Pool
}

var (
	_ pluginsdk.Plugin                 = (*Runtime)(nil)
	_ pluginsdk.ActionHandler          = (*Runtime)(nil)
	_ pluginsdk.ExecutorProviderPlugin = (*Runtime)(nil)
)

// NewRuntime returns a Runtime dialing hosts over the network.
func NewRuntime() *Runtime {
	return &Runtime{dialer: &net.Dialer{}}
}

func (r *Runtime) host() (pluginsdk.Host, error) {
	h := r.Host()
	if h == nil {
		return nil, ErrNoHost
	}
	return h, nil
}

// store returns the registry store over Host state.
func (r *Runtime) store() (hosts.Store, error) {
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	return stateStore{host: h}, nil
}

// loadRegistry reads the registry without taking registryMu: a read never
// needs to wait for a mutation in progress.
func (r *Runtime) loadRegistry(ctx context.Context) (hosts.Registry, error) {
	store, err := r.store()
	if err != nil {
		return hosts.Registry{}, err
	}
	return store.Load(ctx)
}

// mutateRegistry applies change under registryMu and saves the result.
func (r *Runtime) mutateRegistry(ctx context.Context, change func(hosts.Registry) (hosts.Registry, error)) (hosts.Registry, error) {
	store, err := r.store()
	if err != nil {
		return hosts.Registry{}, err
	}
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	current, err := store.Load(ctx)
	if err != nil {
		return hosts.Registry{}, err
	}
	next, err := change(current)
	if err != nil {
		return hosts.Registry{}, err
	}
	if err := store.Save(ctx, next); err != nil {
		return hosts.Registry{}, err
	}
	return next, nil
}

// key returns the plugin's SSH signer and public key line, generating and
// storing the key on first use. One key serves every host; the operator
// authorizes its public half on each with `msbctl host authorize --kandev`.
func (r *Runtime) key(ctx context.Context) (ssh.Signer, string, error) {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	if r.signer != nil {
		return r.signer, r.publicKey, nil
	}
	h, err := r.host()
	if err != nil {
		return nil, "", err
	}
	private, found, err := h.GetSecret(ctx, sshKeySecret)
	if err != nil {
		return nil, "", fmt.Errorf("read ssh key: %w", err)
	}
	if !found || private == "" {
		generated, _, genErr := sshx.GenerateKey()
		if genErr != nil {
			return nil, "", genErr
		}
		if err := h.SetSecret(ctx, sshKeySecret, generated); err != nil {
			return nil, "", fmt.Errorf("store ssh key: %w", err)
		}
		private = generated
	}
	signer, err := sshx.ParseSigner(private)
	if err != nil {
		return nil, "", err
	}
	r.signer, r.publicKey = signer, sshx.AuthorizedLine(signer.PublicKey())
	r.pool = sshx.NewPool(signer, r.dialer)
	return r.signer, r.publicKey, nil
}

// client returns the msbctl client over the shared SSH pool.
func (r *Runtime) client(ctx context.Context) (*msbctl.Client, error) {
	if _, _, err := r.key(ctx); err != nil {
		return nil, err
	}
	r.keyMu.Lock()
	pool := r.pool
	r.keyMu.Unlock()
	return msbctl.New(pool), nil
}

// Close drops every SSH connection.
func (r *Runtime) Close() {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	if r.pool != nil {
		r.pool.Close()
	}
}

// stateStore keeps the registry as one Host state document.
type stateStore struct{ host pluginsdk.Host }

func (s stateStore) Load(ctx context.Context) (hosts.Registry, error) {
	value, found, err := s.host.GetState(ctx, stateScope, "", registryStateKey)
	if err != nil {
		return hosts.Registry{}, fmt.Errorf("read host registry: %w", err)
	}
	if !found {
		return hosts.Registry{Version: hosts.RegistryVersion}, nil
	}
	// Host state round-trips through a protobuf Struct, so decode by
	// re-encoding rather than asserting Go types.
	raw, err := json.Marshal(value)
	if err != nil {
		return hosts.Registry{}, errors.New("host registry is unreadable")
	}
	var registry hosts.Registry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return hosts.Registry{}, errors.New("host registry is unreadable")
	}
	if err := registry.Check(); err != nil {
		return hosts.Registry{}, err
	}
	return registry, nil
}

func (s stateStore) Save(ctx context.Context, registry hosts.Registry) error {
	registry.Version = hosts.RegistryVersion
	raw, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if err := s.host.SetState(ctx, stateScope, "", registryStateKey, value); err != nil {
		return fmt.Errorf("write host registry: %w", err)
	}
	return nil
}
