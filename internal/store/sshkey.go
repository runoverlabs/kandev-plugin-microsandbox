package store

import (
	"context"

	"kandev-plugin-microsandbox/internal/kandev"
)

// SSHKeySecret holds the plugin's SSH private key. One key serves every host.
const SSHKeySecret = "ssh-key"

// SSHKey keeps the plugin's SSH private key in the plugin secret store.
type SSHKey struct{ host kandev.Provider }

// NewSSHKey returns the key store over host.
func NewSSHKey(host kandev.Provider) SSHKey { return SSHKey{host: host} }

// Load returns the stored key in PEM; found is false when there is none.
func (s SSHKey) Load(ctx context.Context) (privatePEM string, found bool, err error) {
	h, err := s.host.Get()
	if err != nil {
		return "", false, err
	}
	privatePEM, found, err = h.GetSecret(ctx, SSHKeySecret)
	return privatePEM, found && privatePEM != "", err
}

// Store replaces the stored key.
func (s SSHKey) Store(ctx context.Context, privatePEM string) error {
	h, err := s.host.Get()
	if err != nil {
		return err
	}
	return h.SetSecret(ctx, SSHKeySecret, privatePEM)
}
