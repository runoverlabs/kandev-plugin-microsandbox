package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func adminKey(t *testing.T, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(private, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte(passphrase))
	}
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block)), signer.PublicKey()
}

func TestAdminRunsCommandsWithStdinAndKeepsStderr(t *testing.T) {
	keyPEM, public := adminKey(t, "")
	server := sshtest.Start(t, public, func(command string, stdin []byte) sshtest.Reply {
		return sshtest.Reply{Stdout: "ran " + command + " with " + string(stdin), Stderr: "warning: x", Status: 3}
	})
	admin, err := DialAdmin(t.Context(), &net.Dialer{}, server.Dest("ubuntu"), server.HostKey, AdminAuth{PrivateKeyPEM: keyPEM})
	require.NoError(t, err)
	defer admin.Close()
	out, err := admin.Exec(t.Context(), "sh -s", []byte("echo hi"))
	require.NoError(t, err)
	assert.Equal(t, "ran sh -s with echo hi", string(out.Stdout))
	assert.Equal(t, "warning: x", string(out.Stderr))
	assert.Equal(t, 3, out.Exit)
	assert.Equal(t, "ubuntu", server.Execs()[0].User)
}

func TestAdminAuthMethods(t *testing.T) {
	keyPEM, public := adminKey(t, "s3cret")
	server := sshtest.Start(t, public, func(string, []byte) sshtest.Reply { return sshtest.Reply{} }, sshtest.WithPassword("pw-1"))
	dial := func(auth AdminAuth) error {
		admin, err := DialAdmin(t.Context(), &net.Dialer{}, server.Dest("root"), server.HostKey, auth)
		if err == nil {
			admin.Close()
		}
		return err
	}
	assert.NoError(t, dial(AdminAuth{PrivateKeyPEM: keyPEM, Passphrase: "s3cret"}))
	assert.NoError(t, dial(AdminAuth{Password: "pw-1"}))
	assert.ErrorIs(t, dial(AdminAuth{Password: "nope"}), ErrNotAuthorized)
	assert.ErrorIs(t, dial(AdminAuth{PrivateKeyPEM: keyPEM}), ErrAdminAuth, "the passphrase is missing")
	assert.ErrorIs(t, dial(AdminAuth{PrivateKeyPEM: keyPEM, Passphrase: "wrong"}), ErrAdminAuth)
	assert.ErrorIs(t, dial(AdminAuth{PrivateKeyPEM: "not a key"}), ErrAdminAuth)
	assert.ErrorIs(t, dial(AdminAuth{}), ErrAdminAuth)

	other := sshtest.Start(t, public, func(string, []byte) sshtest.Reply { return sshtest.Reply{} })
	_, err := DialAdmin(t.Context(), &net.Dialer{}, server.Dest("root"), other.HostKey, AdminAuth{PrivateKeyPEM: keyPEM, Passphrase: "s3cret"})
	assert.ErrorIs(t, err, ErrHostKeyMismatch, "the pin is checked as for the plugin's own key")
}

// The login's secrets never appear in an error.
func TestAdminErrorsCarryNoSecret(t *testing.T) {
	keyPEM, public := adminKey(t, "s3cret")
	server := sshtest.Start(t, public, nil, sshtest.WithPassword("pw-1"))
	for _, auth := range []AdminAuth{{PrivateKeyPEM: keyPEM, Passphrase: "wrong-pass"}, {Password: "wrong-password"}} {
		_, err := DialAdmin(t.Context(), &net.Dialer{}, server.Dest("root"), server.HostKey, auth)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "wrong-pass")
		assert.NotContains(t, err.Error(), "PRIVATE KEY")
	}
}
