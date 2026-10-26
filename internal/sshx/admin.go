package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"kandev-plugin-microsandbox/internal/remote"

	"golang.org/x/crypto/ssh"
)

func adminMethods(a remote.AdminAuth) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if strings.TrimSpace(a.PrivateKeyPEM) != "" {
		var signer ssh.Signer
		var err error
		if a.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(a.PrivateKeyPEM), []byte(a.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(a.PrivateKeyPEM))
		}
		if err != nil {
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) {
				return nil, fmt.Errorf("%w: the key needs its passphrase", remote.ErrAdminAuth)
			}
			return nil, fmt.Errorf("%w: the private key could not be read", remote.ErrAdminAuth)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		password := a.Password
		methods = append(methods, ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: give a private key or a password", remote.ErrAdminAuth)
	}
	return methods, nil
}

// Admin is one SSH connection with an operator's login, for host setup.
type Admin struct {
	client *ssh.Client
}

// MaxAdminOutput bounds each stream of one setup command.
const MaxAdminOutput = 256 << 10

// DialAdmin connects to dest with the operator's login, accepting only the
// pinned host key.
func DialAdmin(ctx context.Context, dialer Dialer, dest, hostKey string, auth remote.AdminAuth) (*Admin, error) {
	methods, err := adminMethods(auth)
	if err != nil {
		return nil, err
	}
	client, err := dialPinned(ctx, dialer, dest, hostKey, methods)
	if err != nil {
		return nil, err
	}
	return &Admin{client: client}, nil
}

// Exec runs command with stdin and returns its output. A non-nil error means
// it did not run to completion; a non-zero exit is in Output.
func (a *Admin) Exec(ctx context.Context, command string, stdin []byte) (remote.Output, error) {
	session, err := openSession(ctx, a.client)
	if err != nil {
		return remote.Output{}, err
	}
	defer session.Close()
	stdout := &cappedBuffer{limit: MaxAdminOutput}
	stderr := &cappedBuffer{limit: MaxAdminOutput}
	session.Stdout, session.Stderr = stdout, stderr
	session.Stdin = bytes.NewReader(stdin)
	if err := session.Start(command); err != nil {
		return remote.Output{}, fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		<-done
		return remote.Output{}, ctx.Err()
	}
	out := remote.Output{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		out.Exit = exit.ExitStatus()
	default:
		return remote.Output{}, fmt.Errorf("command did not complete: %w", err)
	}
	return out, nil
}

// Close ends the connection.
func (a *Admin) Close() { _ = a.client.Close() }
