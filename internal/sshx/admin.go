package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AdminAuth is an operator's own login to a machine, given once to set it up.
// It is secret: it lives only in memory for one setup, never in state, argv,
// a log line or a response.
type AdminAuth struct {
	PrivateKeyPEM string
	Passphrase    string
	Password      string
}

// ErrAdminAuth means the login could not be used: an unreadable key, or a
// key that needs a passphrase that was not given or does not fit.
var ErrAdminAuth = errors.New("the admin login is unusable")

func (a AdminAuth) methods() ([]ssh.AuthMethod, error) {
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
				return nil, fmt.Errorf("%w: the key needs its passphrase", ErrAdminAuth)
			}
			return nil, fmt.Errorf("%w: the private key could not be read", ErrAdminAuth)
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
		return nil, fmt.Errorf("%w: give a private key or a password", ErrAdminAuth)
	}
	return methods, nil
}

// Admin is one SSH connection with an operator's login, for host setup.
type Admin struct {
	client *ssh.Client
}

// Output is what one setup command printed. Unlike msbctl's kandev answers,
// stderr is kept: it is the operator's own machine, and an installer's error
// is the only way to say why a step failed.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// MaxAdminOutput bounds each stream of one setup command.
const MaxAdminOutput = 256 << 10

// DialAdmin connects to dest with the operator's login, accepting only the
// pinned host key.
func DialAdmin(ctx context.Context, dialer Dialer, dest, hostKey string, auth AdminAuth) (*Admin, error) {
	methods, err := auth.methods()
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
func (a *Admin) Exec(ctx context.Context, command string, stdin []byte) (Output, error) {
	session, err := openSession(ctx, a.client)
	if err != nil {
		return Output{}, err
	}
	defer session.Close()
	stdout := &cappedBuffer{limit: MaxAdminOutput}
	stderr := &cappedBuffer{limit: MaxAdminOutput}
	session.Stdout, session.Stderr = stdout, stderr
	session.Stdin = bytes.NewReader(stdin)
	if err := session.Start(command); err != nil {
		return Output{}, fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		<-done
		return Output{}, ctx.Err()
	}
	out := Output{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		out.Exit = exit.ExitStatus()
	default:
		return Output{}, fmt.Errorf("command did not complete: %w", err)
	}
	return out, nil
}

// Close ends the connection.
func (a *Admin) Close() { _ = a.client.Close() }
