// Package sshx is the SSH transport to sandbox hosts: the plugin's key, host
// key pinning, one shared connection per host, and the operator's one-off
// admin login. It knows nothing about msbctl verbs; quoting and the error
// kinds it reports are internal/remote's.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/remote"
)

const (
	// dialTimeout bounds TCP connect plus the SSH handshake.
	dialTimeout = 10 * time.Second
	// idleProbeAfter is how long a cached connection may sit unused before
	// it is checked with a keepalive. A dead connection otherwise surfaces
	// only as a session open that hangs until the caller's deadline.
	idleProbeAfter = 30 * time.Second
	probeTimeout   = 3 * time.Second
	// MaxStdout bounds what one command may print. Every msbctl kandev
	// answer is one small JSON document.
	MaxStdout = 4 << 20
)

var (
	// ErrOutputTooLarge means a command printed more than MaxStdout.
	ErrOutputTooLarge = errors.New("command output exceeds the size limit")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("ssh pool is closed")
)

// Dialer opens the TCP connection under SSH. *net.Dialer satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Pool keeps one SSH connection per host and opens a session per command,
// the equivalent of OpenSSH's ControlMaster. It implements msbctl.Runner.
type Pool struct {
	signer ssh.Signer
	dialer Dialer

	mu     sync.Mutex
	slots  map[string]*slot
	closed bool
}

type slot struct {
	mu       sync.Mutex // held while dialing, so one host is dialed once
	identity string
	client   *ssh.Client
	lastUsed time.Time
}

// NewPool returns a pool authenticating with signer.
func NewPool(signer ssh.Signer, dialer Dialer) *Pool {
	return &Pool{signer: signer, dialer: dialer, slots: map[string]*slot{}}
}

// Run runs one command line on h. The command is retried once on a fresh
// connection only when a cached connection cannot open a session, which is
// before anything ran on the host.
func (p *Pool) Run(ctx context.Context, h hosts.Host, args []string, stdin io.Reader) ([]byte, int, error) {
	command := remote.Join(args)
	for attempt := 0; ; attempt++ {
		client, fresh, err := p.client(ctx, h)
		if err != nil {
			return nil, 0, err
		}
		session, err := openSession(ctx, client)
		if err != nil {
			p.evict(h.Name, client)
			if fresh || attempt > 0 || ctx.Err() != nil {
				return nil, 0, err
			}
			continue
		}
		return runSession(ctx, session, command, stdin)
	}
}

// Close drops every connection. Run fails with ErrClosed afterwards.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	slots := p.slots
	p.slots = map[string]*slot{}
	p.mu.Unlock()
	for _, s := range slots {
		s.mu.Lock()
		if s.client != nil {
			_ = s.client.Close()
			s.client = nil
		}
		s.mu.Unlock()
	}
}

func (p *Pool) slotFor(name string) (*slot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	s := p.slots[name]
	if s == nil {
		s = &slot{}
		p.slots[name] = s
	}
	return s, nil
}

// client returns a live connection to h and whether it was just dialed. A
// cached connection is reused only for the same destination and pinned key,
// so editing a host takes effect on the next call.
func (p *Pool) client(ctx context.Context, h hosts.Host) (*ssh.Client, bool, error) {
	s, err := p.slotFor(h.Name)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := h.SSH + "\x00" + h.HostKey
	if s.client != nil && s.identity == identity {
		if time.Since(s.lastUsed) < idleProbeAfter || alive(s.client) {
			s.lastUsed = time.Now()
			return s.client, false, nil
		}
	}
	if s.client != nil {
		_ = s.client.Close()
		s.client = nil
	}
	client, err := p.dial(ctx, h)
	if err != nil {
		return nil, false, err
	}
	s.client, s.identity, s.lastUsed = client, identity, time.Now()
	return client, true, nil
}

func (p *Pool) evict(name string, client *ssh.Client) {
	_ = client.Close()
	p.mu.Lock()
	s := p.slots[name]
	p.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.client == client {
		s.client = nil
	}
	s.mu.Unlock()
}

func (p *Pool) dial(ctx context.Context, h hosts.Host) (*ssh.Client, error) {
	return dialPinned(ctx, p.dialer, h.SSH, h.HostKey, []ssh.AuthMethod{ssh.PublicKeys(p.signer)})
}

// dialPinned connects to dest and authenticates with auth, accepting only
// the pinned host key.
func dialPinned(ctx context.Context, dialer Dialer, dest, hostKey string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	pinned, err := ParseHostKey(hostKey)
	if err != nil {
		return nil, err
	}
	user, host, port, err := hosts.ParseSSH(dest)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}
	stop := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	defer stop()
	config := &ssh.ClientConfig{
		User:              user,
		Auth:              auth,
		HostKeyAlgorithms: hostKeyAlgorithms(pinned),
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), pinned.Marshal()) {
				return remote.ErrHostKeyMismatch
			}
			return nil
		},
		Timeout: dialTimeout,
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, classifyHandshake(dialCtx, address, err)
	}
	return ssh.NewClient(clientConn, channels, requests), nil
}

func classifyHandshake(ctx context.Context, address string, err error) error {
	switch {
	case errors.Is(err, remote.ErrHostKeyMismatch):
		return fmt.Errorf("%s: %w", address, remote.ErrHostKeyMismatch)
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%s: %w", address, remote.ErrNotAuthorized)
	case ctx.Err() != nil:
		return fmt.Errorf("ssh handshake with %s: %w", address, ctx.Err())
	default:
		return fmt.Errorf("ssh handshake with %s: %w", address, err)
	}
}

// alive sends an OpenSSH keepalive and waits briefly for any answer; a
// refusal still proves the connection carries traffic.
func alive(client *ssh.Client) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(probeTimeout):
		return false
	}
}

func openSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	type result struct {
		session *ssh.Session
		err     error
	}
	done := make(chan result, 1)
	go func() {
		session, err := client.NewSession()
		done <- result{session, err}
	}()
	select {
	case r := <-done:
		return r.session, r.err
	case <-ctx.Done():
		// The caller evicts and closes the client, which unblocks
		// NewSession; a session it still opens is closed here.
		go func() {
			if r := <-done; r.session != nil {
				_ = r.session.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func runSession(ctx context.Context, session *ssh.Session, command string, stdin io.Reader) ([]byte, int, error) {
	defer session.Close()
	stdout := &cappedBuffer{limit: MaxStdout}
	session.Stdout = stdout
	session.Stderr = io.Discard // msbctl's stderr is for the host's operator, never forwarded
	session.Stdin = stdin
	if err := session.Start(command); err != nil {
		return nil, 0, fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		<-done
		return nil, 0, ctx.Err()
	}
	if stdout.overflow {
		return nil, 0, ErrOutputTooLarge
	}
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), exit.ExitStatus(), nil
	}
	return nil, 0, fmt.Errorf("command did not complete: %w", err)
}

// cappedBuffer keeps at most limit bytes and records an overflow instead of
// failing the write, so the remote side is never blocked on a full pipe. The
// buffer is a named field, not embedded: an embedded bytes.Buffer would
// promote ReadFrom, and io.Copy would use it and bypass the limit.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); len(p) > room {
		b.overflow = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }
