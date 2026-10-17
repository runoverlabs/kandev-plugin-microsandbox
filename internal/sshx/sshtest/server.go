// Package sshtest runs an in-process SSH server standing in for a sandbox
// host: it authenticates one client key, accepts exec requests, and answers
// each command line through a scripted handler. Tests across the module use
// it to exercise the real SSH transport with no network and no msbctl.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Reply is what the fake host answers to one command.
type Reply struct {
	Stdout string
	Status int
}

// Handler answers one exec request. Command is the raw command line, as
// `host serve` would see it in SSH_ORIGINAL_COMMAND.
type Handler func(command string, stdin []byte) Reply

// Exec is one command the server ran.
type Exec struct {
	User    string
	Command string
	Stdin   []byte
}

// Server is a running fake host.
type Server struct {
	// Addr is host:port on loopback.
	Addr string
	// HostKey is the server's public key as an authorized_keys line.
	HostKey string

	listener net.Listener
	config   *ssh.ServerConfig
	handler  Handler

	mu       sync.Mutex
	execs    []Exec
	conns    []net.Conn
	accepted int
	wg       sync.WaitGroup
}

// Start runs a server that accepts only clientKey. It stops when the test
// ends.
func Start(t testing.TB, clientKey ssh.PublicKey, handler Handler) *Server {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Addr:     listener.Addr().String(),
		HostKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
		listener: listener,
		handler:  handler,
	}
	s.config = &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if clientKey != nil && string(key.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("key not authorized")
		},
	}
	s.config.AddHostKey(signer)
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(s.Close)
	return s
}

// Dest is an SSH destination for this server as user.
func (s *Server) Dest(user string) string { return user + "@" + s.Addr }

// Execs returns every command run so far.
func (s *Server) Execs() []Exec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Exec(nil), s.execs...)
}

// Accepted is how many TCP connections the server has accepted.
func (s *Server) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// DropConnections closes every open client connection, as a network drop or
// an sshd restart would.
func (s *Server) DropConnections() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// Close stops the server.
func (s *Server) Close() {
	_ = s.listener.Close()
	s.DropConnections()
	s.wg.Wait()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.accepted++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(conn)
		}()
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	var wg sync.WaitGroup
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(serverConn.User(), channel, channelRequests)
		}()
	}
	wg.Wait()
}

func (s *Server) session(user string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		go ssh.DiscardRequests(requests)
		stdin, _ := io.ReadAll(channel)
		s.mu.Lock()
		s.execs = append(s.execs, Exec{User: user, Command: payload.Command, Stdin: stdin})
		s.mu.Unlock()
		reply := s.handler(payload.Command, stdin)
		_, _ = io.WriteString(channel, reply.Stdout)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(reply.Status)}))
		return
	}
}
