package sshx_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/sshx"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func TestQuoteMatchesShlexQuote(t *testing.T) {
	// Expected values are Python 3's shlex.join output for the same argv.
	got := sshx.Join([]string{"msbctl", "kandev", "provision", "k-env 1", "it's", "", "a=b,c:d/e@f%g+h", "é", "$HOME;rm"})
	assert.Equal(t, `msbctl kandev provision 'k-env 1' 'it'"'"'s' '' a=b,c:d/e@f%g+h 'é' '$HOME;rm'`, got)
}

func TestGenerateKeyRoundTrips(t *testing.T) {
	private, authorized, err := sshx.GenerateKey()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(authorized, "ssh-ed25519 "))
	assert.True(t, strings.HasSuffix(authorized, " "+sshx.KeyComment))
	signer, err := sshx.ParseSigner(private)
	require.NoError(t, err)
	public, err := sshx.ParseHostKey(authorized)
	require.NoError(t, err)
	assert.Equal(t, public.Marshal(), signer.PublicKey().Marshal())

	_, err = sshx.ParseSigner("garbage")
	assert.Error(t, err)
}

type fixture struct {
	server *sshtest.Server
	pool   *sshx.Pool
	host   hosts.Host
	signer ssh.Signer
}

func newFixture(t *testing.T, handler sshtest.Handler) fixture {
	t.Helper()
	private, _, err := sshx.GenerateKey()
	require.NoError(t, err)
	signer, err := sshx.ParseSigner(private)
	require.NoError(t, err)
	server := sshtest.Start(t, signer.PublicKey(), handler)
	pool := sshx.NewPool(signer, &net.Dialer{})
	t.Cleanup(pool.Close)
	return fixture{
		server: server, pool: pool, signer: signer,
		host: hosts.Host{Name: "sbx-01", SSH: server.Dest("msb"), HostKey: server.HostKey},
	}
}

func echo(command string, stdin []byte) sshtest.Reply {
	return sshtest.Reply{Stdout: command + "|" + string(stdin), Status: 0}
}

func TestRunSendsQuotedCommandAndStdin(t *testing.T) {
	f := newFixture(t, echo)
	stdout, status, err := f.pool.Run(context.Background(), f.host, []string{"msbctl", "kandev", "health", "a b"}, strings.NewReader(`{"x":1}`))
	require.NoError(t, err)
	assert.Equal(t, 0, status)
	assert.Equal(t, `msbctl kandev health 'a b'|{"x":1}`, string(stdout))
	execs := f.server.Execs()
	require.Len(t, execs, 1)
	assert.Equal(t, "msb", execs[0].User)
}

func TestRunReportsExitStatusWithStdout(t *testing.T) {
	f := newFixture(t, func(string, []byte) sshtest.Reply {
		return sshtest.Reply{Stdout: `{"error":{"code":"not_found"}}`, Status: 3}
	})
	stdout, status, err := f.pool.Run(context.Background(), f.host, []string{"msbctl"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, status)
	assert.Contains(t, string(stdout), "not_found")
}

func TestRunReusesOneConnection(t *testing.T) {
	f := newFixture(t, echo)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.pool.Run(context.Background(), f.host, []string{"msbctl"}, nil)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Len(t, f.server.Execs(), 8)
	assert.Equal(t, 1, f.server.Accepted())
}

func TestRunRedialsAfterTheConnectionDrops(t *testing.T) {
	f := newFixture(t, echo)
	_, _, err := f.pool.Run(context.Background(), f.host, []string{"one"}, nil)
	require.NoError(t, err)
	f.server.DropConnections()
	time.Sleep(50 * time.Millisecond) // let the client notice the close
	stdout, _, err := f.pool.Run(context.Background(), f.host, []string{"two"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "two|", string(stdout))
	assert.Equal(t, 2, f.server.Accepted())
}

func TestRunRefusesAWrongHostKey(t *testing.T) {
	f := newFixture(t, echo)
	other := newFixture(t, echo)
	f.host.HostKey = other.server.HostKey
	_, _, err := f.pool.Run(context.Background(), f.host, []string{"msbctl"}, nil)
	assert.ErrorIs(t, err, sshx.ErrHostKeyMismatch)
	assert.Empty(t, f.server.Execs())
}

func TestRunReportsAnUnauthorizedKey(t *testing.T) {
	f := newFixture(t, echo)
	private, _, err := sshx.GenerateKey()
	require.NoError(t, err)
	stranger, err := sshx.ParseSigner(private)
	require.NoError(t, err)
	pool := sshx.NewPool(stranger, &net.Dialer{})
	defer pool.Close()
	_, _, err = pool.Run(context.Background(), f.host, []string{"msbctl"}, nil)
	assert.ErrorIs(t, err, sshx.ErrNotAuthorized)
}

func TestRunHonorsCancellation(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, func(string, []byte) sshtest.Reply {
		<-release
		return sshtest.Reply{}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := f.pool.Run(ctx, f.host, []string{"slow"}, nil)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRunCapsOutput(t *testing.T) {
	f := newFixture(t, func(string, []byte) sshtest.Reply {
		return sshtest.Reply{Stdout: string(bytes.Repeat([]byte("x"), sshx.MaxStdout+1))}
	})
	_, _, err := f.pool.Run(context.Background(), f.host, []string{"loud"}, nil)
	assert.ErrorIs(t, err, sshx.ErrOutputTooLarge)
}

func TestRunAfterClose(t *testing.T) {
	f := newFixture(t, echo)
	f.pool.Close()
	_, _, err := f.pool.Run(context.Background(), f.host, []string{"x"}, nil)
	assert.ErrorIs(t, err, sshx.ErrClosed)
}

func TestScanHostKeyReturnsThePresentedKey(t *testing.T) {
	f := newFixture(t, echo)
	key, err := sshx.ScanHostKey(context.Background(), f.server.Dest("msb"), &net.Dialer{})
	require.NoError(t, err)
	assert.Equal(t, f.server.HostKey, key)
	assert.Empty(t, f.server.Execs(), "scanning must not run anything")

	fingerprint, err := sshx.Fingerprint(key)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(fingerprint, "SHA256:"))
}

func TestScanHostKeyFailsCleanly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	_, err = sshx.ScanHostKey(context.Background(), "msb@"+address, &net.Dialer{})
	assert.Error(t, err)
	_, err = sshx.ScanHostKey(context.Background(), "no-user", &net.Dialer{})
	assert.Error(t, err)
	assert.False(t, errors.Is(err, context.Canceled))
}
