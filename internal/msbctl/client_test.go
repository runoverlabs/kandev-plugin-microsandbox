package msbctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/hosts"
)

type reply struct {
	stdout string
	status int
	err    error
}

type fakeRunner struct {
	reply reply
	argv  []string
	stdin []byte
}

func (f *fakeRunner) Run(_ context.Context, _ hosts.Host, args []string, stdin io.Reader) ([]byte, int, error) {
	f.argv = args
	if stdin != nil {
		f.stdin, _ = io.ReadAll(stdin)
	}
	return []byte(f.reply.stdout), f.reply.status, f.reply.err
}

const healthy = `{"protocol":1,"msbctl_version":"0.4.0","msb_version":"0.7.7","kvm":true,"enabled":true,
 "platform":"linux-amd64","base_url":"https://sbx-01.tailnet.ts.net",
 "capacity":{"max_sandboxes":12,"sandboxes":3,"max_cpus":32,"cpus":8,"max_memory_mib":98304,"memory_mib":16384},
 "serve":{"ok":true,"mode":"tailscale"}}`

func TestHealthDecodesAndSendsVerb(t *testing.T) {
	runner := &fakeRunner{reply: reply{stdout: healthy}}
	health, err := New(runner).Health(context.Background(), hosts.Host{Name: "sbx-01"})
	require.NoError(t, err)
	assert.Equal(t, []string{"msbctl", "kandev", "health"}, runner.argv)
	assert.Equal(t, "0.7.7", health.MsbVersion)
	assert.Equal(t, "linux-amd64", health.Platform)
	assert.Equal(t, "https://sbx-01.tailnet.ts.net", health.BaseURL)
	assert.Equal(t, 98304-16384, health.Capacity.FreeMemoryMiB())
	assert.Equal(t, "tailscale", health.Serve.Mode)
	assert.True(t, health.Usable())
}

func TestHealthRefusesOtherProtocolVersions(t *testing.T) {
	runner := &fakeRunner{reply: reply{stdout: `{"protocol":2,"kvm":true,"enabled":true,"serve":{"ok":true}}`}}
	_, err := New(runner).Health(context.Background(), hosts.Host{})
	assert.Equal(t, CodeUnsupported, CodeOf(err))
}

func TestCapacityRequiresAUsableHost(t *testing.T) {
	for _, body := range []string{
		`{"protocol":1,"kvm":false,"enabled":true,"serve":{"ok":true}}`,
		`{"protocol":1,"kvm":true,"enabled":false,"serve":{"ok":true}}`,
		`{"protocol":1,"kvm":true,"enabled":true,"serve":{"ok":false}}`,
	} {
		_, err := New(&fakeRunner{reply: reply{stdout: body}}).Capacity(context.Background(), hosts.Host{})
		assert.Equal(t, CodeUnavailable, CodeOf(err), body)
	}
	c, err := New(&fakeRunner{reply: reply{stdout: healthy}}).Capacity(context.Background(), hosts.Host{})
	require.NoError(t, err)
	assert.Equal(t, 12, c.MaxSandboxes)
}

func TestExitStatusMapping(t *testing.T) {
	cases := []struct {
		label string
		reply reply
		code  string
		retry int
	}{
		{"error envelope", reply{`{"error":{"code":"not_found","message":"no such entry"}}`, 3, nil}, CodeNotFound, 0},
		{"rate limited keeps a bounded retry hint", reply{`{"error":{"code":"rate_limited","retry_after_seconds":30}}`, 3, nil}, CodeRateLimited, 30},
		{"retry hint is clamped", reply{`{"error":{"code":"rate_limited","retry_after_seconds":99999}}`, 3, nil}, CodeRateLimited, 600},
		{"unknown code", reply{`{"error":{"code":"kaboom"}}`, 3, nil}, CodeUnavailable, 0},
		{"garbage envelope", reply{`Traceback (most recent call last):`, 3, nil}, CodeUnavailable, 0},
		{"refused by host serve", reply{"", 126, nil}, CodeDenied, 0},
		{"other failure", reply{"", 1, nil}, CodeUnavailable, 0},
		{"unparseable success", reply{"not json", 0, nil}, CodeUnavailable, 0},
	}
	for _, c := range cases {
		_, err := New(&fakeRunner{reply: c.reply}).List(context.Background(), hosts.Host{})
		var e *Error
		require.True(t, errors.As(err, &e), c.label)
		assert.Equal(t, c.code, e.Code, c.label)
		assert.Equal(t, c.retry, e.RetryAfterSeconds, c.label)
		assert.NotContains(t, err.Error(), "no such entry", "host message text must not surface")
	}
}

func TestTransportFailureIsUnreachable(t *testing.T) {
	_, err := New(&fakeRunner{reply: reply{err: errors.New("connection reset")}}).List(context.Background(), hosts.Host{})
	assert.ErrorIs(t, err, ErrUnreachable)
	assert.Equal(t, CodeUnavailable, CodeOf(err))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = New(&fakeRunner{reply: reply{err: errors.New("session closed")}}).List(ctx, hosts.Host{})
	assert.ErrorIs(t, err, ErrUnreachable)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestListDecodes(t *testing.T) {
	runner := &fakeRunner{reply: reply{stdout: `{"sandboxes":[{"env":"env-1","name":"k-env-1","state":"running"}]}`}}
	list, err := New(runner).List(context.Background(), hosts.Host{})
	require.NoError(t, err)
	assert.Equal(t, []string{"msbctl", "kandev", "list"}, runner.argv)
	require.Len(t, list, 1)
	assert.Equal(t, "k-env-1", list[0].Name)
}

func TestHealthReadsProxyAndTLS(t *testing.T) {
	body := `{"protocol":1,"kvm":true,"enabled":true,
 "serve":{"ok":true,"mode":"proxy","listen":"100.64.0.7","running":true},
 "tls":{"installed":true,"subject":"sbx-01.tailnet.ts.net","not_after":"2027-01-17T00:00:00Z","issuer_sha256":"ab"}}`
	health, err := New(&fakeRunner{reply: reply{stdout: body}}).Health(context.Background(), hosts.Host{})
	require.NoError(t, err)
	assert.Equal(t, ServeProxy, health.Serve.Mode)
	assert.True(t, health.Serve.Running)
	require.NotNil(t, health.TLS)
	assert.Equal(t, "sbx-01.tailnet.ts.net", health.TLS.Subject)

	health, err = New(&fakeRunner{reply: reply{stdout: healthy}}).Health(context.Background(), hosts.Host{})
	require.NoError(t, err)
	assert.Nil(t, health.TLS, "hosts without the proxy report no tls")
}

func TestTLSInstallSendsTheKeyOnStdinOnly(t *testing.T) {
	const key = "-----BEGIN PRIVATE KEY-----\nplanted-key-material\n-----END PRIVATE KEY-----\n"
	runner := &fakeRunner{reply: reply{stdout: `{"tls":{"installed":true,"subject":"sbx-01.tailnet.ts.net","not_after":"2027-01-17T00:00:00Z","issuer_sha256":"ab"}}`}}
	status, err := New(runner).TLSInstall(context.Background(), hosts.Host{}, "CHAIN", key)
	require.NoError(t, err)
	assert.True(t, status.Installed)
	assert.Equal(t, []string{"msbctl", "kandev", "tls", "install"}, runner.argv)
	assert.NotContains(t, strings.Join(runner.argv, " "), "planted-key-material")

	require.True(t, bytes.HasSuffix(runner.stdin, []byte("\n")))
	assert.Equal(t, 1, bytes.Count(runner.stdin, []byte("\n")), "exactly one header line")
	var header map[string]string
	require.NoError(t, json.Unmarshal(runner.stdin, &header))
	assert.Equal(t, key, header["key_pem"])
	assert.Equal(t, "CHAIN", header["cert_pem"])

	_, err = New(&fakeRunner{reply: reply{stdout: `{"error":{"code":"invalid_config"}}`, status: 3}}).TLSInstall(context.Background(), hosts.Host{}, "x", "y")
	assert.Equal(t, CodeInvalidConfig, CodeOf(err))
	_, err = New(&fakeRunner{reply: reply{stdout: `{}`}}).TLSInstall(context.Background(), hosts.Host{}, "x", "y")
	assert.Equal(t, CodeUnavailable, CodeOf(err))
}
