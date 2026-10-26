package sandbox_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sandbox"
)

func TestParseBootstrapPorts(t *testing.T) {
	for raw, want := range map[string]msbctl.KandevAPI{
		`{"nonce":"n","api_url":"https://k.example.com/api/v1"}`:    {Host: "k.example.com", Port: 443},
		`{"nonce":"n","api_url":"http://k.example.com/api/v1"}`:     {Host: "k.example.com", Port: 80},
		`{"nonce":"n","api_url":"https://100.64.0.2:38429/api/v1"}`: {Host: "100.64.0.2", Port: 38429},
		`{"nonce":"n","api_url":"https://[fd7a::1]:8443/api/v1"}`:   {Host: "fd7a::1", Port: 8443},
	} {
		_, api, err := sandbox.ParseBootstrap(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, api, raw)
	}
	for _, raw := range []string{`{}`, `{"nonce":"n"}`, `{"nonce":"n","api_url":"ftp://x"}`, `not json`} {
		_, _, err := sandbox.ParseBootstrap(raw)
		assert.Error(t, err, raw)
	}
}

func TestForbiddenLeaseHeadersMatchKandev(t *testing.T) {
	for _, name := range []string{"Authorization", "authorization", "X-Instance-ID", "Host", "Cookie", "Set-Cookie", "Sec-WebSocket-Protocol", "Connection", "Upgrade", "Proxy-Foo", "Transfer-Encoding"} {
		assert.True(t, sandbox.ForbiddenLeaseHeader(name), name)
	}
	for _, name := range []string{"X-Msb-Lease", "X-Custom"} {
		assert.False(t, sandbox.ForbiddenLeaseHeader(name), name)
	}
}
