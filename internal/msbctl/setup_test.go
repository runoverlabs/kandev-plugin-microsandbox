package msbctl

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/hosts"
)

func TestParseVersionsAndOlder(t *testing.T) {
	msb, manager := ParseVersions([]byte("msb=msb 0.7.7\nmsbctl=msbctl 0.5.1 (packaged)\n"))
	assert.Equal(t, "0.7.7", msb)
	assert.Equal(t, "0.5.1", manager)
	msb, manager = ParseVersions([]byte("msb=\nmsbctl=\n"))
	assert.Empty(t, msb+manager)

	assert.True(t, Older("0.4.0", "0.5.1"))
	assert.True(t, Older("0.5.0", "0.5.1"))
	assert.True(t, Older("", "0.5.1"))
	assert.False(t, Older("0.5.1", "0.5.1"))
	assert.False(t, Older("0.10.0", "0.9.9"), "numeric, not lexical")
	assert.False(t, Older("1.0.0", "0.5.1"))
}

func TestConfigureScriptRefusesWhatMsbctlWould(t *testing.T) {
	good := KandevConfig{ProxyListen: "10.0.1.23", BaseURL: "https://sbx-01.example.com"}
	_, err := ConfigureScript(good)
	require.NoError(t, err)
	for _, bad := range []KandevConfig{
		{ProxyListen: "sbx-01", BaseURL: good.BaseURL},
		{ProxyListen: "fe80::1%eth0", BaseURL: good.BaseURL},
		{ProxyListen: good.ProxyListen, BaseURL: "http://sbx-01.example.com"},
		{ProxyListen: good.ProxyListen, BaseURL: "https://sbx-01.example.com/path"},
		{ProxyListen: good.ProxyListen, BaseURL: good.BaseURL, AllowExtra: []string{`x' ]`}},
	} {
		_, err := ConfigureScript(bad)
		assert.ErrorIs(t, err, ErrConfig, "%+v", bad)
	}
}

// The script is one configure call with each value quoted for sh, and
// allow_extra only when asked; it runs in a real shell against a stand-in
// msbctl that prints the argv it got.
func TestConfigureScriptPassesEachFlagIntact(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "msbctl"), []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"), 0o755))
	run := func(c KandevConfig) []string {
		script, err := ConfigureScript(c)
		require.NoError(t, err)
		cmd := exec.Command(sh, "-s")
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.Split(strings.TrimSpace(string(out)), "\n")
	}
	assert.Equal(t, []string{"host", "kandev", "configure", "--enabled", "--serve", "proxy", "--proxy-listen", "10.0.1.23",
		"--base-url", "https://sbx-01.example.com", "--allow-extra", "*", "--allow-extra", "192.168.2.6:8788", "--json"},
		run(KandevConfig{ProxyListen: "10.0.1.23", BaseURL: "https://sbx-01.example.com", AllowExtra: []string{"*", "192.168.2.6:8788"}}))
	assert.NotContains(t, run(KandevConfig{ProxyListen: "10.0.1.23", BaseURL: "https://sbx-01.example.com"}), "--allow-extra")
}

func TestParseConfigure(t *testing.T) {
	changed, err := ParseConfigure([]byte(`{"changed": ["serve", "base_url"], "kandev": {"enabled": true}}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"serve", "base_url"}, changed)
	changed, err = ParseConfigure([]byte(`{"changed": [], "kandev": {}}`))
	require.NoError(t, err)
	assert.Empty(t, changed)
	_, err = ParseConfigure([]byte(`{"error": {"code": "invalid_config"}}`))
	assert.ErrorIs(t, err, ErrConfig)
}

func TestSelfUpdate(t *testing.T) {
	runner := &fakeRunner{reply: reply{stdout: `{"msbctl_version": "0.6.0", "updated": true}`}}
	got, err := New(runner).SelfUpdate(context.Background(), hosts.Host{}, "0.6.0")
	require.NoError(t, err)
	assert.Equal(t, []string{"msbctl", "self-update", "--json", "--version", "v0.6.0"}, runner.argv)
	assert.Equal(t, Updated{MsbctlVersion: "0.6.0", Updated: true}, got)

	for stdout, code := range map[string]string{
		`{"error": {"code": "unsupported", "message": "this is a git checkout"}}`: CodeUnsupported,
		`{"error": {"code": "denied", "message": "kandev is off"}}`:               CodeDenied,
		`{"error": {"code": "unavailable", "message": "get.sh failed"}}`:          CodeUnavailable,
	} {
		_, err := New(&fakeRunner{reply: reply{stdout: stdout, status: 3}}).SelfUpdate(context.Background(), hosts.Host{}, "0.6.0")
		assert.Equal(t, code, CodeOf(err), stdout)
	}
	_, err = New(&fakeRunner{reply: reply{status: 126}}).SelfUpdate(context.Background(), hosts.Host{}, "0.4.0")
	assert.Equal(t, CodeDenied, CodeOf(err), "host serve refuses a downgrade before msbctl runs")
}

func TestCanSelfUpdate(t *testing.T) {
	assert.False(t, Health{MsbctlVersion: "0.5.1"}.CanSelfUpdate())
	assert.True(t, Health{MsbctlVersion: "0.6.0"}.CanSelfUpdate())
	assert.True(t, Health{MsbctlVersion: "0.10.0"}.CanSelfUpdate())
	assert.False(t, Health{}.CanSelfUpdate())
}
