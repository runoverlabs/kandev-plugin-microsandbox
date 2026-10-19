package msbctl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestConfigSectionRefusesWhatMsbctlWould(t *testing.T) {
	good := KandevConfig{ProxyListen: "10.0.1.23", BaseURL: "https://sbx-01.example.com"}
	_, err := ConfigSection(good)
	require.NoError(t, err)
	for _, bad := range []KandevConfig{
		{ProxyListen: "sbx-01", BaseURL: good.BaseURL},
		{ProxyListen: "fe80::1%eth0", BaseURL: good.BaseURL},
		{ProxyListen: good.ProxyListen, BaseURL: "http://sbx-01.example.com"},
		{ProxyListen: good.ProxyListen, BaseURL: "https://sbx-01.example.com/path"},
		{ProxyListen: good.ProxyListen, BaseURL: good.BaseURL, AllowExtra: []string{`x" ]`}},
	} {
		_, err := ConfigSection(bad)
		assert.ErrorIs(t, err, ErrConfig, "%+v", bad)
	}
}

// The script runs in a real shell, and Python's own TOML reader, which
// msbctl uses, reads the result.
func TestConfigureScriptAppendsOnceAndIsValidTOML(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	home := t.TempDir()
	cfg := filepath.Join(home, ".config", "msb", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
	require.NoError(t, os.WriteFile(cfg, []byte("# mine\n[defaults]\ncpus = 2\n"), 0o600))
	script, err := ConfigureScript(KandevConfig{ProxyListen: "10.0.1.23", BaseURL: "https://sbx-01.example.com", AllowExtra: []string{"*", "192.168.2.6:8788"}})
	require.NoError(t, err)
	run := func() string {
		cmd := exec.Command(sh, "-s")
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	assert.Equal(t, "added", run())
	assert.Equal(t, "present", run())
	text, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(text), "[kandev]"))
	assert.True(t, strings.HasPrefix(string(text), "# mine\n[defaults]\ncpus = 2\n"), "the operator's config is kept")

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 to read the TOML")
	}
	out, err := exec.Command(python, "-I", "-c", `import sys, tomllib, json
print(json.dumps(tomllib.load(open(sys.argv[1], "rb"))["kandev"], sort_keys=True))`, cfg).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.JSONEq(t, `{"enabled": true, "serve": "proxy", "proxy_listen": "10.0.1.23",
		"base_url": "https://sbx-01.example.com", "allow_extra": ["*", "192.168.2.6:8788"]}`, string(out))
}
