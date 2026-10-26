package plugin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

// proxyHost is a stateful fake of a serve = "proxy" host: tls install checks
// the pair and records what it was sent, and health reports it back.
type proxyHost struct {
	mu          sync.Mutex
	mode        string
	tls         msbctl.TLSStatus
	installs    int
	failInstall bool
	lastKey     string
}

func newProxyHost() *proxyHost { return &proxyHost{mode: msbctl.ServeProxy} }

func (p *proxyHost) handle(command string, stdin []byte) sshtest.Reply {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch command {
	case "msbctl kandev health":
		body := map[string]any{
			"protocol": 1, "kvm": true, "enabled": true, "platform": "linux-amd64",
			"capacity": map[string]any{"max_sandboxes": 4, "max_cpus": 16, "max_memory_mib": 32768},
			"serve":    map[string]any{"ok": p.mode != msbctl.ServeProxy || p.tls.Installed, "mode": p.mode, "running": true},
		}
		body["tls"] = p.tls // every current host reports tls, proxy or not
		body["features"] = msbctl.RequiredFeatures
		out, _ := json.Marshal(body)
		return sshtest.Reply{Stdout: string(out)}
	case "msbctl kandev tls install":
		p.installs++
		if p.failInstall {
			return sshtest.Reply{Stdout: `{"error":{"code":"unavailable"}}`, Status: 3}
		}
		var in struct{ CertPEM, KeyPEM string }
		if err := json.Unmarshal(stdin, &struct {
			CertPEM *string `json:"cert_pem"`
			KeyPEM  *string `json:"key_pem"`
		}{&in.CertPEM, &in.KeyPEM}); err != nil {
			return sshtest.Reply{Stdout: `{"error":{"code":"invalid_config"}}`, Status: 3}
		}
		if _, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM)); err != nil {
			return sshtest.Reply{Stdout: `{"error":{"code":"invalid_config"}}`, Status: 3}
		}
		leaf, issuer := chain(in.CertPEM)
		sum := sha256.Sum256(issuer.Raw)
		subject := leaf.Subject.CommonName
		p.tls = msbctl.TLSStatus{Installed: true, Subject: subject, NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), IssuerSHA256: hex.EncodeToString(sum[:])}
		p.lastKey = in.KeyPEM
		out, _ := json.Marshal(map[string]any{"tls": p.tls})
		return sshtest.Reply{Stdout: string(out)}
	}
	return sshtest.Reply{Status: 126}
}

func (p *proxyHost) state() (msbctl.TLSStatus, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tls, p.installs
}

func chain(chainPEM string) (leaf, issuer *x509.Certificate) {
	rest := []byte(chainPEM)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, _ := x509.ParseCertificate(block.Bytes)
		certs = append(certs, c)
	}
	return certs[0], certs[len(certs)-1]
}

type caFixture struct {
	r     *Runtime
	host  *fakeHost
	clock time.Time
}

func newCAFixture(t *testing.T) *caFixture {
	f := &caFixture{host: newFakeHost(), clock: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	f.r = newRuntime(t, f.host)
	f.r.now = func() time.Time { return f.clock }
	f.r.trustPool = x509.NewCertPool() // the root is not trusted until a test adds it
	return f
}

func (f *caFixture) createRoot(t *testing.T) map[string]any {
	t.Helper()
	status, body := call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}})
	require.Equal(t, 201, status, body)
	return body
}

func (f *caFixture) trustRoot(t *testing.T) {
	t.Helper()
	root, err := f.r.ca.Root(t.Context())
	require.NoError(t, err)
	f.r.trustPool.AddCert(root.Cert)
}

// restart replaces the runtime with a new one on the same Kandev, as a
// plugin restart does: nothing it had cached survives.
func (f *caFixture) restart(t *testing.T) {
	t.Helper()
	f.r = newRuntime(t, f.host)
	f.r.now = func() time.Time { return f.clock }
	f.r.trustPool = x509.NewCertPool()
}

// addProxyHost registers a proxy-mode fake host; the name is used in its
// base_url, so it is covered by the tailnet.ts.net root.
func (f *caFixture) addProxyHost(t *testing.T, name string, p *proxyHost) (*sshtest.Server, map[string]any) {
	t.Helper()
	server := sshtest.Start(t, pluginKey(t, f.r), p.handle)
	status, body := call(t, f.r, ActionHostsAdd, hostBody(name, server.Dest("msb"), server.HostKey))
	require.Equal(t, 201, status, body)
	return server, body
}

func TestCAGetBeforeCreate(t *testing.T) {
	f := newCAFixture(t)
	status, body := call(t, f.r, ActionCAGet, nil)
	require.Equal(t, 200, status)
	assert.Equal(t, false, body["exists"])
	assert.NotEmpty(t, body["install"])
}

func TestCACreateStoresTheKeyOnlyAsASecret(t *testing.T) {
	f := newCAFixture(t)
	body := f.createRoot(t)
	assert.Equal(t, true, body["exists"])
	assert.Equal(t, false, body["trusted"])
	assert.Contains(t, body["cert_pem"], "BEGIN CERTIFICATE")
	raw, _ := json.Marshal(body)
	assert.NotContains(t, string(raw), "PRIVATE KEY")

	assert.Contains(t, f.host.Secret(caKeySecret), "PRIVATE KEY")
	state, _ := json.Marshal(f.host.State())
	assert.NotContains(t, string(state), "PRIVATE KEY", "the root key never reaches Host state")

	// A restarted plugin loads the same root.
	again := newRuntime(t, f.host)
	_, got := call(t, again, ActionCAGet, nil)
	assert.Equal(t, body["sha256"], got["sha256"])
}

func TestCACreateValidatesAndRefusesAccidentalReplacement(t *testing.T) {
	f := newCAFixture(t)
	assert.Equal(t, 422, first(call(t, f.r, ActionCACreate, map[string]any{})))
	assert.Equal(t, 422, first(call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"net"}})))
	original := f.createRoot(t)
	assert.Equal(t, 409, first(call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}})))
	status, replaced := call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}, "replace": true})
	require.Equal(t, 201, status)
	assert.NotEqual(t, original["sha256"], replaced["sha256"])
}

func TestAddRefusesABaseURLOutsideTheRoot(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	body := hostBody("sbx-01", "msb@sbx-01", unusedHostKey)
	body["base_url"] = "https://sbx-01.example.com"
	status, res := call(t, f.r, ActionHostsAdd, body)
	assert.Equal(t, 422, status)
	assert.Contains(t, res["fields"].([]any)[0].(map[string]any)["field"], "base_url")
}

func TestAddIssuesACertificateAndTheKeyTravelsOnStdinOnly(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	p := newProxyHost()
	server, body := f.addProxyHost(t, "sbx-01", p)
	assert.Equal(t, hostcheck.TLSRenewed, body["tls"].(map[string]any)["state"])
	assert.Equal(t, "missing", body["tls"].(map[string]any)["reason"])

	installed, count := p.state()
	assert.Equal(t, 1, count)
	assert.Equal(t, "sbx-01.tailnet.ts.net", installed.Subject)
	root, err := f.r.ca.Root(t.Context())
	require.NoError(t, err)
	assert.Equal(t, root.Fingerprint(), installed.IssuerSHA256)
	for _, exec := range server.Execs() {
		assert.NotContains(t, exec.Command, "PRIVATE KEY")
	}
	_, list := call(t, f.r, ActionHostsList, nil)
	raw, _ := json.Marshal(list)
	assert.NotContains(t, string(raw), p.lastKey[30:60], "the host key is never echoed")
}

func TestTestReportsAnUntrustedRootThenPasses(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	f.addProxyHost(t, "sbx-01", newProxyHost())

	_, body := call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "root_not_trusted", body["problem"])

	f.trustRoot(t)
	_, body = call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, true, body["ok"], body)
	assert.Equal(t, hostcheck.TLSOK, body["tls"].(map[string]any)["state"])
}

func TestTestWithoutARootSaysSo(t *testing.T) {
	f := newCAFixture(t)
	f.addProxyHost(t, "sbx-01", newProxyHost())
	_, body := call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "no_root", body["problem"])
}

func TestTestHealsAnExpiringCertificateBeforeReporting(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	f.trustRoot(t)
	p := newProxyHost()
	f.addProxyHost(t, "sbx-01", p)
	f.clock = f.clock.Add(61 * 24 * time.Hour) // 29 days left

	_, body := call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, true, body["ok"], body)
	assert.Equal(t, hostcheck.TLSRenewed, body["tls"].(map[string]any)["state"])
	assert.Equal(t, "expiring", body["tls"].(map[string]any)["reason"])
	_, count := p.state()
	assert.Equal(t, 2, count)
}

func TestMaintainerHealsEveryHostWithoutBeingAsked(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	healthy, expiring, failing, draining := newProxyHost(), newProxyHost(), newProxyHost(), newProxyHost()
	f.addProxyHost(t, "healthy", healthy)
	f.addProxyHost(t, "expiring", expiring)
	f.addProxyHost(t, "failing", failing)
	f.addProxyHost(t, "draining", draining)
	require.Equal(t, 200, first(call(t, f.r, ActionHostsDrain, map[string]any{"name": "draining", "draining": true})))
	gone := hostBody("gone", "msb@"+closedAddress(t), unusedHostKey)
	require.Equal(t, 201, first(call(t, f.r, ActionHostsAdd, gone)))

	// Sixty-one days later every certificate is inside the renewal window,
	// one host refuses installs, and one is unreachable.
	f.clock = f.clock.Add(61 * 24 * time.Hour)
	failing.mu.Lock()
	failing.failInstall = true
	failing.mu.Unlock()

	outcomes := f.r.maintainHosts(t.Context())
	assert.Equal(t, hostcheck.TLSRenewed, outcomes["healthy"].State)
	assert.Equal(t, hostcheck.TLSRenewed, outcomes["expiring"].State)
	assert.Equal(t, hostcheck.TLSRenewed, outcomes["draining"].State, "draining hosts still serve sessions")
	assert.Equal(t, hostcheck.TLSFailed, outcomes["failing"].State)
	assert.Equal(t, "unreachable", outcomes["gone"].Reason)

	// The next pass retries what failed, and leaves the rest alone.
	failing.mu.Lock()
	failing.failInstall = false
	failing.mu.Unlock()
	outcomes = f.r.maintainHosts(t.Context())
	assert.Equal(t, hostcheck.TLSRenewed, outcomes["failing"].State)
	assert.Equal(t, hostcheck.TLSOK, outcomes["healthy"].State)
	_, installs := healthy.state()
	assert.Equal(t, 2, installs, "a valid certificate is not re-issued")
}

func TestMaintainerReissuesAfterTheRootIsReplaced(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	p := newProxyHost()
	f.addProxyHost(t, "sbx-01", p)
	status, replaced := call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}, "replace": true})
	require.Equal(t, 201, status)

	outcomes := f.r.maintainHosts(t.Context())
	assert.Equal(t, hostcheck.TLSRenewed, outcomes["sbx-01"].State)
	assert.Equal(t, "other_root", outcomes["sbx-01"].Reason)
	installed, _ := p.state()
	assert.Equal(t, replaced["sha256"], installed.IssuerSHA256)
}

func TestMaintainerLeavesNonProxyHostsAndNoRootAlone(t *testing.T) {
	f := newCAFixture(t)
	p := newProxyHost()
	server, _ := f.addProxyHost(t, "sbx-01", p)
	// Without a root the host is still checked, for its status, but
	// nothing is installed.
	assert.Equal(t, hostcheck.TLSNoRoot, f.r.maintainHosts(t.Context())["sbx-01"].State)
	for _, exec := range server.Execs() {
		assert.Equal(t, "msbctl kandev health", exec.Command, "health only")
	}

	f.createRoot(t)
	p.mu.Lock()
	p.mode = "tailscale"
	p.mu.Unlock()
	outcomes := f.r.maintainHosts(t.Context())
	assert.Equal(t, hostcheck.TLSNotProxy, outcomes["sbx-01"].State)
	_, installs := p.state()
	assert.Equal(t, 0, installs)
}

func TestMaintainerRunsInTheBackgroundAndStopsOnClose(t *testing.T) {
	host := newFakeHost()
	setup := newRuntime(t, host)
	_, body := call(t, setup, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}})
	require.NotEmpty(t, body["sha256"])
	p := newProxyHost()
	server := sshtest.Start(t, pluginKey(t, setup), p.handle)
	require.Equal(t, 201, first(call(t, setup, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey))))
	p.mu.Lock()
	p.tls = msbctl.TLSStatus{} // lose the certificate, as a reinstalled host would
	p.mu.Unlock()

	r := NewRuntime()
	r.maintFirst, r.maintEvery = 10*time.Millisecond, time.Hour
	r.SetHost(host)
	require.Eventually(t, func() bool { installed, _ := p.state(); return installed.Installed }, 10*time.Second, 20*time.Millisecond)

	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop the maintainer")
	}
	r.SetHost(host) // after Close, nothing restarts
	r.maintMu.Lock()
	assert.Nil(t, r.maintCancel)
	r.maintMu.Unlock()
}

// A host that lost its certificate reports its data path down; Test installs
// a new one and then reports the host as it is now, not as it was.
func TestTestReportsTheHealedStateNotTheStaleOne(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	f.trustRoot(t)
	p := newProxyHost()
	f.addProxyHost(t, "sbx-01", p)
	p.mu.Lock()
	p.tls = msbctl.TLSStatus{}
	p.mu.Unlock()

	_, body := call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, true, body["ok"], body)
	assert.Equal(t, hostcheck.TLSRenewed, body["tls"].(map[string]any)["state"])
	assert.Equal(t, true, body["health"].(map[string]any)["serve"].(map[string]any)["ok"])
}

// A root that exists but cannot be used is reported as such everywhere, not
// read as "no root yet" or blamed on a host, and replacing it is the way out.
func TestAnUnusableRootIsReportedAndReplaceable(t *testing.T) {
	f := newCAFixture(t)
	f.createRoot(t)
	f.addProxyHost(t, "sbx-01", newProxyHost())
	require.NoError(t, f.host.DeleteSecret(t.Context(), caKeySecret))
	f.restart(t)

	_, body := call(t, f.r, ActionHostsTest, map[string]any{"name": "sbx-01"})
	assert.Equal(t, "root_unusable", body["problem"])

	status, body := call(t, f.r, ActionHostsAdd, hostBody("sbx-02", "msb@sbx-02", unusedHostKey))
	require.Equal(t, 201, status, body)
	assert.Equal(t, map[string]any{"state": "root_unusable"}, body["tls"])

	status, body = call(t, f.r, ActionSetupStatus, nil)
	require.Equal(t, 200, status, body)
	root := body["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "root", root["key"])
	assert.Equal(t, "failing", root["state"])
	assert.Len(t, body["items"], 3, "the other items are still reported")

	status, body = call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}})
	assert.Equal(t, 409, status)
	assert.Contains(t, body["error"], "replace: true")
	require.Equal(t, 201, first(call(t, f.r, ActionCACreate, map[string]any{"dns_suffixes": []string{"tailnet.ts.net"}, "replace": true})))
	_, body = call(t, f.r, ActionSetupStatus, nil)
	assert.Equal(t, "untrusted", body["items"].([]any)[0].(map[string]any)["state"])
}

// caKeyOutage is a Kandev whose secret store fails to read the root's key,
// as an outage would: the root itself is fine.
type caKeyOutage struct{ *fakeHost }

func (h caKeyOutage) GetSecret(ctx context.Context, key string) (string, bool, error) {
	if key == caKeySecret {
		return "", false, errors.New("secret store down")
	}
	return h.fakeHost.GetSecret(ctx, key)
}

// Failing to read the root says nothing about it, so nothing tells the
// operator to replace it, and a replace does not go ahead blind.
func TestAStoreOutageIsNotAnUnusableRoot(t *testing.T) {
	host := newFakeHost()
	require.Equal(t, 201, first(call(t, newRuntime(t, host), ActionCACreate, map[string]any{"dns_suffixes": []string{"example.com"}})))
	key := host.Secret(caKeySecret)
	r := newRuntime(t, caKeyOutage{host})

	assert.Equal(t, 500, first(call(t, r, ActionSetupStatus, nil)))
	assert.Equal(t, 500, first(call(t, r, ActionCACreate, map[string]any{"dns_suffixes": []string{"example.com"}, "replace": true})))
	assert.Equal(t, key, host.Secret(caKeySecret), "the root is not replaced")

	status, body := call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey))
	require.Equal(t, 201, status, body)
	assert.Equal(t, map[string]any{"state": "failed", "reason": "unavailable"}, body["tls"])
}
