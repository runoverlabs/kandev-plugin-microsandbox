package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func newRoot(t *testing.T, c Constraints) (*Root, string, string) {
	t.Helper()
	root, keyPEM, certPEM, err := NewRoot(c, now)
	require.NoError(t, err)
	return root, keyPEM, certPEM
}

func tailnet() Constraints {
	return Constraints{DNSSuffixes: []string{".Tailnet.TS.net "}}
}

func TestNewRootIsAConstrainedCA(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	c := root.Cert
	assert.True(t, c.IsCA)
	assert.True(t, c.MaxPathLenZero)
	assert.True(t, c.PermittedDNSDomainsCritical)
	assert.Equal(t, []string{"tailnet.ts.net"}, c.PermittedDNSDomains)
	assert.NotEmpty(t, c.ExcludedIPRanges, "a DNS-only root must refuse every IP SAN")
	assert.Equal(t, Constraints{DNSSuffixes: []string{"tailnet.ts.net"}}, root.Constraints())
}

func TestConstraintsValidate(t *testing.T) {
	assert.ErrorIs(t, Constraints{}.Validate(), ErrNoConstraint)
	for _, bad := range []Constraints{
		{DNSSuffixes: []string{"net"}},
		{DNSSuffixes: []string{"bad..example.com"}},
		{DNSSuffixes: []string{"-x.example.com"}},
		{DNSSuffixes: []string{"exa mple.com"}},
		{CIDRs: []string{"100.64.0.0"}},
		{CIDRs: []string{"0.0.0.0/0"}},
		{CIDRs: []string{"10.0.0.0/4"}},
	} {
		assert.Error(t, bad.Normalize().Validate(), "%+v", bad)
	}
	assert.NoError(t, Constraints{DNSSuffixes: []string{"tail.example.com"}, CIDRs: []string{"100.64.0.0/10"}}.Validate())
}

func TestIssueHostVerifiesUnderTheRoot(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	issued, err := root.IssueHost("SBX-01.tailnet.ts.net", now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(HostLifetime).Truncate(time.Second), issued.NotAfter.Truncate(time.Second))

	// The chain and key form a usable TLS pair.
	pair, err := tls.X509KeyPair([]byte(issued.ChainPEM), []byte(issued.KeyPEM))
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"sbx-01.tailnet.ts.net"}, leaf.DNSNames)
	require.Len(t, pair.Certificate, 2, "leaf then root")
	assert.NoError(t, root.Verify(leaf, "sbx-01.tailnet.ts.net", now))
	assert.Error(t, root.Verify(leaf, "sbx-02.tailnet.ts.net", now))
	assert.Error(t, root.Verify(leaf, "sbx-01.tailnet.ts.net", now.Add(HostLifetime+time.Hour)))
}

func TestIssueHostRefusesNamesOutsideTheConstraints(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	for _, host := range []string{"github.com", "tailnet.ts.net.evil.com", "eviltailnet.ts.net", "100.64.0.7"} {
		_, err := root.IssueHost(host, now)
		assert.ErrorIs(t, err, ErrNotPermitted, host)
	}
	_, err := root.IssueHost("tailnet.ts.net", now)
	assert.NoError(t, err, "the suffix itself is permitted")
}

func TestIssueHostByAddress(t *testing.T) {
	root, _, _ := newRoot(t, Constraints{CIDRs: []string{"100.64.0.0/10"}})
	issued, err := root.IssueHost("100.64.0.7", now)
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(issued.ChainPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.7", leaf.IPAddresses[0].String())
	_, err = root.IssueHost("10.0.0.1", now)
	assert.ErrorIs(t, err, ErrNotPermitted)
	_, err = root.IssueHost("sbx-01.tailnet.ts.net", now)
	assert.ErrorIs(t, err, ErrNotPermitted)
}

// The point of the constraints: even with the root key, a certificate for
// another name does not verify. This signs one directly, bypassing
// IssueHost's own check, and asks Go's verifier.
func TestALeakedRootKeyCannotImpersonateOtherNames(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	for _, forged := range []*x509.Certificate{
		{SerialNumber: serial(), Subject: pkix.Name{CommonName: "github.com"}, DNSNames: []string{"github.com"}},
		{SerialNumber: serial(), Subject: pkix.Name{CommonName: "ip"}, IPAddresses: []net.IP{net.ParseIP("140.82.112.3")}},
	} {
		forged.NotBefore, forged.NotAfter = now.Add(-time.Hour), now.Add(time.Hour)
		forged.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificate(rand.Reader, forged, root.Cert, &key.PublicKey, root.key)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now})
		assert.Error(t, err, "forged %v%v must not verify", forged.DNSNames, forged.IPAddresses)
	}
}

func TestLoadRootRoundTrips(t *testing.T) {
	root, keyPEM, certPEM := newRoot(t, tailnet())
	loaded, err := LoadRoot(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Equal(t, root.Fingerprint(), loaded.Fingerprint())
	_, err = loaded.IssueHost("sbx-01.tailnet.ts.net", now)
	assert.NoError(t, err)

	_, otherKey, _ := newRoot(t, tailnet())
	_, err = LoadRoot(certPEM, otherKey)
	assert.Error(t, err, "a key from another root is refused")
	_, err = LoadRoot("garbage", keyPEM)
	assert.Error(t, err)
}

func TestRenewReason(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	host := "sbx-01.tailnet.ts.net"
	good := HostTLS{Installed: true, Subject: host, NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339), IssuerSHA256: root.Fingerprint()}
	assert.Equal(t, "", root.RenewReason(good, host, now))

	cases := map[string]func(*HostTLS){
		"missing":    func(h *HostTLS) { h.Installed = false },
		"other_root": func(h *HostTLS) { h.IssuerSHA256 = "00" },
		"other_name": func(h *HostTLS) { h.Subject = "sbx-02.tailnet.ts.net" },
		"unreadable": func(h *HostTLS) { h.NotAfter = "soon" },
		"expiring":   func(h *HostTLS) { h.NotAfter = now.Add(29 * 24 * time.Hour).Format(time.RFC3339) },
	}
	for want, change := range cases {
		h := good
		change(&h)
		assert.Equal(t, want, root.RenewReason(h, host, now), want)
	}
}

func TestTrusted(t *testing.T) {
	root, _, _ := newRoot(t, tailnet())
	assert.ErrorIs(t, root.Trusted(x509.NewCertPool(), now), ErrUntrusted)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	assert.NoError(t, root.Trusted(pool, now))
	other, _, _ := newRoot(t, tailnet())
	assert.ErrorIs(t, other.Trusted(pool, now), ErrUntrusted)
}
