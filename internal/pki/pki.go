// Package pki is the plugin's small certificate authority: a root that is
// name-constrained to the sandbox hosts, host certificates issued from it,
// the renewal decision, and a check that a host's certificate is trusted by
// the system roots Kandev itself verifies against. It is pure crypto and
// networking: no SDK, no SSH, no msbctl.
//
// Kandev accepts only HTTPS connection leases and verifies them against the
// Kandev server's system trust store, so the operator installs this root
// there. The name constraints are what make that safe for the rest of the
// machine: a leaked root key can impersonate sandbox hosts and nothing else,
// because Go (and every mainstream verifier) enforces them.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	// RootLifetime is long: replacing the root means reinstalling it on
	// the Kandev server and re-issuing every host.
	RootLifetime = 10 * 365 * 24 * time.Hour
	// HostLifetime is short, because renewal is automatic.
	HostLifetime = 90 * 24 * time.Hour
	// RenewBefore is when a host certificate is re-issued.
	RenewBefore = 30 * 24 * time.Hour
	// backdate absorbs clock skew between the plugin and a host.
	backdate = 5 * time.Minute
)

var (
	// ErrNotPermitted means a name or address is outside the root's
	// constraints, so no certificate for it would ever verify.
	ErrNotPermitted = errors.New("outside the root's permitted names")
	// ErrNoConstraint means a root was requested with nothing to permit.
	ErrNoConstraint = errors.New("a root needs at least one permitted DNS suffix or address range")
	// ErrUntrusted means the host's certificate does not chain to a root
	// the system trusts: the root is not installed on the Kandev server.
	ErrUntrusted = errors.New("the host's certificate is not trusted by this machine's system roots")
)

// Constraints are what the root may certify.
type Constraints struct {
	// DNSSuffixes are domains such as "tailnet.ts.net" or a headscale
	// base_domain. A suffix covers itself and every name below it.
	DNSSuffixes []string `json:"dns_suffixes"`
	// CIDRs are address ranges, such as "100.64.0.0/10", for base URLs
	// that use an address.
	CIDRs []string `json:"cidrs"`
}

// Normalize trims, lowercases and deduplicates; a leading dot is dropped.
func (c Constraints) Normalize() Constraints {
	var out Constraints
	seen := map[string]bool{}
	for _, d := range c.DNSSuffixes {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !seen[d] {
			seen[d] = true
			out.DNSSuffixes = append(out.DNSSuffixes, d)
		}
	}
	for _, r := range c.CIDRs {
		r = strings.TrimSpace(r)
		if r != "" && !seen[r] {
			seen[r] = true
			out.CIDRs = append(out.CIDRs, r)
		}
	}
	return out
}

// Validate checks every suffix is a hostname with at least two labels and
// every range parses. A one-label suffix ("net") would be close to an
// unconstrained root.
func (c Constraints) Validate() error {
	if len(c.DNSSuffixes) == 0 && len(c.CIDRs) == 0 {
		return ErrNoConstraint
	}
	for _, d := range c.DNSSuffixes {
		if !validSuffix(d) {
			return fmt.Errorf("permitted DNS suffix %q: expected a domain such as tailnet.ts.net", d)
		}
	}
	for _, r := range c.CIDRs {
		if _, network, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("permitted range %q: expected CIDR notation such as 100.64.0.0/10", r)
		} else if ones, bits := network.Mask.Size(); ones < bits/4 {
			return fmt.Errorf("permitted range %q is too wide", r)
		}
	}
	return nil
}

func validSuffix(d string) bool {
	labels := strings.Split(d, ".")
	if len(labels) < 2 || len(d) > 253 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// noDNS is the only DNS domain a root without DNS suffixes permits: the
// TLD RFC 6761 reserves so that it never resolves. A suffix entered by the
// operator has at least two labels, so it can never be this.
const noDNS = "invalid"

// Root is a loaded certificate authority.
type Root struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewRoot generates a root limited to c. It returns the root and its key and
// certificate as PEM, for the plugin's secret store and state.
func NewRoot(c Constraints, now time.Time) (*Root, string, string, error) {
	c = c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate root key: %w", err)
	}
	var ranges []*net.IPNet
	for _, r := range c.CIDRs {
		_, network, _ := net.ParseCIDR(r)
		ranges = append(ranges, network)
	}
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "kandev-plugin-microsandbox root", Organization: []string{"Kandev sandbox hosts"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(RootLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		// Critical, so a verifier that cannot enforce the constraints
		// refuses the chain instead of ignoring them.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         c.DNSSuffixes,
		PermittedIPRanges:           ranges,
	}
	if len(c.DNSSuffixes) == 0 {
		// With only address ranges, forbid every DNS name: a name type with
		// no constraint is unconstrained, so the root could otherwise certify
		// any name at all. Only noDNS is permitted, which never resolves.
		template.PermittedDNSDomains = []string{noDNS}
	}
	if len(ranges) == 0 {
		// With only DNS constraints, forbid every address explicitly: an
		// unlisted IP SAN would otherwise be unconstrained.
		template.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", "", fmt.Errorf("create root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse root: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, "", "", err
	}
	return &Root{Cert: cert, key: key}, keyPEM, encodeCert(der), nil
}

// LoadRoot reads a root written by NewRoot.
func LoadRoot(certPEM, keyPEM string) (*Root, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, errors.New("stored root certificate is unreadable")
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("stored root key is unreadable")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("stored root key is unreadable")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("stored root key does not match its certificate")
	}
	return &Root{Cert: cert, key: key}, nil
}

// Fingerprint is the SHA-256 of the root certificate, as hex. Hosts report
// their issuer's fingerprint, which is how a certificate from a replaced
// root is noticed.
func (r *Root) Fingerprint() string { return Fingerprint(r.Cert) }

// Fingerprint is the SHA-256 of a certificate's DER, as lowercase hex.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// PEM is the root certificate, for the operator to install.
func (r *Root) PEM() string { return encodeCert(r.Cert.Raw) }

// Constraints reads back what the root permits.
func (r *Root) Constraints() Constraints {
	var c Constraints
	for _, d := range r.Cert.PermittedDNSDomains {
		if d != noDNS {
			c.DNSSuffixes = append(c.DNSSuffixes, d)
		}
	}
	for _, n := range r.Cert.PermittedIPRanges {
		c.CIDRs = append(c.CIDRs, n.String())
	}
	return c
}

// Permits reports whether a certificate for host (a DNS name or an address)
// would verify under the root's constraints.
func (r *Root) Permits(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range r.Cert.PermittedIPRanges {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range r.Constraints().DNSSuffixes {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// HostCert is an issued host certificate.
type HostCert struct {
	// ChainPEM is the leaf followed by the root.
	ChainPEM string
	// KeyPEM is the leaf's private key. It goes to the host once, over
	// SSH stdin, and is never stored by the plugin.
	KeyPEM   string
	NotAfter time.Time
}

// IssueHost issues a server certificate for host, which is a DNS name or an
// address. The certificate is verified against the root before it is
// returned, so a certificate that could not verify is never installed.
func (r *Root) IssueHost(host string, now time.Time) (HostCert, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !r.Permits(host) {
		return HostCert{}, fmt.Errorf("%s: %w", host, ErrNotPermitted)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return HostCert{}, fmt.Errorf("generate host key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(HostLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, r.Cert, &key.PublicKey, r.key)
	if err != nil {
		return HostCert{}, fmt.Errorf("issue host certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return HostCert{}, fmt.Errorf("parse host certificate: %w", err)
	}
	if err := r.Verify(leaf, host, now); err != nil {
		return HostCert{}, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return HostCert{}, err
	}
	return HostCert{ChainPEM: encodeCert(der) + r.PEM(), KeyPEM: keyPEM, NotAfter: leaf.NotAfter}, nil
}

// Verify checks leaf chains to this root for host at now.
func (r *Root) Verify(leaf *x509.Certificate, host string, now time.Time) error {
	pool := x509.NewCertPool()
	pool.AddCert(r.Cert)
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName: host, Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("issued certificate does not verify: %w", err)
	}
	return nil
}

// HostTLS is what a host reports about its installed certificate.
type HostTLS struct {
	Installed    bool   `json:"installed"`
	Subject      string `json:"subject"`
	NotAfter     string `json:"not_after"`
	IssuerSHA256 string `json:"issuer_sha256"`
}

// RenewReason says why a host needs a certificate, or "" when it does not.
// The plugin acts on any non-empty reason without asking: certificates are
// replaceable, and a lapsed one breaks every session on the host.
func (r *Root) RenewReason(t HostTLS, host string, now time.Time) string {
	if !t.Installed {
		return "missing"
	}
	if !strings.EqualFold(t.IssuerSHA256, r.Fingerprint()) {
		return "other_root"
	}
	if !strings.EqualFold(strings.TrimSuffix(t.Subject, "."), strings.TrimSuffix(host, ".")) {
		return "other_name"
	}
	notAfter, err := time.Parse(time.RFC3339, t.NotAfter)
	if err != nil {
		return "unreadable"
	}
	if notAfter.Sub(now) < RenewBefore {
		return "expiring"
	}
	return ""
}

// Trusted reports whether roots (the system pool when nil) trust this root,
// which is exactly the question Kandev's lease transport asks: it verifies
// against the Kandev server's system roots, and the plugin process inherits
// Kandev's environment, SSL_CERT_DIR included. Go loads system roots once
// per process, so a root installed after start is seen only after Kandev
// (and with it this plugin) restarts; the same is true for Kandev itself.
func (r *Root) Trusted(roots *x509.CertPool, now time.Time) error {
	if roots == nil {
		system, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("%w: system roots unavailable", ErrUntrusted)
		}
		roots = system
	}
	if _, err := r.Cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return ErrUntrusted
	}
	return nil
}

func encodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func parseCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		// crypto/rand does not fail on supported platforms; a zero serial
		// would still produce a valid, if less unique, certificate.
		return big.NewInt(1)
	}
	return n.Add(n, big.NewInt(1))
}
