// Package msbctl is the adapter for `msbctl kandev`, the host-side verbs on
// each sandbox host. It owns every detail of that protocol — verb names,
// argv, the stdout JSON documents, the error envelope and exit statuses —
// and nothing above it parses msbctl output. docs/host-protocol.md is the
// contract this package implements.
package msbctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"kandev-plugin-microsandbox/internal/hosts"
)

// ProtocolVersion is the `msbctl kandev` protocol this plugin speaks. A host
// answering health with another version is refused rather than guessed at.
const ProtocolVersion = 1

// Exit statuses with a meaning. Any other non-zero status is `unavailable`.
const (
	exitError   = 3   // stdout carries an error envelope
	exitRefused = 126 // `host serve` refused the command line
)

// Runner runs one msbctl command line on a host and returns its stdout and
// exit status. A non-nil error means the command did not run to completion
// (no connection, a dropped session, cancellation), which says nothing
// about whether it took effect.
type Runner interface {
	Run(ctx context.Context, h hosts.Host, args []string, stdin io.Reader) (stdout []byte, exitStatus int, err error)
}

// Error codes, shared with Kandev's provider error vocabulary so a host
// answer maps through unchanged.
const (
	CodeInvalidConfig  = "invalid_config"
	CodeDenied         = "denied"
	CodeUnsupported    = "unsupported"
	CodeNotFound       = "not_found"
	CodeExpired        = "expired"
	CodeConflict       = "conflict"
	CodeUnavailable    = "unavailable"
	CodeRateLimited    = "rate_limited"
	CodeCleanupPending = "cleanup_pending"
)

var knownCodes = map[string]bool{
	CodeInvalidConfig: true, CodeDenied: true, CodeUnsupported: true, CodeNotFound: true,
	CodeExpired: true, CodeConflict: true, CodeUnavailable: true, CodeRateLimited: true,
	CodeCleanupPending: true,
}

// maxRetryAfterSeconds bounds a host's retry hint.
const maxRetryAfterSeconds = 600

// Error is a host's answer that the verb failed. It never carries the
// host's message text: that is msbctl's, and it is not forwarded.
type Error struct {
	Code              string
	RetryAfterSeconds int
}

func (e *Error) Error() string { return "msbctl kandev: " + e.Code }

// ErrUnreachable wraps every failure to get an answer from a host.
var ErrUnreachable = errors.New("sandbox host unreachable")

// CodeOf returns the provider error code for err: the host's code for an
// *Error, `unavailable` for everything else.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeUnavailable
}

// Client issues `msbctl kandev` verbs through a Runner.
type Client struct {
	runner Runner
}

// New returns a Client over runner.
func New(runner Runner) *Client { return &Client{runner: runner} }

// Health is the answer to `msbctl kandev health`.
type Health struct {
	Protocol      int            `json:"protocol"`
	MsbctlVersion string         `json:"msbctl_version"`
	MsbVersion    string         `json:"msb_version"`
	KVM           bool           `json:"kvm"`
	Enabled       bool           `json:"enabled"`
	Platform      string         `json:"platform"`
	BaseURL       string         `json:"base_url"`
	Capacity      hosts.Capacity `json:"capacity"`
	Serve         ServeStatus    `json:"serve"`
	// TLS is the proxy's installed certificate; absent on hosts that do not
	// run serve = "proxy".
	TLS *TLSStatus `json:"tls,omitempty"`
}

// ServeStatus reports whether the host's HTTPS data path is up. The host
// also sends a `reason` when it is not; that is msbctl's text and is not
// read, like every other message the host writes.
type ServeStatus struct {
	OK      bool   `json:"ok"`
	Mode    string `json:"mode"`              // "proxy", "tailscale" or "none"
	Listen  string `json:"listen,omitempty"`  // proxy: the address its TLS ports bind
	Running bool   `json:"running,omitempty"` // proxy: the service is up
}

// ServeProxy is the mode where msbctl terminates TLS itself, with a
// certificate the plugin issues.
const ServeProxy = "proxy"

// TLSStatus is what a host reports about the proxy's certificate.
type TLSStatus struct {
	Installed    bool   `json:"installed"`
	Subject      string `json:"subject"`
	NotAfter     string `json:"not_after"`
	IssuerSHA256 string `json:"issuer_sha256"`
}

// Usable reports whether a host can take new sandboxes at all, regardless
// of free capacity.
func (h Health) Usable() bool {
	return h.Protocol == ProtocolVersion && h.KVM && h.Enabled && h.Serve.OK
}

// Health runs `msbctl kandev health`.
func (c *Client) Health(ctx context.Context, h hosts.Host) (Health, error) {
	var out Health
	if err := c.call(ctx, h, []string{"health"}, nil, &out); err != nil {
		return Health{}, err
	}
	if out.Protocol != ProtocolVersion {
		return out, &Error{Code: CodeUnsupported}
	}
	return out, nil
}

// Capacity implements hosts.Prober: a host is a placement candidate only if
// it is healthy and speaks this protocol.
func (c *Client) Capacity(ctx context.Context, h hosts.Host) (hosts.Capacity, error) {
	health, err := c.Health(ctx, h)
	if err != nil {
		return hosts.Capacity{}, err
	}
	if !health.Usable() {
		return hosts.Capacity{}, &Error{Code: CodeUnavailable}
	}
	return health.Capacity, nil
}

// Sandbox is one kandev entry in a host's inventory.
type Sandbox struct {
	Env       string `json:"env"`
	Name      string `json:"name"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// List runs `msbctl kandev list`.
func (c *Client) List(ctx context.Context, h hosts.Host) ([]Sandbox, error) {
	var out struct {
		Sandboxes []Sandbox `json:"sandboxes"`
	}
	if err := c.call(ctx, h, []string{"list"}, nil, &out); err != nil {
		return nil, err
	}
	return out.Sandboxes, nil
}

// TLSInstall runs `msbctl kandev tls install`, sending the certificate chain
// and its private key as one JSON header line on stdin. The key never
// appears in argv, and the host never prints it back.
func (c *Client) TLSInstall(ctx context.Context, h hosts.Host, chainPEM, keyPEM string) (TLSStatus, error) {
	header, err := json.Marshal(map[string]string{"cert_pem": chainPEM, "key_pem": keyPEM})
	if err != nil {
		return TLSStatus{}, err
	}
	var out struct {
		TLS *TLSStatus `json:"tls"`
	}
	if err := c.call(ctx, h, []string{"tls", "install"}, bytes.NewReader(append(header, '\n')), &out); err != nil {
		return TLSStatus{}, err
	}
	if out.TLS == nil {
		return TLSStatus{}, &Error{Code: CodeUnavailable}
	}
	return *out.TLS, nil
}

// call runs `msbctl kandev <args>` and decodes its one JSON document.
func (c *Client) call(ctx context.Context, h hosts.Host, args []string, stdin io.Reader, out any) error {
	argv := append([]string{"msbctl", "kandev"}, args...)
	stdout, status, err := c.runner.Run(ctx, h, argv, stdin)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: %w", ErrUnreachable, ctxErr)
		}
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	switch status {
	case 0:
		if err := json.Unmarshal(stdout, out); err != nil {
			return &Error{Code: CodeUnavailable}
		}
		return nil
	case exitError:
		return decodeError(stdout)
	case exitRefused:
		// The forced command refused the verb: this key is not authorized
		// with --kandev, or the host's msbctl predates the verb.
		return &Error{Code: CodeDenied}
	default:
		return &Error{Code: CodeUnavailable}
	}
}

func decodeError(stdout []byte) error {
	var envelope struct {
		Error *struct {
			Code              string `json:"code"`
			RetryAfterSeconds int    `json:"retry_after_seconds"`
		} `json:"error"`
	}
	if err := json.Unmarshal(stdout, &envelope); err != nil || envelope.Error == nil || !knownCodes[envelope.Error.Code] {
		return &Error{Code: CodeUnavailable}
	}
	out := &Error{Code: envelope.Error.Code}
	if out.Code == CodeRateLimited {
		out.RetryAfterSeconds = min(max(envelope.Error.RetryAfterSeconds, 0), maxRetryAfterSeconds)
	}
	return out
}
