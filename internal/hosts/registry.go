// Package hosts owns the sandbox host registry and placement. It declares the
// ports it needs (Store, Prober) and knows nothing about SSH, msbctl or the
// Kandev SDK.
package hosts

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"kandev-plugin-microsandbox/internal/profile"
)

// RegistryVersion is the shape of the stored registry document.
const RegistryVersion = 1

// MaxHosts bounds the registry. Placement probes every candidate in
// parallel, and the whole document is one Host state value.
const MaxHosts = 64

// MaxLabels bounds the labels on one host.
const MaxLabels = 16

// Host is one registered sandbox host. Name is an immutable identifier: it
// is recorded in each resource's state and routes every later call.
type Host struct {
	Name     string   `json:"name"`
	SSH      string   `json:"ssh"`
	HostKey  string   `json:"host_key"`
	BaseURL  string   `json:"base_url"`
	Labels   []string `json:"labels"`
	Draining bool     `json:"draining"`
}

// HasLabel reports whether the host carries label.
func (h Host) HasLabel(label string) bool {
	for _, l := range h.Labels {
		if l == label {
			return true
		}
	}
	return false
}

// Registry is the stored document. It is replaced whole on every change.
type Registry struct {
	Version int    `json:"version"`
	Hosts   []Host `json:"hosts"`
}

var (
	ErrNotFound  = errors.New("host is not registered")
	ErrExists    = errors.New("a host with that name is already registered")
	ErrTooMany   = fmt.Errorf("at most %d hosts can be registered", MaxHosts)
	ErrVersion   = errors.New("host registry was written by a newer plugin version")
	ErrImmutable = errors.New("a host's name cannot change")
)

// FieldError is a rejected host field, reported back to the operator.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError carries every rejected field of one host.
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return "invalid host: " + strings.Join(parts, "; ")
}

// Normalize trims and canonicalizes a host as submitted by the operator.
func Normalize(h Host) Host {
	h.Name = strings.TrimSpace(h.Name)
	h.SSH = strings.TrimSpace(h.SSH)
	h.HostKey = strings.Join(strings.Fields(h.HostKey), " ")
	h.BaseURL = strings.TrimRight(strings.TrimSpace(h.BaseURL), "/")
	labels := make([]string, 0, len(h.Labels))
	seen := map[string]bool{}
	for _, l := range h.Labels {
		l = strings.ToLower(strings.TrimSpace(l))
		if l != "" && !seen[l] {
			seen[l] = true
			labels = append(labels, l)
		}
	}
	sort.Strings(labels)
	h.Labels = labels
	return h
}

// Validate checks one normalized host. The host key is checked for shape
// only; whether it parses as a key is the SSH adapter's job.
func Validate(h Host) error {
	var fields []FieldError
	add := func(field, message string) { fields = append(fields, FieldError{field, message}) }
	if !profile.NamePattern.MatchString(h.Name) {
		add("name", "use 1-63 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if _, _, _, err := ParseSSH(h.SSH); err != nil {
		add("ssh", err.Error())
	}
	if !hostKeyShaped(h.HostKey) {
		add("host_key", "expected one public key line, such as 'ssh-ed25519 AAAA...'")
	}
	if err := validateBaseURL(h.BaseURL); err != nil {
		add("base_url", err.Error())
	}
	if len(h.Labels) > MaxLabels {
		add("labels", fmt.Sprintf("at most %d labels", MaxLabels))
	}
	for _, l := range h.Labels {
		if !profile.NamePattern.MatchString(l) {
			add("labels", fmt.Sprintf("label %q: use lowercase letters, digits, '.', '_' or '-'", l))
			break
		}
	}
	if len(fields) > 0 {
		return &ValidationError{Fields: fields}
	}
	return nil
}

// ParseSSH splits an SSH destination `user@host[:port]`. The user is
// required: on a sandbox host it is the account msb runs as, and the plugin
// never guesses it. IPv6 literals use brackets.
func ParseSSH(dest string) (user, host string, port int, err error) {
	user, rest, found := strings.Cut(dest, "@")
	if !found || user == "" || strings.ContainsAny(user, " \t:/") {
		return "", "", 0, errors.New("expected user@host or user@host:port")
	}
	host, portText, splitErr := net.SplitHostPort(rest)
	if splitErr != nil {
		host, portText = strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]"), "22"
	}
	port, convErr := strconv.Atoi(portText)
	if convErr != nil || port < 1 || port > 65535 {
		return "", "", 0, errors.New("port must be 1-65535")
	}
	if host == "" || strings.ContainsAny(host, " \t/@[]") {
		return "", "", 0, errors.New("expected user@host or user@host:port")
	}
	return user, host, port, nil
}

func hostKeyShaped(key string) bool {
	parts := strings.Fields(key)
	if len(parts) < 2 || len(parts) > 3 || !strings.HasPrefix(parts[0], "ssh-") && !strings.HasPrefix(parts[0], "ecdsa-") {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(parts[1])
	return err == nil
}

// validateBaseURL applies Kandev's connection lease rules early, so a host
// that could never serve a valid lease is refused at registration rather
// than at the first launch: HTTPS, a hostname, no userinfo, query or
// fragment, and not a loopback, link-local, multicast or unspecified literal.
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("expected an https:// URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("must not carry credentials, a query or a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("must not carry a path; the plugin appends /vm/<env>/p/<port>")
	}
	return addressProblem(u.Hostname())
}

// addressProblem refuses the host literals Kandev refuses in a lease.
func addressProblem(host string) error {
	if strings.EqualFold(host, "localhost") {
		return errors.New("loopback addresses are refused by Kandev")
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()) {
		return errors.New("loopback, link-local, multicast and unspecified addresses are refused by Kandev")
	}
	return nil
}

// Find returns the host with name.
func (r Registry) Find(name string) (Host, bool) {
	for _, h := range r.Hosts {
		if h.Name == name {
			return h, true
		}
	}
	return Host{}, false
}

// Add returns a registry with h appended.
func (r Registry) Add(h Host) (Registry, error) {
	h = Normalize(h)
	if err := Validate(h); err != nil {
		return r, err
	}
	if _, exists := r.Find(h.Name); exists {
		return r, ErrExists
	}
	if len(r.Hosts) >= MaxHosts {
		return r, ErrTooMany
	}
	out := r.clone()
	out.Hosts = append(out.Hosts, h)
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Name < out.Hosts[j].Name })
	return out, nil
}

// Update replaces the host named h.Name. The draining flag is kept: it
// changes only through SetDraining.
func (r Registry) Update(h Host) (Registry, error) {
	h = Normalize(h)
	if err := Validate(h); err != nil {
		return r, err
	}
	out := r.clone()
	for i := range out.Hosts {
		if out.Hosts[i].Name == h.Name {
			h.Draining = out.Hosts[i].Draining
			out.Hosts[i] = h
			return out, nil
		}
	}
	return r, ErrNotFound
}

// SetDraining marks a host as draining or not. A draining host gets no new
// placements but keeps serving every call for its existing sandboxes.
func (r Registry) SetDraining(name string, draining bool) (Registry, error) {
	out := r.clone()
	for i := range out.Hosts {
		if out.Hosts[i].Name == name {
			out.Hosts[i].Draining = draining
			return out, nil
		}
	}
	return r, ErrNotFound
}

// Remove returns a registry without name. Whether the host still owns
// sandboxes is the caller's check, because only the host knows.
func (r Registry) Remove(name string) (Registry, error) {
	out := r.clone()
	for i := range out.Hosts {
		if out.Hosts[i].Name == name {
			out.Hosts = append(out.Hosts[:i], out.Hosts[i+1:]...)
			return out, nil
		}
	}
	return r, ErrNotFound
}

// Candidates returns the non-draining hosts a placement selects.
func (r Registry) Candidates(p profile.Placement) []Host {
	var out []Host
	for _, h := range r.Hosts {
		if h.Draining {
			continue
		}
		switch p.Kind {
		case profile.PlacementHost:
			if h.Name == p.Value {
				out = append(out, h)
			}
		case profile.PlacementLabel:
			if h.HasLabel(p.Value) {
				out = append(out, h)
			}
		}
	}
	return out
}

// Check validates a registry read back from storage.
func (r Registry) Check() error {
	if r.Version > RegistryVersion {
		return ErrVersion
	}
	seen := map[string]bool{}
	for _, h := range r.Hosts {
		if err := Validate(h); err != nil {
			return fmt.Errorf("stored host %q: %w", h.Name, err)
		}
		if seen[h.Name] {
			return fmt.Errorf("stored host %q: %w", h.Name, ErrExists)
		}
		seen[h.Name] = true
	}
	return nil
}

func (r Registry) clone() Registry {
	out := Registry{Version: RegistryVersion, Hosts: make([]Host, len(r.Hosts))}
	for i, h := range r.Hosts {
		h.Labels = append([]string(nil), h.Labels...)
		out.Hosts[i] = h
	}
	return out
}
