// Package profile parses and validates a sandbox definition: one Kandev
// executor profile for this provider. It is pure — no SDK, no SSH, no host
// registry — so every rule here is testable from a plain map.
//
// Kandev delivers a profile as map[string]string with canonical string
// encodings for numbers, and the secret fields in a separate transient map.
// The manifest's profile_schema cannot express defaults or cross-field rules,
// so both live here.
package profile

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"kandev-plugin-microsandbox/internal/egress"
)

// Field names, matching manifest.yaml's profile_schema.
const (
	FieldPlacement        = "placement"
	FieldImage            = "image"
	FieldCPUs             = "cpus"
	FieldMemoryMiB        = "memory_mib"
	FieldDiskGiB          = "disk_gib"
	FieldWorkspaceGiB     = "workspace_gib"
	FieldMaxLifetimeHours = "max_lifetime_hours"
	FieldRetainHours      = "retain_hours"
	FieldEgressAllow      = "egress_allow"
	FieldEgressGroups     = "egress_groups"
	FieldEnv              = "env"
	FieldRegistryUsername = "registry_username"
	FieldRegistryPassword = "registry_password"
	FieldSecrets          = "secrets"
	FieldPrivateNames     = "private_names"
)

// Defaults for optional fields. The manifest schema has no `default`
// keyword, so the profile form shows these only in field descriptions.
const (
	DefaultDiskGiB      = 20
	DefaultWorkspaceGiB = 20
	DefaultRetainHours  = 24
)

// MaxLifetimeHours is the manifest's maximum_lifetime_seconds in hours.
// Bounded retention promises Kandev an expiry no later than this.
const MaxLifetimeHours = 168

// Field error codes. They reach Kandev as ExecutorProviderFieldError.Code.
const (
	CodeRequired   = "required"
	CodeInvalid    = "invalid"
	CodeOutOfRange = "out_of_range"
	CodeReserved   = "reserved"
	CodeDuplicate  = "duplicate"
	CodeUnpaired   = "unpaired"
	// CodeNoRegistry: a private image must name its registry host, which is
	// where the host scopes the pull credentials.
	CodeNoRegistry = "no_registry"
	// CodeNotInEgress: a private name must also be reachable through the
	// profile's own egress_allow; resolving is all a private name grants.
	CodeNotInEgress = "not_in_egress"
)

// FieldError is one rejected field. Message text is never carried: Kandev
// renders field errors itself.
type FieldError struct {
	Field string
	Code  string
}

// MessageID is the stable reference Kandev receives alongside the code.
func (e FieldError) MessageID() string {
	return "profile." + e.Field + "." + e.Code
}

// PlacementKind selects how a placement names its candidate hosts.
type PlacementKind string

const (
	PlacementLabel PlacementKind = "label"
	PlacementHost  PlacementKind = "host"
)

// Placement is `label:<label>` or `host:<name>`.
type Placement struct {
	Kind  PlacementKind
	Value string
}

func (p Placement) String() string { return string(p.Kind) + ":" + p.Value }

// EnvVar is one non-secret guest environment variable, in profile order.
type EnvVar struct {
	Name  string
	Value string
}

// Secret is a host-bound msb secret: the guest sees a placeholder, and the
// sandbox host substitutes Value into request headers bound for Hosts only.
type Secret struct {
	Name  string
	Value string
	Hosts []string
}

// Spec is a validated sandbox definition. It holds secret values, so it must
// never be logged, persisted, or put in resource state.
type Spec struct {
	Placement        Placement
	Image            string
	CPUs             int
	MemoryMiB        int
	DiskGiB          int
	WorkspaceGiB     int
	MaxLifetimeHours int
	RetainHours      int
	EgressAllow      []string
	// EgressGroups are names in the plugin's egress policy; whether they
	// exist is checked against that policy, not here.
	EgressGroups     []string
	Env              []EnvVar
	RegistryUsername string
	RegistryPassword string
	// SecretNames name secrets kept by the plugin, which supplies their
	// values and hosts; Secrets is filled from them at provision.
	SecretNames []string
	Secrets     []Secret
	// PrivateNames are exact hostnames this sandbox may resolve to a private
	// address (a LAN forge, say). The host turns DNS rebind protection off
	// for it and denies every other private destination instead. Each is
	// also in EgressAllow.
	PrivateNames []string
}

// NamePattern is the shape of a host name and a host label. Host names end
// up in resource state and in SSH routing, so they are kept to a narrow,
// unambiguous set.
var NamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// imagePattern accepts an OCI reference pinned by digest:
// [registry[:port]/]path[:tag]@sha256:<64 hex>. It cannot start with `/`,
// `.` or `~`: msb boots a host directory given as the image, so anything
// path-shaped is refused here as well as by msbctl.
var imagePattern = regexp.MustCompile(
	`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?` + // first component or registry host
		`(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*` + // path components
		`(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?` + // optional tag, ignored once pinned
		`@sha256:[a-f0-9]{64}$`)

// envNamePattern is msbctl's ENV_NAME: uppercase only, at most 64 bytes.
var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

var hostLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedEnv and reservedEnvPrefixes mirror msbctl's is_reserved_var() and
// KANDEV_RESERVED_NAMES/_PREFIXES, so a profile msbctl would refuse at
// provision is refused when it is saved instead. Kandev delivers agent and
// git credentials itself; secret values are put in the environment of the
// host's `msb` process, so nothing that changes how msb, the dynamic loader
// or a shell behaves may be named; AGENTCTL_ is how agentctl is configured.
var reservedEnv = map[string]bool{
	"GH_TOKEN": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
	"GITHUB_TOKEN": true, "ANTHROPIC_API_KEY": true, "ANTHROPIC_AUTH_TOKEN": true,
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TMPDIR": true, "PWD": true, "TERM": true, "LANG": true,
}

var reservedEnvPrefixes = []string{
	"CLAUDE_CODE_OAUTH_TOKEN_", "AGENTCTL_", "MSB_", "MSBCTL_", "LD_", "SSH_", "XDG_", "LC_",
}

// IsReservedEnv reports whether name is refused as a profile variable or
// secret binding.
func IsReservedEnv(name string) bool {
	upper := strings.ToUpper(name)
	if reservedEnv[upper] {
		return true
	}
	for _, prefix := range reservedEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

type intField struct {
	name     string
	required bool
	min, max int
	fallback int
	target   *int
}

// Parse validates config and secrets and returns the Spec. Every problem is
// reported, not just the first, so the profile form can mark them all.
// Placement is checked for shape only; whether it resolves to a host is the
// registry's question.
func Parse(config, secrets map[string]string) (Spec, []FieldError) {
	p := &parser{config: config, secrets: secrets}
	p.placement()
	p.image()
	p.sizes()
	p.egress()
	p.env()
	p.registry()
	p.names()
	return p.spec, p.errs
}

// parser is one Parse, field group by field group, in the order the
// problems are reported.
type parser struct {
	config, secrets map[string]string
	spec            Spec
	errs            []FieldError
}

func (p *parser) add(field, code string) {
	p.errs = append(p.errs, FieldError{Field: field, Code: code})
}

func (p *parser) value(field string) string { return value(p.config, field) }

func (p *parser) placement() {
	if placement, code := parsePlacement(p.value(FieldPlacement)); code != "" {
		p.add(FieldPlacement, code)
	} else {
		p.spec.Placement = placement
	}
}

func (p *parser) image() {
	switch image := p.value(FieldImage); {
	case image == "":
		p.add(FieldImage, CodeRequired)
	case !imagePattern.MatchString(image):
		p.add(FieldImage, CodeInvalid)
	default:
		p.spec.Image = image
	}
}

func (p *parser) sizes() {
	for _, f := range []intField{
		{FieldCPUs, true, 1, 16, 0, &p.spec.CPUs},
		{FieldMemoryMiB, true, 512, 65536, 0, &p.spec.MemoryMiB},
		{FieldDiskGiB, false, 5, 500, DefaultDiskGiB, &p.spec.DiskGiB},
		{FieldWorkspaceGiB, false, 1, 500, DefaultWorkspaceGiB, &p.spec.WorkspaceGiB},
		{FieldMaxLifetimeHours, true, 1, MaxLifetimeHours, 0, &p.spec.MaxLifetimeHours},
		{FieldRetainHours, false, 0, MaxLifetimeHours, DefaultRetainHours, &p.spec.RetainHours},
	} {
		if code := parseInt(p.config, f); code != "" {
			p.add(f.name, code)
		}
	}
}

func (p *parser) egress() {
	if entries, err := egress.ParseList(p.value(FieldEgressAllow)); err == nil && egress.CheckList(entries) == nil {
		p.spec.EgressAllow = entries
	} else {
		p.add(FieldEgressAllow, CodeInvalid)
	}
	if groups, ok := parseNames(p.value(FieldEgressGroups)); ok {
		p.spec.EgressGroups = groups
	} else {
		p.add(FieldEgressGroups, CodeInvalid)
	}
}

func (p *parser) env() {
	env, errs := parseEnv(p.value(FieldEnv))
	p.spec.Env = env
	p.errs = append(p.errs, errs...)
}

// registry reads the image registry login: both halves or neither, and only
// for an image that names its registry.
func (p *parser) registry() {
	p.spec.RegistryUsername = p.value(FieldRegistryUsername)
	p.spec.RegistryPassword = p.secrets[FieldRegistryPassword]
	switch {
	case p.spec.RegistryUsername == "" && p.spec.RegistryPassword != "":
		p.add(FieldRegistryUsername, CodeUnpaired)
	case p.spec.RegistryUsername != "" && p.spec.RegistryPassword == "":
		p.add(FieldRegistryPassword, CodeUnpaired)
	}
	if p.spec.RegistryUsername != "" && p.spec.Image != "" && !namesRegistry(p.spec.Image) {
		p.add(FieldImage, CodeNoRegistry)
	}
}

// names reads the secrets and private names a profile asks for.
func (p *parser) names() {
	taken := make(map[string]bool, len(p.spec.Env))
	for _, item := range p.spec.Env {
		taken[strings.ToUpper(item.Name)] = true
	}
	names, code := parseSecretNames(p.value(FieldSecrets), taken)
	if code != "" {
		p.add(FieldSecrets, code)
	}
	p.spec.SecretNames = names

	private, code := parsePrivateNames(p.value(FieldPrivateNames), p.spec.EgressAllow)
	if code != "" {
		p.add(FieldPrivateNames, code)
	}
	p.spec.PrivateNames = private
}

// parsePrivateNames reads the comma-separated hostnames a profile asks to
// resolve privately: exact names, no wildcard, port or address, each the host
// of one of the profile's egress_allow entries (msbctl's own rule). Whether a
// host allows them is the registry's question, not this package's.
func parsePrivateNames(raw string, egressAllow []string) ([]string, string) {
	hosts := make(map[string]bool, len(egressAllow))
	for _, entry := range egressAllow {
		host, _, _ := strings.Cut(entry, ":")
		hosts[host] = true
	}
	var out []string
	for _, item := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if strings.Contains(name, ":") || !validHostEntry(name, false) {
			return nil, CodeInvalid
		}
		if !hosts[name] {
			return nil, CodeNotInEgress
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, ""
}

// parseSecretNames reads the comma-separated secret names a profile uses.
// A name an env entry already sets is a duplicate: both would be the same
// variable in the guest.
func parseSecretNames(raw string, taken map[string]bool) ([]string, string) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		name := strings.TrimSpace(item)
		if name == "" {
			continue
		}
		if code := CheckSecretName(name); code != "" {
			return nil, code
		}
		if taken[name] {
			return nil, CodeDuplicate
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, ""
}

// CheckSecretName returns the code for a secret's name, "" when usable: the
// guest sees it as an environment variable.
func CheckSecretName(name string) string {
	switch {
	case name == "":
		return CodeRequired
	case !envNamePattern.MatchString(name):
		return CodeInvalid
	case IsReservedEnv(name):
		return CodeReserved
	}
	return ""
}

// ParseSecretHosts reads the hosts a secret may be sent to: host or
// host:port, no wildcards, at least one.
func ParseSecretHosts(raw string) ([]string, bool) {
	hosts, ok := parseHostList(raw, false)
	return hosts, ok && len(hosts) > 0
}

func value(config map[string]string, field string) string {
	return strings.TrimSpace(config[field])
}

func parsePlacement(raw string) (Placement, string) {
	if raw == "" {
		return Placement{}, CodeRequired
	}
	kind, name, found := strings.Cut(raw, ":")
	if !found || !NamePattern.MatchString(name) {
		return Placement{}, CodeInvalid
	}
	switch PlacementKind(kind) {
	case PlacementLabel, PlacementHost:
		return Placement{Kind: PlacementKind(kind), Value: name}, ""
	default:
		return Placement{}, CodeInvalid
	}
}

func parseInt(config map[string]string, f intField) string {
	raw := value(config, f.name)
	if raw == "" {
		if f.required {
			return CodeRequired
		}
		*f.target = f.fallback
		return ""
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return CodeInvalid
	}
	if parsed < f.min || parsed > f.max {
		return CodeOutOfRange
	}
	*f.target = parsed
	return ""
}

// namesRegistry reports whether an image reference starts with a registry
// host, by the same rule as msbctl's kandev_registry(): a first path
// component with a dot or a port, or `localhost`.
func namesRegistry(image string) bool {
	first, rest, found := strings.Cut(image, "/")
	return found && rest != "" && (strings.ContainsAny(first, ".:") || first == "localhost")
}

// parseHostList splits a comma-separated list of `host` or `host:port`
// entries. Egress rules are hostname-based on the sandbox host, so IP
// literals and URLs are refused. A leading `*.` wildcard is accepted for
// egress only. An empty list is valid.
func parseHostList(raw string, allowWildcard bool) ([]string, bool) {
	if raw == "" {
		return nil, true
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		entry := strings.ToLower(strings.TrimSpace(item))
		if entry == "" {
			continue
		}
		if !validHostEntry(entry, allowWildcard) {
			return nil, false
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out, true
}

func validHostEntry(entry string, allowWildcard bool) bool {
	host, port, hasPort := strings.Cut(entry, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if allowWildcard {
		host = strings.TrimPrefix(host, "*.")
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	// An all-numeric last label means an IP literal, not a hostname, and
	// msbctl's HOSTNAME wants a last label of at least two characters.
	last := labels[len(labels)-1]
	_, numeric := strconv.Atoi(last)
	return numeric != nil && len(last) >= 2
}

// parseEnv reads `KEY=VALUE;KEY2=VALUE2`. Values cannot contain `;`.
func parseEnv(raw string) ([]EnvVar, []FieldError) {
	if raw == "" {
		return nil, nil
	}
	var out []EnvVar
	var errs []FieldError
	seen := map[string]bool{}
	for _, item := range strings.Split(raw, ";") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		name, val, found := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		switch {
		case !found || !envNamePattern.MatchString(name):
			errs = append(errs, FieldError{Field: FieldEnv, Code: CodeInvalid})
		case IsReservedEnv(name):
			errs = append(errs, FieldError{Field: FieldEnv, Code: CodeReserved})
		case seen[strings.ToUpper(name)]:
			errs = append(errs, FieldError{Field: FieldEnv, Code: CodeDuplicate})
		default:
			seen[strings.ToUpper(name)] = true
			out = append(out, EnvVar{Name: name, Value: val})
		}
	}
	return out, dedupe(errs)
}

func dedupe(errs []FieldError) []FieldError {
	if len(errs) < 2 {
		return errs
	}
	seen := map[FieldError]bool{}
	out := errs[:0]
	for _, e := range errs {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// parseNames splits a comma-separated list of egress group names.
func parseNames(raw string) ([]string, bool) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if !egress.ValidName(name) {
			return nil, false
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, true
}
