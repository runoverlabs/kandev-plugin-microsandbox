// Package egress is the plugin's central egress policy: named groups of
// allowed destinations, a set of groups every sandbox gets, and the entry
// grammar both groups and profiles use.
//
// An entry is sent to msbctl as one `egress_allow` target, which msbctl turns
// into an msb net rule and checks against the host's `[kandev] allow_extra`.
// The grammar is a strict subset of what msbctl accepts, so an entry the
// plugin admits is never refused for its shape:
//
//	api.openai.com         a name, HTTPS on 443
//	*.example.com          every name below example.com, HTTPS on 443
//	llm.lan:8080           a name and one TCP port
//	192.168.2.6:8788       an IPv4 address and one TCP port
//	192.168.2.6            an IPv4 address, HTTPS on 443
//	[fd00::5]:8080         an IPv6 address and one TCP port
//
// No ranges, CIDRs, protocols or full rules: per-port precision is the point.
package egress

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Limits. MaxEntries bounds what one sandbox gets after expansion, so a
// provision header stays small and msb's rule list stays readable.
const (
	MaxEntries       = 64
	MaxGroups        = 32
	MaxGroupEntries  = 32
	MaxDescription   = 200
	PolicyVersion    = 1
	maxNameLength    = 40
	wildcardPrefix   = "*."
	defaultHTTPSPort = 443
)

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Errors for entries and policies. Their text is the plugin's own, safe to
// show an admin.
var (
	ErrEntry   = errors.New("invalid egress entry")
	ErrPolicy  = errors.New("invalid egress policy")
	ErrUnknown = errors.New("unknown egress group")
)

// ParseEntry validates and normalizes one entry (lowercase, no default port).
func ParseEntry(raw string) (string, error) {
	entry := strings.ToLower(strings.TrimSpace(raw))
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%w %q: %s", ErrEntry, raw, why)
	}
	if entry == "" {
		return bad("empty")
	}
	if strings.ContainsAny(entry, "@/ ") {
		return bad("give a host, host:port or address:port, not a rule or a range")
	}
	host, port, err := splitHostPort(entry)
	if err != nil {
		return bad(err.Error())
	}
	if addr, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr == nil {
		if why := addressProblem(addr); why != "" {
			return bad(why)
		}
		if addr.Is6() && !strings.HasPrefix(host, "[") {
			return bad("an IPv6 address goes in brackets, like [fd00::1]:8080")
		}
		return join(host, port), nil
	}
	if strings.HasPrefix(host, "[") {
		return bad("only an IPv6 address goes in brackets")
	}
	wildcard := strings.HasPrefix(host, wildcardPrefix)
	if wildcard && port != 0 && port != defaultHTTPSPort {
		return bad("a wildcard is matched on HTTPS only, so it takes no other port")
	}
	if !validName(strings.TrimPrefix(host, wildcardPrefix)) {
		return bad("expected a hostname such as api.example.com")
	}
	if port == defaultHTTPSPort {
		port = 0
	}
	return join(host, port), nil
}

// ParseList reads a comma-separated list, normalized and deduplicated.
func ParseList(raw string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		entry, err := ParseEntry(item)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, entry) {
			out = append(out, entry)
		}
	}
	return out, nil
}

func splitHostPort(entry string) (string, int, error) {
	host, rawPort := entry, ""
	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		if end < 0 {
			return "", 0, errors.New("unclosed bracket")
		}
		host, rawPort = entry[:end+1], strings.TrimPrefix(entry[end+1:], ":")
		if rawPort == "" && len(entry) > end+1 {
			return "", 0, errors.New("expected :port after the address")
		}
	} else if i := strings.LastIndex(entry, ":"); i >= 0 {
		if strings.Count(entry, ":") > 1 {
			return "", 0, errors.New("an IPv6 address goes in brackets, like [fd00::1]:8080")
		}
		host, rawPort = entry[:i], entry[i+1:]
	}
	if rawPort == "" {
		return host, 0, nil
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return "", 0, errors.New("the port is a number from 1 to 65535")
	}
	return host, port, nil
}

func addressProblem(addr netip.Addr) string {
	switch {
	case addr.IsUnspecified():
		return "the unspecified address reaches nothing"
	case addr.IsLoopback():
		return "a loopback address is the sandbox itself"
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return "link-local addresses are refused (they include cloud metadata services)"
	case addr.IsMulticast():
		return "multicast addresses are refused"
	}
	return ""
}

func validName(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return false
		}
	}
	// msbctl's HOSTNAME wants a last label of two characters or more, and an
	// all-numeric one is an address, which ParseAddr already took.
	last := labels[len(labels)-1]
	_, numeric := strconv.Atoi(last)
	return numeric != nil && len(last) >= 2
}

func join(host string, port int) string {
	if port == 0 {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}

// Group is a named set of entries. Built-in groups ship with the plugin and
// cannot be edited; the rest are the admin's.
type Group struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Entries     []string `json:"entries"`
	Builtin     bool     `json:"builtin,omitempty"`
}

// Builtin groups: the API endpoints of common model providers and harnesses.
// Only hosts their clients call for inference or model listing, never a
// whole vendor domain.
var Builtin = []Group{
	{Name: "anthropic", Description: "Anthropic API", Entries: []string{"api.anthropic.com"}},
	{Name: "deepseek", Description: "DeepSeek API", Entries: []string{"api.deepseek.com"}},
	{Name: "google-ai", Description: "Google Gemini API", Entries: []string{"generativelanguage.googleapis.com"}},
	{Name: "groq", Description: "Groq API", Entries: []string{"api.groq.com"}},
	{Name: "mistral", Description: "Mistral API", Entries: []string{"api.mistral.ai"}},
	{Name: "openai", Description: "OpenAI API", Entries: []string{"api.openai.com"}},
	{Name: "opencode", Description: "opencode: its config schema and the models.dev catalog", Entries: []string{"opencode.ai", "models.dev"}},
	{Name: "openrouter", Description: "OpenRouter API", Entries: []string{"openrouter.ai"}},
	{Name: "xai", Description: "xAI API", Entries: []string{"api.x.ai"}},
}

func init() {
	for i := range Builtin {
		Builtin[i].Builtin = true
	}
}

// Policy is the plugin-wide egress configuration, kept in Host state.
type Policy struct {
	Version int     `json:"version"`
	Groups  []Group `json:"groups"`
	// Defaults are group names every sandbox gets, before its profile's own.
	Defaults []string `json:"defaults"`
}

// ValidName reports whether name can name a group.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Lookup finds a group by name, built-in groups first.
func (p Policy) Lookup(name string) (Group, bool) {
	for _, g := range Builtin {
		if g.Name == name {
			return g, true
		}
	}
	for _, g := range p.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// All lists built-in groups, then the admin's, each in name order.
func (p Policy) All() []Group {
	custom := slices.Clone(p.Groups)
	slices.SortFunc(custom, func(a, b Group) int { return strings.Compare(a.Name, b.Name) })
	return append(slices.Clone(Builtin), custom...)
}

// CheckGroup validates and normalizes a custom group.
func CheckGroup(g Group) (Group, error) {
	if !ValidName(g.Name) {
		return Group{}, fmt.Errorf("%w: a group name is lowercase letters, digits and dashes, up to %d", ErrPolicy, maxNameLength)
	}
	for _, b := range Builtin {
		if b.Name == g.Name {
			return Group{}, fmt.Errorf("%w: %q is a built-in group", ErrPolicy, g.Name)
		}
	}
	if len(g.Description) > MaxDescription {
		return Group{}, fmt.Errorf("%w: the description is at most %d characters", ErrPolicy, MaxDescription)
	}
	if len(g.Entries) == 0 || len(g.Entries) > MaxGroupEntries {
		return Group{}, fmt.Errorf("%w: a group has 1 to %d entries", ErrPolicy, MaxGroupEntries)
	}
	var entries []string
	for _, raw := range g.Entries {
		entry, err := ParseEntry(raw)
		if err != nil {
			return Group{}, err
		}
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	return Group{Name: g.Name, Description: strings.TrimSpace(g.Description), Entries: entries}, nil
}

// Check validates a whole policy, as loaded from state.
func (p Policy) Check() error {
	if p.Version != PolicyVersion {
		return fmt.Errorf("%w: version %d", ErrPolicy, p.Version)
	}
	if len(p.Groups) > MaxGroups {
		return fmt.Errorf("%w: at most %d groups", ErrPolicy, MaxGroups)
	}
	seen := map[string]bool{}
	for _, g := range p.Groups {
		if _, err := CheckGroup(g); err != nil {
			return err
		}
		if seen[g.Name] {
			return fmt.Errorf("%w: group %q twice", ErrPolicy, g.Name)
		}
		seen[g.Name] = true
	}
	for _, name := range p.Defaults {
		if _, ok := p.Lookup(name); !ok {
			return fmt.Errorf("%w: default %q", ErrUnknown, name)
		}
	}
	return nil
}

// Expand returns the entries a sandbox gets: the defaults' groups, then the
// named groups, then extra, deduplicated in that order. An unknown group name
// is ErrUnknown; more than MaxEntries is ErrPolicy.
func (p Policy) Expand(groups, extra []string) ([]string, error) {
	var out []string
	add := func(entries []string) {
		for _, e := range entries {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	for _, name := range append(slices.Clone(p.Defaults), groups...) {
		g, ok := p.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknown, name)
		}
		add(g.Entries)
	}
	add(extra)
	if len(out) > MaxEntries {
		return nil, fmt.Errorf("%w: %d entries after expansion, at most %d", ErrPolicy, len(out), MaxEntries)
	}
	return out, nil
}

// Refused returns the entries a host's allow_extra would refuse. allowExtra
// uses msbctl's patterns: "*", a hostname, "*.suffix", an address, an
// address:port, or a CIDR (feature request F21). A hostname pattern covers a
// name on any port, as msbctl matches on the host part alone.
func Refused(entries, allowExtra []string) []string {
	var out []string
	for _, e := range entries {
		if !covered(e, allowExtra) {
			out = append(out, e)
		}
	}
	return out
}

func covered(entry string, patterns []string) bool {
	host, port, _ := splitHostPort(entry)
	addr, addrErr := netip.ParseAddr(strings.Trim(host, "[]"))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "*":
			return true
		case addrErr == nil:
			if addressCovered(addr, port, p) {
				return true
			}
		case p == host:
			return true
		case strings.HasPrefix(p, wildcardPrefix) && strings.HasSuffix(host, p[1:]):
			return true
		}
	}
	return false
}

func addressCovered(addr netip.Addr, port int, pattern string) bool {
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		return prefix.Contains(addr)
	}
	pHost, pPort, err := splitHostPort(pattern)
	if err != nil {
		return false
	}
	pAddr, err := netip.ParseAddr(strings.Trim(pHost, "[]"))
	if err != nil || pAddr != addr {
		return false
	}
	if port == 0 {
		port = defaultHTTPSPort
	}
	return pPort == 0 || pPort == port
}
