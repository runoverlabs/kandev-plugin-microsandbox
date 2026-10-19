package egress

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEntryNormalizes(t *testing.T) {
	for raw, want := range map[string]string{
		" API.OpenAI.com ":   "api.openai.com",
		"api.openai.com:443": "api.openai.com",
		"llm.lan:8080":       "llm.lan:8080",
		"*.Example.com":      "*.example.com",
		"*.example.com:443":  "*.example.com",
		"192.168.2.6:8788":   "192.168.2.6:8788",
		"192.168.2.6":        "192.168.2.6",
		"[fd00::5]:8080":     "[fd00::5]:8080",
		"100.64.0.7:11434":   "100.64.0.7:11434",
	} {
		got, err := ParseEntry(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
}

func TestParseEntryRefuses(t *testing.T) {
	for _, raw := range []string{
		"", "allow@api.openai.com:tcp:443", "10.0.0.0/8", "localhost", "lan",
		"api.openai.com:0", "api.openai.com:65536", "api.openai.com:08", "api.openai.com:tcp:443",
		"*.example.com:8080", "*.*.example.com", "fd00::5", "[fd00::5", "[api.example.com]:80",
		"127.0.0.1:8080", "0.0.0.0:80", "169.254.169.254", "[::1]:22", "[fe80::1]:22", "224.0.0.1:5353",
		"exa mple.com", "-bad.example.com", "example.c",
	} {
		_, err := ParseEntry(raw)
		assert.ErrorIs(t, err, ErrEntry, raw)
	}
}

func TestParseList(t *testing.T) {
	got, err := ParseList(" pypi.org, files.pythonhosted.org:443,*.example.com,PyPI.org ,, 192.168.2.6:8788")
	require.NoError(t, err)
	assert.Equal(t, []string{"pypi.org", "files.pythonhosted.org", "*.example.com", "192.168.2.6:8788"}, got)
	_, err = ParseList("pypi.org, 127.0.0.1:80")
	assert.ErrorIs(t, err, ErrEntry)
}

func TestBuiltinGroupsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range Builtin {
		assert.True(t, g.Builtin, g.Name)
		assert.True(t, ValidName(g.Name), g.Name)
		assert.False(t, seen[g.Name], g.Name)
		seen[g.Name] = true
		for _, e := range g.Entries {
			got, err := ParseEntry(e)
			require.NoError(t, err, e)
			assert.Equal(t, e, got, "built-in entries are already normalized")
		}
	}
}

func TestCheckGroup(t *testing.T) {
	g, err := CheckGroup(Group{Name: "lan-llm", Description: " FreeToken ", Entries: []string{"192.168.2.6:8788", "192.168.2.6:8788"}})
	require.NoError(t, err)
	assert.Equal(t, Group{Name: "lan-llm", Description: "FreeToken", Entries: []string{"192.168.2.6:8788"}}, g)

	for _, bad := range []Group{
		{Name: "openai", Entries: []string{"x.example.com"}},
		{Name: "Bad_Name", Entries: []string{"x.example.com"}},
		{Name: "empty"},
		{Name: "long", Description: strings.Repeat("x", MaxDescription+1), Entries: []string{"x.example.com"}},
	} {
		_, err := CheckGroup(bad)
		assert.ErrorIs(t, err, ErrPolicy, bad.Name)
	}
	_, err = CheckGroup(Group{Name: "bad-entry", Entries: []string{"127.0.0.1:1"}})
	assert.ErrorIs(t, err, ErrEntry)
}

func TestExpandOrdersAndDeduplicates(t *testing.T) {
	p := Policy{Version: PolicyVersion,
		Groups:   []Group{{Name: "lan-llm", Entries: []string{"192.168.2.6:8788"}}},
		Defaults: []string{"lan-llm", "openrouter"}}
	require.NoError(t, p.Check())
	got, err := p.Expand([]string{"opencode", "openrouter"}, []string{"pypi.org", "openrouter.ai"})
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.2.6:8788", "openrouter.ai", "opencode.ai", "models.dev", "pypi.org"}, got)

	_, err = p.Expand([]string{"nope"}, nil)
	assert.ErrorIs(t, err, ErrUnknown)
}

func TestExpandIsBoundedByTheHeaderBudget(t *testing.T) {
	entries := func(prefix string, n int) []string {
		var out []string
		for j := range n {
			out = append(out, prefix+strconv.Itoa(j)+".example.com")
		}
		return out
	}
	// Each entry is about 20 bytes encoded: 1000 fit in a group, two such
	// groups do not fit in one sandbox's list.
	a, b := Group{Name: "ga", Entries: entries("a", 1000)}, Group{Name: "gb", Entries: entries("b", 1000)}
	p := Policy{Version: PolicyVersion, Groups: []Group{a, b}}
	require.NoError(t, p.Check(), "far more than the old 32 entries is fine")
	_, err := p.Expand([]string{"ga"}, nil)
	require.NoError(t, err)
	_, err = p.Expand([]string{"ga", "gb"}, nil)
	assert.ErrorIs(t, err, ErrPolicy)

	assert.ErrorIs(t, Policy{Version: PolicyVersion, Groups: []Group{a, b}, Defaults: []string{"ga", "gb"}}.Check(), ErrPolicy,
		"defaults every sandbox gets must fit on their own")
	_, err = CheckGroup(Group{Name: "huge", Entries: entries("c", 2000)})
	assert.ErrorIs(t, err, ErrPolicy)
}

func TestPolicyCheck(t *testing.T) {
	assert.NoError(t, Policy{Version: PolicyVersion}.Check())
	assert.ErrorIs(t, Policy{Version: 2}.Check(), ErrPolicy)
	assert.ErrorIs(t, Policy{Version: PolicyVersion, Defaults: []string{"nope"}}.Check(), ErrUnknown)
	dup := Group{Name: "x", Entries: []string{"x.example.com"}}
	assert.ErrorIs(t, Policy{Version: PolicyVersion, Groups: []Group{dup, dup}}.Check(), ErrPolicy)
}

func TestRefusedMirrorsAllowExtra(t *testing.T) {
	entries := []string{"api.openai.com", "pypi.org:8443", "x.models.dev", "192.168.2.6:8788", "192.168.2.6", "[fd00::5]:8080"}
	assert.Empty(t, Refused(entries, []string{"*"}))
	assert.Equal(t, entries, Refused(entries, nil))
	assert.Equal(t, []string{"192.168.2.6", "[fd00::5]:8080"},
		Refused(entries, []string{"api.openai.com", "pypi.org", "*.models.dev", "192.168.2.6:8788"}),
		"a name covers any port; an address:port covers that port only")
	assert.Equal(t, []string{"api.openai.com", "pypi.org:8443", "x.models.dev"},
		Refused(entries, []string{"192.168.2.0/24", "fd00::/8"}))
	assert.Empty(t, Refused([]string{"192.168.2.6"}, []string{"192.168.2.6:443"}), "no port means HTTPS")
	assert.Empty(t, Refused([]string{"[fd00::5]:8080"}, []string{"fd00::5"}), "msbctl takes a bare IPv6 address")
	assert.Empty(t, Refused([]string{"[fd00::5]:8080"}, []string{"[fd00::5]"}))
	assert.Equal(t, []string{"192.168.2.6:8788"}, Refused([]string{"192.168.2.6:8788"}, []string{"192.168.2.6:8789"}))
	assert.Equal(t, []string{"192.168.2.6"}, Refused([]string{"192.168.2.6"}, []string{"*.168.2.6", "192.168.2.6.example.com"}),
		"a hostname pattern never covers an address")
}
