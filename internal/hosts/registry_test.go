package hosts

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/profile"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0lGH0Mvc2PwPW7y5mHLUVHMwBNN1k6d0jP2iTgNPg"

func sampleHost(name string, labels ...string) Host {
	return Host{
		Name: name, SSH: "msb@" + name + ".tailnet.ts.net", HostKey: testKey,
		BaseURL: "https://" + name + ".tailnet.ts.net", Labels: labels,
	}
}

func fieldsOf(t *testing.T, err error) []string {
	t.Helper()
	var v *ValidationError
	require.True(t, errors.As(err, &v), "want a ValidationError, got %v", err)
	out := make([]string, len(v.Fields))
	for i, f := range v.Fields {
		out[i] = f.Field
	}
	return out
}

func TestAddNormalizesAndSorts(t *testing.T) {
	r, err := Registry{}.Add(Host{
		Name: " sbx-02 ", SSH: "msb@sbx-02", HostKey: "  " + testKey + "  comment ",
		BaseURL: "https://sbx-02.tailnet.ts.net/", Labels: []string{"Default", "big-mem", "default", ""},
	})
	require.NoError(t, err)
	r, err = r.Add(sampleHost("sbx-01"))
	require.NoError(t, err)

	require.Len(t, r.Hosts, 2)
	assert.Equal(t, RegistryVersion, r.Version)
	assert.Equal(t, "sbx-01", r.Hosts[0].Name)
	h := r.Hosts[1]
	assert.Equal(t, "sbx-02", h.Name)
	assert.Equal(t, testKey+" comment", h.HostKey)
	assert.Equal(t, "https://sbx-02.tailnet.ts.net", h.BaseURL)
	assert.Equal(t, []string{"big-mem", "default"}, h.Labels)
}

func TestAddRefusesDuplicateAndTooMany(t *testing.T) {
	r, err := Registry{}.Add(sampleHost("sbx-01"))
	require.NoError(t, err)
	_, err = r.Add(sampleHost("sbx-01"))
	assert.ErrorIs(t, err, ErrExists)

	full := Registry{}
	for i := 0; i < MaxHosts; i++ {
		full.Hosts = append(full.Hosts, sampleHost("h"+string(rune('a'+i/26))+string(rune('a'+i%26))))
	}
	_, err = full.Add(sampleHost("zz"))
	assert.ErrorIs(t, err, ErrTooMany)
}

func TestValidateReportsEachBadField(t *testing.T) {
	err := Validate(Normalize(Host{
		Name: "Bad Name", SSH: "sbx-01", HostKey: "not a key", BaseURL: "http://sbx-01",
	}))
	assert.Equal(t, []string{"name", "ssh", "host_key", "base_url"}, fieldsOf(t, err))
}

func TestValidateBaseURL(t *testing.T) {
	for _, ok := range []string{"https://sbx-01.tailnet.ts.net", "https://100.64.0.7", "https://10.0.0.5:8443"} {
		assert.NoError(t, validateBaseURL(ok), ok)
	}
	for _, bad := range []string{
		"http://sbx-01.tailnet.ts.net",
		"https://user:pw@sbx-01.tailnet.ts.net",
		"https://sbx-01.tailnet.ts.net?x=1",
		"https://sbx-01.tailnet.ts.net#frag",
		"https://sbx-01.tailnet.ts.net/vm",
		"https://127.0.0.1",
		"https://localhost",
		"https://169.254.1.1",
		"https://[::1]",
		"https://0.0.0.0",
		"sbx-01.tailnet.ts.net",
	} {
		assert.Error(t, validateBaseURL(bad), bad)
	}
}

func TestParseSSH(t *testing.T) {
	cases := map[string]struct {
		user, host string
		port       int
	}{
		"msb@sbx-01":              {"msb", "sbx-01", 22},
		"msb@sbx-01.ts.net:2222":  {"msb", "sbx-01.ts.net", 2222},
		"msb@100.64.0.7":          {"msb", "100.64.0.7", 22},
		"msb@[fd7a:115c::1]:2200": {"msb", "fd7a:115c::1", 2200},
		"msb@[fd7a:115c::1]":      {"msb", "fd7a:115c::1", 22},
	}
	for dest, want := range cases {
		user, host, port, err := ParseSSH(dest)
		require.NoError(t, err, dest)
		assert.Equal(t, want.user, user, dest)
		assert.Equal(t, want.host, host, dest)
		assert.Equal(t, want.port, port, dest)
	}
	for _, bad := range []string{"sbx-01", "@sbx-01", "msb@", "msb@sbx-01:0", "msb@sbx-01:x", "a b@sbx-01", "msb@a/b"} {
		_, _, _, err := ParseSSH(bad)
		assert.Error(t, err, bad)
	}
}

func TestUpdateKeepsDrainingAndRefusesUnknown(t *testing.T) {
	r, err := Registry{}.Add(sampleHost("sbx-01", "default"))
	require.NoError(t, err)
	r, err = r.SetDraining("sbx-01", true)
	require.NoError(t, err)

	changed := sampleHost("sbx-01", "gpu")
	changed.Draining = false
	r, err = r.Update(changed)
	require.NoError(t, err)
	h, _ := r.Find("sbx-01")
	assert.True(t, h.Draining)
	assert.Equal(t, []string{"gpu"}, h.Labels)

	_, err = r.Update(sampleHost("sbx-99"))
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = r.SetDraining("sbx-99", true)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMutationsDoNotAlias(t *testing.T) {
	r, err := Registry{}.Add(sampleHost("sbx-01", "default"))
	require.NoError(t, err)
	drained, err := r.SetDraining("sbx-01", true)
	require.NoError(t, err)
	assert.False(t, r.Hosts[0].Draining)
	assert.True(t, drained.Hosts[0].Draining)

	removed, err := r.Remove("sbx-01")
	require.NoError(t, err)
	assert.Empty(t, removed.Hosts)
	assert.Len(t, r.Hosts, 1)
}

func TestCandidatesSkipDraining(t *testing.T) {
	r := Registry{Hosts: []Host{
		sampleHost("a", "default"),
		sampleHost("b", "default", "gpu"),
		sampleHost("c", "gpu"),
	}}
	r.Hosts[1].Draining = true

	names := func(hs []Host) []string {
		var out []string
		for _, h := range hs {
			out = append(out, h.Name)
		}
		return out
	}
	assert.Equal(t, []string{"a"}, names(r.Candidates(profile.Placement{Kind: profile.PlacementLabel, Value: "default"})))
	assert.Equal(t, []string{"c"}, names(r.Candidates(profile.Placement{Kind: profile.PlacementLabel, Value: "gpu"})))
	assert.Empty(t, r.Candidates(profile.Placement{Kind: profile.PlacementHost, Value: "b"}))
	assert.Equal(t, []string{"c"}, names(r.Candidates(profile.Placement{Kind: profile.PlacementHost, Value: "c"})))
}

func TestCheckRejectsNewerVersionAndCorruptEntries(t *testing.T) {
	assert.ErrorIs(t, Registry{Version: RegistryVersion + 1}.Check(), ErrVersion)
	assert.ErrorIs(t, Registry{Version: 1, Hosts: []Host{sampleHost("a"), sampleHost("a")}}.Check(), ErrExists)
	bad := sampleHost("a")
	bad.BaseURL = "http://a"
	assert.Error(t, Registry{Version: 1, Hosts: []Host{bad}}.Check())
	assert.NoError(t, Registry{}.Check())
}
