package plugin

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

func groupNames(body map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, g := range body["groups"].([]any) {
		group := g.(map[string]any)
		out[group["name"].(string)] = group
	}
	return out
}

func TestEgressListShowsBuiltinGroups(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	status, body := call(t, r, ActionEgressList, map[string]any{})
	require.Equal(t, 200, status)
	groups := groupNames(body)
	require.Contains(t, groups, "openrouter")
	assert.Equal(t, true, groups["openrouter"]["builtin"])
	assert.Equal(t, false, groups["openrouter"]["default"])
	assert.Equal(t, []any{}, body["defaults"])
}

func TestEgressPutValidatesAndNormalizes(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	status, body := call(t, r, ActionEgressPut, map[string]any{
		"name": "lan-llm", "description": "FreeToken", "entries": []string{"192.168.2.6:8788", "LLM.lan:443"},
	})
	require.Equal(t, 201, status)
	assert.Equal(t, []any{"192.168.2.6:8788", "llm.lan"}, groupNames(body)["lan-llm"]["entries"])

	status, _ = call(t, r, ActionEgressPut, map[string]any{"name": "lan-llm", "entries": []string{"192.168.2.6:8789"}})
	assert.Equal(t, 200, status, "an existing group is replaced")

	for _, bad := range []map[string]any{
		{"name": "openai", "entries": []string{"x.example.com"}},
		{"name": "meta", "entries": []string{"169.254.169.254"}},
		{"name": "loop", "entries": []string{"127.0.0.1:8080"}},
		{"name": "range", "entries": []string{"10.0.0.0/8"}},
		{"name": "Bad Name", "entries": []string{"x.example.com"}},
		{"name": "none", "entries": []string{}},
		{"name": "x", "entries": []string{"x.example.com"}, "builtin": true},
	} {
		status, _ := call(t, r, ActionEgressPut, bad)
		assert.Equal(t, 422, status, bad["name"])
	}
}

func TestEgressDefaultsAndRemove(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	require.Equal(t, 201, first(call(t, r, ActionEgressPut, map[string]any{"name": "lan-llm", "entries": []string{"192.168.2.6:8788"}})))

	status, body := call(t, r, ActionEgressDefaults, map[string]any{"groups": []string{"lan-llm", "openrouter", "lan-llm"}})
	require.Equal(t, 200, status)
	assert.Equal(t, []any{"lan-llm", "openrouter"}, body["defaults"])
	assert.Equal(t, true, groupNames(body)["lan-llm"]["default"])

	assert.Equal(t, 422, first(call(t, r, ActionEgressDefaults, map[string]any{"groups": []string{"nope"}})))
	assert.Equal(t, 422, first(call(t, r, ActionEgressRemove, map[string]any{"name": "openrouter"})), "built-ins stay")
	assert.Equal(t, 404, first(call(t, r, ActionEgressRemove, map[string]any{"name": "nope"})))

	status, body = call(t, r, ActionEgressRemove, map[string]any{"name": "lan-llm"})
	require.Equal(t, 200, status)
	assert.Equal(t, []any{"openrouter"}, body["defaults"], "a removed group leaves the defaults")
	assert.NotContains(t, groupNames(body), "lan-llm")
}

func TestValidateChecksEgressGroupsAgainstThePolicy(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey, "default"))))
	config := profileConfig("label:default")
	config["egress_groups"] = "lan-llm, openrouter"
	res := validate(t, r, config, nil)
	assert.Equal(t, map[string]string{"egress_groups": CodeUnresolved}, fieldCodes(res))
	assert.Equal(t, "profile.egress_groups.unresolved", res.FieldErrors[0].MessageId)

	require.Equal(t, 201, first(call(t, r, ActionEgressPut, map[string]any{"name": "lan-llm", "entries": []string{"192.168.2.6:8788"}})))
	assert.Empty(t, validate(t, r, config, nil).FieldErrors)
}

func TestProvisionSendsDefaultsThenProfileEgress(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	require.Equal(t, 201, first(call(t, f.r, ActionEgressPut, map[string]any{"name": "lan-llm", "entries": []string{"192.168.2.6:8788"}})))
	require.Equal(t, 200, first(call(t, f.r, ActionEgressDefaults, map[string]any{"groups": []string{"lan-llm"}})))

	snap := fullProfile()
	snap.Config["egress_groups"] = "opencode"
	snap.Config["egress_allow"] = "pypi.org, models.dev"
	res := f.provision(t, "env-1", "op-1", snap)
	require.Nil(t, res.Error, "%v", res.Error)
	assert.Equal(t, []string{"192.168.2.6:8788", "opencode.ai", "models.dev", "pypi.org"}, f.hosts["sbx-01"].provReqs[0].EgressAllow)
}

func TestProvisionRefusesAGroupRemovedSinceTheProfileWasSaved(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	snap := fullProfile()
	snap.Config["egress_groups"] = "gone"
	res := f.provision(t, "env-1", "op-1", snap)
	require.NotNil(t, res.Error)
	assert.Equal(t, "invalid_config", res.Error.Code)
	assert.Equal(t, "provider.microsandbox.egressInvalid", res.Error.MessageId)
	assert.Empty(t, f.hosts["sbx-01"].provReqs, "nothing is created")
}

// A host that reports allow_extra (F21) and would refuse a default entry
// fails every provision, so Test says so and names the entries.
func TestTestReportsDefaultEgressTheHostRefuses(t *testing.T) {
	for _, tc := range []struct {
		allowExtra string
		refused    []any
	}{
		{`["pypi.org"]`, []any{"192.168.2.6:8788", "openrouter.ai"}},
		{`["*"]`, nil},
		{`["openrouter.ai", "192.168.2.0/24"]`, nil},
	} {
		r := newRuntime(t, newFakeHost())
		require.Equal(t, 201, first(call(t, r, ActionEgressPut, map[string]any{"name": "lan-llm", "entries": []string{"192.168.2.6:8788"}})))
		require.Equal(t, 200, first(call(t, r, ActionEgressDefaults, map[string]any{"groups": []string{"lan-llm", "openrouter"}})))
		withEgress := strings.Replace(healthyJSON, `"features":`, `"egress":{"allow_extra":`+tc.allowExtra+`},"features":`, 1)
		server := sshtest.Start(t, pluginKey(t, r), msbctlHost(map[string]sshtest.Reply{"health": {Stdout: withEgress}}))
		require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", server.Dest("msb"), server.HostKey, "default"))))
		_, body := call(t, r, ActionHostsTest, map[string]any{"name": "sbx-01"})
		if tc.refused == nil {
			assert.Equal(t, true, body["ok"], tc.allowExtra)
			assert.Nil(t, body["egress_refused"], tc.allowExtra)
			continue
		}
		assert.Equal(t, false, body["ok"], tc.allowExtra)
		assert.Equal(t, "egress_refused", body["problem"], tc.allowExtra)
		assert.Equal(t, tc.refused, body["egress_refused"], tc.allowExtra)
		assert.Contains(t, body["hint"], `allow_extra = ["pypi.org", "192.168.2.6:8788", "openrouter.ai"]`, "a line to paste, keeping what the host admits")
	}
}
