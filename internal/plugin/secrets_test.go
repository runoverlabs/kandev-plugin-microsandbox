package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretsAreNeverShownOrKeptInState(t *testing.T) {
	host := newFakeHost()
	r := newRuntime(t, host)
	status, body := call(t, r, ActionSecretsPut, map[string]any{
		"name": "OPENROUTER_API_KEY", "description": "team key", "hosts": "OpenRouter.ai", "value": plantedSecret,
	})
	require.Equal(t, 201, status, body)
	_, list := call(t, r, ActionSecretsList, map[string]any{})
	secrets := list["secrets"].([]any)
	require.Len(t, secrets, 1)
	assert.Equal(t, []any{"openrouter.ai"}, secrets[0].(map[string]any)["hosts"])

	everything, _ := json.Marshal([]any{body, list, host.State()})
	assert.NotContains(t, string(everything), plantedSecret, "the value is in the secret store only")
	assert.Equal(t, plantedSecret, host.Secret(secretValuePrefix+"OPENROUTER_API_KEY"))
}

func TestSecretsPutValidates(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	for label, body := range map[string]map[string]any{
		"lowercase name": {"name": "npm_token", "hosts": "registry.npmjs.org", "value": "x"},
		"reserved name":  {"name": "GH_TOKEN", "hosts": "github.com", "value": "x"},
		"no hosts":       {"name": "TOKEN", "hosts": "", "value": "x"},
		"wildcard host":  {"name": "TOKEN", "hosts": "*.example.com", "value": "x"},
		"empty value":    {"name": "TOKEN", "hosts": "a.example.com", "value": ""},
		"new, no value":  {"name": "TOKEN", "hosts": "a.example.com"},
	} {
		status, res := call(t, r, ActionSecretsPut, body)
		assert.Equal(t, 422, status, label)
		assert.NotEmpty(t, res["fields"], label)
	}
}

// Changing a secret's hosts keeps its value; a new value replaces it.
func TestSecretsPutKeepsTheValueUnlessGiven(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	require.Equal(t, 200, first(call(t, f.r, ActionSecretsPut, map[string]any{"name": "NPM_TOKEN", "hosts": "npm.example.com"})))
	require.Nil(t, f.provision(t, "env-1", "op-1", fullProfile()).Error)
	got := f.hosts["sbx-01"].provReqs[0].Secrets[0]
	assert.Equal(t, plantedSecret, got.Value)
	assert.Equal(t, []string{"npm.example.com"}, got.Hosts)

	require.Equal(t, 200, first(call(t, f.r, ActionSecretsPut, map[string]any{"name": "NPM_TOKEN", "hosts": "npm.example.com", "value": "rotated"})))
	require.Nil(t, f.provision(t, "env-2", "op-2", fullProfile()).Error)
	assert.Equal(t, "rotated", f.hosts["sbx-01"].provReqs[1].Secrets[0].Value)
}

func TestARemovedSecretFailsValidationAndProvision(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	require.Equal(t, 200, first(call(t, f.r, ActionSecretsRemove, map[string]any{"name": "NPM_TOKEN"})))
	assert.Equal(t, 404, first(call(t, f.r, ActionSecretsRemove, map[string]any{"name": "NPM_TOKEN"})))

	config := profileConfig("label:default")
	config["secrets"] = "NPM_TOKEN"
	res := validate(t, f.r, config, nil)
	assert.Equal(t, map[string]string{"secrets": CodeUnresolved}, fieldCodes(res))
	assert.Equal(t, "profile.secrets.unresolved", res.FieldErrors[0].MessageId)

	prov := f.provision(t, "env-1", "op-1", fullProfile())
	require.NotNil(t, prov.Error)
	assert.Equal(t, "invalid_config", prov.Error.Code)
	assert.Equal(t, "provider.microsandbox.secretUnresolved", prov.Error.MessageId)
	assert.Empty(t, f.hosts["sbx-01"].provReqs, "nothing is created")
}
