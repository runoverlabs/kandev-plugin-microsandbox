package plugin

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"kandev-plugin-microsandbox/internal/profile"
)

// These tests fail on purpose when manifest.yaml changes. Update them
// deliberately: a changed capability set re-prompts the operator to approve
// every capability, and the profile schema must match what internal/profile
// reads. `make validate-manifest` checks the file against Kandev's own rules.

type manifestFile struct {
	ID           string          `yaml:"id"`
	Version      string          `yaml:"version"`
	MinKandev    string          `yaml:"min_kandev_version"`
	Capabilities map[string]any  `yaml:"capabilities"`
	Actions      []manifestEntry `yaml:"actions"`
	Providers    []struct {
		Key           string `yaml:"key"`
		ProfileSchema struct {
			Required   []string                  `yaml:"required"`
			Properties map[string]map[string]any `yaml:"properties"`
		} `yaml:"profile_schema"`
		StateSchema struct {
			Properties map[string]map[string]any `yaml:"properties"`
		} `yaml:"resource_state_schema"`
		Capabilities struct {
			Retention       string `yaml:"retention"`
			MaximumLifetime uint64 `yaml:"maximum_lifetime_seconds"`
		} `yaml:"capabilities"`
	} `yaml:"executor_providers"`
}

type manifestEntry struct {
	Key    string `yaml:"key"`
	Scope  string `yaml:"scope"`
	Access string `yaml:"access"`
}

func readManifest(t *testing.T) manifestFile {
	t.Helper()
	raw, err := os.ReadFile("../../manifest.yaml")
	require.NoError(t, err)
	var m manifestFile
	require.NoError(t, yaml.Unmarshal(raw, &m))
	return m
}

func TestManifestCapabilitySet(t *testing.T) {
	m := readManifest(t)
	assert.Equal(t, map[string]any{"executor_provider": true, "state": true, "secrets": true}, m.Capabilities)
	assert.Equal(t, "0.97.0", m.MinKandev)
	assert.Equal(t, "kandev-plugin-microsandbox", m.ID)
}

func TestManifestActionsAreTheHandledOnesAndAdminOnly(t *testing.T) {
	m := readManifest(t)
	var keys []string
	for _, a := range m.Actions {
		keys = append(keys, a.Key)
		assert.Equal(t, "admin", a.Access, a.Key)
		assert.Equal(t, "workspace", a.Scope, a.Key)
	}
	sort.Strings(keys)
	// ca.create and ca.get manage the root certificate (host-side TLS).
	assert.Equal(t, []string{
		ActionCACreate, ActionCAGet,
		ActionHostsAdd, ActionHostsDrain, ActionHostsList, ActionHostsRemove,
		ActionHostsScan, ActionHostsTest, ActionHostsUpdate,
	}, keys)
}

func TestManifestProviderMatchesTheCode(t *testing.T) {
	m := readManifest(t)
	require.Len(t, m.Providers, 1)
	p := m.Providers[0]
	assert.Equal(t, ProviderKey, p.Key)
	assert.Equal(t, "bounded", p.Capabilities.Retention)
	assert.Equal(t, capabilities().MaximumLifetimeSeconds, p.Capabilities.MaximumLifetime)

	want := []string{
		profile.FieldPlacement, profile.FieldImage, profile.FieldCPUs, profile.FieldMemoryMiB,
		profile.FieldDiskGiB, profile.FieldWorkspaceGiB, profile.FieldMaxLifetimeHours, profile.FieldRetainHours,
		profile.FieldEgressAllow, profile.FieldEnv, profile.FieldRegistryUsername, profile.FieldRegistryPassword,
	}
	secret := map[string]bool{profile.FieldRegistryPassword: true}
	for slot := 1; slot <= profile.ExtraSecretSlots; slot++ {
		want = append(want, profile.SecretField(slot, "name"), profile.SecretField(slot, "value"), profile.SecretField(slot, "hosts"))
		secret[profile.SecretField(slot, "value")] = true
	}
	var got []string
	for name, property := range p.ProfileSchema.Properties {
		got = append(got, name)
		assert.Equal(t, secret[name], property["secret"] == true, "secret flag on %s", name)
	}
	assert.ElementsMatch(t, want, got)
	assert.ElementsMatch(t, []string{
		profile.FieldPlacement, profile.FieldImage, profile.FieldCPUs, profile.FieldMemoryMiB, profile.FieldMaxLifetimeHours,
	}, p.ProfileSchema.Required)

	// Resource state routes every later call. It must never grow a field
	// that could carry a secret.
	var state []string
	for name := range p.StateSchema.Properties {
		state = append(state, name)
	}
	// env joined so later calls can address the sandbox by environment id.
	assert.ElementsMatch(t, []string{"host", "sandbox_name", "env", "image", "created_at"}, state)
}
