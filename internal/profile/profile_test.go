package profile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validConfig() map[string]string {
	return map[string]string{
		FieldPlacement:        "label:default",
		FieldImage:            "ghcr.io/acme/api-sbx@" + digest,
		FieldCPUs:             "4",
		FieldMemoryMiB:        "8192",
		FieldMaxLifetimeHours: "8",
	}
}

func with(base map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func TestParseMinimalProfileAppliesDefaults(t *testing.T) {
	spec, errs := Parse(validConfig(), nil)
	require.Empty(t, errs)
	assert.Equal(t, Placement{Kind: PlacementLabel, Value: "default"}, spec.Placement)
	assert.Equal(t, 4, spec.CPUs)
	assert.Equal(t, 8192, spec.MemoryMiB)
	assert.Equal(t, DefaultDiskGiB, spec.DiskGiB)
	assert.Equal(t, DefaultRetainHours, spec.RetainHours)
	assert.Equal(t, 8, spec.MaxLifetimeHours)
	assert.Empty(t, spec.Secrets)
}

// The host's activation probe sends an empty config; it must produce field
// errors, never a panic or a Go error.
func TestParseEmptyConfigReportsEveryRequiredField(t *testing.T) {
	_, errs := Parse(map[string]string{}, nil)
	assert.ElementsMatch(t, []FieldError{
		{FieldPlacement, CodeRequired},
		{FieldImage, CodeRequired},
		{FieldCPUs, CodeRequired},
		{FieldMemoryMiB, CodeRequired},
		{FieldMaxLifetimeHours, CodeRequired},
	}, errs)
}

func TestParsePlacement(t *testing.T) {
	for raw, want := range map[string]string{
		"host:sbx-01":   "",
		"label:big-mem": "",
		"zone:eu":       CodeInvalid,
		"host:":         CodeInvalid,
		"sbx-01":        CodeInvalid,
		"host:SBX":      CodeInvalid,
		"host:a b":      CodeInvalid,
	} {
		_, errs := Parse(with(validConfig(), FieldPlacement, raw), nil)
		if want == "" {
			assert.Empty(t, errs, raw)
		} else {
			assert.Equal(t, []FieldError{{FieldPlacement, want}}, errs, raw)
		}
	}
}

func TestParseImageMustBeDigestPinnedOCIReference(t *testing.T) {
	for _, ok := range []string{
		"ghcr.io/acme/api-sbx@" + digest,
		"registry.example.com:5000/acme/api@" + digest,
		"acme/api:1.2@" + digest,
		"ubuntu@" + digest,
	} {
		_, errs := Parse(with(validConfig(), FieldImage, ok), nil)
		assert.Empty(t, errs, ok)
	}
	for _, bad := range []string{
		"ghcr.io/acme/api-sbx:latest",
		"ghcr.io/acme/api-sbx@sha256:abc",
		"/srv/images/rootfs@" + digest,
		"./rootfs@" + digest,
		"~/rootfs@" + digest,
		"GHCR.IO/acme/api@" + digest,
		"ghcr.io/acme/api@" + strings.ToUpper(digest),
	} {
		_, errs := Parse(with(validConfig(), FieldImage, bad), nil)
		assert.Equal(t, []FieldError{{FieldImage, CodeInvalid}}, errs, bad)
	}
}

func TestParseNumericBounds(t *testing.T) {
	cases := []struct {
		field, raw, code string
	}{
		{FieldCPUs, "0", CodeOutOfRange},
		{FieldCPUs, "17", CodeOutOfRange},
		{FieldCPUs, "two", CodeInvalid},
		{FieldCPUs, "2.5", CodeInvalid},
		{FieldMemoryMiB, "511", CodeOutOfRange},
		{FieldMemoryMiB, "65537", CodeOutOfRange},
		{FieldDiskGiB, "4", CodeOutOfRange},
		{FieldMaxLifetimeHours, "169", CodeOutOfRange},
		{FieldRetainHours, "-1", CodeOutOfRange},
	}
	for _, c := range cases {
		_, errs := Parse(with(validConfig(), c.field, c.raw), nil)
		assert.Equal(t, []FieldError{{c.field, c.code}}, errs, c.field+"="+c.raw)
	}
	spec, errs := Parse(with(validConfig(), FieldRetainHours, "0", FieldDiskGiB, "500"), nil)
	require.Empty(t, errs)
	assert.Equal(t, 0, spec.RetainHours)
	assert.Equal(t, 500, spec.DiskGiB)
}

func TestParseEgressAllow(t *testing.T) {
	spec, errs := Parse(with(validConfig(), FieldEgressAllow, " pypi.org, files.pythonhosted.org:443,*.example.com,PyPI.org "), nil)
	require.Empty(t, errs)
	assert.Equal(t, []string{"pypi.org", "files.pythonhosted.org:443", "*.example.com"}, spec.EgressAllow)

	for _, bad := range []string{
		"https://pypi.org",
		"10.0.0.1",
		"pypi.org:0",
		"pypi.org:080",
		"localhost",
		"pypi.org/simple",
		"-bad.example.com",
	} {
		_, errs := Parse(with(validConfig(), FieldEgressAllow, bad), nil)
		assert.Equal(t, []FieldError{{FieldEgressAllow, CodeInvalid}}, errs, bad)
	}
}

func TestParseEnv(t *testing.T) {
	spec, errs := Parse(with(validConfig(), FieldEnv, "NODE_ENV=development; EMPTY=;URL=https://x.example.com/?a=b"), nil)
	require.Empty(t, errs)
	assert.Equal(t, []EnvVar{
		{"NODE_ENV", "development"}, {"EMPTY", ""}, {"URL", "https://x.example.com/?a=b"},
	}, spec.Env)

	for raw, code := range map[string]string{
		"NOEQUALS":                  CodeInvalid,
		"1BAD=x":                    CodeInvalid,
		"GH_TOKEN=x":                CodeReserved,
		"gh_token=x":                CodeReserved,
		"AGENTCTL_LISTEN_HOST=::":   CodeReserved,
		"CLAUDE_CODE_OAUTH_TOKEN=x": CodeReserved,
		"A=1;a=2":                   CodeDuplicate,
	} {
		_, errs := Parse(with(validConfig(), FieldEnv, raw), nil)
		assert.Equal(t, []FieldError{{FieldEnv, code}}, errs, raw)
	}
}

func TestParseRegistryCredentialsArePaired(t *testing.T) {
	_, errs := Parse(with(validConfig(), FieldRegistryUsername, "bot"), nil)
	assert.Equal(t, []FieldError{{FieldRegistryPassword, CodeUnpaired}}, errs)

	_, errs = Parse(validConfig(), map[string]string{FieldRegistryPassword: "pw"})
	assert.Equal(t, []FieldError{{FieldRegistryUsername, CodeUnpaired}}, errs)

	spec, errs := Parse(with(validConfig(), FieldRegistryUsername, "bot"), map[string]string{FieldRegistryPassword: "pw"})
	require.Empty(t, errs)
	assert.Equal(t, "pw", spec.RegistryPassword)
}

func TestParseExtraSecrets(t *testing.T) {
	config := with(validConfig(),
		SecretField(1, "name"), "NPM_TOKEN",
		SecretField(1, "hosts"), "registry.npmjs.org",
		SecretField(3, "name"), "SENTRY_AUTH_TOKEN",
		SecretField(3, "hosts"), "sentry.io, api.sentry.io",
	)
	secrets := map[string]string{SecretField(1, "value"): "npm-secret", SecretField(3, "value"): "sentry-secret"}
	spec, errs := Parse(config, secrets)
	require.Empty(t, errs)
	assert.Equal(t, []Secret{
		{Name: "NPM_TOKEN", Value: "npm-secret", Hosts: []string{"registry.npmjs.org"}},
		{Name: "SENTRY_AUTH_TOKEN", Value: "sentry-secret", Hosts: []string{"sentry.io", "api.sentry.io"}},
	}, spec.Secrets)
}

func TestParseExtraSecretProblems(t *testing.T) {
	name, val, hosts := SecretField(1, "name"), SecretField(1, "value"), SecretField(1, "hosts")
	cases := []struct {
		label   string
		config  map[string]string
		secrets map[string]string
		want    []FieldError
	}{
		{"value without name or hosts", nil, map[string]string{val: "x"},
			[]FieldError{{name, CodeRequired}, {hosts, CodeRequired}}},
		{"name without value", map[string]string{name: "TOKEN", hosts: "api.example.com"}, nil,
			[]FieldError{{val, CodeRequired}}},
		{"reserved name", map[string]string{name: "GH_TOKEN", hosts: "github.com"}, map[string]string{val: "x"},
			[]FieldError{{name, CodeReserved}}},
		{"collides with env", map[string]string{name: "NODE_ENV", hosts: "api.example.com", FieldEnv: "NODE_ENV=x"}, map[string]string{val: "x"},
			[]FieldError{{name, CodeDuplicate}}},
		{"wildcard host", map[string]string{name: "TOKEN", hosts: "*.example.com"}, map[string]string{val: "x"},
			[]FieldError{{hosts, CodeInvalid}}},
	}
	for _, c := range cases {
		_, errs := Parse(with(validConfig(), flatten(c.config)...), c.secrets)
		assert.ElementsMatch(t, c.want, errs, c.label)
	}
}

func TestParseRejectsDuplicateSecretNamesAcrossSlots(t *testing.T) {
	config := with(validConfig(),
		SecretField(1, "name"), "TOKEN", SecretField(1, "hosts"), "a.example.com",
		SecretField(2, "name"), "token", SecretField(2, "hosts"), "b.example.com",
	)
	secrets := map[string]string{SecretField(1, "value"): "x", SecretField(2, "value"): "y"}
	spec, errs := Parse(config, secrets)
	assert.Equal(t, []FieldError{{SecretField(2, "name"), CodeDuplicate}}, errs)
	assert.Len(t, spec.Secrets, 1)
}

func TestMessageID(t *testing.T) {
	assert.Equal(t, "profile.cpus.out_of_range", FieldError{FieldCPUs, CodeOutOfRange}.MessageID())
}

func flatten(m map[string]string) []string {
	out := make([]string, 0, len(m)*2)
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}
