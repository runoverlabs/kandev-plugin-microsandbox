package plugin

import (
	"context"
	"errors"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func profileConfig(placement string) map[string]string {
	return map[string]string{
		"placement": placement, "image": "ghcr.io/acme/api-sbx@" + digest,
		"cpus": "4", "memory_mib": "8192", "max_lifetime_hours": "8",
	}
}

func validate(t *testing.T, r *Runtime, config, secrets map[string]string) *pluginsdk.ValidateExecutorProfileResponse {
	t.Helper()
	res, err := r.ValidateExecutorProfile(context.Background(), &pluginsdk.ValidateExecutorProfileRequest{
		Profile: &pluginsdk.ExecutorProfileSnapshot{Config: config, SecretValues: secrets},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func fieldCodes(res *pluginsdk.ValidateExecutorProfileResponse) map[string]string {
	out := map[string]string{}
	for _, f := range res.FieldErrors {
		out[f.Field] = f.Code
	}
	return out
}

// Kandev's activation probe: empty config, and possibly no Host yet.
func TestValidateAnswersTheActivationProbe(t *testing.T) {
	r := newRuntime(t, nil)
	for _, req := range []*pluginsdk.ValidateExecutorProfileRequest{
		{Profile: &pluginsdk.ExecutorProfileSnapshot{Config: map[string]string{}}},
		{},
		nil,
	} {
		res, err := r.ValidateExecutorProfile(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Nil(t, res.Error)
		assert.Equal(t, "required", fieldCodes(res)["placement"])
		assert.Equal(t, "bounded", res.Capabilities.Retention)
		assert.Equal(t, uint64(604800), res.Capabilities.MaximumLifetimeSeconds)
	}
}

func TestValidateResolvesPlacementAgainstTheRegistry(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-01", "msb@sbx-01", unusedHostKey, "default"))))
	require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody("sbx-02", "msb@sbx-02", unusedHostKey, "gpu"))))
	require.Equal(t, 200, first(call(t, r, ActionHostsDrain, map[string]any{"name": "sbx-02", "draining": true})))

	assert.Empty(t, validate(t, r, profileConfig("label:default"), nil).FieldErrors)
	assert.Empty(t, validate(t, r, profileConfig("host:sbx-01"), nil).FieldErrors)
	for _, placement := range []string{"label:gpu", "host:sbx-02", "host:sbx-99", "label:none"} {
		res := validate(t, r, profileConfig(placement), nil)
		assert.Equal(t, map[string]string{"placement": CodeUnresolved}, fieldCodes(res), placement)
		assert.Equal(t, "profile.placement.unresolved", res.FieldErrors[0].MessageId)
	}
}

func TestValidateReportsEveryProblemTogether(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	config := profileConfig("label:none")
	config["cpus"] = "64"
	config["env"] = "GH_TOKEN=x"
	res := validate(t, r, config, nil)
	assert.Equal(t, map[string]string{"placement": CodeUnresolved, "cpus": "out_of_range", "env": "reserved"}, fieldCodes(res))
}

func TestValidateNeverEchoesSecretValues(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	config := profileConfig("label:none")
	config["extra_secret_1_name"] = "GH_TOKEN"
	config["extra_secret_1_hosts"] = "github.com"
	res := validate(t, r, config, map[string]string{"extra_secret_1_value": "hunter2-very-secret"})
	assert.NotContains(t, res.String(), "hunter2")
	assert.Equal(t, "reserved", fieldCodes(res)["extra_secret_1_name"])
}

func TestValidateWithUnreadableRegistryIsUnavailable(t *testing.T) {
	host := newFakeHost()
	host.stateErr = errors.New("db locked")
	r := newRuntime(t, host)
	res := validate(t, r, profileConfig("label:default"), nil)
	require.NotNil(t, res.Error)
	assert.Equal(t, "unavailable", res.Error.Code)
	assert.NotContains(t, res.String(), "db locked")
}

// Until provisioning exists the plugin owns no resources, and the other RPCs
// say so rather than erroring.
func TestSkeletonRPCsDescribeAProviderWithNoResources(t *testing.T) {
	r := newRuntime(t, newFakeHost())
	ctx := context.Background()

	provision, err := r.ProvisionExecutorEnvironment(ctx, &pluginsdk.ProvisionExecutorEnvironmentRequest{})
	require.NoError(t, err)
	assert.Equal(t, "unsupported", provision.Error.Code)
	assert.Nil(t, provision.Resource)

	recover, err := r.RecoverExecutorOperation(ctx, &pluginsdk.RecoverExecutorOperationRequest{})
	require.NoError(t, err)
	assert.Equal(t, "absent", recover.Outcome)

	attach, err := r.AttachExecutorEnvironment(ctx, &pluginsdk.AttachExecutorEnvironmentRequest{})
	require.NoError(t, err)
	assert.Equal(t, "not_found", attach.Error.Code)

	inspect, err := r.InspectExecutorEnvironment(ctx, &pluginsdk.InspectExecutorEnvironmentRequest{})
	require.NoError(t, err)
	assert.Equal(t, "absent", inspect.State)

	lease, err := r.ResolveExecutorConnection(ctx, &pluginsdk.ResolveExecutorConnectionRequest{})
	require.NoError(t, err)
	assert.Nil(t, lease.Lease)

	destroy, err := r.DestroyExecutorEnvironment(ctx, &pluginsdk.DestroyExecutorEnvironmentRequest{})
	require.NoError(t, err)
	assert.True(t, destroy.ConfirmedAbsent)
}
