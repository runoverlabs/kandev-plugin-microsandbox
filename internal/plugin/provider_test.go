package plugin

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sshx/sshtest"
)

const (
	plantedNonce  = "planted-nonce-7f3a91"
	plantedSecret = "planted-secret-c0ffee"
	plantedRegPW  = "planted-registry-pw-91"
)

type providerFixture struct {
	r     *Runtime
	api   *fakeProviderAPI
	hosts map[string]*fakeMsbctl
	srv   map[string]*sshtest.Server
}

// newProviderFixture registers one fake msbctl host per name, all labelled
// "default".
func newProviderFixture(t *testing.T, names ...string) *providerFixture {
	t.Helper()
	api := &fakeProviderAPI{artifact: bytes.Repeat([]byte("agentctl-binary-"), 40000)} // ~640 KiB: several chunks
	host := providerFakeHost{fakeHost: newFakeHost(), api: api}
	r := NewRuntime()
	r.maintEvery = 0
	r.SetHost(host)
	t.Cleanup(r.Close)
	f := &providerFixture{r: r, api: api, hosts: map[string]*fakeMsbctl{}, srv: map[string]*sshtest.Server{}}
	// fullProfile names it.
	require.Equal(t, 201, first(call(t, r, ActionSecretsPut, map[string]any{
		"name": "NPM_TOKEN", "hosts": "registry.npmjs.org", "value": plantedSecret,
	})))
	key := pluginKey(t, r)
	for _, name := range names {
		fake := newFakeMsbctl(name)
		server := sshtest.Start(t, key, fake.handle)
		require.Equal(t, 201, first(call(t, r, ActionHostsAdd, hostBody(name, server.Dest("msb"), server.HostKey, "default"))))
		f.hosts[name], f.srv[name] = fake, server
	}
	return f
}

func requestContext(env, op string) *pluginsdk.ExecutorProviderRequestContext {
	return &pluginsdk.ExecutorProviderRequestContext{
		PluginId: "kandev-plugin-microsandbox", ProviderKey: ProviderKey, ContractVersion: 1,
		EnvironmentId: env, OperationId: op, InputDigest: "sha256:digest-" + op, ExecutionId: "exec-" + env,
	}
}

func bootstrapJSON() string {
	raw, _ := json.Marshal(map[string]any{
		"nonce": plantedNonce, "runtime_port": 8765, "api_url": "https://kandev.tailnet.ts.net/api/v1",
		"execution_id": "exec-1", "artifact_id": "agentctl",
	})
	return string(raw)
}

func fullProfile() *pluginsdk.ExecutorProfileSnapshot {
	config := profileConfig("label:default")
	config["egress_allow"] = "pypi.org"
	config["env"] = "NODE_ENV=development"
	config["registry_username"] = "bot"
	config["secrets"] = "NPM_TOKEN"
	return &pluginsdk.ExecutorProfileSnapshot{ProfileId: "p1", Config: config, SecretValues: map[string]string{
		"registry_password": plantedRegPW,
	}}
}

func (f *providerFixture) provision(t *testing.T, env, op string, profileSnap *pluginsdk.ExecutorProfileSnapshot) *pluginsdk.ProvisionExecutorEnvironmentResponse {
	t.Helper()
	res, err := f.r.ProvisionExecutorEnvironment(t.Context(), &pluginsdk.ProvisionExecutorEnvironmentRequest{
		Context: requestContext(env, op), Profile: profileSnap, BootstrapJson: bootstrapJSON(),
	})
	require.NoError(t, err)
	return res
}

func TestProvisionHappyPath(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	// Private images must name a registry host, which this one does.
	snap := fullProfile()
	res := f.provision(t, "env-1", "op-1", snap)
	require.Nil(t, res.Error, "%v", res.Error)
	d := res.Resource

	assert.Equal(t, "msb:sbx-01/k-env-1", d.ResourceHandle)
	assert.Equal(t, "linux-amd64", d.Platform)
	assert.Equal(t, "bounded", d.Retention)
	assert.Equal(t, uint32(1), d.StateVersion)
	var state map[string]any
	require.NoError(t, json.Unmarshal([]byte(d.StateJson), &state))
	assert.Equal(t, "sbx-01", state["host"])
	assert.Equal(t, "env-1", state["env"])
	for key := range state {
		assert.Contains(t, []string{"host", "sandbox_name", "env", "image", "created_at"}, key, "only declared state fields")
	}
	expires, err := time.Parse(time.RFC3339, d.ExpiresAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(8*time.Hour), expires, time.Minute)

	host := f.hosts["sbx-01"]
	req := host.provReqs[0]
	assert.Equal(t, msbctl.KandevAPI{Host: "kandev.tailnet.ts.net", Port: 443}, req.KandevAPI)
	assert.Equal(t, []string{"pypi.org"}, req.EgressAllow)
	assert.Equal(t, plantedSecret, req.Secrets[0].Value, "secrets reach the host on stdin")
	assert.Equal(t, plantedRegPW, req.Registry.Password)
	assert.Equal(t, 20, req.WorkspaceGiB, "every sandbox gets a /workspace disk")

	sandbox := host.sandbox("env-1")
	assert.Equal(t, plantedNonce, sandbox.nonce, "the nonce reaches agentctl's launch on stdin")
	assert.Equal(t, f.api.artifact, sandbox.binary, "the binary arrives intact across chunks")
	assert.Equal(t, "0.0.0.0", sandbox.agentEnv["AGENTCTL_LISTEN_HOST"])
	assert.Equal(t, "41001", sandbox.agentEnv["AGENTCTL_INSTANCE_PORT_BASE"])
	assert.Equal(t, []string{"linux-amd64"}, f.api.platforms)

	// The checkpoint lands before anything that can fail afterwards.
	assert.Equal(t, []string{"checkpoint", "artifact"}, f.api.events)
	assert.Equal(t, "provisioned", f.api.checkpoints[0].GetPhase())
	for _, stage := range f.api.stages {
		assert.Contains(t, []string{"provision", "artifact", "bootstrap", "readiness"}, stage)
	}

	for _, exec := range f.srv["sbx-01"].Execs() {
		for _, secret := range []string{plantedNonce, plantedSecret, plantedRegPW} {
			assert.NotContains(t, exec.Command, secret, "no secret in argv")
		}
	}
}

func TestProvisionLogsNoSecret(t *testing.T) {
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	f := newProviderFixture(t, "sbx-01")
	f.api.failCheck = true // force the failure paths that log
	f.provision(t, "env-1", "op-1", fullProfile())
	bad := fullProfile()
	f.r.ProvisionExecutorEnvironment(t.Context(), &pluginsdk.ProvisionExecutorEnvironmentRequest{
		Context: requestContext("env-2", "op-2"), Profile: bad, BootstrapJson: `{"nonce":"` + plantedNonce + `","api_url":"ftp://x"}`,
	})
	for _, secret := range []string{plantedNonce, plantedSecret, plantedRegPW} {
		assert.NotContains(t, logs.String(), secret)
	}
	assert.NotEmpty(t, logs.String(), "the failures were logged")
}

func TestProvisionRetryReusesTheHostThatHasIt(t *testing.T) {
	f := newProviderFixture(t, "sbx-01", "sbx-02")
	first := f.provision(t, "env-1", "op-1", fullProfile())
	require.Nil(t, first.Error)
	again := f.provision(t, "env-1", "op-1", fullProfile())
	require.Nil(t, again.Error)
	assert.Equal(t, first.Resource.ResourceHandle, again.Resource.ResourceHandle)
	assert.Equal(t, 1, f.hosts["sbx-01"].count()+f.hosts["sbx-02"].count(), "never a second sandbox")
}

func TestProvisionWhenEveryHostIsFull(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	f.hosts["sbx-01"].full = true
	res := f.provision(t, "env-1", "op-1", fullProfile())
	require.NotNil(t, res.Error)
	assert.Equal(t, "rate_limited", res.Error.Code)
	assert.Equal(t, uint32(30), res.Error.RetryAfterSeconds)
}

func TestProvisionRefusesBadInput(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	bad := fullProfile()
	bad.Config["cpus"] = "99"
	assert.Equal(t, "invalid_config", f.provision(t, "env-1", "op-1", bad).Error.Code)

	res, err := f.r.ProvisionExecutorEnvironment(t.Context(), &pluginsdk.ProvisionExecutorEnvironmentRequest{
		Context: requestContext("env-2", "op-2"), Profile: fullProfile(), BootstrapJson: `{"nonce":"x","runtime_port":9000,"api_url":"https://k.example.com"}`,
	})
	require.NoError(t, err)
	assert.Equal(t, "invalid_config", res.Error.Code)

	res, err = f.r.ProvisionExecutorEnvironment(t.Context(), &pluginsdk.ProvisionExecutorEnvironmentRequest{
		Context: &pluginsdk.ExecutorProviderRequestContext{EnvironmentId: "env-3"}, Profile: fullProfile(), BootstrapJson: bootstrapJSON(),
	})
	require.NoError(t, err)
	assert.Equal(t, "invalid_config", res.Error.Code)
	assert.Equal(t, 0, f.hosts["sbx-01"].count(), "nothing was created")
}

func TestProvisionFailsWithoutCreatingWhenTheArtifactIsCorrupt(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	f.api.artifact = nil // an empty stream has no digest
	res := f.provision(t, "env-1", "op-1", fullProfile())
	require.NotNil(t, res.Error)
	assert.Equal(t, "unavailable", res.Error.Code)
	assert.Nil(t, f.hosts["sbx-01"].sandbox("env-1").binary, "no binary reached the host")
}

func TestParseBootstrapPorts(t *testing.T) {
	for raw, want := range map[string]msbctl.KandevAPI{
		`{"nonce":"n","api_url":"https://k.example.com/api/v1"}`:    {Host: "k.example.com", Port: 443},
		`{"nonce":"n","api_url":"http://k.example.com/api/v1"}`:     {Host: "k.example.com", Port: 80},
		`{"nonce":"n","api_url":"https://100.64.0.2:38429/api/v1"}`: {Host: "100.64.0.2", Port: 38429},
		`{"nonce":"n","api_url":"https://[fd7a::1]:8443/api/v1"}`:   {Host: "fd7a::1", Port: 8443},
	} {
		_, api, err := parseBootstrap(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, api, raw)
	}
	for _, raw := range []string{`{}`, `{"nonce":"n"}`, `{"nonce":"n","api_url":"ftp://x"}`, `not json`} {
		_, _, err := parseBootstrap(raw)
		assert.Error(t, err, raw)
	}
}

func (f *providerFixture) provisioned(t *testing.T, env string) *pluginsdk.ExecutorResourceDescriptor {
	t.Helper()
	res := f.provision(t, env, "op-"+env, fullProfile())
	require.Nil(t, res.Error)
	return res.Resource
}

func TestRecover(t *testing.T) {
	f := newProviderFixture(t, "sbx-01", "sbx-02")
	d := f.provisioned(t, "env-1")

	recover := func(rc *pluginsdk.ExecutorProviderRequestContext) *pluginsdk.RecoverExecutorOperationResponse {
		res, err := f.r.RecoverExecutorOperation(t.Context(), &pluginsdk.RecoverExecutorOperationRequest{Context: rc})
		require.NoError(t, err)
		return res
	}
	found := recover(requestContext("env-1", "op-env-1"))
	assert.Equal(t, "found", found.Outcome)
	assert.Equal(t, d.ResourceHandle, found.Resource.ResourceHandle)
	assert.Equal(t, "absent", recover(requestContext("env-9", "op-env-9")).Outcome)

	mismatch := requestContext("env-1", "op-env-1")
	mismatch.InputDigest = "sha256:other"
	assert.Equal(t, "conflict", recover(mismatch).Error.Code)

	// One host down: an operation found nowhere is unknown, not absent.
	f.srv["sbx-02"].Close()
	assert.Equal(t, "unknown", recover(requestContext("env-9", "op-env-9")).Outcome)
}

func TestInspectStates(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	d := f.provisioned(t, "env-1")
	inspect := func() *pluginsdk.InspectExecutorEnvironmentResponse {
		res, err := f.r.InspectExecutorEnvironment(t.Context(), &pluginsdk.InspectExecutorEnvironmentRequest{Context: requestContext("env-1", "op-x"), Resource: d})
		require.NoError(t, err)
		return res
	}
	assert.Equal(t, "running", inspect().State)
	assert.NotEmpty(t, inspect().ExpiresAt)

	sandbox := f.hosts["sbx-01"].sandbox("env-1")
	sandbox.rec.State = msbctl.StateStopped
	assert.Equal(t, "suspended", inspect().State)
	sandbox.rec.State = msbctl.StateAbsent
	assert.Equal(t, "absent", inspect().State)
	sandbox.rec.State = msbctl.StateRunning
	f.r.now = func() time.Time { return time.Now().Add(9 * time.Hour) }
	assert.Equal(t, "terminated", inspect().State)
	f.r.now = time.Now

	f.hosts["sbx-01"].mu.Lock()
	delete(f.hosts["sbx-01"].sandboxes, "env-1")
	f.hosts["sbx-01"].mu.Unlock()
	assert.Equal(t, "absent", inspect().State)

	f.srv["sbx-01"].Close()
	assert.Equal(t, "unknown", inspect().State, "a host that cannot answer is never reported absent")
}

func TestResolveConnection(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	d := f.provisioned(t, "env-1")
	resolve := func(port uint32) *pluginsdk.ResolveExecutorConnectionResponse {
		res, err := f.r.ResolveExecutorConnection(t.Context(), &pluginsdk.ResolveExecutorConnectionRequest{
			Context: requestContext("env-1", "op-x"), Resource: d, Purpose: "agentctl", RuntimePort: port,
		})
		require.NoError(t, err)
		return res
	}
	lease := resolve(8765).Lease
	require.NotNil(t, lease)
	assert.Equal(t, "https://sbx-01.tailnet.ts.net:30001", lease.BaseUrl)
	assert.Equal(t, "1", lease.Generation)
	assert.NotNil(t, resolve(41002).Lease)

	f.hosts["sbx-01"].leaseHdr = map[string]string{"X-Msb-Lease": "v1.token"}
	lease = resolve(8765).Lease
	assert.Equal(t, "v1.token", lease.HttpHeaders["X-Msb-Lease"])
	assert.Equal(t, "v1.token", lease.WebsocketHeaders["X-Msb-Lease"])

	f.hosts["sbx-01"].leaseHdr = map[string]string{"Authorization": "Bearer v1.token"}
	refused := resolve(8765)
	assert.Nil(t, refused.Lease, "a header Kandev refuses never reaches Kandev")
	assert.Equal(t, "unavailable", refused.Error.Code)

	assert.Equal(t, "unsupported", resolve(22).Error.Code)
	assert.Equal(t, "unsupported", resolve(41004).Error.Code)
}

func TestDestroy(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	d := f.provisioned(t, "env-1")
	destroy := func(rc *pluginsdk.ExecutorProviderRequestContext, d *pluginsdk.ExecutorResourceDescriptor) *pluginsdk.DestroyExecutorEnvironmentResponse {
		res, err := f.r.DestroyExecutorEnvironment(t.Context(), &pluginsdk.DestroyExecutorEnvironmentRequest{Context: rc, Resource: d, CleanupReason: "archive"})
		require.NoError(t, err)
		return res
	}
	assert.True(t, destroy(requestContext("env-1", "op-x"), d).ConfirmedAbsent)
	assert.Equal(t, 0, f.hosts["sbx-01"].count())
	assert.True(t, destroy(requestContext("env-1", "op-x"), d).ConfirmedAbsent, "idempotent")

	// No state: a provision that failed before its checkpoint is found by
	// its operation id.
	f.provisioned(t, "env-2")
	assert.True(t, destroy(requestContext("env-2", "op-env-2"), nil).ConfirmedAbsent)
	assert.Equal(t, 0, f.hosts["sbx-01"].count())
	assert.True(t, destroy(requestContext("env-3", "op-never"), nil).ConfirmedAbsent)

	// Unreachable: retryable, never confirmed.
	d4 := f.provisioned(t, "env-4")
	f.srv["sbx-01"].Close()
	res := destroy(requestContext("env-4", "op-x"), d4)
	assert.False(t, res.ConfirmedAbsent)
	assert.Equal(t, "unavailable", res.Error.Code)
	res = destroy(requestContext("env-4", "op-env-4"), nil)
	assert.False(t, res.ConfirmedAbsent, "an operation search with a host down proves nothing")
}

func TestDestroyForARemovedHostConfirms(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	state, _ := json.Marshal(resourceState{Host: "sbx-gone", SandboxName: "k-env-1", Env: "env-1"})
	res, err := f.r.DestroyExecutorEnvironment(t.Context(), &pluginsdk.DestroyExecutorEnvironmentRequest{
		Context: requestContext("env-1", "op-x"), Resource: &pluginsdk.ExecutorResourceDescriptor{ResourceHandle: "msb:sbx-gone/k-env-1", StateJson: string(state)},
	})
	require.NoError(t, err)
	assert.True(t, res.ConfirmedAbsent)
}

func TestAttach(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	attach := func(d *pluginsdk.ExecutorResourceDescriptor) *pluginsdk.AttachExecutorEnvironmentResponse {
		res, err := f.r.AttachExecutorEnvironment(t.Context(), &pluginsdk.AttachExecutorEnvironmentRequest{Context: requestContext("env", "op-x"), Resource: d})
		require.NoError(t, err)
		return res
	}
	withSecrets := f.provisioned(t, "env-1")
	got := attach(withSecrets)
	require.Nil(t, got.Error)
	assert.Equal(t, withSecrets.ResourceHandle, got.Resource.ResourceHandle, "the same sandbox, never a new one")

	f.hosts["sbx-01"].sandbox("env-1").rec.State = msbctl.StateStopped
	assert.Equal(t, "unsupported", attach(withSecrets).Error.Code, "no secret values to re-send at attach")

	plain := fullProfile()
	delete(plain.Config, "secrets")
	res := f.provision(t, "env-2", "op-env-2", plain)
	require.Nil(t, res.Error)
	f.hosts["sbx-01"].sandbox("env-2").rec.State = msbctl.StateStopped
	restarted := attach(res.Resource)
	require.Nil(t, restarted.Error)
	assert.Equal(t, msbctl.StateRunning, f.hosts["sbx-01"].sandbox("env-2").rec.State)

	f.hosts["sbx-01"].mu.Lock()
	delete(f.hosts["sbx-01"].sandboxes, "env-2")
	f.hosts["sbx-01"].mu.Unlock()
	assert.Equal(t, "not_found", attach(res.Resource).Error.Code)
	assert.Equal(t, "not_found", attach(nil).Error.Code)
}

func TestForbiddenLeaseHeadersMatchKandev(t *testing.T) {
	for _, name := range []string{"Authorization", "authorization", "X-Instance-ID", "Host", "Cookie", "Set-Cookie", "Sec-WebSocket-Protocol", "Connection", "Upgrade", "Proxy-Foo", "Transfer-Encoding"} {
		assert.True(t, forbiddenLeaseHeader(name), name)
	}
	for _, name := range []string{"X-Msb-Lease", "X-Custom"} {
		assert.False(t, forbiddenLeaseHeader(name), name)
	}
}

// Kandev must hold the handle before anything else can fail: a refused
// checkpoint stops the provision before agentctl is fetched or installed.
func TestProvisionStopsWhenTheCheckpointIsRefused(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	f.api.failCheck = true
	res := f.provision(t, "env-1", "op-1", fullProfile())
	require.NotNil(t, res.Error)
	assert.Equal(t, "unavailable", res.Error.Code)
	assert.Empty(t, f.api.platforms, "the artifact is not read")
	assert.Nil(t, f.hosts["sbx-01"].sandbox("env-1").binary, "agentctl is not installed")
}

// msbctl refuses a stdin header over 64 KiB, so the plugin refuses it first,
// before creating anything, with a code the operator can act on.
func TestProvisionRefusesARequestLargerThanTheHeader(t *testing.T) {
	f := newProviderFixture(t, "sbx-01")
	snap := fullProfile()
	snap.SecretValues["registry_password"] = strings.Repeat("s", msbctl.MaxHeaderBytes)
	res := f.provision(t, "env-1", "op-1", snap)
	require.NotNil(t, res.Error)
	assert.Equal(t, "invalid_config", res.Error.Code)
	assert.Equal(t, "provider.microsandbox.requestTooLarge", res.Error.MessageId)
	assert.Empty(t, f.hosts["sbx-01"].provReqs, "nothing is sent")
}
