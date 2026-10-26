// Package plugin is the transport: it turns Kandev's calls into calls on the
// features and their answers into SDK responses. Runtime routes the RPCs;
// each surface (hosts, CA, secrets, egress, host jobs, readiness, the
// executor provider) is a handler holding only the ports it uses, and
// wire.go, the one file that builds adapters, puts the graph together.
package plugin

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/kandev"
)

// actionTimeout bounds one action, which may make one SSH round trip.
const actionTimeout = 20 * time.Second

// netDialer opens the TCP connection under SSH. *net.Dialer satisfies it.
type netDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// actionFunc serves one action key.
type actionFunc func(ctx context.Context, body []byte) kandev.Response

// Runtime is the plugin value pluginsdk.Serve runs.
type Runtime struct {
	pluginsdk.UnimplementedPlugin
	maintainer

	// dialer opens every SSH connection; wire.go hands it out at build time.
	dialer netDialer
	// Knobs a test may change before the first call; the graph reads them
	// through closures.
	now func() time.Time
	// getenv reads the plugin process's environment, which is Kandev's.
	getenv func(string) string
	// trustPool is the root pool trust checks use; nil means the system
	// roots, which is what Kandev verifies leases against.
	trustPool *x509.CertPool

	keys     interface{ Close() }
	jobs     *hostsetup.Jobs
	registry registryWriter
	status   statusStore
	ca       rootStore
	connect  connector

	actions  map[string]actionFunc
	provider *provider
}

var (
	_ pluginsdk.Plugin                 = (*Runtime)(nil)
	_ pluginsdk.ActionHandler          = (*Runtime)(nil)
	_ pluginsdk.ExecutorProviderPlugin = (*Runtime)(nil)
)

// SetHost stores the Host and starts the maintainer. Kandev calls it once,
// from a background goroutine, after the broker connection is up.
func (r *Runtime) SetHost(h pluginsdk.Host) {
	r.UnimplementedPlugin.SetHost(h)
	r.startMaintainer()
}

// Close stops the maintainer and any host job, and drops every SSH
// connection.
func (r *Runtime) Close() {
	r.stopMaintainer()
	r.jobs.Stop()
	r.keys.Close()
}

// HandleAction serves the settings pages. Every action is admin-only in the
// manifest.
//
// Kandev masks any Go error from an action as a 503, so every failure the
// operator can act on is returned as a response with its own status.
func (r *Runtime) HandleAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	handler, found := r.actions[req.ActionKey]
	if !found {
		return kandev.Fail(http.StatusNotFound, "unknown action").Encode(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	return handler(ctx, req.Body).Encode(), nil
}

// ValidateExecutorProfile checks a profile against the plugin's own state.
func (r *Runtime) ValidateExecutorProfile(ctx context.Context, req *pluginsdk.ValidateExecutorProfileRequest) (*pluginsdk.ValidateExecutorProfileResponse, error) {
	return r.provider.validate(ctx, req), nil
}

// ProvisionExecutorEnvironment creates a sandbox and starts agentctl in it.
func (r *Runtime) ProvisionExecutorEnvironment(ctx context.Context, req *pluginsdk.ProvisionExecutorEnvironmentRequest) (*pluginsdk.ProvisionExecutorEnvironmentResponse, error) {
	return r.provider.provision(ctx, req), nil
}

// RecoverExecutorOperation resolves a provision whose reply was lost.
func (r *Runtime) RecoverExecutorOperation(ctx context.Context, req *pluginsdk.RecoverExecutorOperationRequest) (*pluginsdk.RecoverExecutorOperationResponse, error) {
	return r.provider.recover(ctx, req), nil
}

// AttachExecutorEnvironment returns the same sandbox, started if stopped.
func (r *Runtime) AttachExecutorEnvironment(ctx context.Context, req *pluginsdk.AttachExecutorEnvironmentRequest) (*pluginsdk.AttachExecutorEnvironmentResponse, error) {
	return r.provider.attach(ctx, req), nil
}

// InspectExecutorEnvironment reports the sandbox's state.
func (r *Runtime) InspectExecutorEnvironment(ctx context.Context, req *pluginsdk.InspectExecutorEnvironmentRequest) (*pluginsdk.InspectExecutorEnvironmentResponse, error) {
	return r.provider.inspect(ctx, req), nil
}

// ResolveExecutorConnection leases one guest port.
func (r *Runtime) ResolveExecutorConnection(ctx context.Context, req *pluginsdk.ResolveExecutorConnectionRequest) (*pluginsdk.ResolveExecutorConnectionResponse, error) {
	return r.provider.lease(ctx, req), nil
}

// DestroyExecutorEnvironment removes the sandbox and confirms absence.
func (r *Runtime) DestroyExecutorEnvironment(ctx context.Context, req *pluginsdk.DestroyExecutorEnvironmentRequest) (*pluginsdk.DestroyExecutorEnvironmentResponse, error) {
	return r.provider.destroy(ctx, req), nil
}
