package plugin

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
)

// RecoverExecutorOperation resolves a provision whose reply was lost: found
// on exactly one host, absent from every host, or unknown while any host
// cannot answer. Kandev never mints a new operation to escape "unknown".
func (r *Runtime) RecoverExecutorOperation(ctx context.Context, req *pluginsdk.RecoverExecutorOperationRequest) (*pluginsdk.RecoverExecutorOperationResponse, error) {
	rc := req.GetContext()
	if !requireIdentity(rc) {
		return &pluginsdk.RecoverExecutorOperationResponse{Error: providerError(msbctl.CodeInvalidConfig, "identityIncomplete")}, nil
	}
	client, registry, perr := r.clientAndRegistry(ctx)
	if perr != nil {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown"}, nil
	}
	found := findOperation(ctx, client, registry.Hosts, rc.GetOperationId())
	switch {
	case found.ok:
		if found.record.Env != rc.GetEnvironmentId() || found.record.InputDigest != rc.GetInputDigest() {
			return &pluginsdk.RecoverExecutorOperationResponse{Error: providerError(msbctl.CodeConflict, "operationMismatch")}, nil
		}
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "found", Resource: descriptorFor(found.host.Name, found.record)}, nil
	case found.unknown:
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown"}, nil
	default:
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "absent"}, nil
	}
}

func (r *Runtime) clientAndRegistry(ctx context.Context) (*msbctl.Client, hosts.Registry, error) {
	client, err := r.client(ctx)
	if err != nil {
		return nil, hosts.Registry{}, err
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return nil, hosts.Registry{}, err
	}
	return client, registry, nil
}

// resolved is a resource's host and env, ready for a verb.
type resolved struct {
	client *msbctl.Client
	host   hosts.Host
	state  resourceState
}

func (r *Runtime) resolve(ctx context.Context, d *pluginsdk.ExecutorResourceDescriptor) (resolved, *pluginsdk.ExecutorProviderError) {
	s, err := stateOf(d)
	if err != nil {
		return resolved{}, providerError(msbctl.CodeNotFound, "notFound")
	}
	client, err := r.client(ctx)
	if err != nil {
		return resolved{}, providerError(msbctl.CodeUnavailable, "hostUnavailable")
	}
	h, err := r.hostFor(ctx, s)
	if err != nil {
		log.Printf("resolve %s: %v", s.Env, err)
		return resolved{}, providerError(msbctl.CodeUnavailable, "hostNotRegistered")
	}
	return resolved{client: client, host: h, state: s}, nil
}

// AttachExecutorEnvironment returns the same sandbox, never a new one. A
// stopped sandbox (after a host reboot) is started again only if it binds no
// secrets: Kandev's attach request carries no profile, so there are no
// values to re-send, and msbctl never starts a half-bound sandbox.
func (r *Runtime) AttachExecutorEnvironment(ctx context.Context, req *pluginsdk.AttachExecutorEnvironmentRequest) (*pluginsdk.AttachExecutorEnvironmentResponse, error) {
	res, perr := r.resolve(ctx, req.GetResource())
	if perr != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: perr}, nil
	}
	rec, err := res.client.Inspect(ctx, res.host, res.state.SandboxName)
	if err != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerFailure(err, "attachFailed")}, nil
	}
	switch rec.State {
	case msbctl.StateAbsent:
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError(msbctl.CodeNotFound, "notFound")}, nil
	case msbctl.StateStopped:
		rec, err = res.client.Start(ctx, res.host, res.state.Env, nil)
		if msbctl.CodeOf(err) == msbctl.CodeInvalidConfig {
			return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnsupported, "restartNeedsSecrets")}, nil
		}
		if err != nil {
			return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerFailure(err, "attachFailed")}, nil
		}
	}
	return &pluginsdk.AttachExecutorEnvironmentResponse{Resource: descriptorFor(res.host.Name, rec)}, nil
}

// InspectExecutorEnvironment maps the host's view onto Kandev's states. An
// unreachable host is "unknown", never "absent": nothing is deleted on a
// network blip.
func (r *Runtime) InspectExecutorEnvironment(ctx context.Context, req *pluginsdk.InspectExecutorEnvironmentRequest) (*pluginsdk.InspectExecutorEnvironmentResponse, error) {
	res, perr := r.resolve(ctx, req.GetResource())
	if perr != nil {
		state := "unknown"
		if perr.GetCode() == msbctl.CodeNotFound {
			state = "absent"
		}
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: state, Reason: perr.GetCode()}, nil
	}
	rec, err := res.client.Inspect(ctx, res.host, res.state.SandboxName)
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeNotFound && err != nil:
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "absent", Reason: msbctl.CodeNotFound}, nil
	case err != nil:
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "unknown", Reason: msbctl.CodeOf(err)}, nil
	}
	return &pluginsdk.InspectExecutorEnvironmentResponse{State: kandevState(rec, r.now()), ExpiresAt: rec.ExpiresAt}, nil
}

func kandevState(rec msbctl.Record, now time.Time) string {
	if expires, err := time.Parse(time.RFC3339, rec.ExpiresAt); err == nil && !now.Before(expires) {
		return "terminated"
	}
	switch rec.State {
	case msbctl.StateRunning:
		return "running"
	case msbctl.StateStopped:
		return "suspended"
	case msbctl.StateAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// forbiddenLeaseHeaders are the names Kandev refuses in a lease
// (normalizeLeaseHeaders, v0.97.0). A host that sends one would make the
// launch fail later with a generic error; this fails it here, clearly.
func forbiddenLeaseHeader(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "x-instance-id", "host", "cookie", "set-cookie", "sec-websocket-protocol",
		"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
		"transfer-encoding", "upgrade":
		return true
	}
	return strings.HasPrefix(lower, "proxy-")
}

// ResolveExecutorConnection leases one guest port: the control port or an
// instance port. Lease headers go into both Kandev's HTTP and WebSocket maps.
func (r *Runtime) ResolveExecutorConnection(ctx context.Context, req *pluginsdk.ResolveExecutorConnectionRequest) (*pluginsdk.ResolveExecutorConnectionResponse, error) {
	port := int(req.GetRuntimePort())
	if req.GetPurpose() != "agentctl" || !(port == controlPort || port >= instancePortFirst && port <= instancePortLast) {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError(msbctl.CodeUnsupported, "unsupportedConnection")}, nil
	}
	res, perr := r.resolve(ctx, req.GetResource())
	if perr != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: perr}, nil
	}
	lease, err := res.client.Lease(ctx, res.host, res.state.Env, port)
	if err != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerFailure(err, "leaseFailed")}, nil
	}
	httpHeaders, wsHeaders := map[string]string{}, map[string]string{}
	for name, value := range lease.Headers {
		if forbiddenLeaseHeader(name) {
			// The value is a token: log the name only.
			log.Printf("lease %s: host sent header %q, which Kandev refuses in a lease", res.state.Env, name)
			return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError(msbctl.CodeUnavailable, "leaseHeaderRefused")}, nil
		}
		httpHeaders[name], wsHeaders[name] = value, value
	}
	return &pluginsdk.ResolveExecutorConnectionResponse{Lease: &pluginsdk.ExecutorConnectionLease{
		BaseUrl: lease.BaseURL, HttpHeaders: httpHeaders, WebsocketHeaders: wsHeaders,
		ExpiresAt: lease.ExpiresAt, Generation: lease.Generation,
	}}, nil
}

// DestroyExecutorEnvironment removes the sandbox and confirms absence. With
// no usable resource state (a provision that failed before its checkpoint),
// the operation id finds it. Absence is confirmed only when every host that
// could hold it has answered; otherwise the error is retryable and Kandev
// keeps the record in cleanup_pending.
func (r *Runtime) DestroyExecutorEnvironment(ctx context.Context, req *pluginsdk.DestroyExecutorEnvironmentRequest) (*pluginsdk.DestroyExecutorEnvironmentResponse, error) {
	unavailable := func(id string) (*pluginsdk.DestroyExecutorEnvironmentResponse, error) {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnavailable, id)}, nil
	}
	if s, err := stateOf(req.GetResource()); err == nil {
		res, perr := r.resolve(ctx, req.GetResource())
		if perr != nil {
			if registry, lerr := r.loadRegistry(ctx); lerr == nil {
				if _, ok := registry.Find(s.Host); !ok {
					// The host was removed from the registry, which is only
					// allowed once it has no kandev sandboxes.
					return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
				}
			}
			return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: perr}, nil
		}
		if err := res.client.Destroy(ctx, res.host, s.SandboxName); err != nil {
			log.Printf("destroy %s on %s: %v", s.Env, s.Host, err)
			return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerFailure(err, "destroyFailed")}, nil
		}
		return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
	}
	op := req.GetContext().GetOperationId()
	if op == "" {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
	}
	client, registry, err := r.clientAndRegistry(ctx)
	if err != nil {
		return unavailable("hostUnavailable")
	}
	found := findOperation(ctx, client, registry.Hosts, op)
	switch {
	case found.ok:
		if err := client.Destroy(ctx, found.host, found.record.Name); err != nil {
			return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerFailure(err, "destroyFailed")}, nil
		}
		return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
	case found.unknown:
		return unavailable("hostsUnreachable")
	default:
		return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
	}
}
