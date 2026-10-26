package plugin

import (
	"context"
	"fmt"
	"log"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/sandbox"
)

// recover resolves a provision whose reply was lost: found on exactly one
// host, absent from every host, or unknown while any host cannot answer.
// Kandev never mints a new operation to escape "unknown".
func (p *provider) recover(ctx context.Context, req *pluginsdk.RecoverExecutorOperationRequest) *pluginsdk.RecoverExecutorOperationResponse {
	rc := req.GetContext()
	op := operationOf(rc)
	if !op.Complete() {
		return &pluginsdk.RecoverExecutorOperationResponse{Error: providerError(msbctl.CodeInvalidConfig, "identityIncomplete")}
	}
	client, registry, err := p.clientAndRegistry(ctx)
	if err != nil {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown"}
	}
	found := sandbox.FindOperation(ctx, client, registry.Hosts, op.ID)
	switch {
	case found.OK:
		if found.Record.Env != op.Environment || found.Record.InputDigest != op.InputDigest {
			return &pluginsdk.RecoverExecutorOperationResponse{Error: providerError(msbctl.CodeConflict, "operationMismatch")}
		}
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "found", Resource: descriptorFor(found.Host.Name, found.Record)}
	case found.Unknown:
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown"}
	default:
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "absent"}
	}
}

func (p *provider) clientAndRegistry(ctx context.Context) (*msbctl.Client, hosts.Registry, error) {
	client, err := p.connect(ctx)
	if err != nil {
		return nil, hosts.Registry{}, err
	}
	registry, err := p.registry.Load(ctx)
	if err != nil {
		return nil, hosts.Registry{}, err
	}
	return client, registry, nil
}

// resolved is a resource's host and env, ready for a verb.
type resolved struct {
	client *msbctl.Client
	host   hosts.Host
	state  sandbox.State
}

func (p *provider) resolve(ctx context.Context, d *pluginsdk.ExecutorResourceDescriptor) (resolved, *pluginsdk.ExecutorProviderError) {
	s, err := sandbox.ParseState(d.GetStateJson())
	if err != nil {
		return resolved{}, providerError(msbctl.CodeNotFound, "notFound")
	}
	client, err := p.connect(ctx)
	if err != nil {
		return resolved{}, providerError(msbctl.CodeUnavailable, "hostUnavailable")
	}
	h, err := p.hostFor(ctx, s)
	if err != nil {
		log.Printf("resolve %s: %v", s.Env, err)
		return resolved{}, providerError(msbctl.CodeUnavailable, "hostNotRegistered")
	}
	return resolved{client: client, host: h, state: s}, nil
}

// hostFor resolves the host a resource's state names. A host removed from
// the registry is reported, never guessed.
func (p *provider) hostFor(ctx context.Context, s sandbox.State) (hosts.Host, error) {
	registry, err := p.registry.Load(ctx)
	if err != nil {
		return hosts.Host{}, err
	}
	h, ok := registry.Find(s.Host)
	if !ok {
		return hosts.Host{}, fmt.Errorf("host %q is no longer registered", s.Host)
	}
	return h, nil
}

// attach returns the same sandbox, never a new one. A stopped sandbox (after
// a host reboot) is started again only if it binds no secrets: Kandev's
// attach request carries no profile, so there are no values to re-send, and
// msbctl never starts a half-bound sandbox.
func (p *provider) attach(ctx context.Context, req *pluginsdk.AttachExecutorEnvironmentRequest) *pluginsdk.AttachExecutorEnvironmentResponse {
	res, perr := p.resolve(ctx, req.GetResource())
	if perr != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: perr}
	}
	rec, err := res.client.Inspect(ctx, res.host, res.state.SandboxName)
	if err != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerFailure(err, "attachFailed")}
	}
	switch rec.State {
	case msbctl.StateAbsent:
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError(msbctl.CodeNotFound, "notFound")}
	case msbctl.StateStopped:
		rec, err = res.client.Start(ctx, res.host, res.state.Env, nil)
		if msbctl.CodeOf(err) == msbctl.CodeInvalidConfig {
			return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnsupported, "restartNeedsSecrets")}
		}
		if err != nil {
			return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerFailure(err, "attachFailed")}
		}
	}
	return &pluginsdk.AttachExecutorEnvironmentResponse{Resource: descriptorFor(res.host.Name, rec)}
}

// inspect maps the host's view onto Kandev's states. An unreachable host is
// "unknown", never "absent": nothing is deleted on a network blip.
func (p *provider) inspect(ctx context.Context, req *pluginsdk.InspectExecutorEnvironmentRequest) *pluginsdk.InspectExecutorEnvironmentResponse {
	res, perr := p.resolve(ctx, req.GetResource())
	if perr != nil {
		state := sandbox.StateUnknown
		if perr.GetCode() == msbctl.CodeNotFound {
			state = sandbox.StateAbsent
		}
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: state, Reason: perr.GetCode()}
	}
	rec, err := res.client.Inspect(ctx, res.host, res.state.SandboxName)
	switch {
	case msbctl.CodeOf(err) == msbctl.CodeNotFound && err != nil:
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: sandbox.StateAbsent, Reason: msbctl.CodeNotFound}
	case err != nil:
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: sandbox.StateUnknown, Reason: msbctl.CodeOf(err)}
	}
	return &pluginsdk.InspectExecutorEnvironmentResponse{State: sandbox.KandevState(rec, p.now()), ExpiresAt: rec.ExpiresAt}
}

// lease leases one guest port: the control port or an instance port. Lease
// headers go into both Kandev's HTTP and WebSocket maps.
func (p *provider) lease(ctx context.Context, req *pluginsdk.ResolveExecutorConnectionRequest) *pluginsdk.ResolveExecutorConnectionResponse {
	port := int(req.GetRuntimePort())
	if req.GetPurpose() != "agentctl" || !sandbox.LeasablePort(port) {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError(msbctl.CodeUnsupported, "unsupportedConnection")}
	}
	res, perr := p.resolve(ctx, req.GetResource())
	if perr != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: perr}
	}
	lease, err := res.client.Lease(ctx, res.host, res.state.Env, port)
	if err != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerFailure(err, "leaseFailed")}
	}
	httpHeaders, wsHeaders := map[string]string{}, map[string]string{}
	for name, value := range lease.Headers {
		if sandbox.ForbiddenLeaseHeader(name) {
			// The value is a token: log the name only.
			log.Printf("lease %s: host sent header %q, which Kandev refuses in a lease", res.state.Env, name)
			return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError(msbctl.CodeUnavailable, "leaseHeaderRefused")}
		}
		httpHeaders[name], wsHeaders[name] = value, value
	}
	return &pluginsdk.ResolveExecutorConnectionResponse{Lease: &pluginsdk.ExecutorConnectionLease{
		BaseUrl: lease.BaseURL, HttpHeaders: httpHeaders, WebsocketHeaders: wsHeaders,
		ExpiresAt: lease.ExpiresAt, Generation: lease.Generation,
	}}
}

// confirmedAbsent is a new response each time: the SDK encodes it, and a
// protobuf message is not safe to share between concurrent encodings.
func confirmedAbsent() *pluginsdk.DestroyExecutorEnvironmentResponse {
	return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}
}

// destroy removes the sandbox and confirms absence. With no usable resource
// state (a provision that failed before its checkpoint), the operation id
// finds it. Absence is confirmed only when every host that could hold it has
// answered; otherwise the error is retryable and Kandev keeps the record in
// cleanup_pending.
func (p *provider) destroy(ctx context.Context, req *pluginsdk.DestroyExecutorEnvironmentRequest) *pluginsdk.DestroyExecutorEnvironmentResponse {
	if s, err := sandbox.ParseState(req.GetResource().GetStateJson()); err == nil {
		return p.destroyByState(ctx, req.GetResource(), s)
	}
	op := req.GetContext().GetOperationId()
	if op == "" {
		return confirmedAbsent()
	}
	client, registry, err := p.clientAndRegistry(ctx)
	if err != nil {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnavailable, "hostUnavailable")}
	}
	found := sandbox.FindOperation(ctx, client, registry.Hosts, op)
	switch {
	case found.OK:
		if err := client.Destroy(ctx, found.Host, found.Record.Name); err != nil {
			return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerFailure(err, "destroyFailed")}
		}
		return confirmedAbsent()
	case found.Unknown:
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnavailable, "hostsUnreachable")}
	default:
		return confirmedAbsent()
	}
}

// destroyByState destroys the sandbox a resource's state names.
func (p *provider) destroyByState(ctx context.Context, d *pluginsdk.ExecutorResourceDescriptor, s sandbox.State) *pluginsdk.DestroyExecutorEnvironmentResponse {
	res, perr := p.resolve(ctx, d)
	if perr != nil {
		if registry, err := p.registry.Load(ctx); err == nil {
			if _, ok := registry.Find(s.Host); !ok {
				// The host was removed from the registry, which is only
				// allowed once it has no kandev sandboxes.
				return confirmedAbsent()
			}
		}
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: perr}
	}
	if err := res.client.Destroy(ctx, res.host, s.SandboxName); err != nil {
		log.Printf("destroy %s on %s: %v", s.Env, s.Host, err)
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerFailure(err, "destroyFailed")}
	}
	return confirmedAbsent()
}
