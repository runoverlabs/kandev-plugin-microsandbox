package plugin

import (
	"context"
	"log"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
)

// ProviderKey matches executor_providers[].key in manifest.yaml.
const ProviderKey = "microsandbox"

// CodeUnresolved marks a placement that names no registered, non-draining
// host.
const CodeUnresolved = "unresolved"

// capabilities are the manifest's declared upper bounds. No profile field
// narrows them, so they are also every profile's effective capabilities.
func capabilities() *pluginsdk.ExecutorProviderCapabilities {
	return &pluginsdk.ExecutorProviderCapabilities{
		Terminal: true, Files: true, Git: true, EmbeddedEditor: true, Preview: true, Reattach: true,
		Retention:              "bounded",
		MaximumLifetimeSeconds: profile.MaxLifetimeHours * 3600,
	}
}

func providerError(code, messageID string) *pluginsdk.ExecutorProviderError {
	return &pluginsdk.ExecutorProviderError{Code: code, MessageId: "provider.microsandbox." + messageID}
}

// ValidateExecutorProfile checks a sandbox definition and that its placement
// selects at least one registered, non-draining host. It reads only the
// local registry: nothing is allocated and no host is contacted.
//
// Kandev also calls it with an empty config to probe the contract when the
// plugin activates, possibly before the Host broker is up. That must produce
// field errors and capabilities, never a Go error.
func (r *Runtime) ValidateExecutorProfile(ctx context.Context, req *pluginsdk.ValidateExecutorProfileRequest) (*pluginsdk.ValidateExecutorProfileResponse, error) {
	config := req.GetProfile().GetConfig()
	if config == nil {
		config = map[string]string{}
	}
	spec, problems := profile.Parse(config, req.GetProfile().GetSecretValues())
	response := &pluginsdk.ValidateExecutorProfileResponse{Capabilities: capabilities()}
	for _, p := range problems {
		response.FieldErrors = append(response.FieldErrors, fieldError(p))
	}
	if spec.Placement.Kind == "" {
		return response, nil
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		log.Printf("validate executor profile: %v", err)
		response.Error = providerError(msbctl.CodeUnavailable, "registryUnavailable")
		return response, nil
	}
	if len(registry.Candidates(spec.Placement)) == 0 {
		response.FieldErrors = append(response.FieldErrors, fieldError(profile.FieldError{Field: profile.FieldPlacement, Code: CodeUnresolved}))
	}
	return response, nil
}

func fieldError(p profile.FieldError) *pluginsdk.ExecutorProviderFieldError {
	return &pluginsdk.ExecutorProviderFieldError{Field: p.Field, Code: p.Code, MessageId: p.MessageID()}
}

// The six RPCs below complete the contract Kandev requires before it offers
// the provider at all. Provisioning is not built yet, so this release never
// allocates a sandbox, and each answer is the truthful one for a provider
// that owns no resources: recovery finds nothing, there is nothing to
// attach, inspect or connect to, and every destroy is already done.

func (r *Runtime) ProvisionExecutorEnvironment(context.Context, *pluginsdk.ProvisionExecutorEnvironmentRequest) (*pluginsdk.ProvisionExecutorEnvironmentResponse, error) {
	return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError(msbctl.CodeUnsupported, "provisionUnavailable")}, nil
}

func (r *Runtime) RecoverExecutorOperation(context.Context, *pluginsdk.RecoverExecutorOperationRequest) (*pluginsdk.RecoverExecutorOperationResponse, error) {
	return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "absent"}, nil
}

func (r *Runtime) AttachExecutorEnvironment(context.Context, *pluginsdk.AttachExecutorEnvironmentRequest) (*pluginsdk.AttachExecutorEnvironmentResponse, error) {
	return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError(msbctl.CodeNotFound, "notFound")}, nil
}

func (r *Runtime) InspectExecutorEnvironment(context.Context, *pluginsdk.InspectExecutorEnvironmentRequest) (*pluginsdk.InspectExecutorEnvironmentResponse, error) {
	return &pluginsdk.InspectExecutorEnvironmentResponse{State: "absent", Reason: msbctl.CodeNotFound}, nil
}

func (r *Runtime) ResolveExecutorConnection(context.Context, *pluginsdk.ResolveExecutorConnectionRequest) (*pluginsdk.ResolveExecutorConnectionResponse, error) {
	return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError(msbctl.CodeNotFound, "notFound")}, nil
}

func (r *Runtime) DestroyExecutorEnvironment(context.Context, *pluginsdk.DestroyExecutorEnvironmentRequest) (*pluginsdk.DestroyExecutorEnvironmentResponse, error) {
	return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
}
