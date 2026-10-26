package plugin

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
	"kandev-plugin-microsandbox/internal/sandbox"
)

// ProviderKey matches executor_providers[].key in manifest.yaml.
const ProviderKey = "microsandbox"

// CodeUnresolved marks a placement that names no registered, non-draining
// host.
const CodeUnresolved = "unresolved"

// CodeUnsupported marks private names that no candidate host takes, by its
// last check: it lacks msb-manager 0.7.0, or its [kandev] private_names
// does not list them.
const CodeUnsupported = "unsupported"

// secretResolver is the secrets a profile names.
type secretResolver interface {
	Unknown(ctx context.Context, names []string) ([]string, error)
	Resolve(ctx context.Context, names []string) ([]profile.Secret, error)
}

// apiURLNotes keeps the API URL a launch carried.
type apiURLNotes interface {
	Note(ctx context.Context, apiURL string)
}

// provider serves Kandev's executor provider calls.
type provider struct {
	host     kandev.Provider
	connect  connector
	registry registryReader
	policy   policyReader
	secrets  secretResolver
	status   statusReader
	apiURL   apiURLNotes
	healer   sandbox.Healer
	now      func() time.Time
}

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

// sdkError is a sandbox failure as Kandev receives it.
func sdkError(f *sandbox.Failure) *pluginsdk.ExecutorProviderError {
	if f == nil {
		return nil
	}
	out := providerError(f.Code, f.MessageID)
	out.RetryAfterSeconds = f.RetryAfterSeconds
	return out
}

// providerFailure turns an msbctl or transport error into a provider error.
func providerFailure(err error, messageID string) *pluginsdk.ExecutorProviderError {
	return sdkError(sandbox.FailureOf(err, messageID))
}

func fieldError(p profile.FieldError) *pluginsdk.ExecutorProviderFieldError {
	return &pluginsdk.ExecutorProviderFieldError{Field: p.Field, Code: p.Code, MessageId: p.MessageID()}
}

// validate checks a sandbox definition and that its placement selects at
// least one registered, non-draining host. It reads only the plugin's own
// state (registry, egress policy, secrets, host status): nothing is
// allocated and no host is contacted.
//
// Kandev also calls it with an empty config to probe the contract when the
// plugin activates, possibly before the Host broker is up. That must produce
// field errors and capabilities, never a Go error.
func (p *provider) validate(ctx context.Context, req *pluginsdk.ValidateExecutorProfileRequest) *pluginsdk.ValidateExecutorProfileResponse {
	config := req.GetProfile().GetConfig()
	if config == nil {
		config = map[string]string{}
	}
	spec, problems := profile.Parse(config, req.GetProfile().GetSecretValues())
	response := &pluginsdk.ValidateExecutorProfileResponse{Capabilities: capabilities()}
	for _, problem := range problems {
		response.FieldErrors = append(response.FieldErrors, fieldError(problem))
	}
	if spec.Placement.Kind == "" {
		return response
	}
	more, unavailable := p.resolveReferences(ctx, spec)
	for _, problem := range more {
		response.FieldErrors = append(response.FieldErrors, fieldError(problem))
	}
	if unavailable != "" {
		response.Error = providerError(msbctl.CodeUnavailable, unavailable)
	}
	return response
}

// resolveReferences checks what a profile names in the plugin's state: hosts,
// egress groups, secrets and private names. A state that cannot be read
// stops the check, with the message id to report; what was found until then
// is still returned.
func (p *provider) resolveReferences(ctx context.Context, spec profile.Spec) ([]profile.FieldError, string) {
	var problems []profile.FieldError
	unresolved := func(field, code string) { problems = append(problems, profile.FieldError{Field: field, Code: code}) }
	registry, err := p.registry.Load(ctx)
	if err != nil {
		log.Printf("validate executor profile: %v", err)
		return nil, "registryUnavailable"
	}
	candidates := registry.Candidates(spec.Placement)
	if len(candidates) == 0 {
		unresolved(profile.FieldPlacement, CodeUnresolved)
	}
	policy, err := p.policy.Load(ctx)
	if err != nil {
		log.Printf("validate executor profile: %v", err)
		return problems, "egressUnavailable"
	}
	if _, err := policy.Expand(spec.EgressGroups, spec.EgressAllow); err != nil {
		code := CodeUnresolved
		if !errors.Is(err, egress.ErrUnknown) {
			code = profile.CodeInvalid
		}
		unresolved(profile.FieldEgressGroups, code)
	}
	unknown, err := p.secrets.Unknown(ctx, spec.SecretNames)
	if err != nil {
		log.Printf("validate executor profile: %v", err)
		return problems, "secretsUnavailable"
	}
	if len(unknown) > 0 {
		unresolved(profile.FieldSecrets, CodeUnresolved)
	}
	if len(spec.PrivateNames) > 0 && !p.privateNamesServed(ctx, candidates, spec.PrivateNames) {
		unresolved(profile.FieldPrivateNames, CodeUnsupported)
	}
	return problems, ""
}

// privateNamesServed reports whether some candidate takes names, by its last
// check rather than a live probe: validation contacts no host. A host never
// checked does not count. Placement checks again, live.
func (p *provider) privateNamesServed(ctx context.Context, candidates []hosts.Host, names []string) bool {
	status, err := p.status.Load(ctx)
	if err != nil {
		log.Printf("validate executor profile: %v", err)
		return false
	}
	for _, h := range candidates {
		if s, ok := status[h.Name]; ok && s.Health != nil && s.Health.AllowsPrivateNames(names) {
			return true
		}
	}
	return false
}
