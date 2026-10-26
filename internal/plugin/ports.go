package plugin

import (
	"context"

	"kandev-plugin-microsandbox/internal/egress"
	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/pki"
)

// The ports the handlers share, each implemented by internal/store or by the
// keyring and msbctl client wire.go builds. A handler holds only the ones it
// uses.

// registryReader reads the host registry.
type registryReader interface {
	Load(ctx context.Context) (hosts.Registry, error)
}

// registryWriter changes the host registry under its lock.
type registryWriter interface {
	registryReader
	Mutate(ctx context.Context, change func(hosts.Registry) (hosts.Registry, error)) (hosts.Registry, error)
}

// statusReader reads the hosts' last checks.
type statusReader interface {
	Load(ctx context.Context) (map[string]hostcheck.Status, error)
}

// statusStore reads and keeps the hosts' last checks.
type statusStore interface {
	statusReader
	statusWriter
}

// rootReader is the plugin's root; pki.ErrNoRoot until one is created.
type rootReader interface {
	Root(ctx context.Context) (*pki.Root, error)
}

// policyReader is the plugin-wide egress policy.
type policyReader interface {
	Load(ctx context.Context) (egress.Policy, error)
}

// publicKeys is the plugin's SSH key line, generated on first use.
type publicKeys interface {
	PublicKey(ctx context.Context) (string, error)
}

// connector reaches sandbox hosts with the plugin's key. It fails only when
// the key is unavailable.
type connector func(ctx context.Context) (*msbctl.Client, error)

// hostTester runs Test on a host and keeps the result as its status.
type hostTester interface {
	Test(ctx context.Context, h hosts.Host) (hostcheck.Result, error)
	Forget(ctx context.Context, name string)
}

// hostKeys scans, checks and fingerprints SSH host keys.
type hostKeys interface {
	Scan(ctx context.Context, dest string) (string, error)
	Check(line string) error
	Fingerprint(line string) string
}
