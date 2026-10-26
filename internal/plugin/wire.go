package plugin

import (
	"context"
	"maps"
	"net"
	"os"
	"time"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/pki"
	"kandev-plugin-microsandbox/internal/readiness"
	"kandev-plugin-microsandbox/internal/remote"
	"kandev-plugin-microsandbox/internal/sshx"
	"kandev-plugin-microsandbox/internal/store"
)

// NewRuntime returns a Runtime dialing hosts over the network. It is the
// composition root: the one place that builds the adapters (the Kandev
// state stores, the SSH keyring, the msbctl client) and hands each handler
// the ports it uses.
func NewRuntime() *Runtime {
	r := &Runtime{dialer: &net.Dialer{}, now: time.Now, getenv: os.Getenv}
	host := kandev.Provider(r.Host)
	now := func() time.Time { return r.now() }

	registry := store.NewRegistry(host)
	ca := store.NewCA(host, now)
	r.registry, r.status, r.ca = registry, store.NewStatus(host, now), ca
	policy := store.NewEgress(host)
	secretStore := store.NewSecrets(host, now)
	apiURL := store.NewAPIURL(host, now)

	keys := sshx.NewKeyring(store.NewSSHKey(host), r.dialer)
	r.keys = keys
	hostKeys := sshx.HostKeys{Dialer: r.dialer}
	r.connect = func(ctx context.Context) (*msbctl.Client, error) {
		pool, err := keys.Pool(ctx)
		if err != nil {
			return nil, err
		}
		return msbctl.New(pool), nil
	}
	trusted := func(root *pki.Root) error { return root.Trusted(r.trustPool, r.now()) }

	checker := &hostcheck.Checker{
		Roots: r.ca, Egress: policy, Trusted: trusted, Now: now,
		PublicKey: func(ctx context.Context) string { key, _ := keys.PublicKey(ctx); return key },
	}
	tester := &statusTester{connect: r.connect, checker: checker, status: r.status}
	scope := &rootScope{roots: r.ca}
	r.jobs = hostsetup.NewJobs(now)
	manager := &hostsetup.Manager{
		Jobs: r.jobs, Registry: r.registry, Test: tester.Test,
		Dial: func(ctx context.Context, dest, hostKey string, auth remote.AdminAuth) (hostsetup.Session, error) {
			return sshx.DialAdmin(ctx, r.dialer, dest, hostKey, auth)
		},
		Connect: func(ctx context.Context) (hostsetup.HostAPI, error) { return r.connect(ctx) },
	}

	r.maintainer = maintainer{
		registry: r.registry, connect: r.connect, checker: checker, record: r.status,
		maintFirst: maintainFirst, maintEvery: maintainEvery,
	}
	r.provider = &provider{
		host: host, connect: r.connect, registry: r.registry, policy: policy, secrets: secretStore,
		status: r.status, apiURL: apiURL, healer: checker, now: now,
	}
	r.actions = merge(
		(&hostActions{
			registry: r.registry, status: r.status, keys: keys, connect: r.connect, tester: tester, scope: scope,
			healer: &healAfterWrite{roots: r.ca, connect: r.connect, checker: checker}, hostKeys: hostKeys,
		}).routes(),
		(&caActions{roots: r.ca, trusted: trusted}).routes(),
		(&secretActions{secrets: secretStore}).routes(),
		(&egressActions{policy: policy}).routes(),
		(&jobActions{manager: manager, jobs: r.jobs, registry: r.registry, keys: keys, connect: r.connect, scope: scope, hostKeys: hostKeys}).routes(),
		(&readinessAction{report: readiness.Report{
			Root: ca.Root, Trusted: trusted, Getenv: func(name string) string { return r.getenv(name) },
			SeenAPI: func(ctx context.Context) (string, string, error) {
				seen, err := apiURL.Load(ctx)
				return seen.URL, seen.SeenAt, err
			},
			Registry: func(ctx context.Context) (hosts.Registry, error) { return r.registry.Load(ctx) },
			Status:   func(ctx context.Context) (map[string]hostcheck.Status, error) { return r.status.Load(ctx) },
		}}).routes(),
	)
	return r
}

func merge(tables ...map[string]actionFunc) map[string]actionFunc {
	out := map[string]actionFunc{}
	for _, table := range tables {
		maps.Copy(out, table)
	}
	return out
}
