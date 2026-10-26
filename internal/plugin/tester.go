package plugin

import (
	"context"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
)

// statusWriter keeps the hosts' last checks.
type statusWriter interface {
	Record(ctx context.Context, name string, result hostcheck.Result)
	Forget(ctx context.Context, name string)
}

// statusTester runs Test on a host and keeps the result as its status, for
// hosts.test and for the end of a setup or an upgrade.
type statusTester struct {
	connect connector
	checker *hostcheck.Checker
	status  statusWriter
}

func (t *statusTester) Test(ctx context.Context, h hosts.Host) (hostcheck.Result, error) {
	client, err := t.connect(ctx)
	if err != nil {
		return hostcheck.Result{}, err
	}
	result := t.checker.Check(ctx, client, h)
	t.status.Record(ctx, h.Name, result)
	return result, nil
}

func (t *statusTester) Forget(ctx context.Context, name string) { t.status.Forget(ctx, name) }
