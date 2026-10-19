package plugin

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// Maintenance cadence. A pass is one health call per host, so it runs often
// enough for the host list's status to be recent; certificate care inside
// it only acts when a certificate is 30 days from expiry. The first pass
// runs soon after start so a fresh install heals without waiting.
const (
	maintainFirst = time.Minute
	maintainEvery = 15 * time.Minute
	// maintainHostTimeout bounds one host's health check plus install.
	maintainHostTimeout = 45 * time.Second
)

// SetHost stores the Host and starts the maintainer. Kandev calls it once,
// from a background goroutine, after the broker connection is up.
func (r *Runtime) SetHost(h pluginsdk.Host) {
	r.UnimplementedPlugin.SetHost(h)
	r.startMaintainer()
}

func (r *Runtime) startMaintainer() {
	r.maintMu.Lock()
	defer r.maintMu.Unlock()
	if r.maintEvery <= 0 || r.maintCancel != nil || r.closed {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.maintCancel = cancel
	r.maintWG.Add(1)
	go func() {
		defer r.maintWG.Done()
		timer := time.NewTimer(r.maintFirst)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			r.maintainHosts(ctx)
			timer.Reset(r.maintEvery)
		}
	}()
}

// stopMaintainer cancels the maintainer and waits for it to finish.
func (r *Runtime) stopMaintainer() {
	r.maintMu.Lock()
	r.closed = true
	cancel := r.maintCancel
	r.maintCancel = nil
	r.maintMu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.maintWG.Wait()
}

// maintainHosts is one pass: every registered host, draining ones included
// (they still serve their sessions), is checked as Test does, which gives a
// proxy host a valid certificate, and its status is kept for hosts.list. An
// unreachable host is retried next pass. It returns what certificate care
// did per host, for tests and logs.
func (r *Runtime) maintainHosts(ctx context.Context) map[string]tlsOutcome {
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		if !errors.Is(err, ErrNoHost) {
			log.Printf("maintain: %v", err)
		}
		return nil
	}
	client, err := r.client(ctx)
	if err != nil {
		log.Printf("maintain: %v", err)
		return nil
	}
	outcomes := map[string]tlsOutcome{}
	for _, h := range registry.Hosts {
		if ctx.Err() != nil {
			return outcomes
		}
		hostCtx, cancel := context.WithTimeout(ctx, maintainHostTimeout)
		result := r.checkHost(hostCtx, client, h)
		cancel()
		outcomes[h.Name] = result.outcome
		r.recordStatus(ctx, h.Name, result)
	}
	return outcomes
}
