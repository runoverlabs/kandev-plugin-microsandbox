package plugin

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// Maintenance cadence. Host certificates last 90 days and are renewed 30
// days out, so a 6 h pass leaves a wide margin for hosts that are down for a
// while; the first pass runs soon after start so a fresh install heals
// without waiting.
const (
	maintainFirst = time.Minute
	maintainEvery = 6 * time.Hour
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
// (they still serve their sessions), gets a valid certificate if it runs the
// proxy. An unreachable host is skipped and retried next pass. It returns
// what happened per host, for tests and logs.
func (r *Runtime) maintainHosts(ctx context.Context) map[string]tlsOutcome {
	if _, err := r.root(ctx); err != nil {
		if !errors.Is(err, errNoRoot) && !errors.Is(err, ErrNoHost) {
			log.Printf("maintain: %v", err)
		}
		return nil
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		log.Printf("maintain: %v", err)
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
		health, err := client.Health(hostCtx, h)
		if err != nil {
			outcomes[h.Name] = tlsOutcome{State: tlsFailed, Reason: "unreachable"}
		} else {
			outcomes[h.Name] = r.healTLS(hostCtx, client, h, health)
		}
		cancel()
	}
	return outcomes
}
