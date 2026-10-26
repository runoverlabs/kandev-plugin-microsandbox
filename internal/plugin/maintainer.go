package plugin

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/kandev"
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

// maintainer is the one background goroutine: SetHost starts it, Close
// cancels and drains it, and nothing restarts it after.
type maintainer struct {
	registry registryReader
	connect  connector
	checker  *hostcheck.Checker
	record   statusWriter

	maintMu     sync.Mutex
	maintFirst  time.Duration
	maintEvery  time.Duration // zero disables the maintainer
	maintCancel context.CancelFunc
	maintWG     sync.WaitGroup
	closed      bool
}

func (m *maintainer) startMaintainer() {
	m.maintMu.Lock()
	defer m.maintMu.Unlock()
	if m.maintEvery <= 0 || m.maintCancel != nil || m.closed {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.maintCancel = cancel
	m.maintWG.Add(1)
	go func() {
		defer m.maintWG.Done()
		timer := time.NewTimer(m.maintFirst)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			m.maintainHosts(ctx)
			timer.Reset(m.maintEvery)
		}
	}()
}

// stopMaintainer cancels the maintainer and waits for it to finish.
func (m *maintainer) stopMaintainer() {
	m.maintMu.Lock()
	m.closed = true
	cancel := m.maintCancel
	m.maintCancel = nil
	m.maintMu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.maintWG.Wait()
}

// maintainHosts is one pass: every registered host, draining ones included
// (they still serve their sessions), is checked as Test does, which gives a
// proxy host a valid certificate, and its status is kept for hosts.list. An
// unreachable host is retried next pass. It returns what certificate care
// did per host, for tests and logs.
func (m *maintainer) maintainHosts(ctx context.Context) map[string]hostcheck.TLSOutcome {
	registry, err := m.registry.Load(ctx)
	if err != nil {
		if !errors.Is(err, kandev.ErrNoHost) {
			log.Printf("maintain: %v", err)
		}
		return nil
	}
	client, err := m.connect(ctx)
	if err != nil {
		log.Printf("maintain: %v", err)
		return nil
	}
	outcomes := map[string]hostcheck.TLSOutcome{}
	for _, h := range registry.Hosts {
		if ctx.Err() != nil {
			return outcomes
		}
		hostCtx, cancel := context.WithTimeout(ctx, maintainHostTimeout)
		result := m.checker.Check(hostCtx, client, h)
		cancel()
		outcomes[h.Name] = result.Outcome()
		m.record.Record(ctx, h.Name, result)
	}
	return outcomes
}
