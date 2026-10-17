package hosts

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Store persists the registry. There is no compare-and-swap in Kandev's
// Host state, so callers serialize read-modify-write cycles themselves.
type Store interface {
	Load(ctx context.Context) (Registry, error)
	Save(ctx context.Context, r Registry) error
}

// Capacity is what a host reports about its kandev limits. Used counts only
// kandev sandboxes; the operator's own sandboxes on the same host are not
// part of the [kandev] budget.
type Capacity struct {
	MaxSandboxes int `json:"max_sandboxes"`
	Sandboxes    int `json:"sandboxes"`
	MaxCPUs      int `json:"max_cpus"`
	CPUs         int `json:"cpus"`
	MaxMemoryMiB int `json:"max_memory_mib"`
	MemoryMiB    int `json:"memory_mib"`
}

// FreeMemoryMiB is the memory budget left.
func (c Capacity) FreeMemoryMiB() int { return c.MaxMemoryMiB - c.MemoryMiB }

// Fits reports whether one more sandbox of this size is within every limit.
func (c Capacity) Fits(d Demand) bool {
	return c.Sandboxes+1 <= c.MaxSandboxes && c.CPUs+d.CPUs <= c.MaxCPUs && c.MemoryMiB+d.MemoryMiB <= c.MaxMemoryMiB
}

// Demand is the size of the sandbox being placed.
type Demand struct {
	CPUs      int
	MemoryMiB int
}

// Prober asks one host for its current capacity.
type Prober interface {
	Capacity(ctx context.Context, h Host) (Capacity, error)
}

var (
	// ErrNoCandidates means the placement selects no non-draining host.
	ErrNoCandidates = errors.New("placement selects no available host")
	// ErrAllFull means at least one candidate answered but none had room.
	// It is the retryable case: capacity frees up as sandboxes go away.
	ErrAllFull = errors.New("every candidate host is at capacity")
	// ErrUnreachable means no candidate answered at all.
	ErrUnreachable = errors.New("no candidate host is reachable")
)

// ProbeTimeout bounds each capacity probe. It is long enough for a cold SSH
// connection and short enough to leave most of a launch deadline.
const ProbeTimeout = 10 * time.Second

// Place picks the host for a new sandbox among candidates: probe all of them
// in parallel, drop the unreachable and the full, then take the most free
// memory, then the fewest sandboxes, then the name. The host enforces its
// limits again under its own lock, so two concurrent placements that both
// pick the last slot end with one refused, never an overcommit.
func Place(ctx context.Context, candidates []Host, prober Prober, d Demand) (Host, error) {
	if len(candidates) == 0 {
		return Host{}, ErrNoCandidates
	}
	type probe struct {
		host Host
		cap  Capacity
		err  error
	}
	results := make([]probe, len(candidates))
	var wg sync.WaitGroup
	for i, h := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
			defer cancel()
			c, err := prober.Capacity(probeCtx, h)
			results[i] = probe{host: h, cap: c, err: err}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return Host{}, err
	}

	var fitting []probe
	answered := false
	for _, r := range results {
		if r.err != nil {
			continue
		}
		answered = true
		if r.cap.Fits(d) {
			fitting = append(fitting, r)
		}
	}
	if len(fitting) == 0 {
		if answered {
			return Host{}, ErrAllFull
		}
		return Host{}, ErrUnreachable
	}
	sort.Slice(fitting, func(i, j int) bool {
		a, b := fitting[i], fitting[j]
		if a.cap.FreeMemoryMiB() != b.cap.FreeMemoryMiB() {
			return a.cap.FreeMemoryMiB() > b.cap.FreeMemoryMiB()
		}
		if a.cap.Sandboxes != b.cap.Sandboxes {
			return a.cap.Sandboxes < b.cap.Sandboxes
		}
		return a.host.Name < b.host.Name
	})
	return fitting[0].host, nil
}
