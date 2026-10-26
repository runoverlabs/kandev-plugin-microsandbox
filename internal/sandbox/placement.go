package sandbox

import (
	"context"
	"errors"
	"sync/atomic"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/profile"
)

// Host is a sandbox host as placement and recovery reach it.
type Host interface {
	hostcheck.Host
	FindOperation(ctx context.Context, h hosts.Host, operationID string) (msbctl.Record, bool, error)
}

// Healer gives a proxy host a valid certificate (hostcheck.Checker.Heal).
type Healer interface {
	Heal(ctx context.Context, api hostcheck.Host, h hosts.Host, health msbctl.Health) hostcheck.TLSOutcome
}

// PlaceOrReuse returns the host that already holds this operation, if any
// candidate does, so a retried provision never lands on a second host;
// otherwise it places a new sandbox.
func PlaceOrReuse(ctx context.Context, api Host, healer Healer, candidates []hosts.Host, spec profile.Spec, operationID string) (hosts.Host, *Failure) {
	if found := FindOperation(ctx, api, candidates, operationID); found.OK {
		return found.Host, nil
	}
	prober := &prober{api: api, healer: healer, privateNames: spec.PrivateNames}
	host, err := hosts.Place(ctx, candidates, prober, hosts.Demand{CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB})
	switch {
	case err == nil:
		return host, nil
	case errors.Is(err, hosts.ErrUnreachable) && int(prober.refused.Load()) == len(candidates):
		// Every candidate answered, and none takes this profile's private
		// names: a profile or host configuration problem, not an outage.
		return hosts.Host{}, Fail(msbctl.CodeInvalidConfig, "privateNamesUnsupported")
	case errors.Is(err, hosts.ErrAllFull):
		return hosts.Host{}, &Failure{Code: msbctl.CodeRateLimited, MessageID: "hostsFull", RetryAfterSeconds: 30}
	case errors.Is(err, hosts.ErrNoCandidates):
		return hosts.Host{}, Fail(msbctl.CodeInvalidConfig, "placementUnresolved")
	default:
		return hosts.Host{}, Fail(msbctl.CodeUnavailable, "hostsUnreachable")
	}
}

// prober heals a proxy host's certificate before it is counted as a
// candidate, so a host whose certificate lapsed takes sessions again as soon
// as it is asked to. A host that does not take the profile's private names
// is no candidate; refused counts them.
type prober struct {
	api          Host
	healer       Healer
	privateNames []string
	refused      atomic.Int32
}

func (p *prober) Capacity(ctx context.Context, h hosts.Host) (hosts.Capacity, error) {
	health, err := p.api.Health(ctx, h)
	if err != nil {
		return hosts.Capacity{}, err
	}
	if health.Serve.Mode == msbctl.ServeProxy && !health.Serve.OK {
		if outcome := p.healer.Heal(ctx, p.api, h, health); outcome.State == hostcheck.TLSRenewed {
			if health, err = p.api.Health(ctx, h); err != nil {
				return hosts.Capacity{}, err
			}
		}
	}
	if !health.Usable() {
		return hosts.Capacity{}, &msbctl.Error{Code: msbctl.CodeUnavailable}
	}
	if !health.AllowsPrivateNames(p.privateNames) {
		p.refused.Add(1)
		return hosts.Capacity{}, &msbctl.Error{Code: msbctl.CodeUnsupported}
	}
	return health.Capacity, nil
}

// Found is where an operation's sandbox is, if anywhere.
type Found struct {
	OK      bool
	Host    hosts.Host
	Record  msbctl.Record
	Unknown bool // some host could not answer
}

// Operations is the one verb FindOperation needs.
type Operations interface {
	FindOperation(ctx context.Context, h hosts.Host, operationID string) (msbctl.Record, bool, error)
}

// FindOperation asks each host for the operation, in parallel.
func FindOperation(ctx context.Context, api Operations, candidates []hosts.Host, operationID string) Found {
	type answer struct {
		host hosts.Host
		rec  msbctl.Record
		err  error
	}
	answers := make(chan answer, len(candidates))
	for _, h := range candidates {
		go func() {
			findCtx, cancel := context.WithTimeout(ctx, hosts.ProbeTimeout)
			defer cancel()
			rec, ok, err := api.FindOperation(findCtx, h, operationID)
			if err == nil && !ok {
				err = &msbctl.Error{Code: msbctl.CodeNotFound}
			}
			answers <- answer{h, rec, err}
		}()
	}
	var out Found
	for range candidates {
		a := <-answers
		switch {
		case a.err == nil && !out.OK:
			out.OK, out.Host, out.Record = true, a.host, a.rec
		case a.err != nil && msbctl.CodeOf(a.err) != msbctl.CodeNotFound:
			out.Unknown = true
		}
	}
	return out
}

// Recovery outcomes, as Kandev names them.
const (
	RecoverFound   = "found"
	RecoverAbsent  = "absent"
	RecoverUnknown = "unknown"
)

// Recovered is what a provision whose reply was lost resolves to: found on
// exactly one host, absent from every host, or unknown while any host cannot
// answer. A sandbox found for the operation but made from another input is a
// conflict. Kandev never mints a new operation to escape "unknown".
func Recovered(found Found, op Operation) (string, *Failure) {
	switch {
	case found.OK && (found.Record.Env != op.Environment || found.Record.InputDigest != op.InputDigest):
		return "", Fail(msbctl.CodeConflict, "operationMismatch")
	case found.OK:
		return RecoverFound, nil
	case found.Unknown:
		return RecoverUnknown, nil
	default:
		return RecoverAbsent, nil
	}
}
