package plugin

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// The last check of each host, by name, kept in Host state so the host list
// shows it without an SSH round trip per host. It is written by Test and by
// every maintainer pass, and holds nothing secret: a health report, the
// diagnosis and when it was made.
const statusStateKey = "status"

type hostStatus struct {
	CheckedAt string `json:"checked_at"`
	testResult
}

func (r *Runtime) loadStatus(ctx context.Context) (map[string]hostStatus, error) {
	h, err := r.host()
	if err != nil {
		return nil, err
	}
	value, found, err := h.GetState(ctx, stateScope, "", statusStateKey)
	if err != nil || !found {
		return map[string]hostStatus{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	out := map[string]hostStatus{}
	if err := json.Unmarshal(raw, &out); err != nil {
		// A status is a cache: an unreadable one is replaced, not fatal.
		return map[string]hostStatus{}, nil
	}
	return out, nil
}

// mutateStatus applies change under statusMu; failures are logged, since a
// status is only ever a convenience for the operator.
func (r *Runtime) mutateStatus(ctx context.Context, change func(map[string]hostStatus)) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	all, err := r.loadStatus(ctx)
	if err != nil {
		log.Printf("status: %v", err)
		return
	}
	change(all)
	raw, err := json.Marshal(all)
	if err != nil {
		log.Printf("status: %v", err)
		return
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		log.Printf("status: %v", err)
		return
	}
	h, err := r.host()
	if err != nil {
		return
	}
	if err := h.SetState(ctx, stateScope, "", statusStateKey, value); err != nil {
		log.Printf("status: %v", err)
	}
}

func (r *Runtime) recordStatus(ctx context.Context, name string, result testResult) {
	r.mutateStatus(ctx, func(all map[string]hostStatus) {
		all[name] = hostStatus{CheckedAt: r.now().UTC().Format(time.RFC3339), testResult: result}
	})
}

func (r *Runtime) forgetStatus(ctx context.Context, name string) {
	r.mutateStatus(ctx, func(all map[string]hostStatus) { delete(all, name) })
}
