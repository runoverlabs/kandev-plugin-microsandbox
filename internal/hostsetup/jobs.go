package hostsetup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
)

// keepFinished is how long a finished job can still be read.
const keepFinished = time.Hour

// Job states.
const (
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// Job is one setup or upgrade run, as hosts.setup.status shows it.
type Job struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	State      string            `json:"state"` // running, done, failed
	Steps      []Step            `json:"steps"`
	Manual     []string          `json:"manual,omitempty"`
	Host       *hosts.Host       `json:"host,omitempty"`
	Test       *hostcheck.Result `json:"test,omitempty"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at,omitempty"`
	finished   time.Time
}

// ErrStopping refuses a job while the plugin shuts down.
var ErrStopping = errors.New("the plugin is stopping")

// BusyError refuses a second job for a host while one runs: setup and
// upgrade both change it.
type BusyError struct{ Name, ID string }

func (e *BusyError) Error() string { return "a job for " + e.Name + " is already running: " + e.ID }

// Jobs holds jobs in memory only: a job carries nothing worth keeping across
// a restart, and a setup interrupted by one is run again.
type Jobs struct {
	now func() time.Time

	mu     sync.Mutex
	byID   map[string]*Job
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewJobs returns an empty job table.
func NewJobs(now func() time.Time) *Jobs {
	ctx, cancel := context.WithCancel(context.Background())
	return &Jobs{now: now, byID: map[string]*Job{}, ctx: ctx, cancel: cancel}
}

// Start runs fn as a job for host name, at most one running per host, and
// returns its id.
func (j *Jobs) Start(name string, steps []Step, timeout time.Duration, fn func(ctx context.Context, id string)) (string, error) {
	j.mu.Lock()
	j.prune()
	for _, job := range j.byID {
		if job.Name == name && job.State == JobRunning {
			j.mu.Unlock()
			return "", &BusyError{Name: name, ID: job.ID}
		}
	}
	if j.ctx.Err() != nil {
		j.mu.Unlock()
		return "", ErrStopping
	}
	id := newJobID()
	j.byID[id] = &Job{ID: id, Name: name, State: JobRunning, Steps: steps, StartedAt: j.now().UTC().Format(time.RFC3339)}
	jobCtx, cancel := context.WithTimeout(j.ctx, timeout)
	j.wg.Add(1)
	j.mu.Unlock()
	go func() {
		defer j.wg.Done()
		defer cancel()
		fn(jobCtx, id)
	}()
	return id, nil
}

// Stop cancels every running job and waits for them.
func (j *Jobs) Stop() {
	// Under the lock, so a Start either registers before the cancel, and is
	// waited for, or sees it and refuses.
	j.mu.Lock()
	j.cancel()
	j.mu.Unlock()
	j.wg.Wait()
}

// Snapshot returns a copy of the job, unless it is unknown or was dropped
// after keepFinished.
func (j *Jobs) Snapshot(id string) (Job, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	job, found := j.byID[id]
	if !found {
		return Job{}, false
	}
	out := *job
	out.Steps = append([]Step(nil), job.Steps...)
	return out, true
}

// update applies change to a job under the lock.
func (j *Jobs) update(id string, change func(*Job)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, found := j.byID[id]; found {
		change(job)
	}
}

// setStep sets one step's state and detail.
func (j *Jobs) setStep(id, key, state, detail string) {
	j.update(id, func(job *Job) {
		for i := range job.Steps {
			if job.Steps[i].Key == key {
				job.Steps[i].State, job.Steps[i].Detail = state, detail
			}
		}
	})
}

// finish ends a job in state, after change.
func (j *Jobs) finish(id, state string, change func(*Job)) {
	j.update(id, func(job *Job) {
		if change != nil {
			change(job)
		}
		job.State, job.finished = state, j.now()
		job.FinishedAt = job.finished.UTC().Format(time.RFC3339)
	})
}

// prune drops finished jobs past keepFinished. Callers hold mu.
func (j *Jobs) prune() {
	for id, job := range j.byID {
		if job.State != JobRunning && j.now().Sub(job.finished) > keepFinished {
			delete(j.byID, id)
		}
	}
}

func newJobID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
