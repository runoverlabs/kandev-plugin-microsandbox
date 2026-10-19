package plugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/hostsetup"
	"kandev-plugin-microsandbox/internal/sshx"
)

// Host setup action keys, matching manifest.yaml.
const (
	ActionHostsSetup       = "hosts.setup"
	ActionHostsSetupStatus = "hosts.setup.status"
)

// Kandev gives an action 15 seconds, and a setup downloads and installs, so
// hosts.setup starts a job and hosts.setup.status follows it.
const (
	setupTimeout = 20 * time.Minute
	// setupKeep is how long a finished job can still be read.
	setupKeep = time.Hour
)

// Plugin-side steps that follow the machine's own.
const (
	stepRegister = "register"
	stepTest     = "test"
)

// setupRequest carries the admin login. It is decoded, handed to the
// job, and never stored, logged or echoed back.
type setupRequest struct {
	Name               string   `json:"name"`
	SSH                string   `json:"ssh"`
	HostKey            string   `json:"host_key"`
	AdminKey           string   `json:"admin_key"`
	AdminKeyPassphrase string   `json:"admin_key_passphrase"`
	AdminPassword      string   `json:"admin_password"`
	BaseURL            string   `json:"base_url"`
	Labels             []string `json:"labels"`
	Account            string   `json:"account"`
	EgressFromPlugin   bool     `json:"egress_from_plugin"`
	KandevAddress      string   `json:"kandev_address"`
}

// setupJob is one run, as hosts.setup.status shows it.
type setupJob struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	State      string           `json:"state"` // running, done, failed
	Steps      []hostsetup.Step `json:"steps"`
	Manual     []string         `json:"manual,omitempty"`
	Host       *hostView        `json:"host,omitempty"`
	Test       *testResult      `json:"test,omitempty"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at,omitempty"`
	finished   time.Time
}

const (
	jobRunning = "running"
	jobDone    = "done"
	jobFailed  = "failed"
)

// jobs holds host setup jobs in memory only: a job carries nothing worth
// keeping across a restart, and a setup interrupted by one is run again.
type jobs struct {
	mu     sync.Mutex
	byID   map[string]*setupJob
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (j *jobs) init() {
	if j.byID == nil {
		j.byID = map[string]*setupJob{}
		j.ctx, j.cancel = context.WithCancel(context.Background())
	}
}

// stop cancels every running job and waits for them.
func (j *jobs) stop() {
	j.mu.Lock()
	j.init()
	j.cancel()
	j.mu.Unlock()
	j.wg.Wait()
}

func (j *jobs) snapshot(id string) (setupJob, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job, found := j.byID[id]
	if !found {
		return setupJob{}, false
	}
	out := *job
	out.Steps = append([]hostsetup.Step(nil), job.Steps...)
	return out, true
}

func (j *jobs) update(id string, change func(*setupJob)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, found := j.byID[id]; found {
		change(job)
	}
}

func (r *Runtime) actionSetup(ctx context.Context, body []byte) response {
	var in setupRequest
	if err := decode(body, &in); err != nil {
		return fail(http.StatusUnprocessableEntity, `expected {"name", "ssh": "admin@host[:port]", "host_key", "admin_key" or "admin_password", "base_url", "labels", "account", "egress_from_plugin"}`)
	}
	auth := sshx.AdminAuth{PrivateKeyPEM: in.AdminKey, Passphrase: in.AdminKeyPassphrase, Password: in.AdminPassword}
	in.AdminKey, in.AdminKeyPassphrase, in.AdminPassword = "", "", ""
	if auth.PrivateKeyPEM == "" && auth.Password == "" {
		return fail(http.StatusUnprocessableEntity, "give the admin login: admin_key (a private key) or admin_password; it is used for this setup only and never stored")
	}
	_, sshHost, sshPort, err := hosts.ParseSSH(strings.TrimSpace(in.SSH))
	if err != nil {
		return fail(http.StatusUnprocessableEntity, "ssh: "+err.Error())
	}
	// The host as it will be registered, checked now so a setup is never
	// run for a host that could not then be added. The account is a
	// placeholder until the machine says which one msb-manager runs under.
	planned := hosts.Normalize(hosts.Host{Name: in.Name, SSH: "msb@" + bracketHost(sshHost, sshPort), HostKey: in.HostKey, BaseURL: in.BaseURL, Labels: in.Labels})
	if planned.BaseURL == "" {
		planned.BaseURL = "https://" + bracketHost(sshHost, 0)
	}
	if err := hosts.Validate(planned); err != nil {
		var invalid *hosts.ValidationError
		if errors.As(err, &invalid) {
			return validationFailure(invalid)
		}
		return fail(http.StatusUnprocessableEntity, err.Error())
	}
	if res, refused := r.refuseOutsideRoot(ctx, planned); refused {
		return res
	}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return internalFailure(ActionHostsSetup, err)
	}
	// Running setup again repairs a registered host, but only the same
	// machine: a name is permanent in every sandbox's resource state.
	if existing, found := registry.Find(planned.Name); found {
		if _, existingHost, existingPort, _ := hosts.ParseSSH(existing.SSH); existingHost != sshHost || existingPort != sshPort {
			return fail(http.StatusConflict, "a host named "+planned.Name+" is registered at another address")
		}
	}
	_, publicKey, err := r.key(ctx)
	if err != nil {
		return internalFailure(ActionHostsSetup, err)
	}

	r.jobs.mu.Lock()
	r.jobs.init()
	r.pruneJobs()
	for _, job := range r.jobs.byID {
		if job.Name == planned.Name && job.State == jobRunning {
			r.jobs.mu.Unlock()
			return fail(http.StatusConflict, "a setup of "+planned.Name+" is already running: job "+job.ID)
		}
	}
	if r.jobs.ctx.Err() != nil {
		r.jobs.mu.Unlock()
		return fail(http.StatusServiceUnavailable, "the plugin is stopping")
	}
	id := newJobID()
	job := &setupJob{ID: id, Name: planned.Name, State: jobRunning, Steps: plannedSteps(), StartedAt: r.now().UTC().Format(time.RFC3339)}
	r.jobs.byID[id] = job
	jobCtx, cancel := context.WithTimeout(r.jobs.ctx, setupTimeout)
	r.jobs.wg.Add(1)
	r.jobs.mu.Unlock()

	input := hostsetup.Input{
		PublicKey: publicKey, SSHHost: sshHost, SSHPort: sshPort, BaseURL: in.BaseURL,
		Account: in.Account, EgressFromPlugin: in.EgressFromPlugin, KandevAddress: in.KandevAddress,
	}
	go func() {
		defer r.jobs.wg.Done()
		defer cancel()
		r.runSetup(jobCtx, id, strings.TrimSpace(in.SSH), planned, auth, input)
	}()
	snapshot, _ := r.jobs.snapshot(id)
	return response{http.StatusAccepted, snapshot}
}

func bracketHost(host string, port int) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != 0 && port != 22 {
		return host + ":" + strconv.Itoa(port)
	}
	return host
}

func newJobID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func plannedSteps() []hostsetup.Step {
	steps := hostsetup.Steps()
	steps = append(steps,
		hostsetup.Step{Key: stepRegister, Title: "Register the host with the plugin"},
		hostsetup.Step{Key: stepTest, Title: "Issue its certificate and run Test"})
	for i := range steps {
		steps[i].State = hostsetup.StateSkipped
	}
	return steps
}

// pruneJobs drops finished jobs past setupKeep. Callers hold jobs.mu.
func (r *Runtime) pruneJobs() {
	for id, job := range r.jobs.byID {
		if job.State != jobRunning && r.now().Sub(job.finished) > setupKeep {
			delete(r.jobs.byID, id)
		}
	}
}

// runSetup is the job: set the machine up over the admin login, drop
// the login, then register the host and test it with the plugin's own key.
func (r *Runtime) runSetup(ctx context.Context, id, adminDest string, planned hosts.Host, auth sshx.AdminAuth, input hostsetup.Input) {
	finish := func(state string, change func(*setupJob)) {
		r.jobs.update(id, func(j *setupJob) {
			if change != nil {
				change(j)
			}
			j.State, j.finished = state, r.now()
			j.FinishedAt = j.finished.UTC().Format(time.RFC3339)
		})
	}
	setStep := func(key, state, detail string) {
		r.jobs.update(id, func(j *setupJob) {
			for i := range j.Steps {
				if j.Steps[i].Key == key {
					j.Steps[i].State, j.Steps[i].Detail = state, detail
				}
			}
		})
	}
	admin, err := sshx.DialAdmin(ctx, r.dialer, adminDest, planned.HostKey, auth)
	auth = sshx.AdminAuth{}
	if err != nil {
		log.Printf("%s %s: %v", ActionHostsSetup, planned.Name, err)
		setStep(hostsetup.StepProbe, hostsetup.StateFailed, adminDialFailure(err))
		finish(jobFailed, nil)
		return
	}
	progress := func(steps []hostsetup.Step) {
		r.jobs.update(id, func(j *setupJob) { copy(j.Steps, steps) })
	}
	result := hostsetup.Run(ctx, admin, input, progress)
	admin.Close()
	r.jobs.update(id, func(j *setupJob) {
		copy(j.Steps, result.Steps)
		j.Manual = result.Manual
	})
	if !result.OK {
		finish(jobFailed, nil)
		return
	}

	h := planned
	h.SSH, h.BaseURL = result.SSH, result.BaseURL
	registry, err := r.mutateRegistry(ctx, func(reg hosts.Registry) (hosts.Registry, error) {
		if _, found := reg.Find(h.Name); found {
			return reg.Update(h)
		}
		return reg.Add(h)
	})
	if err != nil {
		log.Printf("%s %s: register: %v", ActionHostsSetup, h.Name, err)
		detail := "The host is set up but could not be registered."
		var invalid *hosts.ValidationError
		if errors.As(err, &invalid) || errors.Is(err, hosts.ErrTooMany) {
			detail += " " + err.Error()
		}
		setStep(stepRegister, hostsetup.StateFailed, detail)
		finish(jobFailed, nil)
		return
	}
	saved, _ := registry.Find(h.Name)
	setStep(stepRegister, hostsetup.StateChanged, "Registered as "+saved.Name+", reached at "+saved.SSH+".")

	client, err := r.client(ctx)
	if err != nil {
		setStep(stepTest, hostsetup.StateFailed, "The plugin's key is unavailable.")
		finish(jobFailed, nil)
		return
	}
	test := r.checkHost(ctx, client, saved)
	r.recordStatus(ctx, saved.Name, test)
	view := viewOf(saved)
	state, detail := hostsetup.StateOK, "Test passes: the host is ready for sandboxes."
	if !test.OK {
		state, detail = hostsetup.StateManual, "Test reports "+test.Problem+": "+test.Hint
	}
	setStep(stepTest, state, detail)
	finish(jobDone, func(j *setupJob) { j.Host, j.Test = &view, &test })
}

func adminDialFailure(err error) string {
	switch {
	case errors.Is(err, sshx.ErrAdminAuth):
		return strings.TrimPrefix(err.Error(), sshx.ErrAdminAuth.Error()+": ") + "."
	case errors.Is(err, sshx.ErrHostKeyMismatch):
		return "The machine presented a different SSH host key than the one confirmed. Verify it before trying again."
	case errors.Is(err, sshx.ErrNotAuthorized):
		return "The machine refused the admin login."
	default:
		return "Could not reach the machine's SSH server."
	}
}

func (r *Runtime) actionSetupJobStatus(_ context.Context, body []byte) response {
	var in struct {
		ID string `json:"id"`
	}
	if err := decode(body, &in); err != nil || in.ID == "" {
		return fail(http.StatusUnprocessableEntity, `expected {"id": "..."}`)
	}
	r.jobs.mu.Lock()
	r.jobs.init()
	r.pruneJobs()
	r.jobs.mu.Unlock()
	job, found := r.jobs.snapshot(in.ID)
	if !found {
		return fail(http.StatusNotFound, "no such setup job; finished jobs are kept for an hour, and none survives a plugin restart")
	}
	return ok(job)
}
