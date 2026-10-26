// Package hostsetup turns a bare Linux machine into a sandbox host over an
// operator's admin SSH login: it checks the machine, installs what
// msb-manager needs, creates the account it runs under, installs msb and
// msb-manager at pinned versions, writes the [kandev] section, starts the
// services, opens the host firewall to the Kandev server, and authorizes
// the plugin's key.
//
// Every step is idempotent, so running it again on a set-up host repairs
// drift and changes nothing else. A step that needs root and has no
// passwordless sudo is reported as manual, with the commands to run. The
// package owns the machine side (accounts, packages, firewalls); everything
// msb-manager-specific comes from internal/msbctl.
//
// It also runs the jobs that change a host for longer than an action may
// take: setup (setupjob.go), which registers and tests the machine once it is
// set up, and upgrade (upgrade.go), which updates msb-manager through the
// plugin's own key. Jobs live in memory (jobs.go). The registry, the admin
// login, Test and msbctl are ports the transport wires in.
package hostsetup

import (
	"context"
	"regexp"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
)

// Shell runs one command line on the machine with stdin, as the admin login.
type Shell interface {
	Exec(ctx context.Context, command string, stdin []byte) (remote.Output, error)
}

// accountPattern is a portable account name (useradd's default rule).
var accountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// DefaultAccount is the account created for msb-manager when the login may
// use sudo: no sudo of its own and a 0700 home, as msb-manager recommends.
const DefaultAccount = "msb"

// Input is what the operator chose.
type Input struct {
	// PublicKey is the plugin's authorized_keys line.
	PublicKey string
	// SSHHost and SSHPort are the admin destination's; Kandev reaches the
	// machine at SSHHost, and the plugin's key at both.
	SSHHost string
	SSHPort int
	// BaseURL is https://<name> for the data path; empty means
	// https://<SSHHost>.
	BaseURL string
	// Account is the account msb-manager runs under when the login may use
	// sudo; empty means DefaultAccount. Without sudo it is the login itself.
	Account string
	// EgressFromPlugin writes allow_extra = ["*"]: this Kandev server's
	// egress policy decides what sandboxes reach.
	EgressFromPlugin bool
	// KandevAddress is the address the host firewall admits; empty means
	// the address this SSH connection comes from, which is the Kandev
	// server's as the machine sees it.
	KandevAddress string
}

// Step states.
const (
	StateOK      = "ok"      // already as wanted
	StateChanged = "changed" // done now
	StateManual  = "manual"  // the operator must run Commands
	StateFailed  = "failed"
	StateSkipped = "skipped" // not reached, or not applicable
)

// Step is one stage, as the operator sees it.
type Step struct {
	Key      string   `json:"key"`
	Title    string   `json:"title"`
	State    string   `json:"state"`
	Detail   string   `json:"detail,omitempty"`
	Commands []string `json:"commands,omitempty"`
	// Output is the tail of a failed command's output, printable only.
	Output string `json:"output,omitempty"`
}

// Result is the whole run.
type Result struct {
	Steps []Step `json:"steps"`
	// OK means every step is ok or changed and the host can be registered.
	OK bool `json:"ok"`
	// SSH is the destination the plugin's key uses: the account at the
	// machine.
	SSH           string `json:"ssh,omitempty"`
	BaseURL       string `json:"base_url,omitempty"`
	KandevAddress string `json:"kandev_address,omitempty"`
	// Manual are steps outside the machine the operator must still take.
	Manual []string `json:"manual,omitempty"`
}

// Step keys, in order.
const (
	StepProbe     = "probe"
	StepPackages  = "packages"
	StepAccount   = "account"
	StepMsb       = "msb"
	StepManager   = "msb-manager"
	StepConfig    = "config"
	StepServices  = "services"
	StepFirewall  = "firewall"
	StepAuthorize = "authorize"
	StepVerify    = "verify"
)

// Steps lists every step with its title, in order, all skipped: what a run
// reports before it starts.
func Steps() []Step {
	return []Step{
		{Key: StepProbe, Title: "Check the machine: Linux, KVM, sudo"},
		{Key: StepPackages, Title: "Install python3 (3.11+), git, curl and tar"},
		{Key: StepAccount, Title: "Prepare the account msb-manager runs under: KVM access, lingering user services"},
		{Key: StepMsb, Title: "Install msb " + msbctl.MsbPin.Version},
		{Key: StepManager, Title: "Install msb-manager " + msbctl.ManagerPin.Version},
		{Key: StepConfig, Title: "Set msbctl's [kandev] section"},
		{Key: StepServices, Title: "Run the TLS proxy and the reaper"},
		{Key: StepFirewall, Title: "Open the proxy ports " + msbctl.ProxyPorts + " to the Kandev server"},
		{Key: StepAuthorize, Title: "Authorize the plugin's SSH key for msbctl kandev only"},
		{Key: StepVerify, Title: "Check the host's own health report"},
	}
}

// run is one bootstrap.
type run struct {
	sh       Shell
	in       Input
	facts    facts
	account  string
	steps    []Step
	progress func([]Step)
	result   Result
}

// Run sets the machine up, reporting the steps after each one.
func Run(ctx context.Context, sh Shell, in Input, progress func([]Step)) Result {
	r := &run{sh: sh, in: in, steps: Steps(), progress: progress}
	for i := range r.steps {
		r.steps[i].State = StateSkipped
	}
	r.do(ctx)
	r.result.Steps = r.steps
	r.result.OK = true
	for _, s := range r.steps {
		if s.State != StateOK && s.State != StateChanged {
			r.result.OK = false
		}
	}
	return r.result
}

func (r *run) step(key string) *Step {
	for i := range r.steps {
		if r.steps[i].Key == key {
			return &r.steps[i]
		}
	}
	panic("hostsetup: unknown step " + key)
}

func (r *run) set(key, state, detail string, commands ...string) {
	s := r.step(key)
	s.State, s.Detail, s.Commands = state, detail, commands
	if r.progress != nil {
		r.progress(append([]Step(nil), r.steps...))
	}
}

// failed records a failed command with the tail of its output.
func (r *run) failed(key, detail string, out remote.Output, err error) {
	if err != nil {
		detail += " (the command did not complete)"
	}
	r.step(key).Output = tail(out)
	r.set(key, StateFailed, detail)
}

func (r *run) do(ctx context.Context) {
	if !r.probe(ctx) {
		return
	}
	if !r.packages(ctx) {
		return
	}
	if !r.prepareAccount(ctx) {
		return
	}
	msbChanged, ok := r.install(ctx, StepMsb, msbctl.MsbPin, true, msbctl.InstallMsbScript())
	if !ok {
		return
	}
	managerChanged, ok := r.install(ctx, StepManager, msbctl.ManagerPin, false, msbctl.InstallManagerScript())
	if !ok {
		return
	}
	configChanged, ok := r.configure(ctx)
	if !ok {
		return
	}
	if !r.services(ctx, msbChanged || managerChanged || configChanged) {
		return
	}
	r.firewall(ctx)
	if !r.authorize(ctx) {
		return
	}
	r.verify(ctx)
}
