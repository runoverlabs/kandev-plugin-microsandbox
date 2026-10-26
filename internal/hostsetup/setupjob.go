package hostsetup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
)

// Kandev gives an action 15 seconds, and a setup downloads and installs, so
// hosts.setup starts a job and hosts.setup.status follows it.
const setupTimeout = 20 * time.Minute

// Plugin-side steps that follow the machine's own.
const (
	StepRegister = "register"
	StepTest     = "test"
)

// Session is an admin login to the machine, for one setup.
type Session interface {
	Shell
	Close()
}

// AdminDialer opens an admin login, accepting only the pinned host key.
type AdminDialer func(ctx context.Context, dest, hostKey string, auth remote.AdminAuth) (Session, error)

// Registry is the host registry, changed under its lock.
type Registry interface {
	Mutate(ctx context.Context, change func(hosts.Registry) (hosts.Registry, error)) (hosts.Registry, error)
}

// Tester runs Test on a host with the plugin's own key and keeps the result
// as its status. It fails only when the key is unavailable.
type Tester func(ctx context.Context, h hosts.Host) (hostcheck.Result, error)

// HostAPI is what an upgrade asks of msbctl through the plugin's key.
type HostAPI interface {
	Health(ctx context.Context, h hosts.Host) (msbctl.Health, error)
	SelfUpdate(ctx context.Context, h hosts.Host, version string) (msbctl.Updated, error)
	RestartProxy(ctx context.Context, h hosts.Host) (msbctl.ProxyRestart, error)
}

// Manager runs setup and upgrade jobs. Every field is required.
type Manager struct {
	Jobs     *Jobs
	Dial     AdminDialer
	Registry Registry
	Test     Tester
	Connect  func(ctx context.Context) (HostAPI, error)
}

// Request is hosts.setup's body. It carries the admin login, which is
// handed to the job and never stored, logged or echoed back.
type Request struct {
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

// ErrNoLogin is a setup without an admin login.
var ErrNoLogin = errors.New("give the admin login: admin_key (a private key) or admin_password; it is used for this setup only and never stored")

// Plan is a setup ready to start: the host as it will be registered, what
// the machine needs, and the admin login.
type Plan struct {
	Host      hosts.Host
	AdminDest string
	Input     Input
	Auth      remote.AdminAuth
}

// Plan checks a request and works out the host as it will be registered, so
// a setup is never run for a host that could not then be added. The account
// is a placeholder until the machine says which one msb-manager runs under.
// Input.PublicKey is left to the caller.
func (in Request) Plan() (Plan, error) {
	auth := remote.AdminAuth{PrivateKeyPEM: in.AdminKey, Passphrase: in.AdminKeyPassphrase, Password: in.AdminPassword}
	if auth.PrivateKeyPEM == "" && auth.Password == "" {
		return Plan{}, ErrNoLogin
	}
	dest := strings.TrimSpace(in.SSH)
	_, sshHost, sshPort, err := hosts.ParseSSH(dest)
	if err != nil {
		return Plan{}, fmt.Errorf("ssh: %w", err)
	}
	planned := hosts.Normalize(hosts.Host{Name: in.Name, SSH: "msb@" + bracketHost(sshHost, sshPort), HostKey: in.HostKey, BaseURL: in.BaseURL, Labels: in.Labels})
	if planned.BaseURL == "" {
		planned.BaseURL = "https://" + bracketHost(sshHost, 0)
	}
	if err := hosts.Validate(planned); err != nil {
		return Plan{}, err
	}
	return Plan{
		Host: planned, AdminDest: dest, Auth: auth,
		Input: Input{
			SSHHost: sshHost, SSHPort: sshPort, BaseURL: in.BaseURL,
			Account: in.Account, EgressFromPlugin: in.EgressFromPlugin, KandevAddress: in.KandevAddress,
		},
	}, nil
}

// SameMachine reports whether a registered host is the machine the plan
// sets up. Running setup again repairs a registered host, but only the same
// machine: a name is permanent in every sandbox's resource state.
func (p Plan) SameMachine(existing hosts.Host) bool {
	_, host, port, _ := hosts.ParseSSH(existing.SSH)
	return host == p.Input.SSHHost && port == p.Input.SSHPort
}

func bracketHost(host string, port int) string {
	if port != 0 && port != 22 {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return bracket(host)
}

func plannedSteps() []Step {
	steps := Steps()
	steps = append(steps,
		Step{Key: StepRegister, Title: "Register the host with the plugin"},
		Step{Key: StepTest, Title: "Issue its certificate and run Test"})
	for i := range steps {
		steps[i].State = StateSkipped
	}
	return steps
}

// StartSetup starts the setup job and returns its id.
func (m *Manager) StartSetup(p Plan) (string, error) {
	return m.Jobs.Start(p.Host.Name, plannedSteps(), setupTimeout, func(ctx context.Context, id string) {
		m.runSetup(ctx, id, p)
	})
}

// runSetup is the job: set the machine up over the admin login, drop the
// login, then register the host and test it with the plugin's own key.
func (m *Manager) runSetup(ctx context.Context, id string, p Plan) {
	admin, err := m.Dial(ctx, p.AdminDest, p.Host.HostKey, p.Auth)
	p.Auth = remote.AdminAuth{}
	if err != nil {
		log.Printf("hosts.setup %s: %v", p.Host.Name, err)
		m.Jobs.setStep(id, StepProbe, StateFailed, adminDialFailure(err))
		m.Jobs.finish(id, JobFailed, nil)
		return
	}
	progress := func(steps []Step) {
		m.Jobs.update(id, func(j *Job) { copy(j.Steps, steps) })
	}
	result := Run(ctx, admin, p.Input, progress)
	admin.Close()
	m.Jobs.update(id, func(j *Job) {
		copy(j.Steps, result.Steps)
		j.Manual = result.Manual
	})
	if !result.OK {
		m.Jobs.finish(id, JobFailed, nil)
		return
	}
	h := p.Host
	h.SSH, h.BaseURL = result.SSH, result.BaseURL
	saved, ok := m.register(ctx, id, h)
	if !ok {
		m.Jobs.finish(id, JobFailed, nil)
		return
	}
	m.finishWithTest(ctx, id, saved, nil, "Test passes: the host is ready for sandboxes.")
}

// register adds the host, or updates it when setup runs again.
func (m *Manager) register(ctx context.Context, id string, h hosts.Host) (hosts.Host, bool) {
	registry, err := m.Registry.Mutate(ctx, func(reg hosts.Registry) (hosts.Registry, error) {
		if _, found := reg.Find(h.Name); found {
			return reg.Update(h)
		}
		return reg.Add(h)
	})
	if err != nil {
		log.Printf("hosts.setup %s: register: %v", h.Name, err)
		detail := "The host is set up but could not be registered."
		var invalid *hosts.ValidationError
		if errors.As(err, &invalid) || errors.Is(err, hosts.ErrTooMany) {
			detail += " " + err.Error()
		}
		m.Jobs.setStep(id, StepRegister, StateFailed, detail)
		return hosts.Host{}, false
	}
	saved, _ := registry.Find(h.Name)
	m.Jobs.setStep(id, StepRegister, StateChanged, "Registered as "+saved.Name+", reached at "+saved.SSH+".")
	return saved, true
}

// finishWithTest runs Test as the job's last step and ends it.
func (m *Manager) finishWithTest(ctx context.Context, id string, h hosts.Host, manual []string, passes string) {
	test, err := m.Test(ctx, h)
	if err != nil {
		m.Jobs.setStep(id, StepTest, StateFailed, "The plugin's key is unavailable.")
		m.Jobs.finish(id, JobFailed, nil)
		return
	}
	state, detail := StateOK, passes
	if !test.OK {
		state, detail = StateManual, "Test reports "+test.Problem+": "+test.Hint
	}
	m.Jobs.setStep(id, StepTest, state, detail)
	m.Jobs.finish(id, JobDone, func(j *Job) {
		j.Host, j.Test = &h, &test
		if manual != nil {
			j.Manual = manual
		}
	})
}

func adminDialFailure(err error) string {
	switch {
	case errors.Is(err, remote.ErrAdminAuth):
		return strings.TrimPrefix(err.Error(), remote.ErrAdminAuth.Error()+": ") + "."
	case errors.Is(err, remote.ErrHostKeyMismatch):
		return "The machine presented a different SSH host key than the one confirmed. Verify it before trying again."
	case errors.Is(err, remote.ErrNotAuthorized):
		return "The machine refused the admin login."
	default:
		return "Could not reach the machine's SSH server."
	}
}
