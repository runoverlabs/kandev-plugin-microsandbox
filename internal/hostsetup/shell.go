package hostsetup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"unicode"

	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/remote"
)

// root runs script as root: directly when logged in as root, else through
// passwordless sudo.
func (r *run) root(ctx context.Context, script string) (remote.Output, error) {
	command := "sudo -n sh -s"
	if r.facts.get("uid") == "0" {
		command = "sh -s"
	}
	return r.sh.Exec(ctx, command, []byte(script))
}

// accountPreamble gives a script run as the account the environment
// msb-manager's tools expect: their commands on PATH, and the user bus that
// `systemctl --user` talks to, which a sudo or runuser login does not set.
const accountPreamble = `export PATH="$HOME/.local/bin:$PATH"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
if [ -S "$XDG_RUNTIME_DIR/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"; fi
`

// asAccount runs script as the msb-manager account, in its home.
func (r *run) asAccount(ctx context.Context, script string) (remote.Output, error) {
	command := "sh -s"
	switch {
	case r.account == r.facts.get("user"):
	case r.facts.get("uid") == "0":
		command = "runuser -l " + remote.Quote(r.account) + " -c 'sh -s'"
	default:
		command = "sudo -n -iu " + remote.Quote(r.account) + " sh -s"
	}
	return r.sh.Exec(ctx, command, []byte(accountPreamble+"cd\n"+script))
}

// accountRunner runs msbctl commands as the account over the admin login,
// so msbctl's own client reads the host's health before the plugin's key is
// in use.
type accountRunner struct{ r *run }

func (a accountRunner) Run(ctx context.Context, _ hosts.Host, args []string, stdin io.Reader) ([]byte, int, error) {
	var extra []byte
	if stdin != nil {
		var err error
		if extra, err = io.ReadAll(stdin); err != nil {
			return nil, 0, err
		}
	}
	if len(extra) > 0 {
		return nil, 0, fmt.Errorf("host setup runs msbctl without stdin")
	}
	out, err := a.r.asAccount(ctx, remote.Join(args)+" </dev/null\n")
	if err != nil {
		return nil, 0, err
	}
	return out.Stdout, out.Exit, nil
}

// maxOutputTail bounds the output a failed step shows.
const maxOutputTail = 2000

// tail is the end of a failed command's stderr, then stdout, printable only.
func tail(out remote.Output) string {
	text := bytes.TrimSpace(out.Stderr)
	if len(text) == 0 {
		text = bytes.TrimSpace(out.Stdout)
	}
	if len(text) > maxOutputTail {
		text = text[len(text)-maxOutputTail:]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(text))
}
