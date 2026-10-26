package hostsetup

import (
	"context"
	"fmt"
	"strings"

	"kandev-plugin-microsandbox/internal/remote"
)

func (r *run) prepareAccount(ctx context.Context) bool {
	u := remote.Quote(r.account)
	if r.facts.privileged() {
		script := fmt.Sprintf(`set -eu
u=%[1]s
if ! id -u "$u" >/dev/null 2>&1; then useradd -m -s /bin/bash "$u"; echo created; fi
home=$(getent passwd "$u" | cut -d: -f6)
chmod 700 "$home"
group=$(stat -c %%G /dev/kvm)
regrouped=
if [ "$group" != root ] && ! id -nG "$u" | tr ' ' '\n' | grep -qx "$group"; then usermod -aG "$group" "$u"; regrouped=1; echo "kvm group $group"; fi
uid=$(id -u "$u")
if [ ! -e "/var/lib/systemd/linger/$u" ]; then loginctl enable-linger "$u"; echo linger; fi
# A user manager already running keeps the groups it started with.
if [ -n "$regrouped" ]; then systemctl restart "user@$uid.service" 2>/dev/null || true; fi
i=0
while [ ! -S "/run/user/$uid/bus" ] && [ $i -lt 40 ]; do sleep 0.25; i=$((i+1)); done
[ -S "/run/user/$uid/bus" ] || { echo "the account's user services did not start (is dbus-user-session installed?)" >&2; exit 1; }
`, u)
		out, err := r.root(ctx, script)
		if err != nil || out.Exit != 0 {
			r.failed(StepAccount, "Preparing the account "+r.account+" failed.", out, err)
			return false
		}
		changes := strings.Fields(string(out.Stdout))
		kvm, err := r.asAccount(ctx, "[ -r /dev/kvm ] && [ -w /dev/kvm ]\n")
		if err != nil || kvm.Exit != 0 {
			r.set(StepAccount, StateFailed, "The account "+r.account+" still cannot open /dev/kvm for reading and writing. Check its owner and mode (ls -l /dev/kvm): it should be group-writable by its group.")
			return false
		}
		if len(changes) == 0 {
			r.set(StepAccount, StateOK, "The account "+r.account+" exists, can use /dev/kvm, and its user services run without a login.")
		} else {
			r.set(StepAccount, StateChanged, "The account "+r.account+" can use /dev/kvm and runs user services without a login ("+strings.Join(changes, ", ")+").")
		}
		return true
	}
	// No sudo: msb-manager runs as the login, and root's part is the
	// operator's to do.
	out, err := r.asAccount(ctx, `if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then echo kvm=rw; fi
if [ -e "/var/lib/systemd/linger/$(id -un)" ]; then echo linger=yes; fi
`)
	if err != nil || out.Exit != 0 {
		r.failed(StepAccount, "Checking the account failed.", out, err)
		return false
	}
	got := parseFacts(out.Stdout)
	var commands []string
	if got.get("kvm") != "rw" {
		commands = append(commands, "usermod -aG \"$(stat -c %G /dev/kvm)\" "+u)
	}
	if got.get("linger") != "yes" {
		commands = append(commands, "loginctl enable-linger "+u)
	}
	if len(commands) > 0 {
		r.set(StepAccount, StateManual, "Run these as root, log in again, then run setup again.", commands...)
		return false
	}
	r.set(StepAccount, StateOK, r.account+" can use /dev/kvm, and its user services run without a login.")
	return true
}
