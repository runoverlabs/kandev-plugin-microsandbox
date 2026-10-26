package hostsetup

import (
	"context"
	"strings"
)

func (r *run) packages(ctx context.Context) bool {
	f := r.facts
	var missing []string
	if f.get("python") == "" {
		missing = append(missing, "python3")
	}
	for _, c := range []string{"git", "curl", "tar"} {
		if f.get("has_"+c) == "" {
			missing = append(missing, c)
		}
	}
	if f.get("has_sha256sum") == "" {
		missing = append(missing, "coreutils")
	}
	tooOld := f.get("python") != "" && !pythonOK(f.get("python"))
	if tooOld {
		r.set(StepPackages, StateFailed, "python3 here is "+f.get("python")+"; msb-manager needs 3.11 or newer as python3. "+
			"Use a newer distribution (Debian 12, Ubuntu 24.04, Fedora 40 or later).")
		return false
	}
	if len(missing) == 0 {
		r.set(StepPackages, StateOK, "python3 "+f.get("python")+", git, curl and tar are installed.")
		return true
	}
	var install string
	switch {
	case f.get("has_apt-get") != "":
		// dbus-user-session gives the account a user bus, which
		// `systemctl --user` needs on Debian and Ubuntu.
		install = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " +
			strings.Join(append(missing, "dbus-user-session"), " ")
	case f.get("has_dnf") != "":
		install = "dnf install -y -q " + strings.Join(missing, " ")
	default:
		r.set(StepPackages, StateManual, "Missing: "+strings.Join(missing, ", ")+". Install them with the distribution's package manager, then run setup again.")
		return false
	}
	if !f.privileged() {
		r.set(StepPackages, StateManual, "Missing: "+strings.Join(missing, ", ")+". Run this as root, then run setup again.", install)
		return false
	}
	out, err := r.root(ctx, "set -eu\n"+install+"\n")
	if err != nil || out.Exit != 0 {
		r.failed(StepPackages, "Installing "+strings.Join(missing, ", ")+" failed.", out, err)
		return false
	}
	check, err := r.sh.Exec(ctx, "sh -s", []byte(`python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'`))
	if err != nil || !pythonOK(strings.TrimSpace(string(check.Stdout))) {
		r.set(StepPackages, StateFailed, "python3 is still missing or older than 3.11 after installing it. Use a newer distribution (Debian 12, Ubuntu 24.04, Fedora 40 or later).")
		return false
	}
	r.set(StepPackages, StateChanged, "Installed "+strings.Join(missing, ", ")+".")
	return true
}
