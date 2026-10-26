package hostsetup

import (
	"context"

	"kandev-plugin-microsandbox/internal/msbctl"
)

// install brings one tool to its pin unless a version at least as new is
// there; it reports whether it installed.
func (r *run) install(ctx context.Context, key string, pin msbctl.Pin, isMsb bool, script string) (bool, bool) {
	name := map[bool]string{true: "msb", false: "msb-manager"}[isMsb]
	have, err := r.versions(ctx, isMsb)
	if err != nil {
		r.set(key, StateFailed, "Reading the installed version failed.")
		return false, false
	}
	if have != "" && !msbctl.Older(have, pin.Version) {
		r.set(key, StateOK, name+" "+have+" is installed.")
		return false, true
	}
	out, err := r.asAccount(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(key, "Installing "+name+" "+pin.Version+" failed.", out, err)
		return false, false
	}
	now, err := r.versions(ctx, isMsb)
	if err != nil || now == "" || msbctl.Older(now, pin.Version) {
		r.set(key, StateFailed, name+" "+pin.Version+" was installed but does not answer --version on the account's PATH.")
		return false, false
	}
	detail := "Installed " + name + " " + now + "."
	if have != "" {
		detail = "Upgraded " + name + " from " + have + " to " + now + "."
	}
	r.set(key, StateChanged, detail)
	return true, true
}

func (r *run) versions(ctx context.Context, isMsb bool) (string, error) {
	out, err := r.asAccount(ctx, msbctl.VersionsScript())
	if err != nil {
		return "", err
	}
	msb, manager := msbctl.ParseVersions(out.Stdout)
	if isMsb {
		return msb, nil
	}
	return manager, nil
}
