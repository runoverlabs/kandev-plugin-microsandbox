package hostsetup

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"kandev-plugin-microsandbox/internal/msbctl"
	"kandev-plugin-microsandbox/internal/remote"
)

func (r *run) firewall(ctx context.Context) {
	ports := msbctl.ProxyPorts
	cloud := "If the machine is behind a cloud firewall (an EC2 security group, say), allow TCP " + ports + " to it from the Kandev server"
	addr, err := netip.ParseAddr(r.result.KandevAddress)
	if err != nil {
		r.result.Manual = append(r.result.Manual, cloud+".")
		r.set(StepFirewall, StateManual, "The Kandev server's address is unknown, so nothing was opened. Allow TCP "+ports+" from it on the host firewall, if there is one.")
		return
	}
	r.result.Manual = append(r.result.Manual, cloud+" ("+addr.String()+").")
	family := "ipv4"
	if addr.Is6() {
		family = "ipv6"
	}
	rich := fmt.Sprintf(`rule family="%s" source address="%s" port port="%s" protocol="tcp" accept`, family, addr, ports)
	firewalld := fmt.Sprintf("firewall-cmd --permanent --query-rich-rule=%[1]s >/dev/null || { firewall-cmd --permanent --add-rich-rule=%[1]s && firewall-cmd --reload >/dev/null && echo firewalld; }", remote.Quote(rich))
	ufw := fmt.Sprintf("ufw allow proto tcp from %s to any port %s", addr, strings.Replace(ports, "-", ":", 1))
	switch {
	case r.facts.get("firewalld") == "active" && !r.facts.privileged():
		r.set(StepFirewall, StateManual, "firewalld is active. Run this as root:", firewalld)
		return
	case r.facts.get("has_ufw") != "" && !r.facts.privileged():
		r.set(StepFirewall, StateManual, "If ufw is active, run this as root:", ufw)
		return
	case !r.facts.privileged():
		r.set(StepFirewall, StateOK, "No firewalld here; if the host filters traffic otherwise, allow TCP "+ports+" from "+addr.String()+".")
		return
	}
	if r.facts.get("firewalld") != "active" && r.facts.get("has_ufw") == "" {
		r.set(StepFirewall, StateOK, "No host firewall is active (firewalld, ufw); if the host filters traffic otherwise, allow TCP "+ports+" from "+addr.String()+".")
		return
	}
	script := "set -eu\n"
	if r.facts.get("firewalld") == "active" {
		script += firewalld + "\n"
	}
	if r.facts.get("has_ufw") != "" {
		script += "if ufw status | grep -q '^Status: active'; then " + ufw + " >/dev/null && echo ufw; fi\n"
	}
	out, err := r.root(ctx, script)
	if err != nil || out.Exit != 0 {
		r.failed(StepFirewall, "Opening the host firewall failed.", out, err)
		return
	}
	if opened := strings.Fields(string(out.Stdout)); len(opened) > 0 {
		r.set(StepFirewall, StateChanged, "Opened TCP "+ports+" from "+addr.String()+" in "+strings.Join(opened, " and ")+".")
		return
	}
	r.set(StepFirewall, StateOK, "The host firewall already admits "+addr.String()+", or none is active (firewalld, ufw).")
}
