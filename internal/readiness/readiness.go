// Package readiness is setup.status: the one-time setup of the Kandev server
// itself, item by item, with what to do about each one that is not ready. It
// reads the plugin's own state through the ports below and contacts no host.
package readiness

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"

	"kandev-plugin-microsandbox/internal/hostcheck"
	"kandev-plugin-microsandbox/internal/hosts"
	"kandev-plugin-microsandbox/internal/pki"
)

// APIURLEnv is the Kandev setting every plugin launch needs. Kandev passes
// its own environment to the plugin process, so the plugin sees it when it
// is set there; a value from Kandev's config file is invisible until a
// launch carries it in the bootstrap.
const APIURLEnv = "KANDEV_GITHUB_CREDENTIAL_BROKER_PUBLIC_BASE_URL"

// States.
const (
	OK        = "ok"
	Missing   = "missing"
	Invalid   = "invalid"
	Untrusted = "untrusted"
	Unknown   = "unknown"
	Failing   = "failing"
	Unchecked = "unchecked"
)

// Item is one thing to set up.
type Item struct {
	Key    string   `json:"key"`
	Title  string   `json:"title"`
	State  string   `json:"state"`
	Detail string   `json:"detail,omitempty"`
	Fix    []string `json:"fix,omitempty"`
}

// RootInstallSteps tell the operator how to make the Kandev server trust the
// root. Only that machine needs it: it is the only client of the data path.
var RootInstallSteps = []string{
	"Save the root as kandev-sandbox-root.crt on the Kandev server.",
	"Debian/Ubuntu host: copy it to /usr/local/share/ca-certificates/ and run update-ca-certificates.",
	"Fedora/RHEL host: copy it to /etc/pki/ca-trust/source/anchors/ and run update-ca-trust.",
	"Container: mount it in a directory such as /kandev-ca and set SSL_CERT_DIR=/etc/ssl/certs:/kandev-ca for Kandev. Do not use SSL_CERT_FILE: it replaces the system bundle.",
	"Restart Kandev. It reads system roots once, at start.",
	"Run Test on a sandbox host: it reports whether the root is trusted.",
}

var apiURLFix = []string{
	"Set " + APIURLEnv + "=https://<the name sandboxes reach Kandev at> in Kandev's environment (or githubCredentialBroker.publicBaseUrl in its config file), then restart Kandev.",
	"It must be https, with a host name or a public address: not localhost, and not a loopback, private or link-local address literal. Kandev refuses every plugin launch otherwise.",
}

// Report gathers the items. Every field is required.
type Report struct {
	Root     func(ctx context.Context) (*pki.Root, error)
	Trusted  func(root *pki.Root) error
	Getenv   func(name string) string
	SeenAPI  func(ctx context.Context) (url, seenAt string, err error)
	Registry func(ctx context.Context) (hosts.Registry, error)
	Status   func(ctx context.Context) (map[string]hostcheck.Status, error)
}

// Items returns every item, and whether all of them are ready.
func (r Report) Items(ctx context.Context) ([]Item, bool, error) {
	var items []Item
	for _, check := range []func(context.Context) (Item, error){r.rootItem, r.apiURLItem, r.hostsItem} {
		item, err := check(ctx)
		if err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	ready := true
	for _, item := range items {
		ready = ready && item.State == OK
	}
	return items, ready, nil
}

func (r Report) rootItem(ctx context.Context) (Item, error) {
	item := Item{Key: "root", Title: "The plugin's root certificate is trusted by the Kandev server"}
	root, err := r.Root(ctx)
	switch {
	case errors.Is(err, pki.ErrNoRoot):
		item.State, item.Detail = Missing, "No root yet: hosts have no certificate and Kandev cannot reach any sandbox."
		item.Fix = []string{"Create it with ca.create, naming the DNS suffixes or networks your sandbox hosts use."}
	case errors.Is(err, pki.ErrRootUnusable):
		log.Printf("setup.status: root: %v", err)
		item.State, item.Detail = Failing, "The root exists but cannot be loaded; the plugin's log says why."
		item.Fix = []string{"Replace it with ca.create and replace: true, then install the new root on the Kandev server."}
	case err != nil:
		return item, err
	case r.Trusted(root) != nil:
		item.State, item.Detail = Untrusted, "Kandev verifies sandboxes against the system roots, which do not include the plugin's root yet."
		item.Fix = RootInstallSteps
	default:
		item.State, item.Detail = OK, "SHA-256 "+root.Fingerprint()
	}
	return item, nil
}

func (r Report) apiURLItem(ctx context.Context) (Item, error) {
	item := Item{Key: "api_url", Title: "Kandev has an HTTPS API URL that sandboxes can reach"}
	if raw := strings.TrimSpace(r.Getenv(APIURLEnv)); raw != "" {
		if why := APIURLProblem(raw); why != "" {
			item.State, item.Detail, item.Fix = Invalid, APIURLEnv+" is "+raw+": "+why+".", apiURLFix
			return item, nil
		}
		item.State, item.Detail = OK, "Set in Kandev's environment: "+raw
		return item, nil
	}
	seen, seenAt, err := r.SeenAPI(ctx)
	if err != nil {
		return item, err
	}
	if seen != "" {
		item.State, item.Detail = OK, "Not in Kandev's environment, but the launch at "+seenAt+" carried "+seen+"."
		return item, nil
	}
	item.State, item.Fix = Unknown, apiURLFix
	item.Detail = APIURLEnv + " is not in Kandev's environment, and no launch has run yet. It may be set in Kandev's config file, which the plugin cannot read: the first launch will tell."
	return item, nil
}

// APIURLProblem applies Kandev's own rules for the URL (config validation,
// then the plugin launch gate) to a public base URL; "" means acceptable.
func APIURLProblem(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Hostname() == "":
		return "not an absolute URL"
	case u.Scheme != "https":
		return "not https"
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "it must not carry credentials, a query or a fragment"
	}
	return hostProblem(strings.ToLower(u.Hostname()))
}

func hostProblem(host string) string {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "localhost is the Kandev server itself, not reachable from a sandbox"
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate()) {
		return "Kandev refuses a loopback, private or link-local address literal; use a host name"
	}
	return ""
}

func (r Report) hostsItem(ctx context.Context) (Item, error) {
	item := Item{Key: "hosts", Title: "At least one sandbox host passes its check"}
	registry, err := r.Registry(ctx)
	if err != nil {
		return item, err
	}
	if len(registry.Hosts) == 0 {
		item.State, item.Detail = Missing, "No sandbox host is registered."
		item.Fix = []string{"Add one with hosts.setup (an admin SSH login, used once) or hosts.add (a host already set up)."}
		return item, nil
	}
	status, err := r.Status(ctx)
	if err != nil {
		return item, err
	}
	passing, problems := tally(registry.Hosts, status)
	switch {
	case passing > 0:
		item.State = OK
	case len(status) == 0:
		item.State = Unchecked
	default:
		item.State = Failing
	}
	item.Detail = fmt.Sprintf("%d of %d registered hosts pass.", passing, len(registry.Hosts))
	if len(problems) > 0 {
		item.Detail += " " + strings.Join(problems, "; ") + "."
		item.Fix = []string{"Run Test on each host for its hint."}
	}
	return item, nil
}

// tally counts the hosts whose last check passed, and names the others' problem.
func tally(registered []hosts.Host, status map[string]hostcheck.Status) (int, []string) {
	var passing int
	var problems []string
	for _, h := range registered {
		s, found := status[h.Name]
		switch {
		case !found:
			problems = append(problems, h.Name+": not checked yet")
		case s.OK:
			passing++
		default:
			problems = append(problems, h.Name+": "+s.Problem)
		}
	}
	sort.Strings(problems)
	return passing, problems
}
