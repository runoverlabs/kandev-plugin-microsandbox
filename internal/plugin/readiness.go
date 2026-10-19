package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ActionSetupStatus reports the one-time setup of the Kandev server itself,
// item by item, with what to do about each one that is not ready.
const ActionSetupStatus = "setup.status"

// apiURLEnv is the Kandev setting every plugin launch needs. Kandev passes
// its own environment to the plugin process, so the plugin sees it when it
// is set there; a value from Kandev's config file is invisible until a
// launch carries it in the bootstrap.
const apiURLEnv = "KANDEV_GITHUB_CREDENTIAL_BROKER_PUBLIC_BASE_URL"

// apiStateKey keeps the API URL the last launch carried: Kandev's public
// address, which is not secret.
const apiStateKey = "kandev"

// Readiness states.
const (
	readyOK        = "ok"
	readyMissing   = "missing"
	readyInvalid   = "invalid"
	readyUntrusted = "untrusted"
	readyUnknown   = "unknown"
	readyFailing   = "failing"
	readyUnchecked = "unchecked"
)

type readinessItem struct {
	Key    string   `json:"key"`
	Title  string   `json:"title"`
	State  string   `json:"state"`
	Detail string   `json:"detail,omitempty"`
	Fix    []string `json:"fix,omitempty"`
}

type seenAPI struct {
	URL    string `json:"url"`
	SeenAt string `json:"seen_at"`
}

var apiURLFix = []string{
	"Set " + apiURLEnv + "=https://<the name sandboxes reach Kandev at> in Kandev's environment (or githubCredentialBroker.publicBaseUrl in its config file), then restart Kandev.",
	"It must be https, with a host name or a public address: not localhost, and not a loopback, private or link-local address literal. Kandev refuses every plugin launch otherwise.",
}

func (r *Runtime) actionSetupStatus(ctx context.Context, body []byte) response {
	if err := decode(body, &struct{}{}); err != nil {
		return fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	root, err := r.rootItem(ctx)
	if err != nil {
		return internalFailure(ActionSetupStatus, err)
	}
	api, err := r.apiURLItem(ctx)
	if err != nil {
		return internalFailure(ActionSetupStatus, err)
	}
	hostsItem, err := r.hostsItem(ctx)
	if err != nil {
		return internalFailure(ActionSetupStatus, err)
	}
	items := []readinessItem{root, api, hostsItem}
	ready := true
	for _, item := range items {
		ready = ready && item.State == readyOK
	}
	return ok(map[string]any{"ready": ready, "items": items})
}

func (r *Runtime) rootItem(ctx context.Context) (readinessItem, error) {
	item := readinessItem{Key: "root", Title: "The plugin's root certificate is trusted by the Kandev server"}
	root, err := r.root(ctx)
	switch {
	case errors.Is(err, errNoRoot):
		item.State, item.Detail = readyMissing, "No root yet: hosts have no certificate and Kandev cannot reach any sandbox."
		item.Fix = []string{"Create it with ca.create, naming the DNS suffixes or networks your sandbox hosts use."}
	case err != nil:
		return item, err
	case r.rootTrusted(root) != nil:
		item.State, item.Detail = readyUntrusted, "Kandev verifies sandboxes against the system roots, which do not include the plugin's root yet."
		item.Fix = installSteps
	default:
		item.State, item.Detail = readyOK, "SHA-256 "+root.Fingerprint()
	}
	return item, nil
}

func (r *Runtime) apiURLItem(ctx context.Context) (readinessItem, error) {
	item := readinessItem{Key: "api_url", Title: "Kandev has an HTTPS API URL that sandboxes can reach"}
	if raw := strings.TrimSpace(r.getenv(apiURLEnv)); raw != "" {
		if why := apiURLProblem(raw); why != "" {
			item.State, item.Detail, item.Fix = readyInvalid, apiURLEnv+" is "+raw+": "+why+".", apiURLFix
			return item, nil
		}
		item.State, item.Detail = readyOK, "Set in Kandev's environment: "+raw
		return item, nil
	}
	seen, err := r.loadSeenAPI(ctx)
	if err != nil {
		return item, err
	}
	if seen.URL != "" {
		item.State, item.Detail = readyOK, "Not in Kandev's environment, but the launch at "+seen.SeenAt+" carried "+seen.URL+"."
		return item, nil
	}
	item.State, item.Fix = readyUnknown, apiURLFix
	item.Detail = apiURLEnv + " is not in Kandev's environment, and no launch has run yet. It may be set in Kandev's config file, which the plugin cannot read: the first launch will tell."
	return item, nil
}

// apiURLProblem applies Kandev's own rules for the URL (config validation,
// then the plugin launch gate) to a public base URL; "" means acceptable.
func apiURLProblem(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Hostname() == "":
		return "not an absolute URL"
	case u.Scheme != "https":
		return "not https"
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "it must not carry credentials, a query or a fragment"
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "localhost is the Kandev server itself, not reachable from a sandbox"
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate()) {
		return "Kandev refuses a loopback, private or link-local address literal; use a host name"
	}
	return ""
}

func (r *Runtime) hostsItem(ctx context.Context) (readinessItem, error) {
	item := readinessItem{Key: "hosts", Title: "At least one sandbox host passes its check"}
	registry, err := r.loadRegistry(ctx)
	if err != nil {
		return item, err
	}
	if len(registry.Hosts) == 0 {
		item.State, item.Detail = readyMissing, "No sandbox host is registered."
		item.Fix = []string{"Add one with hosts.bootstrap (an admin SSH login, used once) or hosts.add (a host already set up)."}
		return item, nil
	}
	status, err := r.loadStatus(ctx)
	if err != nil {
		return item, err
	}
	var passing int
	var problems []string
	for _, h := range registry.Hosts {
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
	switch {
	case passing > 0:
		item.State = readyOK
	case len(status) == 0:
		item.State = readyUnchecked
	default:
		item.State = readyFailing
	}
	item.Detail = fmt.Sprintf("%d of %d registered hosts pass.", passing, len(registry.Hosts))
	if len(problems) > 0 {
		item.Detail += " " + strings.Join(problems, "; ") + "."
		item.Fix = []string{"Run Test on each host for its hint."}
	}
	return item, nil
}

func (r *Runtime) loadSeenAPI(ctx context.Context) (seenAPI, error) {
	h, err := r.host()
	if err != nil {
		return seenAPI{}, err
	}
	value, found, err := h.GetState(ctx, stateScope, "", apiStateKey)
	if err != nil || !found {
		return seenAPI{}, err
	}
	raw, _ := json.Marshal(value)
	var seen seenAPI
	_ = json.Unmarshal(raw, &seen)
	return seen, nil
}

// noteAPIURL keeps the API URL a launch carried, when it changed: the
// readiness view's evidence when Kandev's environment does not show it.
func (r *Runtime) noteAPIURL(ctx context.Context, apiURL string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	if apiURL == "" || apiURL == r.seenAPIURL {
		return
	}
	h, err := r.host()
	if err != nil {
		return
	}
	value := map[string]any{"url": apiURL, "seen_at": r.now().UTC().Format(time.RFC3339)}
	if err := h.SetState(ctx, stateScope, "", apiStateKey, value); err != nil {
		log.Printf("note api url: %v", err)
		return
	}
	r.seenAPIURL = apiURL
}
