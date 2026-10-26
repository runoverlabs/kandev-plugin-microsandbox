# Changelog

## Unreleased

- A root certificate that exists but cannot be used, such as one whose key
  is gone from the secret store, is reported instead of being read as "no
  root yet": Test reports `root_unusable`, `hosts.add` and `hosts.update`
  answer `tls` `root_unusable`, and `setup.status` shows the `root` item as
  `failing` rather than failing as a whole. `ca.create` with `replace` now
  replaces it; without `replace` it answers 409. A failure to read the
  store stays an error to retry, and never replaces the root.
- The "add a host that is already set up" form no longer pins a host key
  scanned for one SSH destination after the destination was edited.
- A failure to read the plugin's SSH key, or the hosts' last check results,
  is no longer reported as the host registry's, and an admin login refused during setup is no longer logged
  as the plugin's key being refused.
- The maintainer no longer connects, or creates the plugin's SSH key, when
  no host is registered.

## 0.1.1

Private names, for a sandbox that must reach a host on the LAN with a bound
secret, such as a self-hosted Forgejo. Needs msb-manager 0.7.0 on hosts that
serve such profiles; other hosts keep working with 0.5.0 or newer.

- Profile field `private_names`: exact hostnames a sandbox may resolve to a
  private (LAN) address, such as a self-hosted forge a secret is bound to.
  Each must also be in `egress_allow`. Needs msb-manager 0.7.0 on the host,
  with the name in its `[kandev] private_names`; a profile is refused on
  save unless a host its placement selects allows the names, and placement
  skips hosts that do not.
- `hosts.setup` and `hosts.upgrade` install msb-manager 0.7.0.
- Release and CI builds use Go 1.26.10 (GO-2026-6809, crypto/x509).

## 0.1.0

First release: the host registry, the provider's lifecycle, the root
certificate, central egress and secrets, host setup and upgrades, and the
settings pages. Whole agent sessions have run against Kandev 0.97.0 and a
real host. Needs Kandev 0.97.0 or newer; sandbox hosts need msb-manager 0.5.0
or newer, and 0.6.0 or newer for `hosts.upgrade`.

- Executor provider `microsandbox` with the full profile schema. Profiles are
  validated on save: digest-pinned image, resource bounds, egress entries,
  environment, paired registry credentials, secrets by name,
  reserved names, and a placement that selects a registered, non-draining
  host.
- Sandbox host registry in plugin state, with admin-only `hosts.list`,
  `hosts.scan`, `hosts.add`, `hosts.update`, `hosts.drain`, `hosts.remove`
  and `hosts.test` actions.
- One ed25519 SSH key per installation, generated on first use and kept in
  the plugin secret store. Host keys are pinned (trust on first use through
  `hosts.scan`) and verified on every connection.
- `msbctl kandev` host protocol version 1: `health` and `list`
  ([docs/host-protocol.md](docs/host-protocol.md)).
- Placement: healthy candidates with room, most free memory first.
- `health` also reports the host's `platform` and `base_url`; `hosts.test`
  warns when that `base_url` differs from the registered one.
- The provider lifecycle, against msbctl's `kandev` verbs:
  - **Provision** places the sandbox, reusing the host that already holds the
    operation so a retry never creates a second one. It creates the
    sandbox, checkpoints it with Kandev before anything else can fail,
    verifies the agentctl binary from Kandev, and starts it with the nonce.
    Secrets, registry credentials, the nonce and the binary go to the host
    on stdin only.
  - **Recover** reports found, absent, or unknown while any host cannot
    answer.
  - **Attach** returns the same sandbox, restarting a stopped one that binds
    no secrets.
  - **Inspect** maps host states onto Kandev's; an unreachable host is
    `unknown`, never `absent`.
  - **Resolve connection** leases the control port and instance ports
    41001–41003, refusing a lease header Kandev would reject.
  - **Destroy** confirms absence, finds the sandbox by operation id when
    there is no resource state, and stays retryable while a host is down.
  - Placement heals a proxy host's certificate before counting it.
- Resource state gains `env`, the Kandev environment id.
- A central egress policy: named egress groups (built-in presets for common
  model APIs, plus your own), default groups applied to every sandbox, and
  the actions `egress.list`, `egress.put`, `egress.remove` and
  `egress.defaults`. Profiles gain `egress_groups`; `egress_allow` now also
  takes addresses (`192.168.2.6:8788`). Test reports `egress_refused` when a
  host reports an `allow_extra` that would refuse a default. Sizes are
  bounded by msbctl's real limit, its 64 KiB provision header: a sandbox's
  egress list gets 32 KiB of it, and a provision that would not fit fails
  with `invalid_config` (`requestTooLarge`) before anything is created.
- Settings pages: readiness and links on the plugin's own settings page,
  then **Sandbox hosts** (each host's state and detail, Test, Drain, Remove,
  set up a new machine with live step progress, or add a set-up one),
  **Sandbox egress** (groups, defaults, an entry editor) and **Sandbox
  secrets** (an Add list; a stored value is never shown again).
- Secrets kept by the plugin (`secrets.list`, `secrets.put`,
  `secrets.remove`): a name, a value in the plugin's secret store, and the
  hosts it may be sent to. Profiles name the ones they use in one `secrets`
  field, which replaces the nine `extra_secret_N_name/_value/_hosts` fields:
  a profile can use a secret but never read it or redirect it.
- `hosts.setup`: set up a bare KVM machine (an EC2 `.metal` instance, say)
  from an admin SSH login used once and never stored, then register and test
  it. It checks for KVM first, installs missing packages, creates a no-sudo
  `msb` account with KVM access and lingering user services, installs msb
  0.7.7 and msb-manager 0.6.1 from installers pinned by sha256, sets
  `[kandev]` with `msbctl host kandev configure` (proxy on the machine's own
  address, `allow_extra = ["*"]` when asked; other keys kept), starts the services, opens firewalld or ufw to the Kandev server's
  address only, and authorizes the plugin's key. Every step is idempotent;
  without passwordless sudo, root's part is listed as commands to run.
  `hosts.setup.status` follows the job.
- `hosts.upgrade`: update a host's msb-manager to the release setup
  installs, through the plugin's own key (msb-manager 0.6.0's
  `self-update --json`), then make sure the TLS proxy runs that release
  (0.6.1's `kandev restart-proxy` when the update did not restart it), then
  Test. Test warns about a proxy left on an older release, and the host list
  shows an Update button for either.
- Host status: `hosts.list` shows each host's last check (`checked_at`,
  `ok`, `problem`, `hint`, the health report) without contacting any host.
  Test and the maintainer, which now checks every host every 15 minutes,
  record it. Hosts with msbctl feature request F22 also report `host`: OS,
  kernel, CPUs, memory, load, disk and uptime.
- `setup.status`: the Kandev server's one-time setup, with what to do for
  each item that is not ready: the root is trusted, Kandev's API URL is set
  and passes Kandev's own rules (read from Kandev's environment, or from the
  last launch), and at least one host passes.
- Profile field `workspace_gib` (default 20): each sandbox gets a disk of its
  own at `/workspace`, where Kandev starts the agent. Hosts must list
  `workspace_disk` in `health.features` (msbctl feature request F20); Test
  reports others as `outdated` and placement skips them.
- Inventory, inspect, stop and removal use msbctl's generic verbs (`ls`,
  `show`, `stop` and `purge … -y`, with `--json`), addressed by the sandbox
  name from the resource state. A lost provision reply is found by
  filtering `ls --json` on the operation id.
- A root certificate for sandbox hosts: `ca.create` generates one,
  name-constrained to the hosts' domain, and `ca.get` shows it with install
  steps for the Kandev server. Host certificates are issued at `hosts.add`
  and re-issued automatically (missing, expiring within 30 days, another
  name, or a replaced root) every 6 hours and on `hosts.test`, which also
  reports whether the Kandev server trusts the root. Used by hosts with
  msbctl's `serve = "proxy"`.
- Profile validation follows what msbctl accepts, so a profile it would
  refuse at launch is refused on save: uppercase variable names only, the
  wider reserved-name list (`PATH`, `HOME`, `LD_*`, `MSB_*`, `SSH_*`, …), a
  two-character minimum last label in egress hostnames, and a registry host
  in a private image's reference.
