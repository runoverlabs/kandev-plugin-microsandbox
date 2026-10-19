# Changelog

## Unreleased

First development snapshot: the host registry, the provider's lifecycle and
the root certificate. A whole agent session has run against Kandev 0.97.0
and a real host. Sandbox hosts need msb-manager 0.5.0 or newer.

- Executor provider `microsandbox` with the full profile schema. Profiles are
  validated on save: digest-pinned image, resource bounds, egress entries,
  environment, paired registry credentials, up to three host-bound secrets,
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
  host reports an `allow_extra` that would refuse a default.
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
  reports whether the Kandev server trusts the root. Needs msbctl's
  `serve = "proxy"` (not built yet) to take effect.
- Profile validation follows what msbctl accepts, so a profile it would
  refuse at launch is refused on save: uppercase variable names only, the
  wider reserved-name list (`PATH`, `HOME`, `LD_*`, `MSB_*`, `SSH_*`, …), a
  two-character minimum last label in egress hostnames, and a registry host
  in a private image's reference.
