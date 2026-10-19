# Kandev × microsandbox remote executor — implementation plan

Oct 14, 2026 · @Vincent Labreche · revised Oct 17, 2026 to build on msb-manager instead of a new daemon · revised Oct 19, 2026 for host-side TLS with a plugin-issued root

## Decision, Oct 19: host-side TLS from a plugin-issued root

Kandev accepts only HTTPS connection leases and verifies them against the Kandev server's system trust store (`validateLeaseEndpointURL`, `endpoint_transport.go`; `InsecureSkipVerify` is forced off). The built-in SSH and Docker executors need no TLS because Kandev owns their transport; a plugin's lease is dialed directly, so it must be TLS. `tailscale serve` met that with the tailnet's `*.ts.net` certificate, but it ties the design to Tailscale's hosted control plane (headscale does not support Serve or `tailscale cert`, headscale issue #1921) and was still an unrun spike.

The default data path is now:

- **The plugin is a small certificate authority.** On request it generates a root, **name-constrained** to the sandbox hosts' domain (and optionally an address range), and keeps its key in the plugin secret store. The operator installs the root in the Kandev server's trust store; only that one machine ever needs to trust it. A leaked key can impersonate sandbox hosts and nothing else, because Go enforces name constraints.
- **TLS terminates on each sandbox host,** in a small stdlib TLS proxy in msbctl (`[kandev] serve = "proxy"`): one TLS port per published guest port, spliced to the loopback port, with a lease token (`X-Msb-Lease`) checked on the first request of each connection. Traffic goes Kandev → host directly, never through the plugin.
- **The plugin issues each host's certificate** at registration and renewal, and pushes it over SSH on stdin.
- `tailscale serve` stays as an optional mode (`serve = "tailscale"`) where the tailnet supports it; an uploaded wildcard certificate or DNS-01 issuance can later replace the plugin's root as the certificate source without changing the proxy.

The sections below are updated to match; "Data path" has the detail.

## What changed in this revision

The first version planned `sandboxd`, a Go daemon on each host driving microsandbox through its Go SDK, with its own HTTPS control API, SQLite inventory and reverse proxy. Since then msb-manager (`msbctl`) has grown remote hosts, and building that work showed two problems with the daemon design. So this version drops the daemon.

- **No `sandboxd`, and no control API of our own.** Each sandbox host is an ordinary msb-manager install. The plugin drives it the same way the operator's laptop does: `ssh <host> msbctl <verb> …`, through a forced command (`msbctl host serve`) that allows only the verbs it needs. SSH handles authentication and encryption. No new port, token scheme or RPC protocol is needed.
- **No Go SDK.** msbctl drives the `msb` CLI. Only the plugin is Go, because kandev's plugin SDK is.
- **Secrets are re-sent, never stored.** In the SDK path, `SecretEntry{Value}` makes msb persist the raw value in its own host-side sandbox config (upstream `docs/security/secrets.mdx`, "Where the values live"), so "used once, never stored" was not possible that way. The CLI form `--secret ENV@HOST` stores only a reference and reads the value from the environment of `msb` at every start. So the provision **and** every start/attach request carry the profile's extra secrets. msbctl puts them in `msb`'s environment and writes nothing.
- **No proxy of our own in the default design.** kandev only ever leases two guest ports per VM, and both are published at create time. `tailscale serve` provides HTTPS with a publicly trusted tailnet certificate and maps a path prefix to each published loopback port. A small stdlib TLS splice in msbctl is the fallback if `tailscale serve` fails the spike (see Data path).
- **Expiry and reconcile are one-shot timers, not loops in a daemon.** `msbctl host kandev reap` runs from a systemd user timer. `--max-duration` only *stops* a sandbox, so deleting at expiry is the reaper's job.
- **The inventory is msbctl's registry**: one entry per kandev environment, plus msb labels for reconcile. No SQLite.

What already exists in msbctl, and what this plan adds, is marked throughout: **[exists]** or **[new]**.

## Context and goal

Build a kandev remote executor plugin that creates and destroys microsandbox microVMs on demand, one per agent session, on servers separate from kandev. Hosting servers are registered once. Sandbox definitions are per project.

**Deliverables**

1. **`msbctl kandev …` [new]**: host-side verbs in msb-manager (the single-file Python CLI already installed on every sandbox host), plus a `host serve --kandev` forced-command mode and a reaper timer. They own VM lifetime, inventory, published ports and expiry.
2. **`kandev-plugin-microsandbox` [new]**: a kandev runtime plugin implementing the remote executor provider contract (contract version 1). It holds the host registry, places sandboxes on hosts, and maps kandev lifecycle calls to `ssh host msbctl kandev …` calls.
3. Base OCI image guidance and per-project image conventions.

**Environment**

- kandev server and sandbox hosts are separate machines on a private network (Tailscale; WireGuard works for control but the default data path uses `tailscale serve`).
- Sandbox hosts are Linux with KVM, set up as msb-manager remotes: `msbctl remote setup` from the operator's laptop installs `msb` (at the laptop's version) and msbctl, autostart, and the restricted key **[exists]**.
- kandev must be v0.97.0 or later, the first release where remote executor plugins are on by default.

**Non-goals for v1**

- Sharing one VM across several sessions of a task. The plugin contract v1 only supports isolated session environments.
- Reading sandbox definitions from the repository at provision time. The provision request carries no repository data. (msbctl's own `add --repo` sandboxes do read `.msb/` from the repo; kandev sandboxes do not use that path.)
- Multi-tenant or cross-organization isolation beyond what kandev already enforces. msb-manager assumes one operator per host.
- Snapshotting or live migration of VMs between hosts.

## Architecture

```
kandev server ──(plugin, gRPC subprocess)──ssh──▶ sandbox host: msbctl host serve --kandev ─▶ msbctl kandev <verb> ─▶ msb
      │                                                      │
      └──── https://<host>.ts.net/vm/<env>/p/<port>/… ──▶ tailscale serve ─▶ 127.0.0.1:<host port> ─▶ guest agentctl
```

Kandev never talks to microsandbox directly. The plugin runs control calls over SSH, and kandev's agentctl traffic reaches each VM through `tailscale serve` on the host.

- **kandev server** runs kandev and the plugin as a gRPC subprocess. Kandev owns sessions, inventory, recovery policy, repo cloning and credentials.
- **Plugin** is stateless apart from the host registry. It places sandboxes and translates provider RPCs into `msbctl kandev` calls over SSH.
- **msbctl on each host** owns VM lifetime, the registry entries that are the inventory, the port map and expiry. It runs only while a verb runs. msb VMs are detached from the `msb` process that started them, so they survive msbctl exiting, SSH dropping, kandev restarting, and the plugin restarting.
- **microVM** holds one session: agentctl, the agent CLI, terminals, git and the workspace. It reaches back to kandev's `api_url` and only the allowlisted internet hosts.

## Kandev contract (verified in source)

Everything here was read from kandev `main` at commit `73c5ddb` (2026-10-14). Re-check these files before coding.

### Granularity: one microVM per session

The remote executor contract v1 supports isolated session environments only. Launch rejects shared workspace mode and never lets a session borrow another session's resource. Built-in executors instead share one task environment across sessions, so do not copy their behaviour.

- 1 VM = 1 kandev session: agentctl control server + one session instance + agent CLI + terminals + git checkout + editor.
- Stop then resume reattaches the same VM through `AttachExecutorEnvironment`; it must never provision a replacement.
- New sessions, including new workflow steps, get new VMs. Subtasks that inherit a parent workspace are probably unsupported; confirm early.

### Provider RPCs to implement (all seven are mandatory)

Interface: `ExecutorProviderPlugin` in `apps/backend/pkg/pluginsdk/executor_provider.go`. A partial implementation is not offered for profiles or launches.

| RPC | Input | Must return |
| --- | --- | --- |
| `ValidateExecutorProfile` | provider key, profile config, profile secrets | field errors and effective capabilities; no allocation |
| `ProvisionExecutorEnvironment` | request context, profile snapshot, `bootstrap_json` | resource descriptor: handle, non-secret state, platform, retention, expiry |
| `RecoverExecutorOperation` | original operation identity, profile | outcome `found`, `absent` or `unknown` (+ descriptor when found) |
| `AttachExecutorEnvironment` | recorded descriptor, session identity, `expected_runtime_identity` | the same descriptor; never a new VM |
| `InspectExecutorEnvironment` | recorded descriptor | state `running`, `suspended`, `terminated`, `absent` or `unknown`, reason, expiry |
| `ResolveExecutorConnection` | recorded descriptor, purpose `agentctl`, `runtime_port` | a short-lived connection lease for that port |
| `DestroyExecutorEnvironment` | descriptor or unresolved operation id, `cleanup_reason`, `cleanup_claim` | `confirmed_absent` or a retryable error; idempotent |

Host callbacks available during an operation (`ExecutorProviderHostAPI`): `CheckpointExecutorResource` (persist the handle immediately after allocation), `ReportExecutorProgress` (stage codes only, no logs or secrets), `ReadExecutorRuntimeArtifact` (stream the agentctl binary).

**Every request context carries** plugin and installation id, provider key, contract version, workspace, task, session, environment, execution and operation ids, a deadline, environment generation, an input digest and a dispatch generation. The same operation id with a different input digest must return `conflict`.

**Error codes:** `invalid_config`, `denied`, `unsupported`, `not_found`, `expired`, `conflict`, `unavailable`, `rate_limited` (may carry `retry_after_seconds`), `cleanup_pending`. Never put provider response bodies or secrets in errors.

**Deadlines:** control calls 30 s, connection resolution 15 s, provision and attach up to the launch deadline (capped at 10 min). Cleanup runs with a fresh context after cancellation; cancellation does not prove allocation stopped. An SSH round trip over a shared connection is well inside 15 s; a cold connection plus `msb` startup must be measured (Phase 0).

### Bootstrap descriptor

`bootstrap_json` is built in `internal/agent/runtime/lifecycle/executor_plugin.go`:

```json
{"nonce": "<one-time>", "runtime_port": 8765, "api_url": "https://<kandev>/api/v1", "execution_id": "<id>", "artifact_id": "agentctl"}
```

- It is transient. Never store it in resource state, checkpoints, progress messages, registry entries, argv or logs, on either side.
- Fetch the agentctl binary with `ReadExecutorRuntimeArtifact` (chunks up to 256 KiB with version, size and SHA-256). Verify the digest before sending it, and msbctl verifies it again on the host.
- Start agentctl as kandev's launcher does (`internal/agent/runtime/agentctl/launcher/launcher.go`, SSH variant in `executor_ssh.go`): `agentctl -port=<runtime_port>` with env `AGENTCTL_BOOTSTRAP_NONCE=<nonce>` and `AGENTCTL_LISTEN_HOST=0.0.0.0`. msb publishes ports by connecting to the guest's own address, so a server bound to loopback inside the guest is never reached **[exists, documented for `msbctl port`]**. Do not set `AGENTCTL_AUTH_TOKEN`; agentctl generates its token and kandev retrieves it through the nonce handshake.
- agentctl serves each session instance on its own port from `AGENTCTL_INSTANCE_PORT_BASE`..`AGENTCTL_INSTANCE_PORT_MAX` (defaults 41001–41100, `internal/agentctl/server/config/config.go`). Set a small fixed range per VM, 41001–41003, so it can be published at create time (see Guest ports kandev reaches).
- The VM must reach `api_url`. Kandev runs a bounded authenticated callback probe and rolls back provisioning if it fails. The kandev API host is always in the VM's egress rules.
- Agent credentials and git credentials are delivered later by kandev core through agentctl. Neither the plugin nor msbctl injects them, and msbctl must not configure git or Claude credentials in a kandev VM (see Host side).

### Connection lease rules

Source: `internal/agent/runtime/agentctl/endpoint_transport.go`.

- Lease fields: `base_url`, `http_headers`, `websocket_headers`, `websocket_subprotocols`, `expires_at`, `generation`.
- `base_url` must be HTTPS, with a hostname, and no userinfo, fragment or credential-bearing query.
- The hostname must not resolve to loopback, link-local, multicast or unspecified addresses. Private ranges (10.x, Tailscale 100.x) are accepted.
- A path prefix in `base_url` is preserved, so one HTTPS port can route many VMs and ports.
- Kandev refreshes a lease 30 s before expiry. A changed `generation` closes idle connections.
- Header budget is limited (16 KiB total).

### Guest ports kandev reaches

microsandbox only publishes ports declared at create time, and `msb modify` has no port option, so a VM cannot gain a host port later **[exists: msbctl's ports are create-time]**. That is enough, because kandev never dials a guest port itself. It calls `ResolveExecutorConnection` and uses the returned `base_url`, and only ever for two ports (checked at v0.97.0):

1. **8765**, the agentctl control port, which is fixed (`pluginExecutorRuntimePort`, `lifecycle/executor_plugin.go`).
2. **The instance port**, which agentctl allocates from `AGENTCTL_INSTANCE_PORT_BASE`..`_MAX` when kandev creates the session's instance (`createPluginAgentctlInstance`). The range is ours to choose, so the possible ports are known before the VM starts.

Every port that really is dynamic stays inside the VM and is tunnelled over the instance port:

- **Previews and dev servers**: kandev's `/port-proxy/:session/:port` is rewritten to agentctl `/api/v1/port-proxy/:port`, which forwards to `127.0.0.1:<port>` inside the VM (`internal/gateway/websocket/port_proxy.go`, `internal/agentctl/server/api/port_proxy.go`).
- **Embedded editor**: code-server gets a random port (`agentctl/server/process/vscode.go`), reached through `/api/v1/vscode/proxy/*`.

So each VM publishes four ports: 8765 and 41001–41003, each as `127.0.0.1:<host port>:<guest port>` (msbctl's `BIND:HOST:GUEST` form **[exists]**). The range keeps two spares because agentctl's allocator marks a still-bound port unavailable and moves to the next (`agentctl/server/instance/manager.go`, `allocatePortAndListener`), so a range of one can fail an instance create after a restart.

Fallback if a future kandev starts leasing arbitrary ports: tunnel each connection through `msb exec NAME -- socat - TCP:127.0.0.1:<port>`. It costs a process per connection; do not build it unless needed.

### Manifest constraints

Source: `docs/public/plugins-manifest.md`.

- `capabilities.executor_provider: true`, `runtime.type: binary`, `contract_version: 1`.
- `profile_schema`: 1–64 scalar fields (`string`, `boolean`, `number`, `integer`); strings may be `secret: true`.
- `resource_state_schema`: scalar only, no secrets, `additionalProperties: false`.
- Capabilities: `terminal`, `files`, `git`, `embedded_editor`, `preview`, `reattach`, `retention` (`bounded` requires `maximum_lifetime_seconds`, 1 s to 365 days).
- Plugin `config_schema` validates scalars only, which is why the host registry lives in plugin state instead (see Configuration model).

## Configuration model

Hosts are registered once in the plugin. Sandbox definitions are kandev executor profiles, one per project. Project setup lives in kandev repository settings. Host-side limits live in each host's msbctl config. The four layers change at different rates and are owned by different people.

| Layer | Where it lives | Owner | Holds |
| --- | --- | --- | --- |
| Hosts | Plugin state + plugin secret store, edited on a plugin "Sandbox Hosts" page | Operator | name, SSH destination, pinned host key, public base URL, labels, drain flag; the plugin's SSH private key |
| Host limits | `[kandev]` in the host's `~/.config/msb/config.toml` | Operator | capacity, host port pool, base egress, what a profile may add |
| Sandbox definition | Kandev executor profile using this provider | Project lead | placement, image, resources, network allowlist, retention, extra secrets |
| Project setup | Kandev repository settings (setup scripts) | Project | dependency install, env seeding, anything that needs the cloned repo |

### Hosts (plugin-level)

The plugin `config_schema` only validates scalars, so a list of hosts cannot live there. Use the SDK's plugin state and secret store instead (`GetState`/`SetState`, `GetSecret`/`SetSecret` in `pkg/pluginsdk/host.go`).

- UI: the plugin's `ui/bundle.js` adds a "Sandbox Hosts" page built from `host.ui` components.
- Mutations go through manifest-declared authenticated `actions` (`hosts.add`, `hosts.update`, `hosts.drain`, `hosts.remove`, `hosts.test`), never public webhooks.
- State key `hosts` (scope plugin), value:

```json
{"version": 1, "hosts": [{"name": "sbx-01", "ssh": "msb@sbx-01.tailnet.ts.net", "host_key": "ssh-ed25519 AAAA…", "base_url": "https://sbx-01.tailnet.ts.net", "labels": ["default", "big-mem"], "draining": false}]}
```

- **One SSH key for the plugin**, generated by the plugin on first run (ed25519). The private half is stored with `SetSecret("ssh-key")` and the public half is shown on the Sandbox Hosts page. The operator authorizes it on each host with `msbctl host authorize '<pub line>' --kandev` **[new flag]**, which writes `restrict,command="<msbctl> host serve --kandev"`. No `pty`: the plugin never needs a terminal.
- **The host key is pinned.** `hosts.add` fetches it once (trust on first use, shown to the operator to confirm) and every later connection verifies it with `golang.org/x/crypto/ssh` against the pinned key. The plugin never reads the kandev server's `~/.ssh`.
- `hosts.test` runs `msbctl kandev health` and shows msb and msbctl versions, KVM, and free capacity.
- `hosts.remove` is refused while kandev inventory still references the host. Draining hosts get no new placements but keep serving attach, inspect, connection and destroy.
- Host names are immutable identifiers because they are recorded in each resource's state.
- The laptop's own `msbctl remote` list is separate and unaffected. The same host can be both a laptop remote and a kandev host, each with its own key and forced command.

### Host limits (`[kandev]` on each host) [new]

```toml
[kandev]
enabled        = true
max_sandboxes  = 12
max_cpus       = 32           # summed over running kandev VMs
max_memory     = "96G"
port_pool      = "20000-29999" # host ports published on 127.0.0.1
base_url       = "https://sbx-01.tailnet.ts.net"
# Egress every kandev VM gets, as msbctl rule groups from defaults.toml/config.toml
# ("base" is always first). The kandev API host from api_url is added per request.
rule_groups    = ["github", "npm", "python", "claude"]
# What a profile's egress_allow may add. Empty means anything (the kandev server
# is trusted to set policy); a list restricts it to these hostname patterns.
allow_extra    = []
```

These limits are the host's, not kandev's, so a profile cannot raise them. Put the defaults in msbctl's `defaults.toml` with `enabled = false`, following the rule that new defaults go there and not in the template skeleton.

### Sandbox definition (executor profile)

One executor profile per project, e.g. "acme-api sandbox". Proposed `profile_schema` fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `placement` | string | yes | `label:<label>` or `host:<name>` |
| `image` | string | yes | OCI reference pinned by digest (`registry/acme-api-sbx@sha256:…`); msbctl's `image_problem()` refuses anything path-shaped **[exists]** |
| `cpus` | integer | yes | 1–16 |
| `memory_mib` | integer | yes | 512–65536 |
| `disk_gib` | integer | no | root disk, default 20 |
| `max_lifetime_hours` | integer | yes | hard cap, ≤ the manifest maximum |
| `retain_hours` | integer | no | keep a stopped VM this long for review, default 24 |
| `egress_allow` | string | no | comma-separated hostnames (`host` or `host:port`), added to the host's base rules |
| `env` | string | no | `KEY=VALUE;KEY2=VALUE2`, non-secret only |
| `registry_username` | string | no | for private images |
| `registry_password` | string, secret | no | for private images |
| `extra_secret_1_name` / `_value` / `_hosts` | string (value secret) | no | a host-bound msb secret; repeat up to 3 |

`ValidateExecutorProfile` checks that: placement resolves to at least one non-draining host; the image is digest-pinned; numeric values are in bounds; egress entries parse as msbctl `allow` targets; each secret is paired with hosts and is not a reserved name (`GH_TOKEN` or any Claude token variable, which msbctl refuses **[exists]**). It must not allocate anything.

Egress is hostname-based and HTTPS-inspected on :443. On any other port a hostname rule degrades to the resolved IP set, and plain HTTP (:80) is denied outright **[exists, msbctl's base group]**. Say so in the profile field's help text.

### Project setup (repository settings)

Kandev clones the repository into the VM after agentctl is ready, then runs the repository's setup scripts. Put dependency installs and project bootstrapping there. The provision request carries no repository data, so the image and profile must not depend on the repo contents.

### Escape hatch (not in v1)

If 64 scalar fields become limiting, add a `template` field naming a host-side template (a registry-entry skeleton under the host's `~/.config/msb/kandev/`). Do not build this until a real project needs it.

## Host side: `msbctl kandev` [new]

Same file as the rest of msbctl. Same constraints too: Python 3.11+ stdlib and the `msb` binary only, comments as documentation, a one-line changelog entry per behaviour change, and tests in `tests/` against the fake `msb`.

### Interface contract for every `kandev` verb

- **Stdout is exactly one JSON document**, like `ls --json` and `show --json` **[exists]**. Everything else msbctl prints goes to stderr, which the plugin discards: it is never forwarded into kandev errors.
- **Errors** are `{"error": {"code": "<kandev error code>", "message": "<short fixed text>"}}` on stdout, with exit status 3. Exit 126 is a `host serve` refusal **[exists]**, and any other non-zero exit is `unavailable`. The plugin maps the code through unchanged and never forwards `message` text it did not write itself.
- **Inputs that are secret come on stdin, never in argv.** That covers secrets, the nonce, registry credentials and the agentctl binary. argv is visible in `ps` and in sshd logs. Stdin is a JSON header line, optionally followed by raw bytes whose length the header gives.
- **Names**: an environment id becomes the sandbox name `k-<env_id>`, validated by `SANDBOX_NAME` and `name_problem()`. Shorten or hash if kandev ids exceed the length limit; record the full id in the entry.
- Each verb takes a host-wide lock (`fcntl.flock` on `STATE_DIR/kandev.lock`) for the parts that allocate capacity or host ports, so two provisions arriving together cannot both take the last slot or the same port.

### Verbs

| Verb | Stdin | Does | Idempotency |
| --- | --- | --- | --- |
| `kandev health` | – | versions (msbctl, msb), `/dev/kvm`, capacity used/free, `tailscale serve` status | n/a |
| `kandev provision ENV` | header: spec + secrets | create the VM (see below), return the record | same `operation_id` + digest → existing record; different digest → `conflict` |
| `kandev agentctl ENV` | header `{sha256, size, version, nonce, runtime_port}` + binary bytes | write `/opt/kandev/agentctl` in the guest, verify sha256, start it with the nonce, wait for 8765 to accept | same sha256 and running → no-op |
| `show NAME --json` | – | the record under `kandev`: state, expiry, port map, agentctl running (checked live) | n/a |
| `ls --json` | – | every kandev entry, each record under `kandev` (for reconcile, admin, and finding an operation id) | n/a |
| `kandev start ENV` | header: secrets | start a stopped VM with the re-sent secrets, restart agentctl | running → no-op |
| `stop NAME --json` | – | stop the VM, keep its disk | stopped → no-op |
| `kandev expiry ENV --at ISO` | – | set `expires_at`, never past `max_expires_at` | last write wins |
| `kandev lease ENV PORT` | – | `{base_url, expires_at, generation}`; `not_found` for a port not in the map | new expiry each call |
| `purge NAME -y --json` | – | remove the VM, its disk, its serve mappings and its entry; exit 0 when already absent | always safe |
| `host kandev reap` | – | the timer's job: expiry and reconcile (below); refused to the plugin's key | always safe |

`show`, `stop` and `purge` are msbctl's generic verbs: under the plugin's key they see Kandev's sandboxes only, and take the sandbox `NAME` from the record (`k-…`), never one derived from the env id.

### Provision

1. Take the lock. Check capacity against `[kandev]`, and answer `rate_limited` with `retry_after_seconds: 30` when full. Allocate four free host ports from `port_pool`.
2. **Write the registry entry first**, before `msb create`, so a crash mid-create is reconcilable: `source = "kandev"`, `kandev_env`, `operation_id`, `input_digest`, `state = "creating"`, image, resources, `ports = ["127.0.0.1:<h>:8765", …]`, `extra_rules`, `secret_binds` (names and hosts only, never values), `created_at`, `expires_at`, `max_expires_at`, `autostart = false`, `ssh_keys = []`. Render it from a new `templates/registry-kandev.toml.in`, as the other entry kinds are.
3. Run `msb create` through `do_create()`, with flags built by the same `Sandbox` code as every other sandbox:
   - `--net-rule` flags from `[kandev] rule_groups`, the request's egress and the `api_url` host;
   - `--port` for the four ports;
   - `--secret ENV@HOSTS` for each extra secret, with `passthrough=` for the agent's transcript hosts as every binding gets **[exists: `with_transcript_passthrough()`]**;
   - `--label kandev.env=<env> --label msbctl.owner=kandev` **[new: msbctl emits no labels yet]**;
   - `--max-duration` as a backstop.
   The secret values go into the environment of that one `msb` process only. Nothing is written to `secrets/`.
4. **No bootstrap.** The kandev image is complete (see Base image). Kandev entries also skip the profile seed, the git identity, `ensure_git_push()` and the ssh-agent filter, because kandev delivers agent and git credentials itself through agentctl, and msbctl's credential helper and `insteadOf` rewrites would fight them. In code this is one `box.is_kandev` check at each `ensure_*` call site.
5. Add the `tailscale serve` mappings (see Data path), mark the entry `running`, and print the record.

### Start, stop and secrets

- msbctl's normal `start` reads secret values from `secrets/<name>.env` at every start **[exists]**. `kandev start` reads them from stdin instead and hands them to `msb start` the same way. A start that is missing a value the entry binds fails with `invalid_config`. It never starts a half-bound sandbox.
- A host reboot leaves kandev VMs stopped (`autostart = false`), because their secrets exist nowhere on the host. The next `AttachExecutorEnvironment` re-sends them.
- `kandev agentctl` and `kandev start` are the only callers that see the nonce. It is read from stdin and passed to the guest on the stdin of `msb exec` (`read -r n; AGENTCTL_BOOTSTRAP_NONCE=$n setsid … &`), so it is never in any argv or file. Whether a restarted agentctl needs a fresh nonce from kandev is an open question.

### Inventory and reconcile (`host kandev reap`)

The registry entries are the inventory, and msb's labels are the cross-check. `msbctl host kandev install` **[new, modelled on `host autostart install`]** writes a systemd user service + timer that runs `msbctl host kandev reap` every 60 s. It is not a daemon: each run does this and exits:

- **Expiry**: destroy every entry past `expires_at`, including its serve mappings and disk.
- **Reconcile**: an entry whose VM is gone → mark `absent`. An entry stuck in `creating` for longer than the provision deadline → destroy. A VM labelled `msbctl.owner=kandev` with no entry and older than 1 h → `msb rm -f`.
- Never touch a sandbox without the `kandev` source and label. The operator's own sandboxes on the same host are out of reach of every `kandev` verb.

### `host serve --kandev` [new mode of an existing verb]

`host serve` already parses `SSH_ORIGINAL_COMMAND` with `shlex`, decides with `build_parser()` itself, refuses with one stderr line and exit 126, and sets `MSB_RESTRICTED=1` **[exists]**. The `--kandev` mode allows `msbctl kandev <verb>`, `ls --json`, `show NAME --json`, `stop NAME --json`, `purge NAME -y --json` and `msbctl --version` only, and every one of them refuses or hides a name that is not a kandev entry. Add a test row per verb to `tests/test_host_serve.py`, and refused rows for the operator's verbs (`shell`, `secret`, `setup`, `allow`, …) under the kandev key.

This key **does** set egress and secret bindings, which the laptop's key may never do. That is deliberate: the kandev profile is the policy, and the kandev server is an operator-run component. What bounds it is `[kandev] allow_extra`, the reserved-name refusal, and the fact that kandev verbs only see kandev entries.

## Data path: agentctl over HTTPS

### Default: host-side TLS proxy with a plugin-issued certificate [new]

`msbctl kandev proxy` is a systemd user service (installed by `host kandev install`) and the one long-running component in this design. It is stdlib only (`ssl`, `socket`, `selectors` or threads).

- **One TLS listener per published guest port.** `provision` allocates, beside the four loopback ports, four public ports from `[kandev] proxy_port_pool`, bound on `[kandev] proxy_listen` (the host's tailnet or LAN address). Each splices bytes to its `127.0.0.1:<host port>`. Because every lease has its own host:port, a pooled connection can only ever reach one VM port, and the proxy needs no HTTP parser and does no path routing.
- **Lease = `https://<host name>:<public port>`**, from `kandev lease ENV PORT`, with `http_headers` and `websocket_headers` carrying `X-Msb-Lease: <token>`. Not `Authorization`: Kandev rejects a lease that sets it, and overwrites it with agentctl's token on every request.
- **Tokens are stateless and self-healing.** Kandev never re-resolves a lease on a 401, only 30 s before `expires_at`, so a refused token stays refused for up to 10 min. Tokens are therefore bound to the sandbox incarnation (`name`, `created_at` and a random value drawn at provision, since two provisions of one name can share a second) and guest port, not to `generation`. They stay valid 5 min past the lease's `expires_at`, and the previous HMAC key stays accepted after a key change. Only expiry and the sandbox's destruction end one. No IPC between `lease` and the proxy, and a proxy restart invalidates nothing. Details in the msbctl feature request, F18.
- **Certificate:** `CONFIG_DIR/kandev/tls/{cert,key}.pem`, written by `msbctl kandev tls install` from stdin and reloaded by the proxy on change. msbctl cannot generate keys (stdlib only, no `openssl`), so the plugin generates the host key and certificate and sends both over the SSH channel; the key is written 0600 and never printed.
- **Defense in depth:** the network still decides who reaches the public ports (tailnet ACL or firewall: only the Kandev server); the lease token decides which lease may; agentctl's own token, from the nonce handshake, decides who may drive agentctl.
- `destroy` and `reap` close the listeners and free the ports; a destroyed sandbox's port refuses connections.

### Plugin side: the certificate authority [new]

- **`ca.create`** (admin action) takes the permitted DNS suffix (e.g. `.tailnet.ts.net` or a headscale `base_domain`) and optional permitted CIDRs, generates an ECDSA P-256 root (10-year validity) with those name constraints and `pathlen:0`, and stores the key with `SetSecret("ca-key")`. Re-running it replaces the root and requires re-issuing every host.
- **`ca.get`** returns the root PEM, its fingerprint, the constraints, and install instructions: Debian/Ubuntu (`/usr/local/share/ca-certificates/` + `update-ca-certificates`), a container (`SSL_CERT_DIR=/etc/ssl/certs:/kandev-ca`; never `SSL_CERT_FILE`, which replaces the bundle), then restart Kandev, since Go loads roots once per process.
- **Host certificates heal themselves:** issued at `hosts.add`, and re-issued whenever a host reports no certificate, one expiring within 30 days, or one from another root. The checks run from a background maintainer every 6 h, on `hosts.test`, and before each placement. Each certificate is ECDSA P-256, 90 days, SAN = the host name from its registered `base_url` (and an IP SAN if the URL uses one), pushed with `msbctl kandev tls install`. A `base_url` outside the root's constraints is refused at `hosts.add`.
- **Trust check:** `hosts.test` dials one of the host's proxy ports and verifies the chain against the **system roots of the plugin process**, which inherits the Kandev process environment, so "root not trusted yet" is reported before a launch fails on it.

### Optional: `tailscale serve` (`serve = "tailscale"`) [needs spike S2]

Where the tailnet provides HTTPS certificates (Tailscale's hosted control plane; not headscale), msbctl can instead map each published port under one HTTPS listener with the node's certificate:

```
tailscale serve --bg --https=443 --set-path=/vm/<env>/p/8765  http://127.0.0.1:<h8765>
… and the same for 41001–41003
```

`kandev lease ENV PORT` returns `base_url = <[kandev] base_url>/vm/<env>/p/<port>`, an `expires_at` 10 min out and `generation` = a counter in the entry bumped on every VM start. `destroy` and `reap` remove the mappings.

- **Auth.** There is no per-lease bearer token. Reaching the listener requires the tailnet ACL, which should allow only the kandev server to reach sandbox hosts on :443. Reaching agentctl itself requires kandev's agentctl token, obtained through the nonce handshake, which is end-to-end. Leases still expire and still carry `generation`, so kandev's refresh and reconnect logic works unchanged.
- **Spike first**: does `--set-path` strip the prefix before proxying (kandev appends its own paths to `base_url`), do WebSocket upgrades pass, is the response unbuffered, and how many mappings can one node hold? If any of these fail, use the fallback.
- msbctl only runs the `tailscale` CLI. It never needs to be root for this if the operator has granted the `msb` user serve rights (`tailscale set --operator=msb`).

Path routing on one listener depends on how Kandev pools connections; if this mode is kept, the spike must also show that a pooled connection never reaches another VM's path.

## Component B: kandev-plugin-microsandbox

The plugin is a thin, stateless client. It owns the host registry and placement, translates the seven provider RPCs into `msbctl kandev` calls over SSH, and records which host owns each VM in kandev's resource state. All durable VM state lives in kandev inventory and the hosts' registries.

### Repository setup

- Start from `kdlbs/kandev-plugin-template` (or `kdlbs/kandev-plugin-cloudflare`, the first executor plugin repo).
- Check out kandev as a sibling and pin `.kandev-sdk-ref` to a reviewed commit (at least `73c5ddb`). `go.mod` uses `replace github.com/kandev/kandev => ../kandev/apps/backend` until the SDK is published as a module (kandev issue #4358).
- `server/main.go` = `pluginsdk.Serve(&plugin{})`. The plugin struct embeds `pluginsdk.UnimplementedPlugin` and implements `ExecutorProviderPlugin`.
- SSH with `golang.org/x/crypto/ssh`. Keep one connection per host, opening a session per call (the equivalent of msbctl's ControlMaster **[exists]**), and reconnect on failure. Quote every argument with a shell-quoting function matching Python's `shlex.join`, since SSH joins argv with spaces and `host serve` splits it again.
- Use `cmd/plugin-fixture/executor_provider.go` in kandev as the reference for request validation, recovery outcomes and descriptor shape.
- `min_kandev_version: "0.97.0"`.

### Manifest (draft)

```yaml
id: kandev-plugin-microsandbox
version: 0.1.0
min_kandev_version: "0.97.0"
runtime:
  type: binary
  executables:
    linux-amd64: server/plugin-linux-amd64
    linux-arm64: server/plugin-linux-arm64
    darwin-arm64: server/plugin-darwin-arm64
capabilities:
  executor_provider: true
  state: true
  secrets: true
ui:
  bundle: ui/bundle.js
actions:
  - key: hosts.list
  - key: hosts.add
  - key: hosts.update
  - key: hosts.drain
  - key: hosts.remove
  - key: hosts.test
executor_providers:
  - key: microsandbox
    display_name: microsandbox microVM
    description: Isolated microVM per session on registered sandbox hosts.
    contract_version: 1
    supported_state_versions: [1]
    profile_schema:
      type: object
      required: [placement, image, cpus, memory_mib, max_lifetime_hours]
      properties:
        placement: {type: string, title: "Placement (label:<x> or host:<name>)"}
        image: {type: string, title: "OCI image (digest-pinned)"}
        cpus: {type: integer, minimum: 1, maximum: 16}
        memory_mib: {type: integer, minimum: 512, maximum: 65536}
        disk_gib: {type: integer, minimum: 5, maximum: 500}
        max_lifetime_hours: {type: integer, minimum: 1, maximum: 168}
        retain_hours: {type: integer, minimum: 0, maximum: 168}
        egress_allow: {type: string, title: "Extra egress (comma-separated hostnames)"}
        env: {type: string, title: "Env (KEY=VALUE;...)"}
        registry_username: {type: string}
        registry_password: {type: string, secret: true}
    resource_state_schema:
      type: object
      additionalProperties: false
      required: [host, sandbox_name]
      properties:
        host: {type: string}
        sandbox_name: {type: string}
        image: {type: string}
        created_at: {type: string}
    capabilities:
      terminal: true
      files: true
      git: true
      embedded_editor: true
      preview: true
      reattach: true
      retention: bounded
      maximum_lifetime_seconds: 604800
```

Check exact field names for `actions`, `capabilities.state` and `capabilities.secrets` against `docs/public/plugins-manifest.md` at the pinned commit; the executor provider block above follows the documented example.

### RPC mapping

| RPC | Plugin behaviour |
| --- | --- |
| `ValidateExecutorProfile` | Validate fields (see Configuration model); resolve placement against the registry; return effective capabilities. No host calls that write. |
| `ProvisionExecutorEnvironment` | Place → `kandev provision ENV` (spec + secrets on stdin) → `CheckpointExecutorResource` with `{host, sandbox_name}` immediately → stream agentctl with `ReadExecutorRuntimeArtifact`, verify SHA-256 → `kandev agentctl ENV` (header + binary on stdin) → return descriptor (handle `<host>/<env>`, platform `linux/<arch>`, retention `bounded`, `expires_at`). Report progress stages between steps. |
| `RecoverExecutorOperation` | For each host (placement candidates first, then all): `ls --json`, filtered on `kandev.operation_id`. One match → `found` + descriptor. All hosts answered with no match → `absent`. Any host unreachable → `unknown`. |
| `AttachExecutorEnvironment` | `show NAME --json` on the recorded host. Stopped → `kandev start` with the profile's secrets on stdin. Return the same descriptor; if the VM is gone return `not_found`, never re-provision. |
| `InspectExecutorEnvironment` | `show NAME --json` on the recorded host; map `running`→`running`, `stopped`→`suspended`, `absent`→`absent`, past expiry →`terminated`; host unreachable →`unknown`. |
| `ResolveExecutorConnection` | `kandev lease ENV PORT` on the recorded host; return `base_url`, `expires_at`, `generation`, and the lease's `headers` (`X-Msb-Lease: <token>` with the proxy, none with `tailscale serve`) in both header maps, refusing any header Kandev would reject. Must finish within 15 s. |
| `DestroyExecutorEnvironment` | `purge NAME -y --json` on the recorded host (or an operation-id search over `ls --json` first when the handle is missing). Success → `confirmed_absent: true`; host unreachable → `unavailable` (retryable). |

### Placement algorithm

1. Parse `placement`: `host:<name>` selects one host; `label:<x>` selects all hosts carrying that label.
2. Drop draining hosts.
3. Run `kandev health` on candidates in parallel (2 s timeout over an open connection, 10 s cold); drop unreachable ones.
4. Drop hosts without room for the requested CPUs and memory.
5. Pick the host with the most free memory; tie-break by fewest sandboxes, then name.
6. No host left → `rate_limited` with `retry_after_seconds: 30` if any were merely full, else `unavailable`. The host also enforces capacity under its lock, so a race between two plugins' placements still ends in `rate_limited`, never an overcommit.

Placement runs only inside `ProvisionExecutorEnvironment`. Every later call routes by the recorded `host` in resource state.

### Expiry and retention

- `expires_at` at provision = now + `max_lifetime_hours`, sent to the host and returned in the descriptor.
- Bounded retention must report a provider-derived absolute expiry no later than the declared maximum lifetime; attach does not move it.
- When kandev stops a session, the VM stays until `expires_at` or explicit destroy. If `retain_hours` is set, the plugin may shorten expiry on stop via `kandev expiry` (decide in Phase 5; see Open questions).

### Base egress

This is the host's `[kandev] rule_groups`, msbctl rule groups maintained in `defaults.toml` **[exists: `github`, `npm`, `python`, `claude` and others]**, plus the kandev API host from `api_url`, which msbctl adds per request. Profiles only add to it. Keeping the base on the host means the operator changes it in one place per host, with the same groups the operator's own sandboxes use.

## Networking, TLS and security

Control traffic is SSH with a pinned host key and a forced command. Data traffic is HTTPS to each sandbox host's proxy, with a certificate from the plugin's name-constrained root, a per-lease token, and kandev's own agentctl token end to end.

### Paths that must work

| From | To | Purpose | Auth |
| --- | --- | --- | --- |
| Plugin (on kandev server) | `ssh msb@<host>` → `msbctl host serve --kandev` | control | plugin SSH key, pinned host key |
| kandev backend | `https://<host>:<public port>/*` (the host's proxy) | agentctl HTTP + WebSocket | network ACL, lease token, then agentctl token |
| VM | kandev `api_url` | bootstrap callback probe and runtime API | scoped task credentials from kandev |
| VM | allowlisted internet hosts | git, packages, model APIs | per-service |

### TLS

- Kandev rejects non-HTTPS lease URLs and verifies certificates against the Kandev server's system roots; no production code sets a custom TLS config, and `InsecureSkipVerify` is forced off.
- A private CA therefore works exactly when it is in the Kandev server's system trust store. The plugin's root is name-constrained so that trusting it is safe for the rest of that machine.
- Host certificates last 90 days and are renewed by the plugin. `serve = "tailscale"` uses the node's tailnet certificate instead.
- Host names must resolve to tailnet or private addresses; loopback and link-local are rejected by kandev.

### Keys and tokens

- **Plugin SSH key**: one per plugin installation, in the plugin secret store. On each host it is authorized only for `host serve --kandev`. To rotate it, authorize the new key on every host, switch the plugin over, then remove the old line.
- **The operator's laptop key** stays on `host serve` (no `--kandev`) and cannot run kandev verbs. The kandev key cannot run the operator's verbs. A host's `authorized_keys` therefore holds at most three kinds of line: the laptop's restricted key, an optional `--admin` `sk-` key, and the plugin's `--kandev` key **[exists: `host authorize`, `--admin`; new: `--kandev`]**.
- **Plugin CA key**: in the plugin secret store (`ca-key`); never leaves it. Host keys and certificates are generated by the plugin and sent once over SSH stdin.
- **Lease tokens**: HMAC tokens minted by `kandev lease` with a host-local key; they travel only in lease headers, never in URLs or logs.
- **agentctl token**: generated by agentctl, obtained by kandev through the nonce handshake. The plugin and msbctl never see it.
- **Extra secrets**: in the plugin's secret store (as profile secrets) and, during one `msb` call, in that process's environment on the host. They are never in a registry entry, `secrets/`, argv or logs, and never inside the guest, which only sees the placeholder.

### VM isolation

- Default-deny egress with explicit rules, first-match-wins, `base` first **[exists]**. Always allow the kandev API host or bootstrap fails.
- Ports published to `127.0.0.1` only. The only listener reachable off-box is the `tailscale serve` HTTPS port, or the fallback proxy's.
- Extra secrets are host-bound msb secrets: placeholder in the guest, real value substituted on the host into request **headers** only, for the named hosts only. A placeholder in a request body is blocked, which is why msbctl adds `passthrough=` for the agent's own transcript hosts **[exists]**.
- Agent and git credentials are injected by kandev through agentctl after readiness. Never bake them into images or profile env. msbctl's own credential plumbing (Claude token binding, `GH_TOKEN` binding, the git credential helper and `insteadOf` rewrites from `git_push`) is off for kandev entries.
- Images run as a non-root user except where the agent needs otherwise.

### Data handling rules

- Never log or persist `bootstrap_json`, the nonce, profile secret values, or lease tokens.
- Error messages to kandev use the documented codes and short fixed messages, never msbctl's stderr.
- Resource state contains only `host`, `sandbox_name`, `image`, `created_at`.
- The host's registry entry holds names and hosts of secret bindings, never values.

## Lifecycle sequences

Every flow is idempotent by kandev operation id or environment id, and every call after provision is routed by the `host` recorded in resource state.

### Provision (new session)

1. Kandev persists `allocating` with the operation id, then calls `ProvisionExecutorEnvironment`.
2. Plugin runs placement and picks host H.
3. Plugin runs `ssh H msbctl kandev provision <env>` with spec and secrets on stdin. msbctl writes the entry as `creating`, allocates ports, creates the VM with ports, rules, labels and secrets, adds the serve mappings, and marks the entry `running`.
4. Plugin calls `CheckpointExecutorResource` with `{host: H, sandbox_name}` before anything else can fail.
5. Plugin streams agentctl via `ReadExecutorRuntimeArtifact` and verifies SHA-256.
6. Plugin runs `kandev agentctl <env>` with header (sha256, size, nonce, runtime port 8765) and binary on stdin. msbctl verifies, writes `/opt/kandev/agentctl` in the guest, starts it with `AGENTCTL_BOOTSTRAP_NONCE`, `AGENTCTL_LISTEN_HOST=0.0.0.0` and `AGENTCTL_INSTANCE_PORT_BASE=41001`/`_MAX=41003`, and waits for the published 8765 to accept.
7. Plugin returns the descriptor. Kandev calls `ResolveExecutorConnection` for port 8765, performs the nonce handshake, creates the session instance, then leases the instance port.
8. Kandev clones the repo, delivers credentials, runs repository setup scripts and starts the agent.

Failure after step 3: return the error. Kandev then drives `DestroyExecutorEnvironment` using the checkpointed handle.

### Lost provision reply

Kandev calls `RecoverExecutorOperation`. The plugin asks hosts for the `operation_id`. `found` returns the descriptor, `absent` lets kandev retry, and `unknown` blocks a new launch until resolved. Kandev never mints a new operation id to escape uncertainty.

### Stop and resume

- Stop: kandev stops the agent via agentctl. The VM keeps running until its expiry, unless the plugin stops it (Open questions).
- Resume: kandev calls `AttachExecutorEnvironment`. The plugin starts the VM if it is stopped, re-sending secrets, and returns the same descriptor. Kandev re-leases ports and reconnects.

### kandev or plugin restart

Kandev recovers its inventory and calls `InspectExecutorEnvironment` and `AttachExecutorEnvironment` per environment. The plugin process is new but stateless, so it only needs the recorded descriptor and the host registry. VMs on the hosts are unaffected.

### Host-side interruptions

- **An SSH connection drops mid-verb**: the verb may or may not have finished. Every verb is idempotent, and `creating` entries are reconciled by `reap`, so the plugin retries or recovers by operation id.
- **`tailscaled` restarts**: serve config persists in tailscaled. Leases keep working once it is back, and kandev's lease refresh reconnects.
- **Host reboot**: kandev VMs stay stopped (no autostart, no stored secrets). `InspectExecutorEnvironment` reports `suspended`, and attach restarts them with re-sent secrets. agentctl restart is then the open nonce question.

### Destroy

Triggered by task archive or delete, Reset Environment, retention expiry in kandev, or rollback. The plugin runs `purge NAME -y --json` on the recorded host, and success or already-absent → `confirmed_absent`. If the host is unreachable it returns retryable `unavailable`, and kandev keeps the record in `cleanup_pending`.

### Expiry on the host

If kandev never destroys a VM (kandev server lost), the reaper timer destroys it at `expires_at`. The next `InspectExecutorEnvironment` reports `absent` or `terminated`.

## Implementation phases

Seven phases, each ending in a demonstrable check. Do not start a phase until the previous acceptance criteria pass. Host-side phases are msb-manager PRs and follow its rules (`scripts/check.sh` green, a changelog line, docs page updated, fake-`msb` tests). The plugin phases live in the plugin repo.

1. **Phase 0 — Spikes on a real host**, each a `spikes/NN-*.sh` in msb-manager's style, asserting both the allowed and the denied half:
   - a process started with `setsid` from `msb exec` keeps running after the exec and the SSH session end;
   - `tailscale serve --set-path` to a published `127.0.0.1` port: prefix stripping, WebSocket upgrade, streaming, and many mappings on one node;
   - `--label` on `msb create` and `msb ls --label` filtering;
   - a guest reaches a tailnet `api_url` through an egress rule, and a non-allowlisted host is refused;
   - cold and warm SSH + `msb` round-trip times against the 15 s and 30 s deadlines.
   - Accept: all PASS, timings recorded.
2. **Phase 1 — msbctl kandev core.** `[kandev]` config, the `kandev` entry kind and template, `provision`, `start`, `expiry`, `health`, kandev records in `ls`, `show`, `stop` and `purge`, the lock, labels, the `is_kandev` skips.
   - Accept: create is idempotent by operation id; a mismatched digest returns `conflict`; delete of an absent VM succeeds; no secret value reaches argv, stdout or any file (`assert_not_in_argv` **[exists]**); capacity refusal returns `rate_limited`.
3. **Phase 2 — agentctl, leases, data path, reaper.** `kandev agentctl`, `kandev lease`, the serve mappings, `host kandev reap`, `host kandev install`, `host serve --kandev`, `host authorize --kandev`.
   - Phase 2b (Oct 19 decision): `[kandev] serve = "proxy"`, `msbctl host kandev proxy` (installed by `host kandev install`), `kandev tls install`, HMAC lease tokens, `health.tls`. Merged, with the lease-token fix (`dec3dd2`).
   - Accept: from the kandev server, a curl through a leased `base_url` with its `X-Msb-Lease` header reaches agentctl's control port, and without it is refused; a WebSocket echo through it works; a destroyed VM's port refuses connections; the kandev key is refused for every operator verb and the laptop key for every kandev verb.
4. **Phase 3 — plugin skeleton and host registry.** Manifest, Sandbox Hosts page, actions, plugin state and secrets, key generation and host-key pinning, `ValidateExecutorProfile`, placement. Then the certificate authority: `ca.create`/`ca.get`, host certificate issuance and renewal through `kandev tls install`, and the trust check in `hosts.test`.
   - Accept: plugin installs on kandev 0.97+; hosts can be added, tested and drained; a profile saves only with valid placement and a digest-pinned image; with the root installed on the Kandev server, `hosts.test` reports the host's certificate as trusted, and without it reports that it is not.
5. **Phase 4 — happy path.** `Provision`, `ResolveExecutorConnection`, `Inspect`, `Destroy`.
   - Accept: a kandev task on the new profile clones the repo, runs repository setup, starts the agent, and shows terminal, files, git changes and the embedded editor; archiving the task removes the VM and closes its proxy ports.
6. **Phase 5 — resilience.** `RecoverExecutorOperation`, `AttachExecutorEnvironment` with re-sent secrets, expiry handling, capacity and `rate_limited`.
   - Accept: every chaos test in the Test plan passes.
7. **Phase 6 — packaging and ops.** `make package` for the plugin. On the msb-manager side, a docs page "Kandev hosts" (setup, `[kandev]`, authorize, timer, tailnet ACL). Hosts are set up with the existing `msbctl remote setup` plus `host kandev install`.
   - Accept: a new host can be added in under 30 minutes from the docs; a new project needs only an image and a profile.

## Test plan

Unit tests cover each component against fakes. The chaos suite below runs against one real kandev server and two real sandbox hosts, and is the gate for Phase 5.

### Unit and contract tests

- msbctl `kandev` verbs against the fake `msb` (`tests/fake/msb`, `tests/harness.py` **[exists]**): JSON on stdout only, error codes, idempotency, lock, port allocation, labels, no secret or nonce in argv or files.
- `host serve --kandev` allow/refuse rows in `tests/test_host_serve.py`.
- Plugin RPCs against a fake host (a Go `ssh` server in-process answering with recorded `msbctl kandev` JSON), following `server/plugin_test.go` in the template.
- Run kandev's executor conformance tests against the plugin where they can be pointed at an external provider (`internal/plugins/executor_conformance_test.go`).
- Lease validation: run produced leases through kandev's `validateConnectionLease` rules (HTTPS, no userinfo, private IP accepted).
- Secret hygiene: grep test logs on both sides for nonce, token and secret values, and fail if found.

### Chaos suite

| # | Scenario | Expected |
| --- | --- | --- |
| 1 | Kill the kandev process mid-task, restart | Session reattaches to the same VM; uncommitted changes intact |
| 2 | Drop the SSH connection mid-provision | Retry or recovery finds the VM by operation id; no duplicate |
| 3 | Drop the provision reply (fault injection in plugin) | `RecoverExecutorOperation` finds the VM; no duplicate VM |
| 4 | Kill the plugin process during provision | Kandev recovers or cleans up; no orphan after `reap` |
| 5 | Block network kandev→host for 5 min | Inspect returns `unknown`; no deletion; recovers when network returns |
| 6 | Destroy while host unreachable | `cleanup_pending`; destroy succeeds once reachable |
| 7 | VM passes `expires_at` | Reaper destroys it; kandev reports expired |
| 8 | All hosts full | Launch gets `rate_limited` with retry, then succeeds when capacity frees |
| 9 | Drain a host with live VMs | No new placements; existing sessions keep working and can be destroyed |
| 10 | Agent tries a non-allowlisted host | Connection refused inside the VM |
| 11 | Reboot a sandbox host | Kandev sees `suspended` or `unknown`; attach restarts with re-sent secrets, or offers reset |
| 12 | Two sessions launched at once on one host | Distinct VMs, port maps and serve paths; no cross-routing |
| 13 | Restart `tailscaled` | Leases recover after refresh; no VM affected |

## Open questions and risks

The biggest risks are the `tailscale serve` data path (is no daemon actually enough?) and kandev features that may not work with per-session VMs. Phase 0 and early Phase 4 exist to retire them.

- [x] ~~Does `tailscale serve` meet kandev's needs?~~ No longer gating: the default is the host-side proxy (decision of Oct 19). S2 only matters for the optional `serve = "tailscale"` mode.
- [x] ~~Tailnet ACL alone, or a per-lease bearer too?~~ Both: the proxy checks a lease token per connection.
- [x] ~~Does Kandev re-resolve a lease on a 401?~~ No (v0.97.0): only 30 s before `expires_at`. Hence tokens that normal operation never invalidates (msbctl request F18).
- [ ] Does an agentctl restarted after a VM restart need a new nonce from kandev, and does attach provide one? Compare with the SSH executor.
- [ ] **Attach cannot re-send secrets** (found Oct 19): `AttachExecutorEnvironmentRequest` carries the resource and `expected_runtime_identity` but no profile snapshot, so there are no secret values to give `kandev start`. As built, attach restarts a stopped sandbox only if it binds no extra secrets, and answers `unsupported` otherwise. This only arises after a host reboot, since the plugin never stops a VM itself. Options: ask Kandev to pass the profile to attach, or keep VMs running across reboots (which needs the secrets stored on the host, rejected so far).
- [x] ~~Does an instance port range of 8 suffice?~~ Resolved: kandev only leases 8765 and the instance port; previews and the editor go through agentctl's proxy. A range of 3 (41001–41003) leaves spares. Re-check at the pinned commit.
- [ ] Is any agentctl startup configuration beyond nonce, listen host and port required (`InternalAgentctlStartupConfigEnv` in the launcher)?
- [ ] Do workflow steps or subtasks that expect a shared parent workspace fail on plugin executors? Test with real workflows before rollout.
- [ ] On session stop, keep the VM running until expiry, or stop it to free RAM and start it on attach? Decide after measuring resume time. Each idle VM costs about 300 MB. Guest page cache is not returned on its own, but `msbctl reclaim` does it **[exists]**.
- [ ] Should `[kandev] allow_extra` default to empty (trust the kandev server's profiles) or to a list?
- [ ] Exact manifest field names for plugin state, secrets and actions at the pinned commit.
- [x] ~~Does kandev's endpoint transport support a private CA?~~ Only through the Kandev server's system trust store; hence the name-constrained root.
- [ ] Where base images are built and pushed (CI per project vs a shared builder), and registry auth on the hosts.

* Risk: the plugin SDK is pre-1.0 and consumed through a source `replace`; pin `.kandev-sdk-ref` and re-run contract tests on every kandev upgrade.
* Risk: one VM per session multiplies resident memory; size hosts for peak concurrent sessions, not tasks.
* Risk: msb releases change behaviour between patch versions. `msbctl remote setup` installs the laptop's msb version on each host; keep every kandev host on the same version and re-run the Phase 0 spikes on each msb upgrade.

## Base image

Kandev creates the session's agentctl instance with its workspace at **`/workspace`** (`pluginExecutorWorkspacePath`, `lifecycle/executor_plugin.go`), so the image must let the agent user create and write `/workspace`.

The image is complete: kandev VMs run no msbctl bootstrap. It holds git, gh, the agent CLIs a project uses, the language toolchains, `socat` (for the port fallback), and a non-root user. Pin it by digest. msb boots a host directory given as the image, so only OCI references are accepted **[exists: `image_problem()`]**. The msb-manager bootstrap (`bootstrap.sh`) is a usable reference for what to install and from where, since it is written to work under deny-by-default egress (apt over HTTPS, pinned release downloads with checksums).

## What already exists in msb-manager

Read these before writing host-side code. AGENTS.md in the repo describes each in more detail.

- **Remotes**: `msbctl remote add|setup|ls|test|rm`, `host:name` addressing, ControlMaster per host, `ls` across hosts with a cache. `remote setup` installs msb at the laptop's version plus msbctl, copies identities and Claude tokens, and restricts the key.
- **`msbctl host serve`**: a forced command, `shlex` + `build_parser()` allowlist, exit 126 on refusal, `MSB_RESTRICTED=1`. Also `host authorize` (`--admin`, `--replace`), `host check` (hygiene heuristics, `--json`), and `host autostart install` (a systemd user unit).
- **Sandboxes with no host folder** (`source = "repo"`, `add --repo`): a named-volume workspace, a clone in the bootstrap, policy fetched from the repo at a pinned commit. Kandev entries are a third `source` beside `folder` and `repo`.
- **Scripting interfaces**: `ls --json` and `show --json` print exactly one JSON document; `secret set … --stdin` and `read_secret_input()` handle secrets on stdin.
- **Policy authority**: reserved variables (`GH_TOKEN`, Claude tokens) cannot be rebound; project-layer values are pinned until approved; a project's `dev.yaml` is never passed to msb, because msb's `--conf` can mount host paths and interpolate the bound secrets.
- **Secrets**: `--secret ENV@HOST` with values from the `msb` process environment at every start; `passthrough=` for the agent's transcript hosts; `--secret-violation-action block-and-log`.
- **Ports**: `msbctl port` / registry `ports`, `BIND:HOST:GUEST`, create-time only.
- **Git push** (new, PR #60): per-sandbox `git_push = "gh" | "ssh"`, applied on every start through the guest's `/etc/gitconfig`. Kandev entries must skip it, because kandev delivers git credentials itself.
- **Test harness**: `tests/harness.py` (`MsbctlTest`, throwaway HOME, network off) and `tests/fake/msb`, which records argv and named env vars and exits 2 on any call it does not know.

## References

Read these at the pinned commits before writing code.

**msb-manager** ([repo](https://github.com/runoverlabs/sandbox-manager), `main`; the kandev host side ships in v0.4.0)

- `AGENTS.md`: architecture, constraints, and every mechanism listed above
- `msbctl`: `Sandbox` (flag emission), `do_create()`, `secret_env()`, `host_serve()` / `restricted_problem()`, `cmd_host()`, `ls_data()` / `show_data()`, `ensure_*` boot steps
- `defaults.toml`: egress rule groups and their comments (the failure modes)
- `design/remote.md`, `design/remote-plan.md`: the remote design, threat model and its decisions
- `spikes/`: re-runnable PASS/FAIL scripts for each msb mechanism relied on

**kandev** ([repo](https://github.com/kdlbs/kandev), commit `73c5ddb`)

- `apps/backend/pkg/pluginsdk/executor_provider.go`: provider interface and host callbacks
- `apps/backend/proto/kandev/plugin/v1/plugin.proto`: request and response messages
- `apps/backend/cmd/plugin-fixture/executor_provider.go`: reference provider
- `apps/backend/internal/agent/runtime/lifecycle/executor_plugin*.go`: host-side launch, recovery, cleanup
- `apps/backend/internal/agent/runtime/agentctl/endpoint_transport.go`: lease validation and proxying rules
- `apps/backend/internal/agent/runtime/agentctl/launcher/launcher.go` and `lifecycle/executor_ssh.go`: how agentctl is started
- `apps/backend/internal/agentctl/server/config/config.go`: agentctl env settings
- `apps/backend/internal/gateway/websocket/port_proxy.go`, `internal/agentctl/server/api/port_proxy.go`: preview traffic tunnelled through the instance port
- `apps/backend/internal/agentctl/server/instance/manager.go`: instance port allocation within the configured range
- `docs/specs/executors/system-design/remote-executor-plugins.md` and `requirements/remote-executor-plugins.md`
- `docs/public/executors.md`, `docs/public/plugins-authoring.md`, `docs/public/plugins-manifest.md`
- [PR #3985: remote executor plugin support](https://github.com/kdlbs/kandev/pull/3985), [PR #4000: made permanently available](https://github.com/kdlbs/kandev/pull/4000), [v0.97.0 release](https://github.com/kdlbs/kandev/releases/tag/v0.97.0)
- [Issue #4358: publish the plugin SDK as a module](https://github.com/kdlbs/kandev/issues/4358)
- [kandev-plugin-cloudflare](https://github.com/kdlbs/kandev-plugin-cloudflare): plugin repo layout, build and packaging

**microsandbox** ([repo](https://github.com/microsandbox/microsandbox))

- `msb --help` for each verb used (`create`, `start`, `stop`, `exec`, `rm`, `ls --label`, `inspect`); it is more reliable than the published docs
- `docs/security/secrets.mdx`: where secret values live (why the SDK path was dropped)
- `crates/cli/lib/sandbox_config.rs`: `--conf` interpolation (why no conf file is ever passed from a request)
