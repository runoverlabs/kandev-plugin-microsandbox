# Feature request: `msbctl kandev` — sandbox hosts for Kandev

**For:** [msb-manager](https://github.com/runoverlabs/sandbox-manager) (`msbctl`)
**From:** [kandev-plugin-microsandbox](../README.md), the Kandev remote executor plugin
**Status:** requested. Nothing here exists in msbctl 0.3.0.
**Design background:** [implementation plan](plans/implementation-plan.md), sections "Host side" and "Data path"

## Summary

Kandev, the agent task manager, is getting a plugin that runs every agent
session in its own microsandbox microVM, on sandbox hosts separate from the
Kandev server. Each sandbox host is an ordinary msb-manager install. The
plugin drives it the way the laptop drives a remote, over SSH through a
forced command, so it needs no daemon, port or token scheme of its own.

msbctl needs a set of `kandev` verbs that **own VM lifetime, inventory,
published ports and expiry** for those sandboxes. They also need a forced
command mode that admits only them, and a timer that reaps what Kandev
forgets. Everything else stays in msbctl's existing shape: stdlib Python,
flags emitted by `Sandbox`, registry entries rendered from `templates/`,
tests against the fake `msb`.

The plugin side is already built against the contract below. `health` and
`list` are **fixed** (the plugin parses them today). The other verbs are
**proposed**: the plugin adopts whatever shape msb-manager settles on, and
this document is then updated to match.

## Milestones

Each milestone is independently useful and unblocks a plugin phase.

| Milestone | Requests | Unblocks |
| --- | --- | --- |
| **M0: spikes** | [S1–S5](#spikes-needed-first) | Confidence the design works on msb 0.7.x |
| **M1: a host the plugin can register** | [F1](#f1-kandev-config-section) `[kandev]` config · [F2](#f2-host-authorize---kandev) `host authorize --kandev` · [F3](#f3-host-serve---kandev) `host serve --kandev` · [F4](#f4-kandev-health) `health` · [F5](#f5-kandev-list) `list` | The plugin's Sandbox Hosts page against a real host: add, test, drain, remove |
| **M2: one session runs** | [F6](#f6-the-kandev-entry-kind) entry kind · [F7](#f7-kandev-provision) `provision` · [F8](#f8-kandev-agentctl) `agentctl` · [F9](#f9-kandev-inspect-and-kandev-find) `inspect` · [F10](#f10-kandev-lease-and-the-data-path) `lease` + serve mappings · [F11](#f11-kandev-destroy) `destroy` | A Kandev task launches, shows terminal, files, git and editor, and is cleaned up on archive |
| **M3: it survives failure** | [F9](#f9-kandev-inspect-and-kandev-find) `find` · [F12](#f12-kandev-start-and-kandev-stop) `start`/`stop` · [F13](#f13-kandev-expiry) `expiry` · [F14](#f14-kandev-reap-and-host-kandev-install) `reap` + timer | Lost replies, Kandev restarts, host reboots, expiry |
| **M4: docs** | [F15](#f15-documentation) "Kandev hosts" page | A new host in under 30 minutes from the docs |

## Constraints this must respect

The usual msb-manager rules apply unchanged: Python 3.11+ stdlib and `msb`
only, a one-line changelog entry per behaviour change, the docs page updated
in the same PR, `scripts/check.sh` green, tests in `tests/` against the fake
`msb`. In addition:

1. **Kandev verbs never touch the operator's sandboxes.** They address
   sandboxes by Kandev environment id, resolved only through `kandev`
   entries. Nothing else is reachable, with or without a name.
2. **No secret value in argv, a file, stdout or a log.** That covers profile
   secrets, registry credentials and the agentctl bootstrap nonce. They
   arrive on stdin and go into the environment of one `msb` process, or the
   stdin of one `msb exec`. Tests use `assert_not_in_argv()` and assert the
   values appear in no file under the throwaway HOME.
3. **Kandev entries get none of msbctl's credential plumbing.** Kandev
   delivers agent and git credentials itself through agentctl, and msbctl's
   would fight it. That means no `bootstrap.sh`, profile seed, git identity,
   `ensure_git_push()`, ssh-agent filter, Claude token or `GH_TOKEN` binding
   (see [F6](#f6-the-kandev-entry-kind)).
4. **Host limits are the host's.** Nothing in a request can raise
   `[kandev]` limits or remove base egress.

## Common contract for every `kandev` verb

### Invocation

```text
msbctl kandev <verb> [ENV] [options]
```

`ENV` is the Kandev environment id. Accept `[A-Za-z0-9_-]{1,128}` and refuse
anything else with `invalid_config`. The id is not secret, so argv is fine.

### Output

- **stdout is exactly one JSON document**, like `ls --json`. Everything else
  goes to stderr. The plugin discards stderr and never shows it in Kandev.
- **Exit 0**: success.
- **Exit 3**: failure, with an error envelope on stdout:

  ```json
  {"error": {"code": "not_found", "message": "no kandev entry for that environment"}}
  ```

  `code` must be one of Kandev's provider error codes: `invalid_config`,
  `denied`, `unsupported`, `not_found`, `expired`, `conflict`,
  `unavailable`, `rate_limited`, `cleanup_pending`. With `rate_limited`,
  add `"retry_after_seconds": <int>`; the plugin clamps it to 0–600.
  `message` is for the host's own logs. The plugin never forwards it.
- **Exit 126**: refused by `host serve` (existing behaviour).
- Any other exit status, or output that is not the documented JSON, is read
  as `unavailable`. A traceback is therefore safe, just unhelpful.

### Secret input

When a verb takes secrets, stdin is **one JSON header line**, optionally
followed by raw bytes whose length the header gives (`agentctl` only). Refuse
a header over 64 KiB, or one that is not a single line, with
`invalid_config`. Never echo stdin.

### Names

msb sandbox names must match `SANDBOX_NAME` (`[a-z0-9][a-z0-9-]*`), and
Kandev ids may not. **msbctl owns the mapping**:

- `k-<env>` when that lowercased string matches `SANDBOX_NAME` and fits
  msb's length limit;
- otherwise `k-` plus the first 24 hex digits of `sha256(env)`.

Record the full id in the entry's `kandev_env`. Every record returns `name`,
and the plugin stores it but never derives it.

### The record

`provision`, `inspect`, `find`, `start`, `stop` and `expiry` all return the
same document:

```json
{"record": {
  "env": "6f1c2b9e-…",
  "name": "k-6f1c2b9e-…",
  "operation_id": "op-…",
  "input_digest": "sha256:…",
  "state": "running",
  "platform": "linux-amd64",
  "image": "ghcr.io/acme/api-sbx@sha256:…",
  "created_at": "2026-10-17T12:00:00Z",
  "expires_at": "2026-10-17T20:00:00Z",
  "max_expires_at": "2026-10-17T20:00:00Z",
  "generation": 1,
  "ports": {"8765": 20001, "41001": 20002, "41002": 20003, "41003": 20004},
  "agentctl": {"running": true, "sha256": "…"}
}}
```

- `state`: `creating`, `running`, `stopped` or `absent` (the entry exists
  but the VM is gone).
- `platform`: `<goos>-<goarch>` of the guest, as Kandev names platforms
  (`linux-amd64`, `linux-arm64`).
- Timestamps are RFC 3339, UTC.
- `generation`: an integer bumped on every VM start. The plugin passes it to
  Kandev with each connection lease; a change closes idle connections.
- `ports`: guest port → host port on `127.0.0.1`.
- `agentctl.running`: whether the guest's agentctl answers on its control
  port. `inspect` checks it live; the other verbs may report the last known
  value.

No secret, nonce, credential or binding value ever appears in a record.

### Concurrency

Every verb that allocates capacity or host ports takes a host-wide lock
(`fcntl.flock` on `STATE_DIR/kandev.lock`). Two provisions arriving
together then cannot both take the last slot or the same port. Read-only
verbs don't need it.

---

## Spikes needed first

Each one is a `spikes/NN-*.sh` in the existing style, asserting both the
allowed and the denied half, run on msb 0.7.7.

| # | Question |
| --- | --- |
| **S1** | A process started with `setsid … &` from `msb exec` keeps running after the exec returns **and** after the SSH session that ran msbctl ends. |
| **S2** | `tailscale serve --bg --https=443 --set-path=/vm/<env>/p/<port> http://127.0.0.1:<h>`: is the prefix stripped before proxying? Do WebSocket upgrades pass? Is the response streamed unbuffered? How many mappings can one node hold? |
| **S3** | `msb create --label k=v` sets labels, and `msb ls` can filter or report them. If not, reconcile falls back to the `k-` name prefix. |
| **S4** | A guest reaches a Kandev `api_url` on the tailnet through an egress rule, while a non-allowlisted host is refused. The API host is a MagicDNS name resolving to `100.x`, so this likely needs `allow_private_dns`. |
| **S5** | Cold and warm round trip of `ssh host msbctl kandev health` and `inspect`. The budgets are Kandev's 15 s for connection leases and 30 s for control calls. |

If S2 fails, [F10](#f10-kandev-lease-and-the-data-path) switches to the
fallback in the plan ("one stdlib TLS splice per port"), and the plugin then
needs a bearer token in each lease.

---

## F1: `[kandev]` config section

A new table in `defaults.toml`, disabled by default, overridable in
`~/.config/msb/config.toml` like every other table:

```toml
[kandev]
# Kandev may create sandboxes on this host only when true.
enabled        = false
max_sandboxes  = 12
max_cpus       = 32            # summed over running kandev sandboxes
max_memory     = "96G"
port_pool      = "20000-29999" # host ports published on 127.0.0.1
base_url       = ""            # e.g. "https://sbx-01.tailnet.ts.net"
# Egress every kandev sandbox gets ("base" is always first). The Kandev API
# host is added per sandbox from the provision request.
rule_groups    = ["github", "npm", "python", "claude"]
# What a profile's extra egress may add. Empty means anything (the Kandev
# server sets policy); a list restricts it to these hostname patterns.
allow_extra    = []
```

- `msbctl config` shows it with origins, as for other tables.
- Every limit counts **kandev sandboxes only**. The operator's own
  sandboxes are outside the budget.
- `enabled = false` makes every verb except `health` answer `denied`.

**Accept:** values validated at load (a bad `port_pool` or `max_memory` is a
clear error); `msbctl config` lists the section.

## F2: `host authorize --kandev`

```text
msbctl host authorize '<public key line>' --kandev [--replace]
```

Writes `restrict,command="<msbctl> host serve --kandev" <key>`. There is **no
`pty`**: the plugin never needs a terminal. `--replace` behaves as it does
today. One host may then hold three kinds of line: the laptop's restricted
key, an optional `--admin` key and the plugin's `--kandev` key.

**Accept:** the written line is exact; `--kandev` with `--admin` is refused.

## F3: `host serve --kandev`

A mode of the existing forced command that admits only `msbctl kandev
<verb> …` and `msbctl --version`. It keeps everything `host serve` already
does: shlex-split `SSH_ORIGINAL_COMMAND`, decide with `build_parser()`, one
stderr line and exit 126 on refusal, `MSB_RESTRICTED=1`, PATH set up.

- The plugin sends exactly `shlex.join(argv)`. Its quoting is
  byte-identical to Python's `shlex.quote`, and a test pins that.
- **The two keys are disjoint.** Under `--kandev` every operator verb is
  refused (`shell`, `exec`, `secret`, `setup`, `allow`, `add`, `edit`,
  `rm`, …). Under plain `host serve` every `kandev` verb is refused.
- This key **does** set egress and secret bindings, which the laptop key may
  never do. That is deliberate: the Kandev profile is the policy, and the
  Kandev server is operator-run. It stays bounded by `[kandev] allow_extra`,
  the reserved-name refusal and the fact that kandev verbs see only kandev
  entries.

**Accept:** a row in `tests/test_host_serve.py` per kandev verb (allowed
under `--kandev`, refused without it), and refused rows under `--kandev` for
each operator verb.

## F4: `kandev health`

**Fixed.** The plugin parses this today. Adding fields is fine; changing or
removing one needs a protocol version bump.

```json
{
  "protocol": 1,
  "msbctl_version": "0.4.0",
  "msb_version": "0.7.7",
  "kvm": true,
  "enabled": true,
  "platform": "linux-amd64",
  "base_url": "https://sbx-01.tailnet.ts.net",
  "capacity": {
    "max_sandboxes": 12, "sandboxes": 3,
    "max_cpus": 32, "cpus": 8,
    "max_memory_mib": 98304, "memory_mib": 16384
  },
  "serve": {"ok": true}
}
```

- `protocol` is `1`. The plugin refuses a host reporting another version.
- `capacity` counts kandev sandboxes that are not `absent`, against
  `[kandev]`, with memory in MiB.
- `serve.ok`: `tailscale serve` is running and this node can serve HTTPS
  (or the fallback proxy is up).
- `platform` is the guest's `<goos>-<goarch>`; the plugin uses it to fetch
  the matching agentctl from Kandev.
- `base_url` is `[kandev] base_url`; the plugin's host test warns when it
  differs from the URL registered in the plugin.
- Answers even when `enabled = false`, so the plugin can say why.

**Accept:** one JSON document; no network calls beyond local `tailscale
status`; under 1 s on a warm host.

## F5: `kandev list`

**Fixed.**

```json
{"sandboxes": [
  {"env": "6f1c2b9e-…", "name": "k-6f1c2b9e-…", "state": "running",
   "created_at": "2026-10-17T12:00:00Z", "expires_at": "2026-10-17T20:00:00Z"}
]}
```

Every kandev entry and nothing else. The plugin refuses to unregister a host
while this list is non-empty.

**Accept:** an operator sandbox on the same host never appears.

## F6: the `kandev` entry kind

A third registry `source` beside `folder` and `repo`, rendered from a new
`templates/registry-kandev.toml.in`:

```toml
source         = "kandev"
kandev_env     = "6f1c2b9e-…"
operation_id   = "op-…"
input_digest   = "sha256:…"
state          = "creating"            # creating | running | stopped | absent
image          = "ghcr.io/acme/api-sbx@sha256:…"
cpus           = 4
memory         = "8192M"
disk           = "20G"
ports          = ["127.0.0.1:20001:8765", "127.0.0.1:20002:41001", "127.0.0.1:20003:41002", "127.0.0.1:20004:41003"]
extra_rules    = ["pypi.org", "kandev.tailnet.ts.net:443"]
secret_binds   = ["NPM_TOKEN@registry.npmjs.org"]   # names and hosts only, never values
created_at     = "…"
expires_at     = "…"
max_expires_at = "…"
generation     = 0
autostart      = false
ssh_keys       = []
```

- `box.is_kandev` is checked at each `ensure_*` call site and skips
  bootstrap, profile seed, git identity, `ensure_git_push()`, the agent
  filter, the Claude token and the `GH_TOKEN` binding.
- msb labels `msbctl.owner=kandev` and `kandev.env=<env>` (S3) are the
  cross-check reconcile uses.
- Operator verbs (`ls`, `show`, `shell`, `rm`) may display kandev entries,
  but `edit`, `rebuild` and `rename` refuse them: Kandev owns them.

**Accept:** a kandev entry round-trips through `tomllib`; no `ensure_*`
plumbing runs for one (asserted through the fake `msb`'s argv).

## F7: `kandev provision`

```text
msbctl kandev provision ENV        # stdin: one JSON header line
```

```json
{
  "operation_id": "op-…",
  "input_digest": "sha256:…",
  "image": "ghcr.io/acme/api-sbx@sha256:…",
  "cpus": 4,
  "memory_mib": 8192,
  "disk_gib": 20,
  "expires_at": "2026-10-17T20:00:00Z",
  "kandev_api": {"host": "kandev.tailnet.ts.net", "port": 443},
  "egress_allow": ["pypi.org", "files.pythonhosted.org:443"],
  "env": [{"name": "NODE_ENV", "value": "development"}],
  "secrets": [{"name": "NPM_TOKEN", "value": "…", "hosts": ["registry.npmjs.org"]}],
  "registry": {"username": "bot", "password": "…"}
}
```

`env`, `secrets`, `egress_allow` and `registry` are optional. Steps:

1. **Idempotency first.** If an entry for `ENV` exists with the same
   `operation_id` and `input_digest`, return its record with no other
   effect. If the `operation_id` matches but the digest differs, or `ENV`
   belongs to another `operation_id`, answer `conflict`.
2. **Validate.** The image passes `image_problem()` and is digest-pinned.
   Secret names are not reserved (`is_reserved_var()`, plus `GITHUB_TOKEN`,
   `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `AGENTCTL_*`) and do not
   collide with `env`. `egress_allow` entries parse as `allow` targets and
   pass `[kandev] allow_extra`. `expires_at` is in the future. Any failure is
   `invalid_config`.
3. **Take the lock and check capacity.** If one more sandbox of this size
   would exceed `[kandev]`, answer `rate_limited` with `retry_after_seconds:
   30`. Then allocate 4 free host ports from `port_pool`.
4. **Write the entry first**, as `creating`, before `msb create`, so a crash
   mid-create is reconcilable. `max_expires_at = expires_at`.
5. **Create** through `do_create()` with flags from the same `Sandbox` code
   as every other sandbox:
   - `--net-rule` for `base`, `[kandev] rule_groups`, `egress_allow` and the
     `kandev_api` host (with private DNS allowed for it, per S4);
   - `--port` for the four ports;
   - `--secret NAME@HOSTS` per secret, with `with_transcript_passthrough()`
     as every binding gets;
   - the labels; `--max-duration` up to `max_expires_at`, as a backstop;
   - `env` as `-e`;
   - **no** `--vsock` agent filter.
   Secret values and registry credentials go into the environment of that
   one `msb` process only. Nothing is written to `secrets/`.
6. Add the serve mappings ([F10](#f10-kandev-lease-and-the-data-path)), mark
   the entry `running`, set `generation = 1`, and print the record.

On failure after step 4, leave the entry for `reap` or a later `destroy`,
and return the error. Never leave a VM without an entry.

**Accept:** same `operation_id` + digest twice → one VM; a mismatched digest
→ `conflict`; a full host → `rate_limited`; two concurrent provisions never
share a port; no secret or registry password in argv, a file or stdout.

## F8: `kandev agentctl`

Installs and starts Kandev's agentctl in the guest. It is called right after
`provision`, and again after `start` if needed (see
[open questions](#open-questions)).

```text
msbctl kandev agentctl ENV         # stdin: header line, then exactly `size` bytes
```

```json
{
  "sha256": "…",
  "size": 41943040,
  "version": "0.97.0",
  "nonce": "…",
  "runtime_port": 8765,
  "args": ["-port=8765"],
  "env": {
    "AGENTCTL_LISTEN_HOST": "0.0.0.0",
    "AGENTCTL_INSTANCE_PORT_BASE": "41001",
    "AGENTCTL_INSTANCE_PORT_MAX": "41003"
  }
}
```

1. Read exactly `size` bytes, refusing more than 512 MiB, and verify
   `sha256`. A mismatch is `invalid_config`.
2. If agentctl is already running with this `sha256`, return the record
   (no-op).
3. Write `/opt/kandev/agentctl` (0755) in the guest by streaming over `msb
   exec` stdin.
4. Start it detached (S1) with `env` plus `AGENTCTL_BOOTSTRAP_NONCE`. The
   nonce travels on the stdin of `msb exec` (`read -r n;
   AGENTCTL_BOOTSTRAP_NONCE=$n setsid … &`), never in argv or a file.
5. Wait for the published host port of `runtime_port` to accept, up to 30 s,
   and return the record with `agentctl.running = true`.

- `env` keys must match `AGENTCTL_[A-Z0-9_]+`; others are `invalid_config`.
- `AGENTCTL_LISTEN_HOST=0.0.0.0` is required: msb publishes a port by
  connecting to the guest's own address, so a server bound to loopback is
  never reached (already documented for `msbctl port`).

**Accept:** the nonce appears in no argv (fake `msb` records it) and no
file; a corrupted binary is refused before anything runs.

## F9: `kandev inspect` and `kandev find`

```text
msbctl kandev inspect ENV
msbctl kandev find --operation OP
```

- `inspect` returns the record, checking the VM state with `msb` and
  agentctl's port live. An entry whose VM is gone is `state: "absent"`. No
  entry at all is `not_found`.
- `find` returns the record of the entry with that `operation_id`, or
  `not_found`. The plugin asks every host to tell "found", "absent
  everywhere" and "unknown" apart after a lost provision reply.

**Accept:** both are read-only and lock-free; `inspect` takes under 2 s on a
warm host (S5).

## F10: `kandev lease` and the data path

```text
msbctl kandev lease ENV PORT
```

```json
{"lease": {
  "base_url": "https://sbx-01.tailnet.ts.net/vm/k-6f1c2b9e-…/p/8765",
  "expires_at": "2026-10-17T12:10:00Z",
  "generation": "1"
}}
```

- `PORT` must be a guest port in the entry's `ports`, else `not_found`. If
  the VM is not running, the answer is `unavailable`.
- `base_url` = `[kandev] base_url` + `/vm/<name>/p/<guest port>`. It must
  stay HTTPS with no credentials, query or fragment: Kandev refuses
  anything else.
- `expires_at` is now + 10 min. Kandev refreshes 30 s before expiry.
- `generation` is the entry's counter, as a string.

**Serve mappings.** `provision` adds one `tailscale serve --bg --https=443
--set-path=/vm/<name>/p/<guest> http://127.0.0.1:<host port>` per published
port. `destroy` and `reap` remove them. msbctl only runs the `tailscale` CLI;
the operator grants serve rights once (`tailscale set --operator=<user>`).

There is no bearer token in this design. Reaching :443 requires the tailnet
ACL (only the Kandev server should reach sandbox hosts), and reaching
agentctl requires Kandev's own token from the nonce handshake.

**Accept:** a curl through a leased `base_url` from another tailnet node
reaches agentctl; a WebSocket echo through it works; a destroyed sandbox's
path answers 404.

## F11: `kandev destroy`

```text
msbctl kandev destroy ENV
```

Removes the VM (`msb rm -f`), its disk, its serve mappings and its entry,
and prints `{"destroyed": true}`. It is **always safe**: an unknown `ENV`, or
an entry whose VM is already gone, also succeeds. A failure partway leaves
the entry, so a retry or `reap` finishes the job.

**Accept:** destroy twice → success twice; an operator sandbox is never
touched even when names collide.

## F12: `kandev start` and `kandev stop`

```text
msbctl kandev start ENV            # stdin: {"secrets": [...], "registry": {...}}
msbctl kandev stop ENV
```

- `stop` stops the VM and keeps its disk. A stopped VM is a no-op.
- `start` starts a stopped VM with the **re-sent** secret values in that one
  `msb start`'s environment. They exist nowhere on the host between starts,
  which is also why kandev entries are `autostart = false`. A request
  missing a value the entry binds is `invalid_config`; never start a
  half-bound sandbox. A running VM is a no-op.
- `start` bumps `generation`.

**Accept:** after a host reboot, kandev VMs are stopped, and `start` with
the secrets brings one back with its workspace intact.

## F13: `kandev expiry`

```text
msbctl kandev expiry ENV --at 2026-10-17T15:00:00Z
```

Sets `expires_at`, clamped to `max_expires_at`; last write wins. It returns
the record. The plugin may use it to shorten retention after a session
stops.

## F14: `kandev reap` and `host kandev install`

```text
msbctl kandev reap
msbctl host kandev install         # systemd user service + timer, every 60 s
```

`reap` is one pass that exits; it is not a daemon. It prints a summary:

```json
{"destroyed": ["k-…"], "marked_absent": ["k-…"], "orphans_removed": ["k-…"]}
```

- **Expiry**: destroy every entry past `expires_at`, including its serve
  mappings and disk.
- **Stuck creates**: an entry in `creating` for over 15 min (past Kandev's
  10 min provision deadline) is destroyed.
- **Gone VMs**: an entry whose VM no longer exists is marked `absent`.
- **Orphans**: a VM labelled `msbctl.owner=kandev` with no entry and older
  than 1 h is removed with `msb rm -f`.
- It never touches a sandbox without both the `kandev` source and the
  label.

`host kandev install` is modelled on `host autostart install`.

**Accept:** each rule has a fake-`msb` test, plus one proving an operator
sandbox with a `k-` name survives a reap.

## F15: documentation

A "Kandev hosts" page on the docs site covering:

- the `[kandev]` section;
- authorizing the plugin's key (`host authorize --kandev`);
- `tailscale serve` rights and the tailnet ACL (only the Kandev server
  reaches sandbox hosts on :443);
- `host kandev install`;
- a `### msbctl kandev …` section per verb, which `docs/build.py --check`
  requires.

---

## Open questions

1. **agentctl after a VM restart.** Does a restarted agentctl need a fresh
   nonce, and does Kandev's attach provide one? Until this is answered,
   `start` only starts the VM and reports `agentctl.running`, and the plugin
   decides whether to call `agentctl` again.
2. **Private images.** How does msb pull with registry credentials? The
   request carries them, but the mechanism (`msb pull` with auth, a
   per-call config) needs checking on 0.7.7.
3. **`allow_extra` default.** Should it be empty (trust the Kandev server's
   profiles) or a starter list?
4. **Name length.** What is msb's maximum sandbox name length? It decides
   when `k-<env>` falls back to the hash.
5. **Idle VMs.** On session stop, keep the VM running until expiry, or stop
   it and restart on attach? Decide after measuring resume time; each idle VM
   costs about 300 MB.

## Out of scope

- Sharing one VM between sessions: Kandev's contract v1 isolates sessions.
- Reading `.msb/` from a repository: kandev sandboxes take their whole
  definition from the request.
- Snapshots and migration between hosts.
- Multi-tenant isolation beyond one operator per host.
