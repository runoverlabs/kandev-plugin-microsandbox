# Feature request: `msbctl kandev` — sandbox hosts for Kandev

**For:** [msb-manager](https://github.com/runoverlabs/sandbox-manager) (`msbctl`)
**From:** [kandev-plugin-microsandbox](../README.md), the Kandev remote executor plugin
**Status:** built, and **released in msb-manager
[0.4.0](https://github.com/runoverlabs/sandbox-manager/releases/tag/v0.4.0)**
([PR #61](https://github.com/runoverlabs/sandbox-manager/pull/61), merge
`66f03f7`, 2026-10-17). This document now describes what was built;
the differences from the original request are listed in
[Changes from the request](#changes-from-the-request), and what is left in
[Current state](#current-state).
**Fourth request, 2026-10-19:** [F21](#f21-allow_extra-admits-addresses-and-health-reports-it), central egress from the plugin. Released in 0.5.1.
**Third request, 2026-10-19:** [F20](#f20-a-workspace-disk-at-workspace), from the first real run. Released in 0.5.0.
**Second request, 2026-10-19:** host-side TLS, [F16–F19](#request-2-host-side-tls-2026-10-19). Built and released in 0.4.0 (PR #62, then the lease-token fix `dec3dd2`, 2026-10-19). It changes F1, F4, F10 and F14 as marked there; what differs from the request is in [Changes from request 2](#changes-from-request-2).
**Verbs since then:** list, inspect, find, stop, destroy, reap and proxy moved into msbctl's generic verbs and `host kandev`, before any of them shipped; the F-sections below keep the original request's names. The current shapes are in the [change notice](msbctl-kandev-verb-changes.md) and the [host protocol](host-protocol.md).
**Design background:** [implementation plan](plans/implementation-plan.md), sections "Decision, Oct 19", "Host side" and "Data path"

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
`list` are **fixed** (the plugin parses them today). The other verbs were
proposed, and this document has been updated to the shape msb-manager
settled on.

## Current state

As of 2026-10-17:

| | State |
| --- | --- |
| F1–F15 | Built, released in 0.4.0. |
| Tests | `tests/test_kandev.py` (28) and `host serve --kandev` rows in `tests/test_host_serve.py`, against the fake `msb` and a fake `tailscale`. CI green. |
| Live run | The whole lifecycle against real msb 0.7.7, nested in an msb sandbox: provision, agentctl, inspect, lease, stop/start with re-sent secrets, expiry, reap, destroy. No secret, password or nonce reached argv or disk. |
| Spikes | `spikes/16-kandev-host.sh`: S1, S3, S4 (pinned address) and the registry check PASS nested. **S2 (`tailscale serve`) and S5 (round trips) not run yet**: they need a tailnet node and a remote (`SPIKE_TS=1`, `SPIKE_SSH_DEST`). S4 should be re-run on a real host. |
| Docs | "Kandev hosts" page and a `msbctl kandev` section on the Commands page. |
| F16–F19 | Built, released in 0.4.0. `tests/test_kandev_tls.py` runs real TLS on loopback against certificates `openssl` makes at test time (a name-constrained root and its leaves). An end-to-end run of the CLI, with `curl` as the client, gave 200 with a lease, 401 without one, and connection refused after `destroy`. Not yet run against real msb or from another machine; the 10-minute WebSocket idle check hasn't been run either. |

For the plugin:

- **Gate on `health.protocol == 1`, not on `msbctl_version`.** The version
  string is `0.4.0` on a release install, but a checkout reports
  `<version>+<sha> (git checkout)`.
- **The data path is the one open risk.** If S2 shows `tailscale serve`
  does not strip the `/vm/<name>/p/<port>` prefix or does not pass
  WebSocket upgrades, F10 switches to the fallback in the plan (a TLS
  splice in msbctl), and leases gain a lease token (`X-Msb-Lease`).
- **Open question 1** (agentctl after a VM restart) is still Kandev's to
  answer; see Open questions.

## Changes from the request

What the plugin has to adopt. Each one is also in place below.

1. **`allow_extra = []` allows nothing extra**, as everywhere else in
   msb-manager. `["*"]` trusts the Kandev server's profiles. A host outside
   it is `invalid_config` (F1, F7).
2. **The Kandev API is pinned by address, not by `allow_private_dns`.** The
   host resolves `kandev_api.host`, emits one rule for that address and
   port, and writes the name into the guest's `/etc/hosts`. DNS rebind
   protection stays on. msb writes a fresh `/etc/hosts` at every boot, so
   `start` writes the line again. `kandev_api` is required (F7).
3. **Operator verbs on a kandev sandbox:** `ls`, `status`, `show`, and
   `shell`/`exec` while it is running. Every other operator verb refuses, a
   stopped sandbox is never started from the operator side, and new
   operator names may not start with `k-` (F6).
4. **Private registries work through msb's `password_env`:** one `msb pull`
   with a throwaway `MSB_CONFIG_PATH` copy naming the variable and the
   username, the password in that process's environment only, then
   `msb create --pull never`. A private image must name its registry host.
   `msb registry login` is not used, because it stores the credential (F7).
5. **Names:** `k-<env>` only when that is already a valid sandbox name
   (no lowercasing) and at most 40 characters, else the hash form, so two
   ids that differ only in case cannot collide (Names).
6. **Secrets:** every secret in `provision` must carry `hosts`; `start`
   must get exactly the names the sandbox binds (hosts optional there).
   Besides the reserved names requested, secret and env names may not be
   `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`, `TERM`,
   `LANG` or start with `MSB_`, `MSBCTL_`, `LD_`, `SSH_`, `XDG_`, `LC_`:
   secret values go into msb's own environment (F7, F12).
7. **agentctl `env`** may not set `AGENTCTL_BOOTSTRAP_NONCE`; the nonce
   field is the only way in (F8).
8. **`destroy`** answers `conflict`, and leaves it alone, if a VM under
   that name lacks the Kandev label (F11).
9. **Additions:** `[kandev] serve = "tailscale" | "none"` (F1);
   `health.serve` also has `mode` and, when not ok, `reason` (F4); `reap`
   also reports `errors` (F14).
10. **Open questions 1, 2 and 4 are answered** (see Open questions).

### Changes from request 2

1. **`issuer_sha256` is the SHA-256 of the issuing certificate's DER**, the
   usual fingerprint of your root. So `cert_pem` **must** hold the leaf and
   then the certificate that issued it (the root, for a root that signs leaves
   directly). `tls install` refuses a lone leaf, or a second certificate whose
   subject is not the leaf's issuer (F17, F19).
2. **The leaf must name the host in a subjectAltName** (DNS, or IP for an IP
   `base_url`), as Go's verifier requires; the CN is not consulted. A
   single-label wildcard (`*.domain`) matches. `tls install` needs
   `[kandev] base_url` set, and refuses an encrypted `key_pem` (F17).
3. **`proxy_listen` is an IP address, not a name.** `proxy_port_pool` may not
   overlap `port_pool` (F16).
4. **The serve mode is recorded per entry** (`serve`). Changing
   `[kandev] serve` applies to new sandboxes. `lease`, `destroy` and `reap`
   follow the mode the entry was made with, so a host switched to `"proxy"`
   still removes its old `tailscale serve` paths (F16).
5. **`lease` in proxy mode answers `unavailable`** while `proxy_listen` is
   unset or no certificate is installed, as well as when the VM isn't running
   (F18).
6. **Exactly one `X-Msb-Lease` header** (originally `Authorization`, fixed in
   `dec3dd2`). Two, even if one is valid, get the 401. Every header,
   `Authorization` included, is forwarded to the guest unchanged with the
   rest of the request: the proxy does not rewrite heads (F16).
7. **The proxy offers ALPN `http/1.1` only**, so Kandev's Go client never
   negotiates HTTP/2, which would carry many requests on one connection past
   the head check (F16).
8. **Listeners exist for every proxied entry, whatever its state.** A valid
   token for a stopped VM gets a fixed `502` (F16).
9. **Rescans every 2 s**, and the proxy also re-reads the entry on each
   connection. A destroyed sandbox therefore refuses new connections at once,
   its ports close within 2 s, and its open connections are cut. A new
   generation's token works the moment `start` returns (F16).
10. **`health.serve` in proxy mode** also says not ok when `base_url` is
    unset, and `reason` names the first problem found. `health.tls` is just
    `{"installed": false}` until a certificate exists (F19).
11. **`msbctl kandev proxy` is refused under `host serve --kandev`**: it is
    the host's own service, not a verb for the plugin. `tls install` is
    allowed. `host kandev install` writes `msb-kandev-proxy.service` and
    restarts it, so re-running it after an upgrade picks up new code (F14,
    F16).

### Plugin review of request 2 (2026-10-19): two blockers, both fixed

The first build of request 2 sent the lease token as `Authorization: Bearer`
and bound it to `generation`. Kandev v0.97.0 refuses a lease that sets
`Authorization` (`normalizeLeaseHeaders` in
`apps/backend/internal/agent/runtime/agentctl/endpoint_transport.go`), sets
that header itself on every request for agentctl, and refreshes a lease only
30 s before `expires_at`, never on a 401. So `serve = "proxy"` could not
work, and a generation-bound token would have broken every VM restart for up
to 10 minutes.

**Fixed** in msb-manager `main`, commit `dec3dd2` (2026-10-19), checked in
its diff:

- `lease` returns `"headers": {"X-Msb-Lease": "v1.…"}`. The proxy reads
  exactly one `X-Msb-Lease` header, never looks at `Authorization`, and
  forwards every byte as it came, so agentctl's token reaches the guest
  untouched.
- The HMAC covers `name | guest port | incarnation | valid_until`. The
  incarnation is the entry's `created_at` plus 8 random bytes drawn at
  provision, a deviation from the request, which named `created_at` alone:
  two provisions of one name can land in the same second, and an old token
  would then work on the new sandbox. Only the host computes and checks the
  token, so the plugin is unaffected and still treats it as opaque.
- `expires_at` is now + 10 min; the token is accepted until `valid_until` =
  now + 15 min, with 30 s of clock skew.
- `host kandev rotate-lease-key` moves the key to `lease.key.prev`, accepted
  for 15 min after the rotation. Rotating twice within 15 min drops the
  older key.

The plugin still refuses any lease whose `headers` set a name Kandev refuses,
answering `unavailable`, in case a host regresses.

## Milestones

Each milestone is independently useful and unblocks a plugin phase.

| Milestone | Requests | Unblocks |
| --- | --- | --- |
| **M0: spikes** | [S1–S5](#spikes-needed-first) | Confidence the design works on msb 0.7.x |
| **M1: a host the plugin can register** | [F1](#f1-kandev-config-section) `[kandev]` config · [F2](#f2-host-authorize---kandev) `host authorize --kandev` · [F3](#f3-host-serve---kandev) `host serve --kandev` · [F4](#f4-kandev-health) `health` · [F5](#f5-kandev-list) `list` | The plugin's Sandbox Hosts page against a real host: add, test, drain, remove |
| **M2: one session runs** | [F6](#f6-the-kandev-entry-kind) entry kind · [F7](#f7-kandev-provision) `provision` · [F8](#f8-kandev-agentctl) `agentctl` · [F9](#f9-kandev-inspect-and-kandev-find) `inspect` · [F10](#f10-kandev-lease-and-the-data-path) `lease` + serve mappings · [F11](#f11-kandev-destroy) `destroy` | A Kandev task launches, shows terminal, files, git and editor, and is cleaned up on archive |
| **M3: it survives failure** | [F9](#f9-kandev-inspect-and-kandev-find) `find` · [F12](#f12-kandev-start-and-kandev-stop) `start`/`stop` · [F13](#f13-kandev-expiry) `expiry` · [F14](#f14-kandev-reap-and-host-kandev-install) `reap` + timer | Lost replies, Kandev restarts, host reboots, expiry |
| **M4: docs** | [F15](#f15-documentation) "Kandev hosts" page | A new host in under 30 minutes from the docs |
| **M5: host-side TLS** (request 2), released in 0.4.0 | [F16](#f16-serve--proxy-the-tls-proxy) proxy · [F17](#f17-kandev-tls-install) `tls install` · [F18](#f18-lease-tokens) lease tokens · [F19](#f19-health-reports-tls) `health.tls` | The default data path: works without Tailscale's hosted control plane (headscale, WireGuard, a LAN), with the plugin's own root |

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

- `k-<env>` when that string, **not** lowercased, matches `SANDBOX_NAME`
  and is at most 40 characters (msb uses the name as the guest hostname,
  limited to 64 bytes, and in socket paths);
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
| **S4** | A guest reaches the Kandev API through one rule naming the address the host resolved, plus a guest `/etc/hosts` line, while a non-allowlisted host is refused, with DNS rebind protection on. |
| **S5** | Cold and warm round trip of `ssh host msbctl kandev health` and `inspect`. The budgets are Kandev's 15 s for connection leases and 30 s for control calls. |

All five are `spikes/16-kandev-host.sh` in msb-manager (with a registry
credential check). Run 2026-10-17 on msb 0.7.7, nested inside an msb
sandbox: S1, S3 and the registry check PASS; S4 PASS for the pinned
address and the refused host, and showed that `/etc/hosts` is rewritten at
every boot. S2 and S5 need a tailnet node and a remote, and are still to
run on a real host (`SPIKE_TS=1`, `SPIKE_SSH_DEST`).

S2 no longer gates anything: request 2 makes the host-side proxy
([F16](#f16-serve--proxy-the-tls-proxy)) the default, and S2 only matters
for `serve = "tailscale"`.

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
# What serves base_url: "tailscale" (`tailscale serve --set-path`) or "none".
serve          = "tailscale"
# What a profile's extra egress may add, as hostname patterns. Empty allows
# nothing extra; ["*"] trusts whatever the Kandev server's profiles ask for.
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
- `serve`: `{"ok": bool, "mode": "tailscale" | "none"}`, plus `reason` when
  not ok. `ok` means `tailscale status` reports a running node with a DNS
  name (always true with `serve = "none"`).
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
- Operator verbs: `ls`, `status` and `show` display kandev entries, and
  `shell`/`exec` work while one runs (never starting a stopped one). Every
  other operator verb refuses them: Kandev owns them. New operator sandbox
  names may not start with `k-`.

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
   Secret and env names are not reserved (`is_reserved_var()`, plus
   `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `PATH`,
   `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`, `TERM`, `LANG`, and
   the prefixes `AGENTCTL_`, `MSB_`, `MSBCTL_`, `LD_`, `SSH_`, `XDG_`,
   `LC_`), do not collide with each other, and every secret has `hosts`.
   `egress_allow` entries are a host or `host:port` (not a rule) and match
   `[kandev] allow_extra`. `kandev_api` is required. `expires_at` is in the
   future. A private `image` names its registry host. Any failure is
   `invalid_config`.
3. **Take the lock and check capacity.** If one more sandbox of this size
   would exceed `[kandev]`, answer `rate_limited` with `retry_after_seconds:
   30`. Then allocate 4 free host ports from `port_pool`.
4. **Write the entry first**, as `creating`, before `msb create`, so a crash
   mid-create is reconcilable. `max_expires_at = expires_at`.
5. **Create** through `do_create()` with flags from the same `Sandbox` code
   as every other sandbox:
   - `--net-rule` for `base`, `[kandev] rule_groups`, `egress_allow`, and
     one rule for the address `kandev_api.host` resolves to **on the host**
     (`allow@<addr>:tcp:<port>`). The name goes into the guest's
     `/etc/hosts` after create, and again on every `start`, because msb
     writes a fresh `/etc/hosts` at boot. DNS rebind protection stays on;
     `allow_private_dns` is not used;
   - `--port` for the four ports;
   - `--secret NAME@HOSTS` per secret, with `with_transcript_passthrough()`
     as every binding gets;
   - the labels; `--max-duration` up to `max_expires_at`, as a backstop;
   - `env` as `-e`;
   - **no** `--vsock` agent filter.
   Secret values go into the environment of that one `msb create` only.
   Nothing is written to `secrets/`.
   - **Registry credentials** are used by a `msb pull` before the create:
     msb is pointed with `MSB_CONFIG_PATH` at a throwaway copy of its
     config that adds `registries.hosts.<host>.auth = {username,
     password_env}`, the password is in that pull's environment, the copy
     is deleted, and the create uses `--pull never`. (`msb registry login`
     is not used: it stores the credential in the OS keyring.)
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

- `env` keys must match `AGENTCTL_[A-Z0-9_]+` and may not be
  `AGENTCTL_BOOTSTRAP_NONCE`; others are `invalid_config`.
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

**Changed by request 2:** with `serve = "proxy"` (the new default),
`base_url` is `https://<host name>:<public port>` with no path, and the
lease carries headers; see [F16](#f16-serve--proxy-the-tls-proxy) and
[F18](#f18-lease-tokens). The serve mappings above apply only to
`serve = "tailscale"`.

## F11: `kandev destroy`

```text
msbctl kandev destroy ENV
```

Removes the VM (`msb rm -f`), its disk, its serve mappings and its entry,
and prints `{"destroyed": true}`. It is **always safe**: an unknown `ENV`, or
an entry whose VM is already gone, also succeeds. A failure partway leaves
the entry, so a retry or `reap` finishes the job. A VM under that name that
does not carry the Kandev label is not Kandev's: `destroy` answers
`conflict` and leaves it alone.

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
  half-bound sandbox. The request must name **exactly** the secrets the
  entry binds (`hosts` may be omitted here); extra names are
  `invalid_config` too. A running VM is a no-op. `start` does not relaunch
  agentctl: it reports `agentctl.running = false`, and the plugin calls
  `agentctl` again if it needs to.
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
{"destroyed": ["k-…"], "marked_absent": ["k-…"], "orphans_removed": ["k-…"], "errors": []}
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

## Request 2: host-side TLS (2026-10-19)

**Why.** Kandev accepts only HTTPS leases and verifies them against the
Kandev server's system trust store (`validateLeaseEndpointURL`; no custom
TLS config, `InsecureSkipVerify` forced off). `tailscale serve` met that with
`*.ts.net` certificates, but only on Tailscale's hosted control plane:
headscale supports neither Serve nor `tailscale cert` (headscale #1921). The
plugin will therefore act as a small certificate authority. It generates a
root **name-constrained** to the sandbox hosts' domain, which the operator
trusts on the Kandev server only, and issues each host's certificate. TLS
terminates **on the sandbox host**, so traffic goes Kandev → host directly.

What msbctl needs is below. The plugin owns the CA, key generation and
renewal; msbctl stores the certificate and serves it.

**Built** and released in msb-manager 0.4.0; the differences are in
[Changes from request 2](#changes-from-request-2) and
[Plugin review of request 2](#plugin-review-of-request-2-2026-10-19-two-blockers-both-fixed).
F16 and F18 below are the shape as built after the lease-token fix.

### F16: `serve = "proxy"`, the TLS proxy

**Changes F1 and F14.** New `[kandev]` keys:

```toml
serve            = "proxy"          # new default; "tailscale" and "none" remain
proxy_listen     = ""               # address the TLS ports bind, e.g. the tailnet or LAN IP; required for "proxy"
proxy_port_pool  = "30000-39999"    # public TLS ports, one per published guest port
```

`msbctl kandev proxy` is a long-running, stdlib-only service: `ssl`, plus
`socket` with `selectors` or threads.

- **One TLS listener per published guest port**, on
  `proxy_listen:<public port>`, splicing bytes to that port's
  `127.0.0.1:<host port>`. `provision` allocates the four public ports from
  `proxy_port_pool` under the same lock as the loopback ports, and records
  them in the entry (`proxy_ports`, guest port → public port). One port per
  lease means a pooled connection can only ever reach one VM port, so there
  is **no HTTP parsing and no path routing**.
- **Per connection:** complete the TLS handshake, then read the first
  request head (cap 16 KiB, 10 s). Check its one `X-Msb-Lease` token
  ([F18](#f18-lease-tokens)) for *this* sandbox incarnation and guest port.
  `Authorization` is never read and passes through untouched.
  On failure, answer a fixed `401` and close. On success, forward the bytes
  read so far, then splice both directions until either side closes.
  WebSocket upgrades and streaming need nothing special.
- **Source of truth:** the proxy reads the kandev entries. A new or
  destroyed sandbox opens or closes its listeners within a few seconds,
  through a rescan or a signal from `provision`/`destroy`. A destroyed
  sandbox's port refuses connections.
- **Certificate:** `CONFIG_DIR/kandev/tls/cert.pem` (leaf + chain) and
  `key.pem` (0600), reloaded when they change. Until both exist, the proxy
  listens on nothing and `health` says why.
- `host kandev install` also installs and enables the proxy's systemd user
  service. `health` reports whether it is running.
- **Never logged:** tokens and request heads. Log only the sandbox name,
  guest port and outcome.

**Accept:** from another machine, a request with a valid lease header
reaches agentctl, and one without, with another sandbox's token or with an
expired token gets 401. A WebSocket echo survives 10 min of idle. Two
sandboxes' ports never cross. A destroyed sandbox's port refuses within
5 s. No token appears in logs (fake-`msb` plus loopback TLS tests).

### F17: `kandev tls install`

```text
msbctl kandev tls install          # stdin: one JSON header line
```

```json
{"cert_pem": "-----BEGIN CERTIFICATE-----…(leaf, then chain)", "key_pem": "-----BEGIN PRIVATE KEY-----…"}
```

- Check that the key matches the leaf, and that the leaf is valid now and
  covers the host name in `[kandev] base_url`. Stdlib `ssl` can load the
  pair into an `SSLContext` to prove it. Then write both files atomically
  (key 0600) and print `{"tls": <F19 document>}`.
- The plugin generates the host key because msbctl is stdlib-only and
  cannot. The key crosses the SSH channel once, on stdin, never in argv,
  and is never printed.
- Allowed under `host serve --kandev`; refused under plain `host serve`.

**Accept:** a mismatched pair, an expired certificate or a wrong name is
`invalid_config`, and the files on disk are unchanged; the key never
appears in argv or stdout.

### F18: lease tokens

**Changes F10** when `serve = "proxy"`:

```json
{"lease": {
  "base_url": "https://sbx-01.tailnet.ts.net:30001",
  "expires_at": "2026-10-19T12:10:00Z",
  "generation": "1",
  "headers": {"X-Msb-Lease": "v1.1792244100.…"}
}}
```

- `token = "v1." + valid_until + "." + base64url(HMAC-SHA256(key, name | guest port | incarnation | valid_until))`,
  where incarnation is `created_at | <random value drawn at provision>` and
  `valid_until` is `expires_at` + 5 min. The key is 32 random bytes in
  `STATE_DIR/kandev/lease.key` (0600), created on first use.
- These tokens are stateless: `lease` and the proxy share only the key
  file, so no IPC is needed, and a proxy restart invalidates nothing. The
  proxy accepts a token until `valid_until`, with 30 s of clock skew, signed
  with the current key or, for 15 min after `host kandev rotate-lease-key`,
  the previous one. A stop and start keeps tokens valid; a destroy and
  re-provision retires them.
- Not `Authorization`: Kandev refuses a lease that sets it.
- The plugin puts `headers` in both Kandev's `http_headers` and
  `websocket_headers`.
- `kandev lease` output is now secret-bearing. The plugin treats it so;
  msbctl must not log it.

**Accept:** a token for one sandbox or port is refused on another; a token
past expiry is refused; a token minted before `stop`/`start` still works; after
`destroy` and a re-provision of the same name, even within one second, it
is refused.

### F19: `health` reports TLS

**Changes F4**, additively, so `protocol` stays 1:

```json
"serve": {"ok": true, "mode": "proxy", "listen": "100.64.0.7", "running": true},
"tls": {"installed": true, "subject": "sbx-01.tailnet.ts.net",
        "not_after": "2027-01-17T00:00:00Z", "issuer_sha256": "…"}
```

- With `mode = "proxy"`, `serve.ok` means the proxy is running with a
  certificate installed and `proxy_listen` set.
- `tls.not_after` drives the plugin's renewal: it re-issues within 30 days.
- `issuer_sha256` lets the plugin see that the host carries a certificate
  from its current root, and re-issue after a root change.
- **Also in the `tailscale` mode:** report `serve.ok = false` when the
  node cannot get certificates. Today `ok` only checks that tailscaled runs
  with a DNS name, which is also true on headscale, where `tailscale serve
  --https` then fails. `tailscale status --json` lists `CertDomains`, and
  an empty list means no certificates.

**Accept:** each state has a test: no certificate, an expired one, the
proxy not running, `proxy_listen` unset, and `tailscale` mode with empty
`CertDomains`.

## Request 3: from the first real run (2026-10-19)

Kandev 0.97.0 and the plugin against msb-manager 0.4.0 on a real host
(`serve = "proxy"`) ran a whole agent session: provision, agentctl, the
lease through the proxy, agent turns streamed back, inspect, and expiry by
the reaper. One gap is on msbctl's side.

### F20: a workspace disk at `/workspace`

Kandev creates every session's agentctl instance at **`/workspace`**
(`pluginExecutorWorkspacePath`, fixed, in
`apps/backend/internal/agent/runtime/lifecycle/executor_plugin.go`) and
starts the agent there. Nothing creates it: Kandev does not, agentctl does
not, and only a task with a repository gets a checkout under it. With a
stock image (`debian:13-slim`), the agent fails with `fork/exec <agent>: no
such file or directory`, which is Go's report of a missing working directory.

Give each Kandev sandbox **its own disk at `/workspace`**, the way repo
sandboxes already keep their clone on `<prefix>-workspace`
(`Sandbox.workspace_volume`, `named_disk_flags`):

- `provision` takes **`workspace_gib`** (integer, 1–500) in the header and
  mounts a disk volume of that size at `/workspace`
  (`--mount-named <prefix>-workspace:/workspace:kind=disk,size=<n>G`). The
  plugin always sends it (default 20). Refuse a missing or out-of-range
  value with `invalid_config`; a provision without a workspace is the
  failure this fixes.
- `/workspace` must be writable by the user agentctl runs as (root today),
  empty on a new sandbox.
- **Removed with the sandbox.** `purge`, the reaper's expiry and its
  reconcile delete the volume with the VM, under the same lock. A volume
  named for a Kandev sandbox with no entry is an orphan, removed like an
  unlabelled VM. Nothing of a Kandev workspace may outlive its sandbox: the
  data is the agent's and the task's, and Kandev does not know about it.
- `stop`/`start` keep it, as they keep the root disk.
- **`health.features` lists `"workspace_disk"`.** `protocol` stays 1. The
  plugin refuses a host that does not list it, because 0.4.0 ignores
  unknown header keys: it would provision without a workspace and report
  success. `features` is the place for later additions within protocol 1.
- Optional (not built): count workspace disks against a `[kandev] max_disk` limit, and
  report `max_disk_gib`/`disk_gib` in `capacity`. The plugin does not use
  them yet.

Why a disk and not a host directory: a host mount is virtiofs, which is
slow for git and builds and has corrupted git's index in practice; it has
no quota, so one build can fill the host; it puts what untrusted code wrote
on the host's own filesystem; and a host path can outlive its sandbox.

**Built** and released in msb-manager
[0.5.0](https://github.com/runoverlabs/sandbox-manager/releases/tag/v0.5.0)
([PR #65](https://github.com/runoverlabs/sandbox-manager/pull/65), merge
`5e3bc64`, 2026-10-19). Verified with Kandev on a real host: an agent ran in
a 7 GiB ext4 `/workspace` on a stock image, and `purge` left no disk behind. One difference, an improvement:
the disk is msb's **owned** kind (`--mount-owned
/workspace:kind=disk,size=<n>G`), not a named `<prefix>-workspace` volume.
msb deletes an owned disk with its VM, so nothing of a workspace outlives
its sandbox however the VM goes (purge, expiry, an orphan's removal, `msb rm
-f`), with no second deletion step that could fail. Checked on real msb
0.7.7: an empty ext4 `/workspace` of the requested size (no `lost+found`),
kept across `stop` and `kandev start`, and gone after purge and after
expiry. The optional `max_disk` limit and capacity fields were not built.

**Accept:** a sandbox gets an empty, writable ext4 `/workspace` of the
requested size; it survives `stop`/`start`; `purge`, expiry and reconcile
leave no volume behind; a header without `workspace_gib` is
`invalid_config`; `health.features` contains `"workspace_disk"`.

## Request 4: central egress from the plugin (2026-10-19)

Sandboxes run arbitrary agent harnesses (opencode, pi, hermes, …) against
models that live anywhere: a LAN server, OpenRouter, a vendor API. So the
plugin now keeps a central egress policy (named groups, default groups for
every sandbox) and sends the expanded list as provision's `egress_allow`,
which msbctl already accepts, including address targets such as
`192.168.2.6:8788`. Two gaps remain on the host side.

### F21: `allow_extra` admits addresses, and `health` reports it

- **`[kandev] allow_extra` accepts address entries**, alongside `"*"` and
  hostname patterns: an address (`192.168.2.6`, any port), an
  `address:port` (`192.168.2.6:8788`), and a CIDR (`192.168.2.0/24`, any
  port). Today an address target passes only with `"*"`, because
  `kandev_egress` compares the target's host part against hostname patterns,
  so an operator who wants a bound cannot admit one LAN model server without
  admitting everything. A hostname pattern keeps matching the host part on
  any port, as now. Refuse a CIDR wider than /8 (IPv4) or /32 (IPv6) at
  config load, like the plugin's own range limits.
- **`health.egress = {"allow_extra": [...]}`**, the effective list. The
  plugin's Test then checks its default groups against it before any launch:
  msbctl refuses a whole provision over one entry, so a host that would refuse
  a default is unusable for every profile, and the operator should hear that
  from Test rather than from a failed task. Not secret: it is the operator's
  own policy.
- No change to provision itself: `egress_allow` keeps its shape and its
  checks.

**Built** and released in msb-manager
[0.5.1](https://github.com/runoverlabs/sandbox-manager/releases/tag/v0.5.1)
(`fbb1bcc`, `a3c6a98`). As requested; it also takes a bare IPv6 address
(`fd00::1`), which the plugin's Test now understands too.

**Accept:** `allow_extra = ["192.168.2.6:8788"]` admits `192.168.2.6:8788`
and refuses `192.168.2.6:8789`; `["192.168.2.0/24"]` admits any port on
`192.168.2.6`; `["pypi.org"]` still refuses `192.168.2.6:8788`; a /4 is a
config error; `health.egress.allow_extra` equals the loaded list.

## Open questions

1. **agentctl after a VM restart.** Does a restarted agentctl need a fresh
   nonce, and does Kandev's attach provide one? Still open on Kandev's
   side. As built, `start` only starts the VM and reports
   `agentctl.running = false`, and the plugin decides whether to call
   `agentctl` again.
2. ~~Private images.~~ Answered: msb's config `password_env`, through a
   throwaway `MSB_CONFIG_PATH` for one pull (F7). Verified on 0.7.7.
3. ~~`allow_extra` default.~~ Answered: empty allows nothing extra;
   `["*"]` trusts the profiles.
4. ~~Name length.~~ Answered: 40 characters for `k-<env>` (msb's guest
   hostname is limited to 64 bytes).
5. **Idle VMs.** On session stop, keep the VM running until expiry, or stop
   it and restart on attach? Decide after measuring resume time; each idle VM
   costs about 300 MB.

## Out of scope

- Sharing one VM between sessions: Kandev's contract v1 isolates sessions.
- Reading `.msb/` from a repository: kandev sandboxes take their whole
  definition from the request.
- Snapshots and migration between hosts.
- Multi-tenant isolation beyond one operator per host.
