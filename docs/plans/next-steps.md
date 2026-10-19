# Next steps (agreed 2026-10-19)

Written down before a context compaction, then built the same day. Each
item starts with where it stands. Section "State" is where testing stands.

| Item | Status |
| --- | --- |
| 1. Host setup | Built as `hosts.setup` / `hosts.setup.status` (`internal/hostsetup`). sudo: passwordless sudo is used when the login has it; without it, root's part is listed as commands. The pinned installers ran for real in a throwaway home; a full run against a fresh machine has not happened yet. |
| 2. Readiness | Built as `setup.status`. The API URL is read from Kandev's environment (Kandev passes it to the plugin process unfiltered), else from the last launch's bootstrap. Not built: a direct TLS check from Kandev to a proxy port, which needs a running sandbox. |
| 3. Host detail | Built: each host's last check in `hosts.list`, refreshed every 15 minutes. Host facts wait on msbctl F22 (requested). |
| 4. UI | Built: overview, Sandbox hosts, Sandbox egress, Sandbox secrets, verified in Kandev 0.97.0. Secrets became plugin-kept and named by a `secrets` profile field, since a profile form cannot hold lists; `env` stays a string (an upstream key/value schema type would fix both). |
| 5. msbctl | Written up as Request 5 in [msbctl-feature-request.md](../msbctl-feature-request.md): F22 host facts, F23 `host kandev configure`, F24 `self-update` under the kandev key. |
| 6. Egress | Done: sizes bounded by msbctl's 64 KiB header; Test's hint gives the exact `allow_extra` line. |
| 7. Kandev upstream | Not filed: waits for the user's go-ahead. |
| 8. Smaller items | The test host's egress line is the user's call (see State). New: attach could restart a stopped sandbox with secrets now that their values live in the plugin, if resource state kept the secret names. |

## Goal

Using Kandev with this plugin should not mean hand-configuring each sandbox
host. An operator creates a KVM-capable machine (for example an EC2 `.metal`
instance), hands the plugin an admin SSH login once, and everything else is
done and shown by the plugin.

## 1. `hosts.bootstrap`: set up a host from an admin login

One admin action, given an SSH destination and an admin login (key, used
once, never stored), that turns a bare Linux machine into a ready host:

1. Pin the host key (scan; the operator confirms the fingerprint, as with
   `hosts.scan`).
2. Check KVM (`/dev/kvm` present and usable) first, and stop with a clear
   message if it is missing: nothing in software fixes that, and on EC2 it
   means a `.metal` or nested-virtualization instance type.
3. Install `msb` and msb-manager at pinned versions, checksums verified,
   through msb-manager's own installer (`get.sh` / `install.sh`), so the
   plugin needs nothing new from msbctl.
4. Write the `[kandev]` section from what the plugin knows: `enabled = true`,
   `serve = "proxy"`, `proxy_listen` and `base_url` from the host's address,
   and `allow_extra = ["*"]` only if the operator ticks "this Kandev decides
   egress" (see 6).
5. `msbctl host kandev install` (proxy and reaper services); enable lingering
   so user services run without a login.
6. Open the host firewall (firewalld or nftables, whichever is present) for
   the proxy port range, **from the Kandev server's address only**. That
   address is the one the plugin's SSH connection comes from, which the host
   sees as `$SSH_CONNECTION`; `kandev.vild.party` showed that it is not
   necessarily the address Kandev's public name resolves to.
7. `msbctl host authorize '<plugin key>' --kandev`, add the host to the
   registry, issue its certificate, run Test, and drop the admin login.

Open decision for the user: may the plugin use `sudo` for the steps that need
it (KVM device permission, lingering, the firewall), or should it stop and
print those commands? Proposed default: use passwordless `sudo` when the
login has it, otherwise print the commands and continue with the rest.

Cannot be automated, so Test and the bootstrap result say exactly what to do:
the KVM-capable instance type, and the cloud firewall (an EC2 security group
rule allowing the Kandev server's address to the proxy ports).

Design notes:

- The admin login travels like every other secret: on stdin of the SSH
  session the plugin opens, never in argv, logs, state or responses. It is
  held only for the duration of the action.
- Idempotent: running it again on a set-up host repairs drift (an older
  msb-manager, a missing service, a missing firewall rule) and changes
  nothing else.
- Upgrades afterwards need no admin login: `msbctl self-update` can be offered
  as a host action through the restricted key once msbctl allows it there
  (a request to msbctl, F22 below), and certificates already self-heal.

## 2. Kandev server readiness, shown by the plugin

A view (an admin action first, then the page in 4) of the one-time
Kandev-server setup, with what to do for each item that is not ready:

- **Root trusted**: already known (`ca.get` returns `trusted`).
- **`KANDEV_GITHUB_CREDENTIAL_BROKER_PUBLIC_BASE_URL`**: whether it is set and
  passes Kandev's rule (`https`, not a loopback, link-local or private IP
  literal, not `localhost`). Without it every plugin launch fails with
  "plugin executor requires a reachable HTTPS Kandev API URL".
  **To investigate:** how the plugin can see it. Options: the plugin
  process's own environment (does Kandev pass it through or sanitize plugin
  env?); the `api_url` from the last provision's bootstrap, kept in state
  ("last seen"); a Kandev Host call if one exists. If none works before a
  launch, show "unknown until the first launch" and the exact env line.
- **Each host reachable from Kandev on its proxy ports**: Test already shows
  TLS and connection outcomes; add a direct check that the Kandev server can
  open a TLS connection to one proxy port.
- Later: hosts with a publicly trusted certificate (ACME DNS-01 or an
  uploaded wildcard) make the root-trust step unnecessary, as the original
  plan listed.

## 3. Host detail: what each node is and has

The list and a detail view show, per host, as of the last health check
(kept in state with a timestamp by the maintainer and by Test):

- msbctl and msb versions (in `health` already), protocol, features;
- OS and version, kernel, architecture;
- total and free memory, CPU count and load, free disk where sandboxes live;
- Kandev capacity used and limits (in `health` already), sandbox count;
- proxy and TLS state, certificate expiry, `allow_extra`, KVM;
- last check time and its problem, if any.

**Needs msbctl** (F22): `health` reports the host facts it does not yet
include: `os` (`/etc/os-release` `PRETTY_NAME`), `kernel`, `arch`,
`cpus_total`, `memory_total_mib`, `memory_available_mib`, `load_1m`,
`disk_free_gib` for the sandboxes' filesystem. All non-secret.

## 4. UI

The plugin has only actions so far. Build:

- **Sandbox Hosts page**: host list with state (3), add via bootstrap (1),
  test, drain, update, remove; the readiness panel (2); the root
  certificate (create, show, install steps).
- **Egress page**: the built-in and custom groups, defaults, add/edit.
- **Profile form**: `extra_secret_1_*` … `extra_secret_3_*` (nine fixed
  fields) is poor. It should be an "Add" list, like Environment Variables on
  the local executor's profile. **To investigate:** Kandev's profile schema
  allows only `type`, `title`, `description`, `enum`, `secret`, `format`,
  `minimum` and `maximum` (no arrays or objects), and plugin profiles reject
  Kandev's own `env_vars` ("provider profiles accept schema fields only").
  Options: a plugin UI contribution that edits the profile; a Kandev schema
  extension for key/value lists with secret values (an upstream request);
  or secrets kept in the plugin (named, managed on a plugin page) and
  referenced from the profile by name. Same question for `env`, today a
  `KEY=VALUE;…` string.

## 5. msbctl request F22

- `host authorize '<key>' --kandev --egress=plugin`: also writes
  `allow_extra = ["*"]`, so trusting the key and trusting its egress are one
  decision at setup. Without the flag, today's bounded default.
- The host facts in `health` (3).
- Possibly `self-update` allowed under `host serve --kandev`, for upgrades
  without an admin login (1).

## 6. Egress follow-ups

- Replace the invented limits (64 entries per sandbox, 32 groups, 32 entries
  per group) with the real constraint, msbctl's 64 KiB provision header,
  checked when a profile or group is saved.
- `hosts.list` / Test hint: show the exact `allow_extra` line (or the F22
  command) when Test reports `egress_refused`.

## 7. Kandev upstream (needs the user's go-ahead before filing on kdlbs/kandev)

- Passthrough agents and the task's user shell run on the Kandev server for
  plugin executors (`GetInteractiveRunner` is local-only; plugin executions
  never set `is_remote`).
- Deleting a task leaks its sandbox (the environment row goes before the
  cleanup job, so `DestroyExecutorEnvironment` is never called).
- Launch-gate failures log only the stage and the Go error type; plugin
  stderr does not reach the log at info level.
- No reattach after a failed launch (agentctl's token is transient).
- No provider call on session stop, and no bootstrap nonce on attach, so a
  provider cannot stop an idle VM and restart agentctl later.
- On `kandev.vild.party`, tasks created with `start_agent` stay deferred
  until `sessions/ensure` (possibly its Autopilot workflow; confirm before
  reporting).

## 8. Smaller items

- msbctl wrote a "decision" that a session stop stops the VM into its copy
  of the feature request. Not decided, and not possible (7); our plan says
  so. Their edits to that document never reached this repo.
- Put the egress decision for the test host in place (the user's call) and
  rerun the opencode task with the FreeToken model.

## State (2026-10-19)

- Plugin `0.1.0-dev.9` on local `main`, installed on `kandev.vild.party`
  (Kandev v0.97.0; Kandev itself connects out from 192.168.2.10, its name
  resolves to 192.168.2.6). Root trusted there; API URL set by the user.
- Egress policy there: custom group `lan-llm` = `192.168.2.6:8788` (the
  FreeToken OpenAI-compatible server, no key); defaults `lan-llm`, `opencode`.
  Profile "alloy (node)": `node:22-bookworm-slim` by digest, 2 CPUs, 4 GiB,
  `workspace_gib` 10, 2 h, `agent_config_bundles = ["opencode.config"]`.
- Host alloy (192.168.2.8): msb-manager 0.5.1. Its `config.toml` now has
  **two** `allow_extra` lines under `[kandev]` (the bounded one and `["*"]`),
  which TOML refuses, so msbctl cannot load its config and Test reports
  `unavailable`. One line must go (the user's call); that is the blocker for
  the opencode run. Runtime-only firewall rules open 30000–30099 to 192.168.1.121 (this
  sandbox) and 192.168.2.10 (Kandev). Test leftovers: `~/kandev-test/mock-agent`,
  the `/etc/hosts` line `kandev-api.home.arpa`, config backups
  `config.toml.bak-*`, `authorized_keys.bak-kandev-*`.
- Verified for real so far: provision with workspace disk, opencode config
  bundle copied, agentctl handshake through the proxy, an opencode agent turn
  (refused only at the model, by egress), inspect, reaper expiry, purge.
- Leftover test tasks in the Cursed workspace: "[msb plugin test] opencode
  ping 2" (REVIEW), "opencode ping" (FAILED), "provision probe" (FAILED).
  Delete with `POST /api/v1/tasks/delete-preflight` and the confirmation
  header; their sandboxes expire on their own (task delete leaks, see 7).
