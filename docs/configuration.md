# Configuration

Setup has two halves: register the sandbox hosts once, then write one
executor profile per project.

## Sandbox hosts

The host list is plugin-wide Host state, not plugin settings: the settings
schema validates only scalars, so a list cannot live there. Every host action
is **admin-only**. There is no Sandbox Hosts page yet; the actions below are
what it will call, and they can be invoked over Kandev's plugin action API in
the meantime (`POST /api/plugins/kandev-plugin-microsandbox/actions/<key>`,
with any workspace as the action scope).

| Action | Body | Does |
| --- | --- | --- |
| `hosts.list` | `{}` | The hosts, each with its pinned key's SHA256 fingerprint and its last check (`status`, below), plus the plugin's public key and the exact `authorize` command to run on a host. Generates the plugin's key on first use. Contacts no host. |
| `hosts.scan` | `{"ssh": "msb@sbx-01.tailnet.ts.net"}` | Connects and returns the host key the server presents, with its fingerprint, for the operator to compare with `ssh-keygen -lf` on the host. Stores nothing. |
| `hosts.add` | a host (below) | Registers a host. Returns 201. |
| `hosts.update` | a host | Replaces a host's SSH destination, pinned key, base URL and labels. The name cannot change, and the draining flag is kept. |
| `hosts.drain` | `{"name": "...", "draining": true}` | A draining host gets no new sandboxes but keeps serving its existing ones. |
| `hosts.remove` | `{"name": "...", "force": false}` | Asks the host for its kandev sandboxes and refuses (409) while it has any. If the host cannot be reached, it refuses (502) unless `force` is set. |
| `ca.get` | `{}` | The plugin's root certificate (PEM, SHA-256, constraints, expiry), whether this Kandev server trusts it yet, and how to install it. `exists: false` before `ca.create`. |
| `ca.create` | `{"dns_suffixes": ["tailnet.ts.net"], "cidrs": [], "replace": false}` | Generates the root, name-constrained to those suffixes and ranges. Refuses (409) to replace an existing root unless `replace` is set; hosts are then re-issued automatically. |
| `hosts.test` | `{"name": "..."}` | Runs `msbctl kandev health` and returns `ok`, a `problem` code with a `hint`, the health report, a `tls` outcome for proxy hosts, and a `warning` when the host's own `base_url` differs from the registered one. The result becomes the host's `status`. |
| `hosts.setup` | below | Sets up a bare machine over an admin login and registers it: [Setting up a new machine](#setting-up-a-new-machine). Returns 202 with a job. |
| `hosts.setup.status` | `{"id": "..."}` | A setup job's steps so far. Jobs live in memory, for an hour after they finish. |
| `setup.status` | `{}` | The Kandev server's own one-time setup, item by item (below), each with what to do when it is not ready. |

A host:

```json
{
  "name": "sbx-01",
  "ssh": "msb@sbx-01.tailnet.ts.net",
  "host_key": "ssh-ed25519 AAAA...",
  "base_url": "https://sbx-01.tailnet.ts.net",
  "labels": ["default", "big-mem"]
}
```

- `name`: 1–63 lowercase letters, digits, `.`, `_`, `-`. It is recorded in
  every sandbox's resource state, so it is permanent.
- `ssh`: `user@host[:port]`. The user is required.
- `host_key`: the pinned key line. Every connection verifies it; a changed key
  is refused (`host_key_mismatch`) and never re-pinned automatically.
- `base_url`: the host's HTTPS base for the data path. It must be `https://`,
  carry no path, credentials, query or fragment, and not be a loopback,
  link-local, multicast or unspecified address, which Kandev refuses for
  connection leases.
- `labels`: what `label:<x>` placements select. Lowercased and deduplicated.

A host's `status` in `hosts.list` is its last check, by Test or by the
plugin's maintainer, which checks every host every 15 minutes: `checked_at`,
`ok`, `problem` and `hint` as Test returns them, and the health report. That
report has versions, capacity, TLS and `allow_extra`, and on hosts with
feature request F22 also `host`: OS, kernel, CPUs, memory, load, disk and
uptime.

### Kandev server readiness

`setup.status` returns `ready` and three items, each with a `state`, a
`detail` and, when not `ok`, the steps to `fix` it:

| Item | States | Checks |
| --- | --- | --- |
| `root` | `ok`, `missing`, `untrusted` | The plugin's root exists and the Kandev server's system roots trust it. |
| `api_url` | `ok`, `invalid`, `unknown` | `KANDEV_GITHUB_CREDENTIAL_BROKER_PUBLIC_BASE_URL`, which every plugin launch needs, against Kandev's own rules (below). Kandev passes its environment to the plugin, so the plugin reads it there. A value set in Kandev's config file instead is invisible to the plugin until a launch carries it, so before the first launch the state is `unknown`, and afterwards the URL the last launch carried counts. |
| `hosts` | `ok`, `missing`, `unchecked`, `failing` | At least one registered host passes its last check; failing hosts are named with their problem. |

### The root certificate

Kandev reaches each sandbox over HTTPS and verifies the certificate against
the **Kandev server's** system trust store. With `[kandev] serve = "proxy"`
on a host (the planned default), the host's certificate comes from the
plugin's own root:

1. `ca.create` with the domain your sandbox hosts' `base_url`s use, such as
   `tailnet.ts.net` or a headscale `base_domain`. Add `cidrs` only if a
   `base_url` uses an address.
2. `ca.get`, and install the root on the Kandev server only, following its
   `install` steps. Restart Kandev afterwards.

The root is **name-constrained**: it can only ever certify names under those
suffixes, so trusting it does not let it impersonate any other site to the
Kandev server, even if its key leaked. Its key stays in the plugin's secret
store.

**Host certificates need no attention.** The plugin issues one when a host is
added. It re-issues one whenever a host reports none, one expiring within 30
days, one for another name, or one from a replaced root. It checks from a
background pass every 15 minutes and on every **Test**. A host whose
`base_url` is outside the root's constraints is refused at `hosts.add`.

### Setting up a new machine

`hosts.setup` turns a bare Linux machine with KVM into a registered host,
from an admin SSH login you give once. Nothing else is needed on the
machine first.

1. `hosts.scan` with the admin destination (`ubuntu@203.0.113.10`), and
   compare the fingerprint with the machine's (on EC2, the instance's
   console output lists it).
2. `hosts.setup`:

   ```json
   {
     "name": "sbx-01",
     "ssh": "ubuntu@203.0.113.10",
     "host_key": "ssh-ed25519 AAAA...",
     "admin_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
     "base_url": "https://sbx-01.example.com",
     "labels": ["default"],
     "egress_from_plugin": true
   }
   ```

   - `admin_key` (with `admin_key_passphrase` if it has one) or
     `admin_password`: the login. It is used for this setup only, held in
     memory, and never stored, logged or shown.
   - `base_url`: the name Kandev reaches the machine at, within the root's
     constraints. Defaults to `https://<the ssh host>`; an address there
     needs the root's `cidrs` to cover it.
   - `account`: the account msb-manager runs under, default `msb`.
   - `egress_from_plugin`: writes `allow_extra = ["*"]`, so this plugin's
     egress policy decides what sandboxes reach ([Egress](#egress)).
     Without it the host admits nothing beyond its own rule groups.
   - `kandev_address`: the address the host firewall admits. Defaults to
     the address the setup's SSH connection comes from, which is the Kandev
     server's as the machine sees it.

   It answers 202 with a job; `hosts.setup.status` with `{"id": "..."}`
   follows it (Kandev gives an action 15 seconds, and a setup takes
   minutes).

The steps, each reported `ok`, `changed`, `manual`, `failed` or `skipped`:

| Step | Does |
| --- | --- |
| `probe` | Linux on x86_64 or aarch64, `/dev/kvm` present (else it stops: on EC2 use a `.metal` instance type), and whether the login has passwordless sudo. |
| `packages` | Installs python3 (3.11+ is required), git, curl and tar with apt or dnf, and `dbus-user-session` on Debian and Ubuntu. |
| `account` | Creates the `msb` account (no sudo, 0700 home), adds it to `/dev/kvm`'s group, and enables lingering so its user services run without a login. |
| `msb`, `msb-manager` | Installs msb 0.7.7 and msb-manager 0.5.1 from their own installers, each pinned by sha256; never downgrades. |
| `config` | Appends `[kandev]` to msbctl's `config.toml`: `serve = "proxy"`, `proxy_listen` on the machine's own address for the connection, `base_url`. An existing section is left alone (see `verify`). |
| `services` | `msbctl host kandev install` (the TLS proxy and the reaper), only when something changed or a service is down. |
| `firewall` | With firewalld or ufw active, opens TCP 30000–39999 to the Kandev server's address only. |
| `authorize` | `msbctl host authorize '<plugin key>' --kandev --replace` for the account. |
| `verify` | The host's own `health`, compared with what the setup would write; a difference is reported with the lines to change. |
| `register`, `test` | Registers the host as `msb@<machine>` with the confirmed host key, issues its certificate and runs Test. |

Without passwordless sudo, msb-manager is set up for the login itself, and
the steps that need root are reported `manual` with the commands to run.
Run `hosts.setup` again afterwards: every step is idempotent, so a second
run on a set-up machine changes nothing, and one on a drifted machine
repairs it. The job also lists what it cannot do from inside the machine:
a cloud firewall (an EC2 security group) must allow TCP 30000–39999 from
the Kandev server.

A failed step shows the end of its command's output. That is the one place
the plugin shows output from a host: it is your machine and your login.

### Adding a host that is already set up

1. `hosts.list`, and run the returned `authorize` command on the host:
   `msbctl host authorize '<plugin public key>' --kandev`.
2. `hosts.scan` with the SSH destination; compare the fingerprint with
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host.
3. `hosts.add` with the scanned `host_key`.
4. `hosts.test`. `problem` tells you what is missing:

| `problem` | Meaning |
| --- | --- |
| `not_authorized` | The host refused the plugin's key. Run the `authorize` command. |
| `refused` | The key is accepted but `msbctl kandev` was refused: authorize it with `--kandev`, and check msbctl on the host is recent enough. |
| `host_key_mismatch` | The host presented a different key than the pinned one. |
| `unreachable` | No answer from the host's SSH server. |
| `protocol` | msbctl speaks a different host protocol version. |
| `outdated` | msbctl lacks a feature this plugin needs (the hint names it, such as `workspace_disk`). Update msb-manager there. |
| `disabled` | `[kandev] enabled` is not true in the host's msbctl config. |
| `no_kvm` | `/dev/kvm` is missing on the host. |
| `no_data_path` | The host's HTTPS front end for sandboxes is not up (for `serve = "tailscale"`: tailscaled is not running with a DNS name). |
| `unavailable` | msbctl ran but returned no health report. |
| `no_root` | The host runs the TLS proxy, but the plugin has no root yet. Run `ca.create`. |
| `not_permitted` | The host's `base_url` is outside the root's constraints. |
| `tls_install_failed` | The host did not accept a new certificate. It is retried automatically. |
| `egress_refused` | The host's `allow_extra` would refuse a default egress entry (listed in `egress_refused`), so every provision there fails. See [Egress](#egress). |
| `root_not_trusted` | The Kandev server does not trust the plugin's root yet. Install it (`ca.get`) and restart Kandev. |

### What Kandev and the network need

Found on the first real run (Kandev 0.97.0, msb-manager 0.4.0):

- **Kandev's API URL must be `https` and must not be a private address.**
  Kandev refuses to launch on any plugin executor unless
  `KANDEV_GITHUB_CREDENTIAL_BROKER_PUBLIC_BASE_URL` is set to an `https` URL
  whose host is not `localhost`, a loopback, link-local or private IP literal
  (so `https://192.168.1.5` is refused). A DNS name passes. Every sandbox
  host must be able to resolve that name: msbctl resolves it on the host,
  pins the sandbox's egress to that address, and writes it into the guest's
  `/etc/hosts`. Agents call back to Kandev through it.
- **The Kandev server must reach each host's proxy ports**, `proxy_listen`
  on `proxy_port_pool` (default 30000–39999), with four ports per sandbox. On
  a host with a firewall (firewalld on Fedora allows only `ssh`), open that
  range to the Kandev server's address only.
- **Hosts need a workspace disk** (feature request F20): Kandev starts every
  agent in `/workspace`, and nothing else creates it. msb-manager 0.5.0 gives
  each sandbox its own disk there; 0.4.0 does not, so Test reports
  `outdated` there and placement skips it.
- **One root per sandbox host.** A host holds one certificate. If two Kandev
  servers (two plugin installations, each with its own root) register the
  same host, each one re-issues the certificate from its own root whenever
  it checks the host, and the other loses it. Give each Kandev server its
  own hosts.
- **Terminal-passthrough agents and the task's shell terminal do not run in
  the sandbox** in Kandev 0.97.0: Kandev starts them on the Kandev server
  instead. Use agents that speak ACP.

The plugin has **one SSH key** for every host. It is generated on first use,
kept in the plugin's secret store, and only its public half is ever shown.

## Egress

Sandboxes are deny-by-default. Beyond the host's own base rules
(`[kandev] rule_groups`, which nothing here can remove), a sandbox may reach:

1. the **default groups** of the plugin's egress policy, for every sandbox;
2. the groups its profile names in `egress_groups`;
3. the entries in its profile's `egress_allow`.

The policy is the plugin's, kept centrally, so the agent harness and model
endpoints (a local LLM, OpenRouter, a vendor API) are configured once for
every host and profile. Changes apply to sandboxes provisioned afterwards.

**Entries**, in groups and in `egress_allow`:

| Entry | Means |
| --- | --- |
| `api.openai.com` | that name, HTTPS on 443 |
| `*.example.com` | every name below `example.com`, HTTPS on 443 only |
| `llm.lan:8080` | that name, TCP port 8080 (enforced as the addresses it resolves to on the host) |
| `192.168.2.6:8788` | that address, TCP port 8788 |
| `192.168.2.6` | that address, 443 |
| `[fd00::5]:8080` | an IPv6 address and port |

No ranges, CIDRs, protocols or full msb rules: per-port precision is the
point. Loopback, unspecified, link-local (which includes cloud metadata at
169.254.169.254) and multicast addresses are refused. Plain HTTP on :80 is
always denied by the host, but a LAN service on another port works by address.

**Built-in groups**, read-only: `anthropic`, `deepseek`, `google-ai`, `groq`,
`mistral`, `openai`, `opencode` (`opencode.ai` and the `models.dev` catalog),
`openrouter`, `xai`. Each holds only its provider's API host.

**Actions** (admin):

| Action | Body | Does |
| --- | --- | --- |
| `egress.list` | `{}` | Every group, built-in and custom, each marked `default` when it is, and the `defaults` list. |
| `egress.put` | `{"name": "lan-llm", "description": "...", "entries": ["192.168.2.6:8788"]}` | Creates (201) or replaces (200) a custom group. Names are lowercase letters, digits and dashes; built-in names are taken. |
| `egress.remove` | `{"name": "lan-llm"}` | Deletes a custom group and drops it from the defaults. A profile still naming it fails validation, and a launch from it fails with `invalid_config`. |
| `egress.defaults` | `{"groups": ["lan-llm", "opencode"]}` | Sets the groups every sandbox gets. |

There is no count limit. The real one is msbctl's: it reads a provision as
one JSON line of at most 64 KiB and refuses all of it beyond that. So a
sandbox's egress list (defaults, then the profile's groups, then its
`egress_allow`) gets 32 KiB of that as sent, about 1,500 typical hostnames,
and image, environment and secrets keep the rest. A group, and the defaults
on their own, must fit in it, which `egress.put` and `egress.defaults` check
when you save. A launch whose whole request would still exceed 64 KiB fails
with `invalid_config` (`requestTooLarge`) and creates nothing.

**The host keeps the last word.** msbctl checks every entry against the
host's `[kandev] allow_extra` and refuses the whole provision over one it does
not admit. Its default, `[]`, admits nothing extra; for central control from
this plugin, set `allow_extra = ["*"]` on hosts that trust this Kandev server.
To keep a bound instead, list what may be added: hostname patterns (any
port), addresses (any port), `address:port` (that port) and CIDRs up to /8
(IPv4) or /32 (IPv6), from msb-manager 0.5.1. A 0.5.1 host reports its
`allow_extra`, and Test checks the default groups against it and reports
`egress_refused` with the entries it would refuse.

## Secrets

Secrets live in the plugin, not in profiles: each is a name, a value and the
hosts the value may be sent to, managed by an admin with these actions (and
on the plugin's Secrets page). A profile only names the ones it uses, in its
`secrets` field. So whoever edits a profile can give a sandbox a secret, but
never read the value or send it to a host the admin did not choose.

| Action | Body | Does |
| --- | --- | --- |
| `secrets.list` | `{}` | Every secret's name, description, hosts and when it was last changed. Never a value. |
| `secrets.put` | `{"name": "NPM_TOKEN", "description": "...", "hosts": "registry.npmjs.org", "value": "..."}` | Creates (201) or changes (200) a secret. `value` is required to create; leave it out to change only the hosts or description. Up to 16 KiB, 100 secrets. |
| `secrets.remove` | `{"name": "NPM_TOKEN"}` | Deletes it. Profiles still naming it fail validation, and their launches fail with `invalid_config` (`secretUnresolved`). |

Names follow the `env` rules below, reserved names included. Hosts are
`host` or `host:port`, comma-separated, without wildcards. The value is kept
in the plugin's secret store, never in its state, a log line or a response.

## Executor profile

One profile per project, using the **microsandbox microVM** provider. Kandev
delivers every field as a string; these rules are checked when the profile is
saved.

| Field | Required | Rule |
| --- | --- | --- |
| `placement` | yes | `label:<label>` or `host:<name>`, selecting at least one registered, non-draining host |
| `image` | yes | An OCI reference pinned by digest: `registry/path[:tag]@sha256:<64 hex>`. Path-shaped values are refused |
| `cpus` | yes | 1–16 |
| `memory_mib` | yes | 512–65536 |
| `disk_gib` | no | 5–500, default 20 |
| `workspace_gib` | no | 1–500, default 20. A disk of its own at `/workspace`, where Kandev starts the agent; removed with the sandbox |
| `max_lifetime_hours` | yes | 1–168. The sandbox is destroyed at this age |
| `retain_hours` | no | 0–168, default 24 |
| `egress_allow` | no | Comma-separated egress entries this profile adds (grammar under [Egress](#egress)), within the 32 KiB egress budget |
| `egress_groups` | no | Comma-separated egress group names this profile adds to the defaults, such as `openrouter` or one of your own. Each must exist in the plugin's egress policy |
| `env` | no | `KEY=VALUE;KEY2=VALUE2`, non-secret values only. Names are uppercase `A-Z`, `0-9`, `_`, at most 64 characters |
| `registry_username` / `registry_password` | no | Both or neither. A private image must name its registry host (`ghcr.io/…`, `registry.example.com:5000/…`) |
| `secrets` | no | Comma-separated names of the plugin's [secrets](#secrets), such as `NPM_TOKEN, OPENROUTER_API_KEY`. Each must exist |

Names refused for `env` and secrets, the same list msbctl refuses:
`GH_TOKEN`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, the
Claude token variables, `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`,
`PWD`, `TERM`, `LANG`, and anything starting with `AGENTCTL_`, `MSB_`,
`MSBCTL_`, `LD_`, `SSH_`, `XDG_` or `LC_`. Kandev delivers agent and git
credentials itself, the plugin configures agentctl, and secret values pass
through the environment of the host's `msb` process. A name also cannot
appear twice across `env` and the secrets.

**The image** must be complete: no bootstrap runs in a Kandev sandbox. It
needs git, the agent CLIs the project uses, its toolchains, and a writable
**`/workspace`**, where Kandev puts the session's checkout. Kandev installs
agentctl itself at launch.

A secret is a host-bound msb secret: the guest only ever sees a
placeholder, and the sandbox host substitutes the real value into request
**headers** bound for the secret's hosts. Secret values are re-sent on every
start and never stored on the host.
