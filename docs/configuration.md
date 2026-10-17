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
| `hosts.list` | `{}` | The hosts, each with its pinned key's SHA256 fingerprint, plus the plugin's public key and the exact `authorize` command to run on a host. Generates the plugin's key on first use. |
| `hosts.scan` | `{"ssh": "msb@sbx-01.tailnet.ts.net"}` | Connects and returns the host key the server presents, with its fingerprint, for the operator to compare with `ssh-keygen -lf` on the host. Stores nothing. |
| `hosts.add` | a host (below) | Registers a host. Returns 201. |
| `hosts.update` | a host | Replaces a host's SSH destination, pinned key, base URL and labels. The name cannot change, and the draining flag is kept. |
| `hosts.drain` | `{"name": "...", "draining": true}` | A draining host gets no new sandboxes but keeps serving its existing ones. |
| `hosts.remove` | `{"name": "...", "force": false}` | Asks the host for its kandev sandboxes and refuses (409) while it has any. If the host cannot be reached, it refuses (502) unless `force` is set. |
| `hosts.test` | `{"name": "..."}` | Runs `msbctl kandev health` and returns `ok`, a `problem` code with a `hint`, the health report, and a `warning` when the host's own `base_url` differs from the registered one. |

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

### Adding a host

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
| `disabled` | `[kandev] enabled` is not true in the host's msbctl config. |
| `no_kvm` | `/dev/kvm` is missing on the host. |
| `no_data_path` | `tailscale serve` is not up on the host. |
| `unavailable` | msbctl ran but returned no health report. |

The plugin has **one SSH key** for every host. It is generated on first use,
kept in the plugin's secret store, and only its public half is ever shown.

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
| `max_lifetime_hours` | yes | 1–168. The sandbox is destroyed at this age |
| `retain_hours` | no | 0–168, default 24 |
| `egress_allow` | no | Comma-separated `host` or `host:port`; `*.` wildcards allowed. No IPs, URLs or single-label names |
| `env` | no | `KEY=VALUE;KEY2=VALUE2`, non-secret values only |
| `registry_username` / `registry_password` | no | Both or neither |
| `extra_secret_N_name` / `_value` / `_hosts` | no | N = 1–3. A name, a value and at least one host, all together |

Names refused for `env` and secrets: `GH_TOKEN`, `GITHUB_TOKEN`,
`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, and
anything starting with `AGENTCTL_`. Kandev delivers agent and git credentials
itself, and the plugin configures agentctl. A name also cannot appear twice
across `env` and the secrets.

Egress is hostname-based and inspected on :443. On any other port a hostname
rule degrades to the IPs it resolves to, and plain HTTP (:80) is always
denied. Profile entries are added to the host's own base rules
(`[kandev] rule_groups`), which a profile cannot remove.

An extra secret is a host-bound msb secret: the guest only ever sees a
placeholder, and the sandbox host substitutes the real value into request
**headers** bound for the listed hosts. Secret values are re-sent on every
start and never stored on the host.
