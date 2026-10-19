# Host protocol: `msbctl kandev`

The plugin controls each sandbox host by running `msbctl kandev <verb>` over
SSH. This page is the contract between `internal/msbctl` and msbctl on the
host ([msb-manager](https://github.com/runoverlabs/sandbox-manager)). The
plugin implements it today; what msbctl needs to build is in the
[msbctl feature request](msbctl-feature-request.md).

**Protocol version: 1.** `health` reports it, and the plugin refuses a host
reporting any other version rather than guessing. It never gates on
`msbctl_version`: a checkout reports `0.3.0+<sha> (git checkout)`, and the
first hosts with these verbs run msb-manager `main` ahead of a release.

The host side is built on msb-manager `main`
([PR #61](https://github.com/runoverlabs/sandbox-manager/pull/61)), not yet
in a release.

## Transport

- The plugin connects as `user@host[:port]` with its own ed25519 key and
  verifies the pinned host key. It never reads `~/.ssh` on the Kandev server.
- On the host the key is authorized with `msbctl host authorize '<line>'
  --kandev`, which writes `restrict,command="<msbctl> host serve --kandev"`.
  No `pty`.
- The plugin sends one command line, `shlex.join(argv)`, which `host serve`
  splits again with `shlex.split` and checks with its parser. Under
  `--kandev` it allows `msbctl kandev <verb> …`, the four generic verbs
  below in their exact shapes, and `msbctl --version`. A refusal is exit status **126**.
- One SSH connection per host is reused, with one session per command.

## Output

- **stdout is exactly one JSON document.** Everything else goes to stderr,
  which the plugin discards and never forwards to Kandev.
- **Exit 0**: success; stdout is the verb's document.
- **Exit 3**: failure; stdout is an error envelope:

  ```json
  {"error": {"code": "rate_limited", "message": "host at capacity", "retry_after_seconds": 30}}
  ```

  `code` is one of Kandev's provider error codes: `invalid_config`,
  `denied`, `unsupported`, `not_found`, `expired`, `conflict`,
  `unavailable`, `rate_limited`, `cleanup_pending`. An unknown code is read
  as `unavailable`. `message` is for the host's logs and is never shown in
  Kandev. `retry_after_seconds` is read only with `rate_limited`, clamped to
  0–600.
- **Exit 126**: `host serve` refused the command line. The plugin reports
  `denied`: the key is not authorized with `--kandev`, or msbctl predates the
  verb.
- **Any other status**, or stdout that is not the expected JSON:
  `unavailable`.
- stdout is capped at 4 MiB.

## Input

Secret inputs (profile secrets, the bootstrap nonce, registry credentials,
the agentctl binary) come **on stdin, never in argv**: argv is visible in
`ps` and in sshd's logs. Stdin is a JSON header line, optionally followed by
raw bytes whose length the header gives. The verbs below take no stdin yet.

## Verbs the plugin calls today

### `msbctl kandev health`

```json
{
  "protocol": 1,
  "msbctl_version": "0.3.0+66f03f7 (git checkout)",
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
  "serve": {"ok": true, "mode": "tailscale"}
}
```

- `enabled` is `[kandev] enabled` from the host's msbctl config.
- `capacity` counts **kandev sandboxes only**, against the `[kandev]`
  limits. `max_memory` is reported in MiB.
- `platform` is the guest's `<goos>-<goarch>`, as Kandev names platforms.
- `base_url` is `[kandev] base_url`, the HTTPS base leases are built on.
- `serve.mode` is `[kandev] serve`: `tailscale` or `none` today; `proxy`, the
  planned default, is requested in the feature request (F16, F19). `serve.ok` means
  `tailscale status` shows a running node with a DNS name (always true with
  `none`). A `reason` sent when it is not ok is msbctl's text and is not
  read.

A host is a placement candidate only when `protocol` is 1 and `kvm`,
`enabled` and `serve.ok` are all true. Among those, placement drops hosts
without room for the requested CPUs and memory and a sandbox slot, then picks
the most free memory, then the fewest sandboxes, then the name. The host
enforces the same limits again under its own lock at provision time.

Used by: placement, and the Sandbox Hosts page's **Test**.

### `msbctl ls --json`

Inventory goes through msbctl's generic verbs, which under the plugin's key
see Kandev's sandboxes only ([change notice](msbctl-kandev-verb-changes.md)):

```json
{"msbctl": "0.3.0 (git checkout)", "sandboxes": [
  {"name": "k-6f1c2b9e", "source": "kandev", "state": "running",
   "kandev": {"env": "6f1c2b9e", "name": "k-6f1c2b9e", "operation_id": "op-1",
              "state": "running", "created_at": "…", "expires_at": "…", "…": "the rest of the record"}}
]}
```

The plugin reads each row's `kandev` record and its `kandev.state`, never
the row's top-level `state`, which is msb's own view and does not know
`creating`. **Remove** on the Sandbox Hosts page refuses while a host still
lists sandboxes. Lost provision replies are resolved by filtering this list
on `kandev.operation_id`: found on a host, absent once every host answered,
unknown while any host did not.

## Session verbs

| Purpose | Command line | Addressed by |
| --- | --- | --- |
| create | `msbctl kandev provision ENV` (stdin) | env id |
| install and start agentctl | `msbctl kandev agentctl ENV` (stdin + binary) | env id |
| restart a stopped VM | `msbctl kandev start ENV` (stdin) | env id |
| lease a port | `msbctl kandev lease ENV PORT` | env id |
| inspect | `msbctl show NAME --json` → its `kandev` record | name |
| stop | `msbctl stop NAME --json` → `sandboxes[0].kandev` | name |
| remove | `msbctl purge NAME -y --json`; exit 0 = gone, whether or not it existed | name |

`NAME` is always the record's `name`, stored in the resource state, never
derived from the env id. The argv shapes are exact: `host serve --kandev`
refuses anything near them with exit 126. The documents are in the
[msbctl feature request](msbctl-feature-request.md) (F7–F12) and the
[change notice](msbctl-kandev-verb-changes.md); the code is
`internal/msbctl/sandbox.go`. Secret values, registry
credentials, the bootstrap nonce and the agentctl binary go on stdin: one
JSON header line, then for `agentctl` exactly `size` bytes. The plugin
refuses a `lease` whose `headers` include a name Kandev refuses in a lease
(`Authorization`, `X-Instance-ID`, `Host`, `Cookie`, `Set-Cookie`,
`Sec-WebSocket-Protocol`, hop-by-hop, `Proxy-*`), answering `unavailable`.

## Verbs the plugin calls ahead of the host

The plugin already calls these, but msbctl has not built them yet (feature
request F17 and F19). Until it has, a host never reports `serve.mode =
"proxy"`, and the plugin never calls `tls install`.

### `health` fields for `serve = "proxy"`

```json
"serve": {"ok": true, "mode": "proxy", "listen": "100.64.0.7", "running": true},
"tls": {"installed": true, "subject": "sbx-01.tailnet.ts.net",
        "not_after": "2027-01-17T00:00:00Z", "issuer_sha256": "<hex SHA-256 of the issuing root>"}
```

The plugin re-issues the certificate when `tls` is missing or not
`installed`, when `issuer_sha256` is not its current root, when `subject` is
not the host part of the registered `base_url`, or when `not_after` is less
than 30 days away.

### `msbctl kandev tls install`

Stdin is one JSON header line, `{"cert_pem": "<leaf, then root>", "key_pem":
"<PKCS#8 EC key>"}`. The answer is `{"tls": <the document above>}`. The key
is sent once, on stdin, and is never in argv or any output.

## Verbs still to define

`kandev expiry` and `stop` are built and wrapped, but not called by the
plugin yet. `reap` and `proxy` are the host's own (`msbctl host kandev …`)
and refused to the plugin's key.
