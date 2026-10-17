# Host protocol: `msbctl kandev`

The plugin controls each sandbox host by running `msbctl kandev <verb>` over
SSH. This page is the contract between `internal/msbctl` and msbctl on the
host ([msb-manager](https://github.com/runoverlabs/sandbox-manager)). The
plugin implements it today; what msbctl needs to build is in the
[msbctl feature request](msbctl-feature-request.md).

**Protocol version: 1.** `health` reports it, and the plugin refuses a host
reporting any other version rather than guessing.

## Transport

- The plugin connects as `user@host[:port]` with its own ed25519 key and
  verifies the pinned host key. It never reads `~/.ssh` on the Kandev server.
- On the host the key is authorized with `msbctl host authorize '<line>'
  --kandev`, which writes `restrict,command="<msbctl> host serve --kandev"`.
  No `pty`.
- The plugin sends one command line, `shlex.join(argv)`, which `host serve`
  splits again with `shlex.split` and checks with its parser. Only
  `msbctl kandev <verb> …` and `msbctl --version` are allowed under
  `--kandev`. A refusal is exit status **126**.
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

- `enabled` is `[kandev] enabled` from the host's msbctl config.
- `capacity` counts **kandev sandboxes only**, against the `[kandev]`
  limits. `max_memory` is reported in MiB.
- `platform` is the guest's `<goos>-<goarch>`, as Kandev names platforms.
- `base_url` is `[kandev] base_url`, the HTTPS base leases are built on.
- `serve.ok` is whether `tailscale serve` (or the fallback proxy) is up.

A host is a placement candidate only when `protocol` is 1 and `kvm`,
`enabled` and `serve.ok` are all true. Among those, placement drops hosts
without room for the requested CPUs and memory and a sandbox slot, then picks
the most free memory, then the fewest sandboxes, then the name. The host
enforces the same limits again under its own lock at provision time.

Used by: placement, and the Sandbox Hosts page's **Test**.

### `msbctl kandev list`

```json
{"sandboxes": [
  {"env": "<kandev environment id>", "name": "k-<env>", "state": "running",
   "created_at": "2026-10-17T12:00:00Z", "expires_at": "2026-10-17T20:00:00Z"}
]}
```

Every kandev entry on the host, and nothing else: the operator's own
sandboxes are never listed. `state` is `creating`, `running`, `stopped` or
`absent`.

Used by: **Remove** on the Sandbox Hosts page, which refuses while a host
still lists sandboxes.

## Verbs still to define

`provision`, `agentctl`, `inspect`, `find`, `start`, `stop`, `expiry`,
`lease`, `destroy` and `reap` are proposed in the
[msbctl feature request](msbctl-feature-request.md). Each moves here, with
its tests in `internal/msbctl`, when the plugin starts calling it.
