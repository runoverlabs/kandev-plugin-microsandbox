# Change notice: Kandev verbs folded into msbctl's generic verbs

**For:** kandev-plugin-microsandbox (the Kandev remote executor plugin)
**From:** msb-manager (`msbctl`),
[PR #62](https://github.com/runoverlabs/sandbox-manager/pull/62), branch `kandev-tls`
**Date:** 2026-10-19
**Status:** open PR, not merged and in no release. No msbctl release has ever
shipped any `kandev` verb, so this is the time to break the contract.

## Summary

`msbctl kandev` now holds only the verbs that need Kandev's own input. To
list, inspect, stop and remove its sandboxes, the plugin uses msbctl's
ordinary verbs with `--json`. Under the plugin's key, those verbs see Kandev's
sandboxes and nothing else. The reaper and the TLS proxy moved under `host`,
since they belong to the host and the plugin never runs them.

| Was | Now |
| --- | --- |
| `msbctl kandev list` | `msbctl ls --json` |
| `msbctl kandev inspect ENV` | `msbctl show NAME --json` |
| `msbctl kandev find --operation OP` | **removed**: filter `ls --json` |
| `msbctl kandev stop ENV` | `msbctl stop NAME --json` |
| `msbctl kandev destroy ENV` | `msbctl purge NAME -y --json` |
| `msbctl kandev reap` | `msbctl host kandev reap`: the host's timer; **refused** to the plugin's key |
| `msbctl kandev proxy` | `msbctl host kandev proxy`: the host's service; **refused** to the plugin's key |

**Unchanged:** `kandev health`, `kandev provision`, `kandev agentctl`,
`kandev start`, `kandev expiry`, `kandev lease`, `kandev tls install`, the
record's fields, and `health.protocol` (still `1`).

## What the plugin must change

1. **Address by `NAME`, not `ENV`, for these four verbs.** `NAME` is the
   record's `name` (`k-…`), which every record already carries and the plugin
   already stores. Never derive it from the env id: long or mixed-case ids map
   to a hash. If the plugin has only the env id (a lost provision reply), it
   finds the name through `ls --json` (step 4).
2. **Send exactly these argv shapes**, as `shlex.join(argv)` as today:

   ```text
   msbctl ls --json
   msbctl show NAME --json
   msbctl stop NAME --json
   msbctl purge NAME -y --json
   ```

   `host serve --kandev` admits these and nothing near them: one explicit
   name, `--json` always, `-y` on `purge`, and no other flag. `ls` with
   `--refresh`, `--porcelain` or `--picker`, several names, `.`, or a missing
   name are all refused with exit 126.
3. **Read the record from the `kandev` key** of each document (below), not
   from a top-level `record`.
4. **Replace `find --operation OP`** with `ls --json` and a filter on
   `sandboxes[].kandev.operation_id`. For lost provision replies, read the
   results across hosts like this:
   - **found**: a host lists the operation;
   - **absent everywhere**: every host answered `ls --json` with exit 0, and
     none lists it;
   - **unknown**: any host failed or was unreachable.
5. **Treat `purge` as idempotent**: exit 0 whether or not there was
   anything. `{"destroyed": true}` is gone; read `purged`/`absent` if you
   care, or just the exit status.
6. **Stop calling `reap`.** The host's systemd timer runs it, and the
   plugin's key is now refused it (exit 126). If the plugin's host test
   checked the reaper by calling it, check `health` instead.
7. **Detect a host with this change** with `"tls" in health`. `health.tls`
   ships in the same PR (request 2, F19), and no host without the folded
   verbs reports it. `protocol` is unchanged, so it can't tell them apart.
   A host without `tls` still has the old verbs, and is also missing
   request 2's proxy, so in practice: refuse it and tell the operator to
   update msb-manager.

## The documents

All four print **one JSON document** on stdout. They exit **0** on success,
or **3** with the error envelope every `kandev` verb uses:

```json
{"error": {"code": "not_found", "message": "…"}}
```

### `ls --json`

```json
{
  "msbctl": "0.3.0 (git checkout)",
  "sandboxes": [
    {
      "name": "k-6f1c2b9e",
      "source": "kandev",
      "state": "running",
      "location": "kandev:6f1c2b9e",
      "repo": "", "ref": "", "autostart": false, "updates": [],
      "kandev": {
        "env": "6f1c2b9e", "name": "k-6f1c2b9e",
        "operation_id": "op-1", "input_digest": "sha256:1",
        "state": "running", "platform": "linux-amd64",
        "image": "ghcr.io/acme/api@sha256:…",
        "created_at": "2026-10-19T10:43:05Z",
        "expires_at": "2026-10-19T20:00:00Z",
        "max_expires_at": "2026-10-19T20:00:00Z",
        "generation": 1,
        "ports": {"8765": 20000, "41001": 20001, "41002": 20002, "41003": 20003},
        "agentctl": {"running": false, "sha256": ""}
      }
    }
  ]
}
```

- Under the plugin's key, it lists **Kandev's sandboxes only**: never the
  operator's.
- **Use `kandev.state`**, not the row's top-level `state`. The top-level one
  is msb's view of the VM (`running`/`stopped`), and doesn't know `creating`.
  `kandev.state` is the record's `creating | running | stopped | absent`, as
  before.
- `kandev.agentctl.running` is the last known value here, not checked live.
- This is more than the old `list` (`env`, `name`, `state`, `created_at`,
  `expires_at`): those fields are all in `kandev`, plus the rest of the record.

### `show NAME --json` (was `inspect`)

```json
{
  "name": "k-6f1c2b9e", "source": "kandev", "state": "running",
  "location": "kandev:6f1c2b9e",
  "kandev": { "…": "the record, as in ls" }
}
```

- `kandev.agentctl.running` **is checked live**, as `inspect` did. For an
  entry whose VM is gone, `kandev.state` is `"absent"`.
- No entry under that name is **`not_found`**. So is a name that exists but
  isn't Kandev's: the plugin's key can't tell an operator sandbox from
  nothing.

### `stop NAME --json`

```json
{"sandboxes": [ { "…": "what show NAME --json says, after the stop" } ]}
```

- The record is `sandboxes[0].kandev`, with `state: "stopped"`.
- The disk is kept, and a stopped sandbox is a no-op, as before.
- Unknown or not Kandev's: `not_found`. msb failing to stop a running VM:
  `unavailable`.

### `purge NAME -y --json` (was `destroy`)

```json
{"purged": ["k-6f1c2b9e"], "absent": []}
```

A second call, or a name with nothing under it:

```json
{"purged": [], "absent": ["k-6f1c2b9e"]}
```

- It removes the serve mappings, the VM and the entry, under the same host
  lock the reaper takes. Exit 0 in both cases above.
- A name that isn't Kandev's is reported `absent` and **never touched**.
- A VM under that name without the `msbctl.owner=kandev` label is
  **`conflict`** and left alone, as `destroy` did.
- A failure partway (`unavailable`) keeps the entry, so a retry or the
  reaper finishes the job, as before.

## Error codes from these verbs

| Code | When |
| --- | --- |
| `denied` | `[kandev] enabled = false` on the host (all four, as `list` was) |
| `not_found` | `show` / `stop`: no Kandev sandbox under that name |
| `conflict` | `purge`: a VM under that name lacks the Kandev label |
| `unavailable` | msb failed, or anything else; also any non-JSON or other exit status, as today |

Exit **126** is still a refusal by `host serve` (a wrong argv shape, a verb
the key may not run).

## Checklist

- [ ] `list` → `ls --json`, record from `sandboxes[].kandev`, state from `kandev.state`
- [ ] `inspect ENV` → `show NAME --json`, record from `kandev`
- [ ] `find --operation` → filter `ls --json` on `kandev.operation_id`
- [ ] `stop ENV` → `stop NAME --json`, record from `sandboxes[0].kandev`
- [ ] `destroy ENV` → `purge NAME -y --json`, success on exit 0
- [ ] drop any call to `reap`
- [ ] require `"tls" in health` from a host
- [ ] a `shlex.join` test pinning the four new argv shapes
