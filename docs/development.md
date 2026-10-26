# Development

## Getting set up

The Kandev SDK is not yet a standalone module, so this repo builds against a
**sibling checkout** of the Kandev monorepo:

```text
parent/
├── kandev/                       # github.com/kdlbs/kandev, at the pinned tag
└── kandev-plugin-microsandbox/   # this repo
```

`go.mod` has `replace github.com/kandev/kandev => ../kandev/apps/backend`. If
a build fails with an unresolvable `github.com/kandev/kandev`, the sibling is
missing; do not edit `go.mod` to fix it.

CI checks the SDK out at **`v0.97.0`** (`KANDEV_REF` in every workflow under
`.github/workflows/`), which is also the manifest's `min_kandev_version`.
Build locally against the same tag (`git -C ../kandev checkout v0.97.0`).
When a newer Kandev is the target, move `KANDEV_REF` in all three workflows,
run `go mod tidy` against that checkout, and commit the `go.mod`/`go.sum` it
produces. Raising the target above `min_kandev_version` is when a second
"minimum" CI leg becomes necessary.

## Commands

```sh
make claude-md             # local-only CLAUDE.md pointing at AGENTS.md
make lint                  # gofmt, go vet, manifest check, tsc, golangci-lint, ESLint, dependency-cruiser
make test                  # Go tests (layer rules included)
make test-race             # the same with the race detector (what CI runs)
make test-ui               # UI: typecheck, build ui/bundle.js, vitest
make metrics               # the most complex functions, without failing
make deadcode              # functions unreachable from server/
make security              # gitleaks, govulncheck
make verify-package-host   # host-platform tarball + checksums
make package               # all five platforms, for a release
```

`make validate-manifest` runs Kandev's own manifest validator, which is an
internal package of the Kandev module and cannot be imported from here.
`scripts/_manifestcheck/main.go` is compiled inside the sibling module through
`go run -overlay`, so nothing is written into the checkout.

## Layout

The packages are layered, and an import only points down. The layer table and
the rules that enforce it are in [architecture.md](architecture.md).

| Package | Owns |
| --- | --- |
| `internal/remote/` | Running a command on a host: shlex-compatible quoting, a command's output, the admin login, the error kinds (host key mismatch, not authorized, unusable admin login). Standard library only. |
| `internal/kandev/` | Reaching Kandev: the late-bound Host, the plugin-wide state document codec, JSON action responses. `kandevtest/` is an in-memory host for tests. |
| `internal/egress/` | Egress entries, groups and the plugin-wide policy. Pure. |
| `internal/profile/` | Parsing and validating an executor profile. Pure. |
| `internal/secrets/` | The secret index and the validation of a put. Pure. |
| `internal/hosts/` | The host registry model and placement, with `Store` and `Prober` ports. No SSH, no SDK. |
| `internal/pki/` | The root CA, host certificates, renewal and trust. Pure crypto. |
| `internal/msbctl/` | The `msbctl kandev` protocol: verbs, JSON documents, error envelope, exit statuses ([host-protocol.md](host-protocol.md)), run through a `Runner`. |
| `internal/hostcheck/` | Test's diagnosis of a host and certificate care, over `Host`, `Roots` and `Policies` ports. |
| `internal/sandbox/` | The executor provider's decisions: resource state, bootstrap, the provision request, placement or reuse, finding an operation, Kandev's states, lease headers. No SDK. |
| `internal/readiness/` | The `setup.status` items. |
| `internal/hostsetup/` | Setting a machine up over an admin login (`hosts.setup`): steps, accounts, packages, firewall, one file each; the in-memory job table and the setup and upgrade jobs. |
| `internal/sshx/` | SSH transport: the keyring (the plugin key, generated on first use), host key pinning and scanning, the connection pool, the admin login. |
| `internal/sshx/sshtest/` | An in-process SSH server standing in for a sandbox host, for tests. |
| `internal/store/` | Where the plugin keeps its state in Kandev: the registry, egress policy, secrets, host status, root CA, API URL and SSH key. |
| `internal/plugin/` | The transport: one handler per surface (hosts, CA, secrets, egress, host jobs, readiness, the executor provider) holding only the ports it uses; `Runtime` routes the RPCs and runs the maintainer, and `wire.go` builds the graph. |
| `internal/archtest/` | The layer rules as a test. |
| `server/` | `main`: `pluginsdk.Serve`. |
| `ui/` | The settings pages. `src/` is TypeScript over the host's React and components; `bundle.js` is built (`npm ci`, then `make test-ui` or `make ui/bundle.js`) and not committed. |
| `assets/` | `icon.svg`, the manifest's icon: a 16×16 dot grid in the style of the forgejo plugin's and msb-manager's. |

The UI resolves `@kandev/plugin-sdk` from the sibling checkout, like the Go
module. `npm install` hits an npm resolver bug on that linked package
(`Cannot read properties of null (reading 'edgesOut')`); `npm ci` from the
committed lockfile works.

Tests never need a real host: the plugin and transport tests run real SSH
against `sshtest` servers on loopback, answering scripted `msbctl kandev`
output.

## Trying it on a real Kandev

Use a disposable Kandev instance, never a primary one:

1. `make verify-package-host`.
2. Install the tarball through **Settings > Plugins** and approve its
   capabilities (`executor_provider`, `state`, `secrets`).
3. Kandev probes the provider contract at activation; the provider must show
   as available under the executor settings.
4. Register a host through the actions in [configuration.md](configuration.md)
   and create a profile, then launch a task on it. Read "What Kandev and the
   network need" there first: Kandev's API URL and the proxy ports are the
   usual blockers.

### When a launch fails

Kandev logs only the stage that failed, such as
`plugin executor launch gate failed {"stage": "control_handshake"}`, and the
session says "plugin executor launch failed; allocated resource was removed".
It keeps neither the cause nor the plugin's log lines. Narrow it down on the
host:

- `journalctl --user -u msb-kandev-proxy`: one line per connection
  (`forwarded`, `unauthorized`). No line means Kandev's connection never
  arrived, which is a network or firewall problem.
- `msb exec <sandbox> -- cat /var/log/agentctl.log` while the sandbox
  exists: agentctl's own log, including the instance Kandev created.
- To test the data path without Kandev, provision by hand with
  `msbctl kandev provision`, take `msbctl kandev lease ENV 8765`, and call
  `https://<base_url host>:<port>/health` with
  `curl --cacert <root> -H 'X-Msb-Lease: <token>'`. Expect 401 without the
  header. Keep the token out of logs and shell history, and purge the
  sandbox afterwards.

Credential-free agents: Kandev's `mock-agent` (start Kandev with
`KANDEV_MOCK_AGENT=true`, and put a linux build of `cmd/mock-agent` on the
image's `PATH`) runs a whole session without any agent credentials.

Bump `version` in `manifest.yaml` before reinstalling: Kandev refuses to
install an id and version it already has.
