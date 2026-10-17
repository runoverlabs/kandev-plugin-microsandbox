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
make lint                  # gofmt, go vet, manifest check against Kandev's validator
make test                  # Go tests
make test-race             # the same with the race detector (what CI runs)
make security              # gitleaks, govulncheck
make verify-package-host   # host-platform tarball + checksums
make package               # all five platforms, for a release
```

`make validate-manifest` runs Kandev's own manifest validator, which is an
internal package of the Kandev module and cannot be imported from here.
`scripts/_manifestcheck/main.go` is compiled inside the sibling module through
`go run -overlay`, so nothing is written into the checkout.

## Layout

| Package | Owns |
| --- | --- |
| `internal/profile/` | Parsing and validating an executor profile. Pure. |
| `internal/hosts/` | The host registry model and placement, with `Store` and `Prober` ports. No SSH, no SDK. |
| `internal/msbctl/` | The `msbctl kandev` protocol: verbs, JSON documents, error envelope, exit statuses ([host-protocol.md](host-protocol.md)). |
| `internal/sshx/` | SSH transport: the plugin key, host key pinning and scanning, the connection pool, shlex-compatible quoting. |
| `internal/sshx/sshtest/` | An in-process SSH server standing in for a sandbox host, for tests. |
| `internal/plugin/` | SDK wiring: Host state and secrets, the `hosts.*` actions, the executor provider RPCs. |
| `server/` | `main`: `pluginsdk.Serve`. |

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
   and create a profile. Launching a task on it fails with `unsupported`
   until provisioning is built.

Bump `version` in `manifest.yaml` before reinstalling: Kandev refuses to
install an id and version it already has.
