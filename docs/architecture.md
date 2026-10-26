# Architecture

This page is the design the Go backend and the browser bundle follow, the rules
that keep it that way, and the tools that check those rules. The tools catch the
mechanical part. The practices at the end cover what a linter cannot see.

## The guiding design: ports and adapters, in six layers

The plugin sits between Kandev, which calls it and keeps its state, and the
sandbox hosts, which it reaches over SSH with `msbctl kandev`. Every package
belongs to exactly one layer. **An import may only point to a lower layer.**

```text
 L5  entry        server/                 pluginsdk.Serve(plugin.NewRuntime())
 L4  transport    internal/plugin         Kandev → plugin: actions, provider RPCs, the
                                          maintainer; error → status or provider code
 L3  adapters     internal/sshx           SSH: the plugin's key, host key pinning, the
                                          connection pool, the operator's admin login
                  internal/store          Kandev Host state and secret store: every
                                          document's key and layout
 L2  features     internal/hostcheck      Test's diagnosis and certificate care (the base
                                          feature the others may use)
                  internal/sandbox        the executor provider's decisions: resource
                                          state, bootstrap, placement, recovery, states
                  internal/readiness      setup.status's items
                  internal/hostsetup      setting a machine up; the setup and upgrade jobs
 L1  model        internal/egress         egress entries, groups and the policy
                  internal/profile        executor profile parsing and validation
                  internal/hosts          the host registry and placement
                  internal/secrets        the secret index and its validation
                  internal/pki            the root CA and host certificates
                  internal/msbctl         the msbctl kandev protocol: argv and answers,
                                          run through a Runner port
 L0  foundation   internal/remote         running a command on a host: quoting, output,
                                          the kinds of failure to reach one
                  internal/kandev         the late-bound Host, state documents, action
                                          responses
```

Two test-support packages sit beside the code they fake and may only be
imported from `_test.go` files: `internal/kandev/kandevtest` (an in-memory
Kandev host) and `internal/sshx/sshtest` (an in-process SSH server).

| Layer | May import | Must not import |
| --- | --- | --- |
| foundation | the standard library; `kandev` also the SDK | anything else in `internal/` |
| model | the standard library, and lower model packages: `egress` ← `profile` ← `hosts`, `secrets` ← `msbctl` | the SDK, foundation, features, adapters |
| features | foundation (`remote`), model, and `hostcheck` | the SDK, `kandev`, another feature, any adapter |
| `sshx` | `remote`, model, `golang.org/x/crypto/ssh` | the SDK, features, `store` |
| `store` | `kandev`, model, `hostcheck`, the SDK | `sshx`, `plugin` |
| `plugin` | foundation, model, features, the SDK. Only `wire.go` imports `sshx` and `store` | |

Three consequences are the point of the layering:

- **Features decide; adapters carry.** A feature owns what a failing health
  report means, when a certificate is renewed, which host a sandbox goes to and
  what a lost provision resolves to. It reaches a host, the registry or the root
  only through interfaces it declares itself (`hostcheck.Host`, `Roots`,
  `sandbox.Host`, `hostsetup.Registry`, …), and no feature knows the SDK. The
  placement and diagnosis code is therefore testable with a scripted host.
- **`msbctl` is the protocol, not a transport.** It turns a verb into argv and
  an answer into types, and runs everything through `msbctl.Runner`, which
  `sshx.Pool` implements. Nothing outside it names a verb or parses output.
  Its types (`Health`, `Record`, error codes) are the vocabulary the features
  decide on, which is why it sits in the model layer.
- **Only `store` knows how state is kept.** Every Host state key, secret key and
  document layout lives there; a feature or handler sees a typed store behind a
  port. The transport turns an SDK request into a feature call and the result
  into an SDK response, and `plugin/wire.go` is the one file that builds the
  adapters.

The browser bundle follows the same rule at a smaller scale:

```text
 bundle.ts                         entry: registers the pages with the host
 hosts.ts, host-row.ts,            components: elements through host.jsx, each a
 host-forms.ts, job-view.ts,       hook or two for state and effects plus plain
 egress.ts, secrets.ts,            render helpers
 overview.ts, common.ts
 api.ts                            the action client: invoke, ActionError
 model.ts                          the pure model: types, parsing, formatting,
                                   detail rows. No React, no host calls
 host-contract.ts                  type-level contract with the host
```

The model never imports a component or the action client. Nothing imports
`bundle.ts`. A page is split into hooks and render helpers called directly, not
into child components, where that keeps a test able to walk the element tree it
renders against a stub host (`ui/test/pages.test.ts`).

## What enforces it

| Check | Tool | Where |
| --- | --- | --- |
| Layer rules above (Go) | `internal/archtest`: a test that parses every import and fails on an edge the layer table does not list, or on a package missing from it | `make test`, CI |
| Module rules (UI): no cycles, the model imports no component, nothing imports `bundle.ts`, no orphans | `dependency-cruiser` (`.dependency-cruiser.cjs`) | `make lint-ui`, CI |
| Cyclomatic complexity ≤ 15 per function | `gocyclo` via golangci-lint (`.golangci.yml`) | `make lint-go`, CI |
| Cognitive complexity ≤ 20 per function | `gocognit` via golangci-lint | `make lint-go`, CI |
| Nesting ≤ 5, ≤ 50 statements per function | `nestif`, `funlen` via golangci-lint. Statements, not lines: the comments carry the reasoning | `make lint-go`, CI |
| Copy-paste of 150 tokens or more | `dupl` via golangci-lint | `make lint-go`, CI |
| Bugs and API misuse | `staticcheck`, `govet`, `errorlint`, `errcheck`, `unparam`, `unused`, `ineffassign`, `unconvert` | `make lint-go`, CI |
| Formatting and import grouping | `gofmt`, `goimports` with the module as the local prefix | `make lint-go`, CI |
| UI complexity ≤ 12, ≤ 100 lines per function, ≤ 400 lines per file, nesting ≤ 4, ≤ 4 parameters | ESLint with `typescript-eslint` (`eslint.config.mjs`) | `make lint-ui`, CI |
| Dead code across packages | `deadcode` (reachability from `server/`) | `make deadcode`, before a release |

Tests are exempt from the length and complexity rules: a table-driven test is
long by design.

The thresholds are ceilings, not targets. A function at the limit is a warning
to split before the next feature lands in it.

`make metrics` prints the worst offenders without failing (`gocyclo`,
`gocognit`, and the ESLint complexity report), so a pull request can show what
it moved. To see the package graph itself, `goda graph ./...:noroot` (from
`github.com/loov/goda`) renders it for Graphviz.

## Practices a linter cannot check

### Structure

- **Put a decision in a feature, a mechanism in an adapter.** If an `if` exists
  because an SSH server answers a refused key differently, it belongs in
  `sshx`. If it exists because a refused key means "authorize the plugin's key
  on the host", it belongs in `hostcheck`. A change that needs both is two
  changes: a port method, then its use.
- **Declare an interface where it is consumed, not where it is implemented.**
  Keep it to what that consumer calls. A port with one implementation and one
  caller is normal here: it is the seam the tests use.
- **A new shared helper goes in the lowest layer that every caller can
  import, once.** Two copies of a helper in two packages are a missing
  foundation or model function. The state document codec in `kandev` replaced
  six copies of the same load and save.
- **No `util`, `common` or `helpers` packages.** A foundation package is named
  for what it holds (`remote`: running commands on a host, `kandev`: talking to
  Kandev).
- **One file, one concern.** Split a file that needs a table of contents. The
  name says what is in it (`upgrade.go`, not `jobs2.go`).
- **Each handler gets its own dependencies.** A transport handler gets the
  ports it uses as fields. It does not get the whole `Runtime`. A handler that
  needs everything is doing too much.
- **Secrets stay where they are.** A port that carries a secret value (the
  admin login, a profile's secrets, a key) never logs it and never returns it
  in an error; see the secrets section of `AGENTS.md`.

### Functions

- **Keep the happy path at the left margin.** Return early on refusal. A
  function that reads top to bottom as "check, check, check, act" rarely needs
  splitting.
- **Name the step, not the mechanism.** Extract `machineProblem(facts)` rather
  than `checkStuff2`, so the caller reads as the policy it implements. A long
  procedure becomes a small struct with one method per step, as the provision
  (`provisioning`) and the profile parser do.
- **Make a big `switch` a table** when its cases do the same thing with
  different data: the action routes, the registry error statuses, the TLS
  problems.
- **Push I/O to the edges.** A function that decides should take the
  observation and return the decision, so a test can call it without fakes.

### Changes

- **A refactor changes no behaviour and no test expectation.** If a test has to
  change, the change was not a refactor: split it out and say why.
- **Tests go through the outermost stable surface.** The plugin tests drive
  `NewRuntime()` with an in-memory Kandev host and real SSH to `sshtest`
  servers. That is what lets the packages underneath move without the tests
  moving with them.
- **Do not raise a threshold to make CI green.** Split the function. If a
  function really cannot be split, a `//nolint:<linter> // <reason>` on it is
  the record of that decision.
