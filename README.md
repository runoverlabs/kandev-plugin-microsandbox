# kandev-plugin-microsandbox

Run each [Kandev](https://github.com/kdlbs/kandev) session in its own
[microsandbox](https://github.com/microsandbox/microsandbox) microVM, on
sandbox hosts separate from the Kandev server.

This is a Kandev runtime plugin providing a **remote executor**. Hosts are
registered once in the plugin; each project gets an executor profile saying
which hosts, which image, how much CPU and memory, and what the sandbox may
reach. Each host is an ordinary [msb-manager](https://github.com/runoverlabs/sandbox-manager)
install, driven over SSH through a restricted forced command
(`msbctl host serve --kandev`). No daemon, port or token scheme of its own.

> **Status: early development.** The host registry, profile validation and
> placement work. Provisioning is not built yet, so a profile can be saved
> but a task cannot launch on it. See the [implementation plan](docs/plans/implementation-plan.md)
> for the phases, the [host protocol](docs/host-protocol.md) for what a
> sandbox host must answer, and the [msbctl feature request](docs/msbctl-feature-request.md)
> for what msb-manager still has to build.

## What it adds

| Surface | What you get |
| --- | --- |
| Executor provider `microsandbox` | An executor profile type: placement, digest-pinned image, CPUs, memory, disk, lifetime, extra egress, environment, registry credentials and up to three host-bound secrets. Profiles are validated on save, including that the placement selects a registered, non-draining host. |
| Sandbox host registry | Admin-only actions to list, scan (trust on first use), add, update, drain, remove and test hosts. A host that still has sandboxes cannot be removed. |

## Requirements

- Kandev **0.97.0** or newer: the first release where remote executor plugins
  are on by default.
- Sandbox hosts: Linux with KVM, set up as msb-manager remotes, with msbctl
  speaking [host protocol](docs/host-protocol.md) version 1.
- A private network between Kandev and the hosts (Tailscale is the default
  design: the data path uses `tailscale serve`).

## Install

Releases are not published yet. To build a package from source, see
[docs/development.md](docs/development.md), then install the tarball through
Kandev's **Settings > Plugins**.

## Configuration

[docs/configuration.md](docs/configuration.md) covers registering hosts and
the executor profile fields.

## License

MIT. See [LICENSE](LICENSE).
