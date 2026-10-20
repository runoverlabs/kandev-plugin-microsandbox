<p align="center">
  <img src="assets/icon.svg" alt="kandev-plugin-microsandbox: a Kandev-indigo node feeding a session into an msb-manager-purple microVM, drawn in dots" width="140" height="140">
</p>

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

> **Status: early development.** The host registry, profile validation,
> placement, the provider's whole lifecycle (provision, connect, inspect,
> recover, attach, destroy) and the root certificate are built. A whole agent
> session has run against Kandev 0.97.0 and a real msb-manager 0.5.0 host;
> the known gaps, mostly on Kandev's side, are listed in
> [configuration](docs/configuration.md#what-kandev-and-the-network-need). See the [implementation plan](docs/plans/implementation-plan.md)
> for the phases, the [host protocol](docs/host-protocol.md) for what a
> sandbox host must answer, and the [msbctl feature request](docs/msbctl-feature-request.md)
> for how the host side was built.

## What it adds

| Surface | What you get |
| --- | --- |
| Executor provider `microsandbox` | An executor profile type: placement, digest-pinned image, CPUs, memory, disk, lifetime, extra egress, environment, registry credentials and up to three host-bound secrets. Profiles are validated on save, including that the placement selects a registered, non-draining host. |
| Sandbox host registry | Admin-only actions to list, scan (trust on first use), add, update, drain, remove and test hosts. A host that still has sandboxes cannot be removed. |
| Root certificate | A name-constrained root the Kandev server trusts for sandbox hosts only; host certificates are issued and renewed automatically. |

## Requirements

- Kandev **0.97.0** or newer: the first release where remote executor plugins
  are on by default.
- Sandbox hosts: Linux with KVM, set up as msb-manager remotes, with
  msb-manager **0.5.0** or newer (msbctl speaking
  [host protocol](docs/host-protocol.md) version 1).
- A private network between Kandev and the hosts: Tailscale, headscale,
  WireGuard or a LAN. Kandev reaches each sandbox over HTTPS: by default
  through a TLS proxy on each host (`[kandev] serve = "proxy"`) with a
  certificate from the plugin's own root, which you trust on the Kandev
  server once; or through `tailscale serve`. See the
  [implementation plan](docs/plans/implementation-plan.md), "Decision, Oct 19".

## Install

Releases are not published yet. To build a package from source, see
[docs/development.md](docs/development.md), then install the tarball through
Kandev's **Settings > Plugins**.

## Configuration

[docs/configuration.md](docs/configuration.md) covers registering hosts and
the executor profile fields.

## Related projects

- [msb-manager](https://github.com/runoverlabs/sandbox-manager) (`msbctl`):
  the host side. Every sandbox host runs it, and this plugin drives it over
  SSH; the [host protocol](docs/host-protocol.md) is the contract between them.
- [kandev-plugin-forgejo](https://github.com/runoverlabs/kandev-plugin-forgejo):
  the sibling Kandev plugin, connecting a self-hosted Forgejo or Gitea to
  Kandev's repository, pull-request and review surfaces. The two share their
  layout, build and release conventions.

## License

MIT. See [LICENSE](LICENSE).
