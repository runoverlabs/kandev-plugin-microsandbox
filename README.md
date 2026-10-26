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

> **Status: 0.2.0.** The provider's whole lifecycle
> (provision, connect, inspect, recover, attach, destroy), the host registry
> with setup and upgrades, the root certificate, central egress and secrets,
> and the settings pages are built. Whole agent sessions have run against
> Kandev 0.97.0 and a real msb-manager host; the known gaps, mostly on
> Kandev's side, are listed in
> [configuration](docs/configuration.md#what-kandev-and-the-network-need). See
> the [host protocol](docs/host-protocol.md) for what a sandbox host must
> answer, and the [msbctl feature request](docs/msbctl-feature-request.md) for
> how the host side was built.

## What it adds

| Surface | What you get |
| --- | --- |
| Executor provider `microsandbox` | An executor profile type: placement, digest-pinned image, CPUs, memory, workspace disk, lifetime, egress groups and extra egress, environment, registry credentials and the plugin secrets it uses. Profiles are validated on save, including that the placement selects a registered, non-draining host. |
| Sandbox hosts | Register, test, drain and remove hosts (a host that still has sandboxes cannot be removed); set up a bare KVM machine from a one-off admin login; update a host's msb-manager. |
| Root certificate | A name-constrained root the Kandev server trusts for sandbox hosts only; host certificates are issued and renewed automatically. |
| Egress and secrets | Named egress groups with defaults applied to every sandbox, and secrets kept by the plugin that profiles name but can never read. |
| Settings pages | Readiness on the plugin's settings page, then **Sandbox hosts**, **Sandbox egress** and **Sandbox secrets**. |

## Requirements

- Kandev **0.97.0** or newer: the first release where remote executor plugins
  are on by default.
- Sandbox hosts: Linux with KVM, set up as msb-manager remotes, with
  msb-manager **0.5.0** or newer (msbctl speaking
  [host protocol](docs/host-protocol.md) version 1), and **0.7.0** or newer
  for profiles with `private_names`.
- A private network between Kandev and the hosts: Tailscale, headscale,
  WireGuard or a LAN. Kandev reaches each sandbox over HTTPS: by default
  through a TLS proxy on each host (`[kandev] serve = "proxy"`) with a
  certificate from the plugin's own root, which you trust on the Kandev
  server once; or through `tailscale serve`. See the
  [implementation plan](docs/plans/implementation-plan.md), "Decision, Oct 19".

## Install

1. Download `kandev-plugin-microsandbox-<version>.tar.gz` from
   [Releases](https://github.com/runoverlabs/kandev-plugin-microsandbox/releases).
2. In Kandev: **Settings → Plugins → Install from file**.
3. Follow the readiness list on the plugin's settings page: create and trust
   the root certificate, then set up or add a sandbox host.

To build a package from source instead, see
[docs/development.md](docs/development.md).

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
