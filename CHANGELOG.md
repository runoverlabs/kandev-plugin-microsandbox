# Changelog

## Unreleased

First development snapshot: the provider skeleton and the host registry
(Phase 3 of the implementation plan). Not yet able to launch a task.

- Executor provider `microsandbox` with the full profile schema. Profiles are
  validated on save: digest-pinned image, resource bounds, egress entries,
  environment, paired registry credentials, up to three host-bound secrets,
  reserved names, and a placement that selects a registered, non-draining
  host.
- Sandbox host registry in plugin state, with admin-only `hosts.list`,
  `hosts.scan`, `hosts.add`, `hosts.update`, `hosts.drain`, `hosts.remove`
  and `hosts.test` actions.
- One ed25519 SSH key per installation, generated on first use and kept in
  the plugin secret store. Host keys are pinned (trust on first use through
  `hosts.scan`) and verified on every connection.
- `msbctl kandev` host protocol version 1: `health` and `list`
  ([docs/host-protocol.md](docs/host-protocol.md)).
- Placement: healthy candidates with room, most free memory first.
- `health` also reports the host's `platform` and `base_url`; `hosts.test`
  warns when that `base_url` differs from the registered one.
- Profile validation follows what msbctl accepts, so a profile it would
  refuse at launch is refused on save: uppercase variable names only, the
  wider reserved-name list (`PATH`, `HOME`, `LD_*`, `MSB_*`, `SSH_*`, …), a
  two-character minimum last label in egress hostnames, and a registry host
  in a private image's reference.
