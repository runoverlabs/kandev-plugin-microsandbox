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
