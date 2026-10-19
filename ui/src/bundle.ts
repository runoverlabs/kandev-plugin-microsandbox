import "./host-contract";
import type { PluginHostApi } from "@kandev/plugin-sdk";
import { PLUGIN_ID } from "./api";
import { ROUTES, kit } from "./common";
import { createEgressPage } from "./egress";
import { createHostsPage } from "./hosts";
import { createOverview } from "./overview";
import { createSecretsPage } from "./secrets";

/** Links under Settings, next to the workspaces section. */
function createSettingsNav(host: PluginHostApi) {
  const k = kit(host);
  return function MicrosandboxSettingsNav() {
    return k.h(
      "div",
      { className: "msb-nav", "data-testid": "microsandbox-settings-nav" },
      k.link("Sandbox hosts", ROUTES.hosts),
      k.link("Sandbox egress", ROUTES.egress),
      k.link("Sandbox secrets", ROUTES.secrets),
    );
  };
}

window.registerKandevPlugin(PLUGIN_ID, {
  initialize(registry, host) {
    registry.registerComponent("plugin-settings", createOverview(host));
    registry.registerSettingsRoute(ROUTES.hosts, createHostsPage(host));
    registry.registerSettingsRoute(ROUTES.egress, createEgressPage(host));
    registry.registerSettingsRoute(ROUTES.secrets, createSecretsPage(host));
    registry.registerComponent("settings-nav", createSettingsNav(host));
  },
});
