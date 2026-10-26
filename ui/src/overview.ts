import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { ROUTES, kit, useLoad } from "./common";
import { readinessTone, type Readiness } from "./model";

interface RootView {
  exists: boolean;
  usable?: boolean;
  problem?: string;
  cert_pem?: string;
  sha256?: string;
  not_after?: string;
  trusted?: boolean;
  install: string[];
}

/**
 * The one-time setup of the Kandev server, item by item, with what to do for
 * each one that is not ready. Rendered on the plugin's own settings page and
 * at the top of the Sandbox hosts page.
 */
export function createReadinessPanel(host: PluginHostApi): Component {
  const k = kit(host);
  return function MicrosandboxReadiness() {
    const readiness = useLoad<Readiness>(host, "setup.status");
    const root = useLoad<RootView>(host, "ca.get");
    const r = readiness.data;
    return k.card(
      "Kandev server setup",
      r ? (r.ready ? "Ready: sessions can run in microsandboxes." : "Not ready yet. Each item says what to do.") : "Checking...",
      k.error(readiness.error),
      r
        ? k.h(
            "ul",
            { className: "msb-checklist" },
            ...r.items.map((item) =>
              k.h(
                "li",
                { key: item.key, className: "msb-checklist__item", "data-testid": `readiness-${item.key}` },
                k.h("div", { className: "msb-row" }, k.badge(readinessTone(item.state), item.state), k.h("strong", null, item.title)),
                item.detail ? k.h("p", { className: "msb-muted" }, item.detail) : null,
                item.fix?.length ? k.h("ol", { className: "msb-steps" }, ...item.fix.map((step, i) => k.h("li", { key: i }, step))) : null,
                item.key === "root" && root.data?.exists && item.state !== "ok" && root.data.cert_pem
                  ? k.h(
                      "details",
                      { className: "msb-details" },
                      k.h("summary", null, "The root certificate"),
                      k.code(root.data.cert_pem),
                      k.h("div", { className: "msb-row" }, k.button("Copy", () => void navigator.clipboard?.writeText(root.data?.cert_pem ?? ""))),
                    )
                  : null,
              ),
            ),
          )
        : null,
      k.h("div", { className: "msb-row" }, k.button("Check again", () => {
        readiness.reload();
        root.reload();
      })),
    );
  };
}

/** The plugin's own settings page: readiness, then where everything else is. */
export function createOverview(host: PluginHostApi): Component {
  const k = kit(host);
  const Readiness = createReadinessPanel(host);
  return function MicrosandboxOverview() {
    return k.h(
      "div",
      { className: "msb-page" },
      k.h(Readiness, null),
      k.card(
        "Manage",
        null,
        k.h(
          "ul",
          { className: "msb-links" },
          k.h("li", null, k.link("Sandbox hosts", ROUTES.hosts), ": set up machines, see their state, test them."),
          k.h("li", null, k.link("Egress", ROUTES.egress), ": what every sandbox may reach."),
          k.h("li", null, k.link("Secrets", ROUTES.secrets), ": values profiles can use by name, bound to hosts."),
        ),
      ),
    );
  };
}
