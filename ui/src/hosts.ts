import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { kit, useLoad } from "./common";
import { createAddExistingForm, createSetupForm } from "./host-forms";
import { createHostRow } from "./host-row";
import type { HostList } from "./model";
import { createReadinessPanel } from "./overview";

export function createHostsPage(host: PluginHostApi): Component {
  const k = kit(host);
  const Row = createHostRow(host);
  const Readiness = createReadinessPanel(host);
  const Setup = createSetupForm(host);
  const AddExisting = createAddExistingForm(host);

  return function MicrosandboxHostsPage() {
    const list = useLoad<HostList>(host, "hosts.list");
    const [adding, setAdding] = host.React.useState<"setup" | "existing" | null>(null);
    const hosts = list.data?.hosts ?? [];
    return k.h(
      "div",
      { className: "msb-page" },
      k.h("h2", { className: "msb-title" }, "Sandbox hosts"),
      k.h(Readiness, null),
      k.card(
        "Hosts",
        "Each host's last check, by Test or by the plugin every 15 minutes.",
        k.error(list.error),
        hosts.length === 0 && list.data ? k.h("p", { className: "msb-muted" }, "No sandbox host yet.") : null,
        ...hosts.map((h) => k.h(Row, { key: h.name, h, release: list.data?.msbctl_release ?? "", onChanged: list.reload })),
        k.h(
          "div",
          { className: "msb-row" },
          k.button("Set up a new machine", () => setAdding("setup"), { variant: adding === "setup" ? "default" : "outline", testId: "add-setup" }),
          k.button("Add a host that is already set up", () => setAdding("existing"), { variant: adding === "existing" ? "default" : "outline" }),
          k.button("Refresh", list.reload, { variant: "ghost" }),
        ),
      ),
      adding === "setup" ? k.h(Setup, { onDone: list.reload, onCancel: () => setAdding(null) }) : null,
      adding === "existing" && list.data
        ? k.h(AddExisting, { authorize: list.data.authorize, onDone: () => { setAdding(null); list.reload(); }, onCancel: () => setAdding(null) })
        : null,
    );
  };
}
