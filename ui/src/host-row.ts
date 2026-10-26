import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { kit, useMutation, type Node } from "./common";
import { createJobView } from "./job-view";
import { hostBadge, hostDetail, olderVersion, proxyStale, type HostView, type SetupJob, type TestResult } from "./model";

type Kit = ReturnType<typeof kit>;

export interface HostRowProps {
  h: HostView;
  release: string;
  onChanged: () => void;
}

/** One host's state and the actions on it. */
function useHostRow(host: PluginHostApi, props: HostRowProps) {
  const { h } = props;
  const [upgrade, setUpgrade] = host.React.useState<SetupJob | null>(null);
  const [open, setOpen] = host.React.useState(false);
  const [test, setTest] = host.React.useState<TestResult | null>(null);
  const m = useMutation(host);
  const runTest = async () => {
    const result = await m.run<TestResult>("test", "hosts.test", { name: h.name });
    if (result) {
      setTest(result);
      setOpen(true);
      props.onChanged();
    }
  };
  const drain = async () => {
    if (await m.run("drain", "hosts.drain", { name: h.name, draining: !h.draining })) props.onChanged();
  };
  const remove = async () => {
    if (!window.confirm(`Remove ${h.name} from the plugin? Its sandboxes must be gone first.`)) return;
    if (await m.run("remove", "hosts.remove", { name: h.name, force: false })) props.onChanged();
  };
  const startUpgrade = async () => {
    const job = await m.run<SetupJob>("upgrade", "hosts.upgrade", { name: h.name });
    if (job) setUpgrade(job);
  };
  return { m, open, setOpen, upgrade, setUpgrade, shown: test ?? h.status ?? null, runTest, drain, remove, startUpgrade };
}

type RowState = ReturnType<typeof useHostRow>;

/** The label of the update button, or null when the host needs none. */
function updateLabel(h: HostView, release: string): string | null {
  const version = h.status?.health?.msbctl_version;
  if (version !== undefined && olderVersion(version, release)) return `Update to ${release}`;
  return proxyStale(h) ? "Restart proxy onto the new release" : null;
}

function actions(k: Kit, props: HostRowProps, s: RowState): Node {
  const { h } = props;
  const busy = s.m.busy !== null;
  const update = updateLabel(h, props.release);
  return k.h(
    "span",
    { className: "msb-host__actions" },
    k.button(s.m.busy === "test" ? "Testing..." : "Test", () => void s.runTest(), { disabled: busy, testId: `test-${h.name}` }),
    update
      ? k.button(update, () => void s.startUpgrade(), { disabled: busy || s.upgrade?.state === "running", testId: `upgrade-${h.name}` })
      : null,
    k.button(h.draining ? "Undrain" : "Drain", () => void s.drain(), { disabled: busy }),
    k.button("Remove", () => void s.remove(), { variant: "ghost", disabled: busy }),
  );
}

function summary(k: Kit, props: HostRowProps, s: RowState): Node {
  const { h } = props;
  const badge = hostBadge(h);
  const version = h.status?.health?.msbctl_version;
  const cap = h.status?.health?.capacity;
  return k.h(
    "div",
    { className: "msb-host__summary" },
    k.h("button", { className: "msb-host__toggle", onClick: () => s.setOpen(!s.open), "aria-expanded": s.open }, s.open ? "▾" : "▸"),
    k.h("strong", { className: "msb-host__name" }, h.name),
    k.badge(badge.tone, badge.label),
    k.h("span", { className: "msb-muted" }, h.ssh),
    version ? k.h("span", { className: "msb-muted" }, `msbctl ${version}`) : null,
    cap ? k.h("span", { className: "msb-muted" }, `${cap.sandboxes ?? 0}/${cap.max_sandboxes ?? "?"} sandboxes`) : null,
    actions(k, props, s),
  );
}

/** What the last check found wrong, as hints above the facts. */
function hints(k: Kit, shown: RowState["shown"]): Node[] {
  if (!shown) return [];
  return [
    !shown.ok && shown.hint
      ? k.h("p", { className: "msb-hint" }, k.h("strong", null, (shown.problem ?? "").replace(/_/g, " "), ": "), shown.hint)
      : null,
    shown.warning ? k.h("p", { className: "msb-hint" }, shown.warning) : null,
    shown.egress_refused?.length ? k.h("p", { className: "msb-hint" }, "Refused by the host's allow_extra: ", shown.egress_refused.join(", ")) : null,
  ];
}

function detail(k: Kit, h: HostView, shown: RowState["shown"]): Node {
  const noFacts = h.status && !h.status.health?.host;
  return k.h(
    "div",
    { className: "msb-host__detail" },
    ...hints(k, shown),
    k.h(
      "dl",
      { className: "msb-facts" },
      ...hostDetail(h).flatMap(([label, value]) => [k.h("dt", { key: `${label}-t` }, label), k.h("dd", { key: `${label}-d` }, value)]),
    ),
    noFacts ? k.h("p", { className: "msb-muted" }, "OS, CPU, memory and disk appear once the host's msbctl reports them (feature request F22).") : null,
  );
}

/** One host in the list: a summary line with its actions, and its detail when open. */
export function createHostRow(host: PluginHostApi): Component<HostRowProps> {
  const k = kit(host);
  const JobView = createJobView(host);
  return function Row(props: HostRowProps) {
    const s = useHostRow(host, props);
    const { h } = props;
    return k.h(
      "div",
      { className: "msb-host", "data-testid": `host-${h.name}` },
      summary(k, props, s),
      k.error(s.m.error),
      s.upgrade
        ? k.h(JobView, { job: s.upgrade, title: `Updating ${h.name}`, onFinished: props.onChanged, onClose: () => s.setUpgrade(null) })
        : null,
      s.open ? detail(k, h, s.shown) : null,
    );
  };
}
