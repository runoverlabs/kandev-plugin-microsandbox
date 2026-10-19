import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { invoke, toActionError, type ActionError } from "./api";
import { kit, useLoad, useMutation, type Node } from "./common";
import { createReadinessPanel } from "./overview";
import {
  hostBadge,
  hostDetail,
  olderVersion,
  parseDestination,
  proxyStale,
  splitList,
  stepTone,
  type HostList,
  type HostView,
  type SetupJob,
  type TestResult,
} from "./model";

// A setup job is followed this often; one runs for minutes.
const POLL_MS = 1500;

export function createHostsPage(host: PluginHostApi): Component {
  const k = kit(host);
  JobView = createJobView(host);
  const Readiness = createReadinessPanel(host);
  const Setup = createSetupForm(host);
  const AddExisting = createAddExistingForm(host);

  function Row(props: { h: HostView; release: string; onChanged: () => void }) {
    const { h } = props;
    const [upgrade, setUpgrade] = host.React.useState<SetupJob | null>(null);
    const [open, setOpen] = host.React.useState(false);
    const [test, setTest] = host.React.useState<TestResult | null>(null);
    const m = useMutation(host);
    const badge = hostBadge(h);
    const cap = h.status?.health?.capacity;
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
    const version = h.status?.health?.msbctl_version;
    const behind = (version !== undefined && olderVersion(version, props.release)) || proxyStale(h);
    const shown = test ?? h.status ?? null;
    return k.h(
      "div",
      { className: "msb-host", "data-testid": `host-${h.name}` },
      k.h(
        "div",
        { className: "msb-host__summary" },
        k.h("button", { className: "msb-host__toggle", onClick: () => setOpen(!open), "aria-expanded": open }, open ? "▾" : "▸"),
        k.h("strong", { className: "msb-host__name" }, h.name),
        k.badge(badge.tone, badge.label),
        k.h("span", { className: "msb-muted" }, h.ssh),
        h.status?.health?.msbctl_version ? k.h("span", { className: "msb-muted" }, `msbctl ${h.status.health.msbctl_version}`) : null,
        cap ? k.h("span", { className: "msb-muted" }, `${cap.sandboxes ?? 0}/${cap.max_sandboxes ?? "?"} sandboxes`) : null,
        k.h(
          "span",
          { className: "msb-host__actions" },
          k.button(m.busy === "test" ? "Testing..." : "Test", () => void runTest(), { disabled: m.busy !== null, testId: `test-${h.name}` }),
          behind
            ? k.button(version !== undefined && olderVersion(version, props.release) ? `Update to ${props.release}` : "Restart proxy onto the new release", () => void startUpgrade(), { disabled: m.busy !== null || upgrade?.state === "running", testId: `upgrade-${h.name}` })
            : null,
          k.button(h.draining ? "Undrain" : "Drain", () => void drain(), { disabled: m.busy !== null }),
          k.button("Remove", () => void remove(), { variant: "ghost", disabled: m.busy !== null }),
        ),
      ),
      k.error(m.error),
      upgrade
        ? k.h(JobView, { job: upgrade, title: `Updating ${h.name}`, onFinished: props.onChanged, onClose: () => setUpgrade(null) })
        : null,
      open
        ? k.h(
            "div",
            { className: "msb-host__detail" },
            shown && !shown.ok && shown.hint
              ? k.h("p", { className: "msb-hint" }, k.h("strong", null, (shown.problem ?? "").replace(/_/g, " "), ": "), shown.hint)
              : null,
            shown?.warning ? k.h("p", { className: "msb-hint" }, shown.warning) : null,
            shown?.egress_refused?.length
              ? k.h("p", { className: "msb-hint" }, "Refused by the host's allow_extra: ", shown.egress_refused.join(", "))
              : null,
            k.h(
              "dl",
              { className: "msb-facts" },
              ...hostDetail(h).flatMap(([label, value]) => [k.h("dt", { key: `${label}-t` }, label), k.h("dd", { key: `${label}-d` }, value)]),
            ),
            h.status?.health?.host ? null : h.status ? k.h("p", { className: "msb-muted" }, "OS, CPU, memory and disk appear once the host's msbctl reports them (feature request F22).") : null,
          )
        : null,
    );
  }

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

/** Scans a destination's host key for the operator to confirm. */
function useScan(host: PluginHostApi) {
  const [scanned, setScanned] = host.React.useState<{ dest: string; key: string; fingerprint: string } | null>(null);
  const [confirmed, setConfirmed] = host.React.useState(false);
  const m = useMutation(host);
  const scan = async (dest: string) => {
    setScanned(null);
    setConfirmed(false);
    const res = await m.run<{ host_key: string; fingerprint: string }>("scan", "hosts.scan", { ssh: dest });
    if (res) setScanned({ dest, key: res.host_key, fingerprint: res.fingerprint });
  };
  return { scanned, confirmed, setConfirmed, scan, busy: m.busy !== null, error: m.error };
}

function scanBlock(k: ReturnType<typeof kit>, s: ReturnType<typeof useScan>, dest: string): Node {
  const current = s.scanned && s.scanned.dest === dest ? s.scanned : null;
  return k.h(
    "div",
    { className: "msb-stack" },
    k.h(
      "div",
      { className: "msb-row" },
      k.button(s.busy ? "Scanning..." : current ? "Scan again" : "Scan its host key", () => void s.scan(dest), {
        disabled: s.busy || !parseDestination(dest),
        testId: "scan",
      }),
    ),
    k.error(s.error),
    current
      ? k.h(
          "label",
          { className: "msb-row" },
          k.h("input", { type: "checkbox", checked: s.confirmed, onChange: () => s.setConfirmed(!s.confirmed), "data-testid": "confirm-key" }),
          k.h("span", null, "The machine's host key is ", k.h("code", null, current.fingerprint), ". It matches ssh-keygen -lf on the machine."),
        )
      : null,
  );
}

interface JobViewProps {
  job: SetupJob;
  title: string;
  onFinished(): void;
  onAgain?: () => void;
  onClose(): void;
}

/** A setup or upgrade job's steps, followed until it finishes. */
function createJobView(host: PluginHostApi): Component<JobViewProps> {
  const k = kit(host);
  return function JobView(props: JobViewProps) {
    const [job, setJob] = host.React.useState<SetupJob>(props.job);
    const [error, setError] = host.React.useState<ActionError | null>(null);
    host.React.useEffect(() => {
      if (job.state !== "running") return;
      const controller = new AbortController();
      const timer = window.setTimeout(() => {
        invoke<SetupJob>(host, "hosts.setup.status", { id: job.id }, controller.signal)
          .then((next) => {
            setJob(next);
            if (next.state !== "running") props.onFinished();
          })
          .catch((cause: unknown) => {
            if (!controller.signal.aborted) setError(toActionError(cause));
          });
      }, POLL_MS);
      return () => {
        window.clearTimeout(timer);
        controller.abort();
      };
    }, [job]);
    return k.card(
      props.title,
      job.state === "running" ? "Running. This can take a few minutes." : job.state === "done" ? "Done." : "Stopped. Fix what the failed step says, then run it again: every step is safe to repeat.",
      k.error(error),
      k.h(
        "ol",
        { className: "msb-checklist" },
        ...job.steps.map((step) =>
          k.h(
            "li",
            { key: step.key, className: "msb-checklist__item", "data-testid": `step-${step.key}` },
            k.h("div", { className: "msb-row" }, k.badge(stepTone(step.state), step.state), k.h("span", null, step.title)),
            step.detail ? k.h("p", { className: "msb-muted" }, step.detail) : null,
            step.commands?.length ? k.code(step.commands.join("\n")) : null,
            step.output ? k.code(step.output) : null,
          ),
        ),
      ),
      job.manual?.length ? k.h("div", null, k.h("strong", null, "Still to do:"), k.h("ul", null, ...job.manual.map((m, i) => k.h("li", { key: i }, m)))) : null,
      k.h(
        "div",
        { className: "msb-row" },
        job.state !== "running" && props.onAgain ? k.button("Run it again", props.onAgain) : null,
        k.button("Close", props.onClose, { variant: "ghost" }),
      ),
    );
  };
}

let JobView: Component<JobViewProps>;

function createSetupForm(host: PluginHostApi): Component<{ onDone(): void; onCancel(): void }> {
  const k = kit(host);
  return function SetupForm(props: { onDone(): void; onCancel(): void }) {
    const [dest, setDest] = host.React.useState("");
    const [name, setName] = host.React.useState("");
    const [baseURL, setBaseURL] = host.React.useState("");
    const [labels, setLabels] = host.React.useState("default");
    const [mode, setMode] = host.React.useState<"key" | "password">("key");
    const [key, setKey] = host.React.useState("");
    const [passphrase, setPassphrase] = host.React.useState("");
    const [password, setPassword] = host.React.useState("");
    const [account, setAccount] = host.React.useState("");
    const [egress, setEgress] = host.React.useState(true);
    const [job, setJob] = host.React.useState<SetupJob | null>(null);
    const [error, setError] = host.React.useState<ActionError | null>(null);
    const s = useScan(host);

    const start = async () => {
      setError(null);
      const body: Record<string, unknown> = {
        name: name.trim(),
        ssh: dest.trim(),
        host_key: s.scanned?.key ?? "",
        labels: splitList(labels),
        egress_from_plugin: egress,
      };
      if (baseURL.trim()) body.base_url = baseURL.trim();
      if (account.trim()) body.account = account.trim();
      if (mode === "key") {
        body.admin_key = key;
        if (passphrase) body.admin_key_passphrase = passphrase;
      } else {
        body.admin_password = password;
      }
      try {
        const started = await invoke<SetupJob>(host, "hosts.setup", body);
        // The login goes no further than this request.
        setKey("");
        setPassphrase("");
        setPassword("");
        setJob(started);
      } catch (cause) {
        setError(toActionError(cause));
      }
    };

    const ready = s.confirmed && s.scanned?.dest === dest && name.trim() !== "" && (mode === "key" ? key.trim() !== "" : password !== "");
    if (job) {
      return k.h(JobView, {
        job,
        title: `Setting up ${job.name}`,
        onFinished: props.onDone,
        onAgain: () => {
          setJob(null);
          s.setConfirmed(true);
        },
        onClose: props.onCancel,
      });
    }
    return k.card(
      "Set up a new machine",
      "A Linux machine with KVM (on EC2, a .metal instance type). The plugin installs and configures everything over an admin SSH login you give once; the login is never stored.",
      k.field("Admin SSH destination", k.input(dest, setDest, { placeholder: "ubuntu@203.0.113.10", testId: "setup-dest" }), "user@host or user@host:port, with sudo for the full setup."),
      scanBlock(k, s, dest),
      k.field("Name", k.input(name, setName, { placeholder: "sbx-01", testId: "setup-name" }), "Permanent: every sandbox records it.", error?.fields.name),
      k.field("Base URL", k.input(baseURL, setBaseURL, { placeholder: "https://sbx-01.example.com" }), "The name Kandev reaches the machine at, within the root certificate's names. Empty means https://<the ssh host>.", error?.fields.base_url),
      k.field("Labels", k.input(labels, setLabels), "Comma-separated; profiles place on label:<x>."),
      k.h(
        "div",
        { className: "msb-row" },
        k.button("Private key", () => setMode("key"), { variant: mode === "key" ? "default" : "outline" }),
        k.button("Password", () => setMode("password"), { variant: mode === "password" ? "default" : "outline" }),
      ),
      mode === "key"
        ? k.h(
            "div",
            { className: "msb-stack" },
            k.field("Admin private key", k.textarea(key, setKey, { placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----", rows: 5, testId: "setup-key" })),
            k.field("Passphrase", k.input(passphrase, setPassphrase, { type: "password" }), "Only if the key has one."),
          )
        : k.field("Admin password", k.input(password, setPassword, { type: "password", testId: "setup-password" })),
      k.field("Account", k.input(account, setAccount, { placeholder: "msb" }), "The no-sudo account msb-manager runs under. Without sudo, the login itself."),
      k.h(
        "label",
        { className: "msb-row" },
        k.h("input", { type: "checkbox", checked: egress, onChange: () => setEgress(!egress) }),
        k.h("span", null, "This Kandev server decides egress (allow_extra = [\"*\"]): sandboxes reach what the plugin's egress policy allows."),
      ),
      k.error(error),
      k.h(
        "div",
        { className: "msb-row" },
        k.button("Set it up", () => void start(), { variant: "default", disabled: !ready, testId: "setup-start" }),
        k.button("Cancel", props.onCancel, { variant: "ghost" }),
      ),
    );
  };
}

function createAddExistingForm(host: PluginHostApi): Component<{ authorize: string; onDone(): void; onCancel(): void }> {
  const k = kit(host);
  return function AddExistingForm(props: { authorize: string; onDone(): void; onCancel(): void }) {
    const [dest, setDest] = host.React.useState("");
    const [name, setName] = host.React.useState("");
    const [baseURL, setBaseURL] = host.React.useState("");
    const [labels, setLabels] = host.React.useState("default");
    const s = useScan(host);
    const m = useMutation(host);
    const add = async () => {
      const res = await m.run("add", "hosts.add", {
        name: name.trim(), ssh: dest.trim(), host_key: s.scanned?.key ?? "", base_url: baseURL.trim(), labels: splitList(labels),
      });
      if (res) props.onDone();
    };
    const fields = m.error?.fields ?? {};
    return k.card(
      "Add a host that is already set up",
      "msb-manager is installed and [kandev] is configured. First authorize the plugin's key on it:",
      k.code(props.authorize),
      k.h("div", { className: "msb-row" }, k.button("Copy", () => void navigator.clipboard?.writeText(props.authorize))),
      k.field("SSH destination", k.input(dest, setDest, { placeholder: "msb@sbx-01.example.com" }), "The account msb-manager runs under."),
      scanBlock(k, s, dest),
      k.field("Name", k.input(name, setName, { placeholder: "sbx-01" }), undefined, fields.name),
      k.field("Base URL", k.input(baseURL, setBaseURL, { placeholder: "https://sbx-01.example.com" }), "[kandev] base_url on the host.", fields.base_url),
      k.field("Labels", k.input(labels, setLabels)),
      k.error(m.error),
      k.h(
        "div",
        { className: "msb-row" },
        k.button("Add", () => void add(), { variant: "default", disabled: !s.confirmed || !name.trim() || m.busy !== null }),
        k.button("Cancel", props.onCancel, { variant: "ghost" }),
      ),
    );
  };
}
