import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { invoke, toActionError, type ActionError } from "./api";
import { kit, useMutation, type Node } from "./common";
import { createJobView } from "./job-view";
import { parseDestination, splitList, type SetupJob } from "./model";

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

export function createSetupForm(host: PluginHostApi): Component<{ onDone(): void; onCancel(): void }> {
  const k = kit(host);
  const JobView = createJobView(host);
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

export function createAddExistingForm(host: PluginHostApi): Component<{ authorize: string; onDone(): void; onCancel(): void }> {
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
        k.button("Add", () => void add(), { variant: "default", disabled: !s.confirmed || s.scanned?.dest !== dest || !name.trim() || m.busy !== null, testId: "add-host" }),
        k.button("Cancel", props.onCancel, { variant: "ghost" }),
      ),
    );
  };
}
