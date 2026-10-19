// Shapes the plugin's actions return, and pure helpers the pages render
// with. Nothing here touches the host, so it is all unit-tested.

export type Tone = "ok" | "warn" | "bad" | "muted";

export interface HostFacts {
  os?: string;
  kernel?: string;
  cpus?: number;
  memory_total_mib?: number;
  memory_available_mib?: number;
  load_1m?: number;
  disk_total_gib?: number;
  disk_free_gib?: number;
  uptime_seconds?: number;
}

export interface Health {
  msbctl_version?: string;
  msb_version?: string;
  platform?: string;
  kvm?: boolean;
  enabled?: boolean;
  base_url?: string;
  features?: string[];
  capacity?: {
    max_sandboxes?: number;
    sandboxes?: number;
    max_cpus?: number;
    cpus?: number;
    max_memory_mib?: number;
    memory_mib?: number;
  };
  serve?: { ok?: boolean; mode?: string; listen?: string; running?: boolean; version?: string };
  tls?: { installed?: boolean; subject?: string; not_after?: string };
  egress?: { allow_extra?: string[] };
  host?: HostFacts;
}

export interface TestResult {
  ok: boolean;
  problem?: string;
  hint?: string;
  warning?: string;
  health?: Health;
  tls?: { state?: string; reason?: string; not_after?: string };
  egress_refused?: string[];
}

export interface HostStatus extends TestResult {
  checked_at: string;
}

export interface HostView {
  name: string;
  ssh: string;
  host_key: string;
  base_url: string;
  labels: string[];
  draining?: boolean;
  fingerprint: string;
  status?: HostStatus;
}

export interface HostList {
  /** The msb-manager release setup installs and hosts.upgrade brings a host to. */
  msbctl_release: string;
  public_key: string;
  authorize: string;
  hosts: HostView[];
}

export interface SetupStep {
  key: string;
  title: string;
  state: "ok" | "changed" | "manual" | "failed" | "skipped";
  detail?: string;
  commands?: string[];
  output?: string;
}

export interface SetupJob {
  id: string;
  name: string;
  state: "running" | "done" | "failed";
  steps: SetupStep[];
  manual?: string[];
  host?: HostView;
  test?: TestResult;
}

export interface ReadinessItem {
  key: string;
  title: string;
  state: string;
  detail?: string;
  fix?: string[];
}

export interface Readiness {
  ready: boolean;
  items: ReadinessItem[];
}

export interface EgressGroup {
  name: string;
  description?: string;
  entries: string[];
  builtin?: boolean;
  default: boolean;
}

export interface EgressView {
  groups: EgressGroup[];
  defaults: string[];
}

export interface SecretMeta {
  name: string;
  description?: string;
  hosts: string[];
  updated_at: string;
}

/** What a host's last check says, in one badge. */
export function hostBadge(h: HostView): { tone: Tone; label: string } {
  if (h.draining) return { tone: "muted", label: "draining" };
  if (!h.status) return { tone: "muted", label: "not checked" };
  if (h.status.ok) return { tone: "ok", label: "ready" };
  return { tone: "bad", label: (h.status.problem ?? "failing").replace(/_/g, " ") };
}

export function readinessTone(state: string): Tone {
  switch (state) {
    case "ok":
      return "ok";
    case "unknown":
    case "unchecked":
      return "warn";
    default:
      return "bad";
  }
}

export function stepTone(state: SetupStep["state"]): Tone {
  switch (state) {
    case "ok":
    case "changed":
      return "ok";
    case "manual":
      return "warn";
    case "failed":
      return "bad";
    default:
      return "muted";
  }
}

export function formatMiB(mib: number | undefined): string {
  if (mib === undefined) return "";
  return mib >= 1024 ? `${(mib / 1024).toFixed(mib % 1024 === 0 ? 0 : 1)} GiB` : `${mib} MiB`;
}

export function formatGiB(gib: number | undefined): string {
  if (gib === undefined) return "";
  return gib >= 1024 ? `${(gib / 1024).toFixed(1)} TiB` : `${Math.round(gib)} GiB`;
}

export function formatUptime(seconds: number | undefined): string {
  if (seconds === undefined) return "";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days} d ${hours} h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`;
}

/** The detail rows for one host: what it is, what it has, how it is set up. */
export function hostDetail(h: HostView): Array<[string, string]> {
  const health = h.status?.health;
  const facts = health?.host;
  const cap = health?.capacity;
  const rows: Array<[string, string]> = [
    ["SSH", h.ssh],
    ["Base URL", h.base_url],
    ["Labels", h.labels.length ? h.labels.join(", ") : "none"],
    ["Host key", h.fingerprint],
  ];
  if (!health) return rows;
  const push = (label: string, value: string | undefined) => {
    if (value) rows.push([label, value]);
  };
  push("msbctl", health.msbctl_version);
  push("msb", health.msb_version);
  push("OS", facts?.os);
  push("Kernel", facts?.kernel);
  push("Platform", health.platform);
  if (facts?.cpus !== undefined) push("CPUs", `${facts.cpus}${facts.load_1m !== undefined ? `, load ${facts.load_1m.toFixed(2)}` : ""}`);
  if (facts?.memory_total_mib !== undefined) {
    push("Memory", `${formatMiB(facts.memory_available_mib)} free of ${formatMiB(facts.memory_total_mib)}`);
  }
  if (facts?.disk_total_gib !== undefined) {
    push("Disk", `${formatGiB(facts.disk_free_gib)} free of ${formatGiB(facts.disk_total_gib)}`);
  }
  push("Uptime", formatUptime(facts?.uptime_seconds));
  if (cap) {
    push(
      "Kandev sandboxes",
      `${cap.sandboxes ?? 0} of ${cap.max_sandboxes ?? "?"}, ${cap.cpus ?? 0} of ${cap.max_cpus ?? "?"} CPUs, ` +
        `${formatMiB(cap.memory_mib ?? 0)} of ${formatMiB(cap.max_memory_mib)}`,
    );
  }
  push("KVM", health.kvm === undefined ? undefined : health.kvm ? "usable" : "not usable");
  if (health.serve) {
    push(
      "Data path",
      `${health.serve.mode ?? "?"}${health.serve.listen ? ` on ${health.serve.listen}` : ""}, ${health.serve.ok ? "up" : "down"}` +
        (proxyStale(h) ? `, proxy on ${health.serve.version || "an older release"}` : ""),
    );
  }
  if (health.tls?.installed) push("Certificate", `${health.tls.subject ?? ""}, until ${health.tls.not_after ?? "?"}`);
  if (health.egress) push("allow_extra", health.egress.allow_extra?.length ? health.egress.allow_extra.join(", ") : "[] (nothing extra)");
  push("Last checked", h.status?.checked_at);
  return rows;
}

/** Splits a list typed with commas or newlines, trimmed, empty items dropped. */
export function splitList(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

/** Parses `user@host[:port]`, as the plugin does, or returns null. */
export function parseDestination(raw: string): { user: string; host: string; port: number } | null {
  const at = raw.indexOf("@");
  if (at <= 0) return null;
  const user = raw.slice(0, at);
  let rest = raw.slice(at + 1);
  let port = 22;
  const bracket = rest.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) {
    rest = bracket[1] ?? "";
    if (bracket[2]) port = Number(bracket[2]);
  } else {
    const colon = rest.lastIndexOf(":");
    if (colon >= 0 && rest.indexOf(":") === colon) {
      port = Number(rest.slice(colon + 1));
      rest = rest.slice(0, colon);
    }
  }
  if (!rest || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { user, host: rest, port };
}

/** Whether release `have` (x.y.z) is older than `want`; unreadable is never older. */
export function olderVersion(have: string, want: string): boolean {
  const parse = (v: string) => v.match(/(\d+)\.(\d+)\.(\d+)/)?.slice(1).map(Number);
  const h = parse(have);
  const w = parse(want);
  if (!h || !w) return false;
  for (let i = 0; i < 3; i++) {
    if (h[i] !== w[i]) return (h[i] ?? 0) < (w[i] ?? 0);
  }
  return false;
}

/** Whether the host's TLS proxy runs another release than its msbctl: an update it missed. */
export function proxyStale(h: HostView): boolean {
  const health = h.status?.health;
  if (!health?.serve || health.serve.mode !== "proxy" || !health.serve.running) return false;
  return (health.serve.version ?? "") !== (health.msbctl_version ?? "");
}
