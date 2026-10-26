import { describe, expect, it } from "vitest";
import { createEgressPage } from "../src/egress";
import { createHostRow } from "../src/host-row";
import type { HostView } from "../src/model";

// A stub host whose jsx returns a plain element tree, and whose state hooks
// return their initial values, so a component renders once without React.
interface El {
  type: unknown;
  props: Record<string, unknown>;
  children: unknown[];
}

function stubHost(state: unknown[] = []): any {
  let call = 0;
  return {
    jsx: (type: unknown, props: Record<string, unknown> | null, ...children: unknown[]) => ({ type, props: props ?? {}, children }),
    ui: new Proxy({}, { get: (_, name) => String(name) }),
    React: {
      useState: (initial: unknown) => [call < state.length ? state[call++] : initial, () => undefined],
      useEffect: () => undefined,
    },
    context: { getActiveWorkspaceId: () => "ws", getWorkspaceIds: () => ["ws"] },
    api: { invokeAction: () => new Promise(() => undefined) },
  };
}

function render(component: unknown, props: unknown): El {
  const tree = (component as (p: unknown) => El)(props);
  const expand = (node: unknown): unknown => {
    if (!node || typeof node !== "object") return node;
    const el = node as El;
    if (typeof el.type === "function") return expand((el.type as (p: unknown) => unknown)({ ...el.props, children: el.children }));
    return { ...el, children: el.children.map(expand) };
  };
  return expand(tree) as El;
}

function text(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node !== "object") return String(node);
  return (node as El).children.map(text).join(" ");
}

function find(node: unknown, testId: string): El | undefined {
  if (!node || typeof node !== "object") return undefined;
  const el = node as El;
  if (el.props["data-testid"] === testId) return el;
  for (const child of el.children) {
    const found = find(child, testId);
    if (found) return found;
  }
  return undefined;
}

const host: HostView = {
  name: "sbx-01",
  ssh: "msb@sbx-01",
  host_key: "ssh-ed25519 AAAA",
  base_url: "https://sbx-01.example.com",
  labels: ["default"],
  draining: false,
  fingerprint: "SHA256:abc",
  status: {
    checked_at: "2026-10-26T00:00:00Z",
    ok: false,
    problem: "root_not_trusted",
    hint: "Install the root.",
    egress_refused: ["api.example.com"],
    health: {
      msbctl_version: "0.6.0",
      kvm: true,
      capacity: { sandboxes: 2, max_sandboxes: 12 },
      serve: { ok: true, mode: "proxy", running: true, version: "0.6.0" },
    },
  },
} as HostView;

describe("host row", () => {
  it("offers the update to the release a host is behind", () => {
    const Row = createHostRow(stubHost());
    const tree = render(Row, { h: host, release: "0.7.0", onChanged: () => undefined });
    expect(text(find(tree, "upgrade-sbx-01"))).toBe("Update to 0.7.0");
    expect(text(tree)).toContain("2/12 sandboxes");
    expect(text(tree)).toContain("msbctl 0.6.0");
  });

  it("offers no update to a current host", () => {
    const Row = createHostRow(stubHost());
    const tree = render(Row, { h: host, release: "0.6.0", onChanged: () => undefined });
    expect(find(tree, "upgrade-sbx-01")).toBeUndefined();
  });

  it("shows the last check's hints when open", () => {
    // useHostRow's state, in order: upgrade, open, test.
    const Row = createHostRow(stubHost([null, true, null]));
    const tree = text(render(Row, { h: host, release: "0.6.0", onChanged: () => undefined }));
    expect(tree).toContain("root not trusted");
    expect(tree).toContain("Install the root.");
    expect(tree).toContain("Refused by the host's allow_extra:");
    expect(tree).toContain("api.example.com");
    expect(tree).toContain("Kandev sandboxes");
  });
});

describe("egress page", () => {
  it("lists built-in groups without edit buttons", () => {
    const view = {
      groups: [
        { name: "openrouter", description: "OpenRouter", entries: ["openrouter.ai"], builtin: true, default: true },
        { name: "lan-llm", description: "", entries: ["192.168.2.6:8788"], builtin: false, default: false },
      ],
      defaults: ["openrouter"],
    };
    // useLoad's state, in order: data, error, generation.
    const Page = createEgressPage(stubHost([view, null, 0]));
    const tree = render(Page, {});
    const builtin = find(tree, "group-openrouter");
    const custom = find(tree, "group-lan-llm");
    expect(text(builtin)).toContain("built-in");
    expect(text(builtin)).not.toContain("Edit");
    expect(text(custom)).toContain("Edit");
    expect(text(custom)).toContain("192.168.2.6:8788");
  });
});
