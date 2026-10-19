import { describe, expect, it, vi } from "vitest";

describe("bundle", () => {
  it("registers the overview and three settings pages", async () => {
    let lifecycle: any;
    (globalThis as any).window = { registerKandevPlugin: (id: string, l: unknown) => { expect(id).toBe("kandev-plugin-microsandbox"); lifecycle = l; } };
    await import("../src/bundle");
    const registry = { registerComponent: vi.fn(), registerSettingsRoute: vi.fn() };
    lifecycle.initialize(registry, { jsx: () => null, ui: {}, React: {} });
    expect(registry.registerComponent.mock.calls.map((c: unknown[]) => c[0])).toEqual(["plugin-settings", "settings-nav"]);
    expect(registry.registerSettingsRoute.mock.calls.map((c: unknown[]) => c[0])).toEqual([
      "/settings/plugins/kandev-plugin-microsandbox/hosts",
      "/settings/plugins/kandev-plugin-microsandbox/egress",
      "/settings/plugins/kandev-plugin-microsandbox/secrets",
    ]);
  });
});
