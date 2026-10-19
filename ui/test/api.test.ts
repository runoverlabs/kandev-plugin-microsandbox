import { describe, expect, it, vi } from "vitest";
import { ActionError, invoke, toActionError, workspaceOf } from "../src/api";

function host(overrides: Record<string, unknown> = {}): any {
  return {
    context: { getActiveWorkspaceId: () => undefined, getWorkspaceIds: () => ["ws-1", "ws-2"] },
    api: { invokeAction: vi.fn().mockResolvedValue({ ok: true }) },
    ...overrides,
  };
}

describe("actions", () => {
  // Every action is scope "workspace": Kandev refuses one without the
  // selector before it reaches the plugin.
  it("sends a workspace and the body", async () => {
    const h = host();
    await invoke(h, "hosts.test", { name: "sbx-01" });
    expect(h.api.invokeAction).toHaveBeenCalledWith("hosts.test", { workspaceId: "ws-1", body: { name: "sbx-01" } }, undefined);
  });

  it("prefers the active workspace", () => {
    expect(workspaceOf(host({ context: { getActiveWorkspaceId: () => "ws-2", getWorkspaceIds: () => ["ws-1"] } }))).toBe("ws-2");
  });

  it("refuses without any workspace", async () => {
    const h = host({ context: { getActiveWorkspaceId: () => undefined, getWorkspaceIds: () => [] } });
    await expect(invoke(h, "hosts.list")).rejects.toBeInstanceOf(ActionError);
    expect(h.api.invokeAction).not.toHaveBeenCalled();
  });

  it("keeps the plugin's message and field errors", async () => {
    const h = host({ api: { invokeAction: vi.fn().mockRejectedValue({ status: 422, body: { error: "the host is invalid", fields: [{ field: "name", message: "bad name" }] } }) } });
    const err = (await invoke(h, "hosts.add", {}).catch((e: unknown) => e)) as ActionError;
    expect(err.status).toBe(422);
    expect(err.message).toBe("the host is invalid");
    expect(err.fields).toEqual({ name: "bad name" });
    expect(toActionError({ status: 422, body: { error: "x", fields: { hosts: "at least one" } } }).fields).toEqual({ hosts: "at least one" });
  });

  // Pages convert whatever a call throws; one already converted must keep
  // the plugin's message and fields.
  it("leaves an already converted error alone", () => {
    const once = toActionError({ status: 422, body: { error: "the secret is invalid", fields: { name: "reserved" } } });
    expect(toActionError(once)).toBe(once);
  });

  it("says something useful for host-side failures", () => {
    expect(toActionError({ status: 504 }).message).toContain("did not answer in time");
    expect(toActionError(new TypeError("fetch failed")).message).toContain("Could not reach");
  });
});
