import type { PluginHostApi } from "@kandev/plugin-sdk";

// Must equal manifest.yaml's `id`.
export const PLUGIN_ID = "kandev-plugin-microsandbox";

/** A failed action, with the plugin's own message and field errors. */
export class ActionError extends Error {
  readonly status: number;
  readonly fields: Record<string, string>;

  constructor(message: string, status: number, fields: Record<string, string>) {
    super(message);
    this.status = status;
    this.fields = fields;
  }
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * The plugin's error body is `{"error": "...", "fields": ...}`, where fields
 * is a map or a list of `{field, message}`. Host errors (a timeout, a missing
 * workspace) carry no such body and get a generic message.
 */
export function toActionError(cause: unknown): ActionError {
  if (cause instanceof ActionError) return cause;
  const status = typeof (cause as { status?: unknown })?.status === "number" ? (cause as { status: number }).status : 0;
  const body = (cause as { body?: unknown })?.body;
  const fields: Record<string, string> = {};
  let message = "";
  if (body && typeof body === "object") {
    message = text((body as { error?: unknown }).error);
    const raw = (body as { fields?: unknown }).fields;
    if (Array.isArray(raw)) {
      for (const item of raw) {
        const field = text((item as { field?: unknown })?.field);
        if (field) fields[field] = text((item as { message?: unknown })?.message);
      }
    } else if (raw && typeof raw === "object") {
      for (const [field, value] of Object.entries(raw)) fields[field] = text(value);
    }
  }
  if (!message) {
    message =
      status === 504
        ? "The plugin did not answer in time. Try again."
        : "Could not reach the microsandbox plugin. Check the Kandev server logs.";
  }
  return new ActionError(message, status, fields);
}

/** The workspace an action is scoped to: every action here is plugin-wide, but Kandev requires one. */
export function workspaceOf(host: PluginHostApi): string {
  return host.context.getActiveWorkspaceId() ?? host.context.getWorkspaceIds()[0] ?? "";
}

/** Invokes a plugin action, throwing an ActionError on failure. */
export async function invoke<T>(host: PluginHostApi, key: string, body: unknown = {}, signal?: AbortSignal): Promise<T> {
  const workspaceId = workspaceOf(host);
  if (!workspaceId) throw new ActionError("Create a workspace first: Kandev scopes every plugin action to one.", 0, {});
  try {
    return await host.api.invokeAction<T>(key, { workspaceId, body }, signal ? { signal } : undefined);
  } catch (cause) {
    throw toActionError(cause);
  }
}
