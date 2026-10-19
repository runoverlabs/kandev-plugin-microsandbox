import type { PluginHostApi } from "@kandev/plugin-sdk";
import { invoke, toActionError, type ActionError } from "./api";
import type { Tone } from "./model";

// Settings routes, under the prefix Kandev reserves for plugins.
export const ROUTES = {
  hosts: "/settings/plugins/kandev-plugin-microsandbox/hosts",
  egress: "/settings/plugins/kandev-plugin-microsandbox/egress",
  secrets: "/settings/plugins/kandev-plugin-microsandbox/secrets",
} as const;

export type Node = unknown;

/** The pieces every page uses, bound to one host. */
export function kit(host: PluginHostApi) {
  const h = host.jsx as (type: unknown, props?: Record<string, unknown> | null, ...children: Node[]) => Node;
  const ui = host.ui as unknown as Record<string, unknown>;

  const badge = (tone: Tone, label: string) =>
    h(ui.Badge, { variant: tone === "bad" ? "destructive" : tone === "ok" ? "default" : "secondary", "data-tone": tone, className: `msb-badge msb-badge--${tone}` }, label);

  const button = (label: string, onClick: () => void, opts: { variant?: string; disabled?: boolean; testId?: string } = {}) =>
    h(ui.Button, { size: "sm", variant: opts.variant ?? "outline", disabled: opts.disabled ?? false, onClick, "data-testid": opts.testId }, label);

  const field = (label: string, input: Node, help?: string, error?: string) =>
    h(
      "label",
      { className: "msb-field" },
      h("span", { className: "msb-field__label" }, label),
      input,
      help ? h("span", { className: "msb-field__help" }, help) : null,
      error ? h("span", { className: "msb-field__error" }, error) : null,
    );

  const input = (value: string, onChange: (v: string) => void, opts: { placeholder?: string; type?: string; testId?: string; mono?: boolean } = {}) =>
    h(ui.Input, {
      value,
      type: opts.type ?? "text",
      placeholder: opts.placeholder,
      autoComplete: opts.type === "password" ? "new-password" : "off",
      spellCheck: false,
      className: opts.mono ? "msb-mono" : undefined,
      "data-testid": opts.testId,
      onChange: (e: { target: { value: string } }) => onChange(e.target.value),
    });

  const textarea = (value: string, onChange: (v: string) => void, opts: { placeholder?: string; rows?: number; testId?: string } = {}) =>
    h(ui.Textarea, {
      value,
      rows: opts.rows ?? 4,
      placeholder: opts.placeholder,
      spellCheck: false,
      className: "msb-mono",
      "data-testid": opts.testId,
      onChange: (e: { target: { value: string } }) => onChange(e.target.value),
    });

  const error = (err: ActionError | null) =>
    err ? h(ui.Alert, { variant: "destructive", className: "msb-alert" }, h(ui.AlertDescription, null, err.message)) : null;

  const card = (title: string, description: string | null, ...children: Node[]) =>
    h(
      ui.Card,
      { className: "msb-card" },
      h(ui.CardHeader, null, h(ui.CardTitle, null, title), description ? h(ui.CardDescription, null, description) : null),
      h(ui.CardContent, null, ...children),
    );

  const code = (text: string) => h("pre", { className: "msb-code" }, text);

  const link = (label: string, path: string) =>
    h(
      "a",
      {
        href: path,
        className: "msb-link",
        onClick: (e: { preventDefault(): void }) => {
          e.preventDefault();
          host.navigate(path);
        },
      },
      label,
    );

  return { h, ui, badge, button, field, input, textarea, error, card, code, link };
}

/**
 * Loads one action's answer on mount and on reload(). Requests are aborted
 * when the page unmounts or reloads, so a late answer never lands on a page
 * that moved on.
 */
export function useLoad<T>(host: PluginHostApi, key: string) {
  const [data, setData] = host.React.useState<T | null>(null);
  const [error, setError] = host.React.useState<ActionError | null>(null);
  const [generation, setGeneration] = host.React.useState(0);
  host.React.useEffect(() => {
    const controller = new AbortController();
    invoke<T>(host, key, {}, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) {
          setData(value);
          setError(null);
        }
      })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(toActionError(cause));
      });
    return () => controller.abort();
  }, [generation]);
  return { data, error, reload: () => setGeneration((g: number) => g + 1) };
}

/** Runs one mutation, keeping its error and a busy flag. */
export function useMutation(host: PluginHostApi) {
  const [busy, setBusy] = host.React.useState<string | null>(null);
  const [error, setError] = host.React.useState<ActionError | null>(null);
  const run = async <T>(label: string, key: string, body: unknown): Promise<T | null> => {
    setBusy(label);
    setError(null);
    try {
      return await invoke<T>(host, key, body);
    } catch (cause) {
      setError(toActionError(cause));
      return null;
    } finally {
      setBusy(null);
    }
  };
  return { busy, error, setError, run };
}
