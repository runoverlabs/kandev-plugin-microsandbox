import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { kit, useLoad, useMutation } from "./common";
import type { SecretMeta } from "./model";

interface Draft {
  name: string;
  description: string;
  hosts: string;
  value: string;
  // saved is the stored name, absent for a row not saved yet.
  saved?: string;
}

function draftOf(s: SecretMeta): Draft {
  return { name: s.name, description: s.description ?? "", hosts: s.hosts.join(", "), value: "", saved: s.name };
}

/**
 * Secrets profiles use by name: an add list, like a local executor's
 * environment variables. A value is never shown again once saved; leaving it
 * empty keeps the stored one.
 */
export function createSecretsPage(host: PluginHostApi): Component {
  const k = kit(host);

  function SecretRow(props: { draft: Draft; onSaved(): void; onDiscard(): void }) {
    const [d, setD] = host.React.useState<Draft>(props.draft);
    const m = useMutation(host);
    const set = (patch: Partial<Draft>) => setD({ ...d, ...patch });
    const save = async () => {
      const body: Record<string, unknown> = { name: d.name.trim(), description: d.description.trim(), hosts: d.hosts };
      if (d.value !== "" || !d.saved) body.value = d.value;
      if (await m.run("save", "secrets.put", body)) {
        setD({ ...d, value: "", saved: d.name.trim() });
        props.onSaved();
      }
    };
    const remove = async () => {
      if (!d.saved) {
        props.onDiscard();
        return;
      }
      if (!window.confirm(`Delete the secret ${d.saved}? Profiles naming it fail until edited.`)) return;
      if (await m.run("remove", "secrets.remove", { name: d.saved })) props.onSaved();
    };
    const fields = m.error?.fields ?? {};
    return k.h(
      "div",
      { className: "msb-secret", "data-testid": `secret-${d.saved ?? "new"}` },
      k.h(
        "div",
        { className: "msb-secret__grid" },
        d.saved
          ? k.field("Name", k.h("code", { className: "msb-secret__name" }, d.saved))
          : k.field("Name", k.input(d.name, (v) => set({ name: v.toUpperCase() }), { placeholder: "NPM_TOKEN", mono: true, testId: "secret-name" }), undefined, fields.name),
        k.field("Hosts", k.input(d.hosts, (v) => set({ hosts: v }), { placeholder: "registry.npmjs.org", mono: true, testId: "secret-hosts" }), "Where the value may be sent: host or host:port, comma-separated.", fields.hosts),
        k.field(
          "Value",
          k.input(d.value, (v) => set({ value: v }), { type: "password", placeholder: d.saved ? "unchanged" : "", testId: "secret-value" }),
          d.saved ? "Leave empty to keep the stored value." : undefined,
          fields.value,
        ),
        k.field("Description", k.input(d.description, (v) => set({ description: v })), undefined, fields.description),
      ),
      m.error && !Object.keys(fields).length ? k.error(m.error) : null,
      k.h(
        "div",
        { className: "msb-row" },
        k.button(m.busy === "save" ? "Saving..." : "Save", () => void save(), { variant: "default", disabled: m.busy !== null, testId: "secret-save" }),
        k.button(d.saved ? "Delete" : "Discard", () => void remove(), { variant: "ghost", disabled: m.busy !== null }),
      ),
    );
  }

  return function MicrosandboxSecretsPage() {
    const list = useLoad<{ secrets: SecretMeta[] }>(host, "secrets.list");
    const [fresh, setFresh] = host.React.useState<number[]>([]);
    const [next, setNext] = host.React.useState(0);
    const saved = list.data?.secrets ?? [];
    return k.h(
      "div",
      { className: "msb-page" },
      k.h("h2", { className: "msb-title" }, "Secrets"),
      k.card(
        "Secrets",
        "A profile names the secrets it uses in its Secrets field, such as NPM_TOKEN. The guest sees a placeholder; the sandbox host puts the value into request headers bound for the secret's hosts only.",
        k.error(list.error),
        saved.length === 0 && fresh.length === 0 && list.data ? k.h("p", { className: "msb-muted" }, "No secret yet.") : null,
        ...saved.map((s) => k.h(SecretRow, { key: `${s.name}@${s.updated_at}`, draft: draftOf(s), onSaved: list.reload, onDiscard: () => {} })),
        ...fresh.map((id) =>
          k.h(SecretRow, {
            key: `new-${id}`,
            draft: { name: "", description: "", hosts: "", value: "" },
            onSaved: () => {
              setFresh(fresh.filter((f) => f !== id));
              list.reload();
            },
            onDiscard: () => setFresh(fresh.filter((f) => f !== id)),
          }),
        ),
        k.h(
          "div",
          { className: "msb-row" },
          k.button("Add secret", () => {
            setFresh([...fresh, next]);
            setNext(next + 1);
          }, { testId: "add-secret" }),
        ),
      ),
    );
  };
}
