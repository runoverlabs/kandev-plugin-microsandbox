import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { kit, useLoad, useMutation, type Node } from "./common";
import type { EgressGroup, EgressView } from "./model";

/**
 * The plugin-wide egress policy: built-in and custom groups, and which ones
 * every sandbox gets. A host's own allow_extra still has the last word.
 */
export function createEgressPage(host: PluginHostApi): Component {
  const k = kit(host);
  const Editor = createEgressEditor(host);

  return function MicrosandboxEgressPage() {
    const view = useLoad<EgressView>(host, "egress.list");
    const [editing, setEditing] = host.React.useState<EgressGroup | "new" | null>(null);
    const m = useMutation(host);
    const groups = view.data?.groups ?? [];
    const toggleDefault = async (g: EgressGroup) => {
      const current = view.data?.defaults ?? [];
      const next = g.default ? current.filter((n) => n !== g.name) : [...current, g.name];
      if (await m.run("defaults", "egress.defaults", { groups: next })) view.reload();
    };
    const remove = async (g: EgressGroup) => {
      if (!window.confirm(`Delete the group ${g.name}? Profiles naming it fail until edited.`)) return;
      if (await m.run("remove", "egress.remove", { name: g.name })) view.reload();
    };
    return k.h(
      "div",
      { className: "msb-page" },
      k.h("h2", { className: "msb-title" }, "Egress"),
      k.card(
        "Groups",
        "Every sandbox gets the default groups, then its profile's egress_groups, then its egress_allow. Changes apply to sandboxes created from now on.",
        k.error(view.error ?? m.error),
        k.h(
          host.ui.Table as unknown,
          null,
          k.h(
            host.ui.TableHeader as unknown,
            null,
            k.h(host.ui.TableRow as unknown, null, ...["Default", "Group", "Entries", ""].map((t) => k.h(host.ui.TableHead as unknown, { key: t }, t))),
          ),
          k.h(
            host.ui.TableBody as unknown,
            null,
            ...groups.map((g) => groupRow(k, host, g, { busy: m.busy !== null, toggleDefault, remove, edit: () => setEditing(g) })),
          ),
        ),
        k.h("div", { className: "msb-row" }, k.button("New group", () => setEditing("new"), { testId: "new-group" })),
      ),
      editing
        ? k.h(Editor, {
            key: editing === "new" ? "new" : editing.name,
            group: editing === "new" ? null : editing,
            onSaved: () => {
              setEditing(null);
              view.reload();
            },
            onCancel: () => setEditing(null),
          })
        : null,
    );
  };
}

interface GroupActions {
  busy: boolean;
  toggleDefault(g: EgressGroup): Promise<void>;
  remove(g: EgressGroup): Promise<void>;
  edit(): void;
}

/** One group in the table: whether it is a default, what it is, its entries. */
function groupRow(k: ReturnType<typeof kit>, host: PluginHostApi, g: EgressGroup, actions: GroupActions): Node {
  return k.h(
    host.ui.TableRow as unknown,
    { key: g.name, "data-testid": `group-${g.name}` },
    k.h(
      host.ui.TableCell as unknown,
      null,
      k.h("input", { type: "checkbox", checked: g.default, disabled: actions.busy, onChange: () => void actions.toggleDefault(g), "aria-label": `${g.name} is a default` }),
    ),
    k.h(
      host.ui.TableCell as unknown,
      null,
      k.h("strong", null, g.name),
      g.builtin ? k.h("span", { className: "msb-muted" }, " built-in") : null,
      g.description ? k.h("div", { className: "msb-muted" }, g.description) : null,
    ),
    k.h(host.ui.TableCell as unknown, { className: "msb-mono" }, g.entries.join(", ")),
    k.h(
      host.ui.TableCell as unknown,
      null,
      g.builtin
        ? null
        : k.h(
            "span",
            { className: "msb-row" },
            k.button("Edit", actions.edit),
            k.button("Delete", () => void actions.remove(g), { variant: "ghost" }),
          ),
    ),
  );
}

interface EditorProps {
  group: EgressGroup | null;
  onSaved(): void;
  onCancel(): void;
}

/** Creates or edits a custom group. */
function createEgressEditor(host: PluginHostApi): Component<EditorProps> {
  const k = kit(host);
  return function Editor(props: EditorProps) {
    const [name, setName] = host.React.useState(props.group?.name ?? "");
    const [description, setDescription] = host.React.useState(props.group?.description ?? "");
    const [entries, setEntries] = host.React.useState<string[]>(props.group?.entries.length ? [...props.group.entries] : [""]);
    const m = useMutation(host);
    const save = async () => {
      const res = await m.run("save", "egress.put", {
        name: name.trim(), description: description.trim(), entries: entries.map((e) => e.trim()).filter((e) => e !== ""),
      });
      if (res) props.onSaved();
    };
    return k.card(
      props.group ? `Edit ${props.group.name}` : "New egress group",
      "Each entry is a host (HTTPS), *.suffix (HTTPS), host:port, an address or address:port.",
      props.group ? null : k.field("Name", k.input(name, setName, { placeholder: "lan-llm", testId: "group-name" }), "Lowercase letters, digits and dashes."),
      k.field("Description", k.input(description, setDescription)),
      k.h("span", { className: "msb-field__label" }, "Entries"),
      ...entries.map((entry, i) =>
        k.h(
          "div",
          { key: i, className: "msb-row" },
          k.input(entry, (v) => setEntries(entries.map((e, j) => (j === i ? v : e))), { placeholder: "192.168.2.6:8788", mono: true, testId: `entry-${i}` }),
          k.button("Remove", () => setEntries(entries.length > 1 ? entries.filter((_, j) => j !== i) : [""]), { variant: "ghost" }),
        ),
      ),
      k.h("div", { className: "msb-row" }, k.button("Add entry", () => setEntries([...entries, ""]), { testId: "add-entry" })),
      k.error(m.error),
      k.h(
        "div",
        { className: "msb-row" },
        k.button("Save", () => void save(), { variant: "default", disabled: m.busy !== null, testId: "save-group" }),
        k.button("Cancel", props.onCancel, { variant: "ghost" }),
      ),
    );
  };
}
