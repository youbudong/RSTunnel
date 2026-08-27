//! DOM 工具（T-24）：无 UI 框架，用 `createElement` 构造、`textContent` 注入避免 XSS。

type Attrs = Record<string, string | number | boolean | null | undefined>;
type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = String(value);
    else if (key === "text") node.textContent = String(value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function button(
  label: string,
  opts: { className?: string; onClick?: () => void; type?: string } = {},
): HTMLButtonElement {
  const b = el("button", {
    class: opts.className ?? "btn",
    type: opts.type ?? "button",
    text: label,
  });
  if (opts.onClick) b.addEventListener("click", opts.onClick);
  return b;
}

export function formData(form: HTMLFormElement): Record<string, string> {
  const out: Record<string, string> = {};
  for (const elem of form.elements) {
    const input = elem as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
    if (!input.name) continue;
    if (input instanceof HTMLInputElement && input.type === "checkbox") {
      out[input.name] = input.checked ? "true" : "false";
    } else {
      out[input.name] = input.value;
    }
  }
  return out;
}

export function toast(message: string, kind: "info" | "error" | "success" = "info"): void {
  const host = document.getElementById("toast");
  if (!host) return;
  const t = el("div", { class: `toast toast-${kind}`, text: message });
  host.append(t);
  window.setTimeout(() => t.remove(), 4000);
}

/** 带下拉选择（保留 `selected`）的 select 构造。 */
export function select(
  name: string,
  options: Array<{ value: string; label: string; selected?: boolean }>,
  opts: { disabled?: boolean } = {},
): HTMLSelectElement {
  const s = el("select", { name, ...(opts.disabled ? { disabled: true } : {}) });
  for (const o of options) {
    const opt = el("option", { value: o.value, text: o.label });
    if (o.selected) opt.selected = true;
    s.append(opt);
  }
  return s;
}

/** 表格构建：`columns` 为表头，`rows` 为每行的单元格（已按 textContent 注入）。 */
export function table(
  columns: string[],
  rows: Array<Array<string | Node>>,
  emptyHint = "暂无数据",
): HTMLElement {
  const thead = el("thead", {}, [el("tr", {}, columns.map((c) => el("th", { text: c })))]);
  const tbody = el("tbody");
  if (rows.length === 0) {
    tbody.append(
      el("tr", {}, [
        el("td", { colspan: String(columns.length), class: "empty", text: emptyHint }),
      ]),
    );
  }
  for (const row of rows) {
    tbody.append(
      el(
        "tr",
        {},
        row.map((cell) =>
          typeof cell === "string"
            ? el("td", { text: cell })
            : el("td", {}, [cell]),
        ),
      ),
    );
  }
  return el("table", { class: "table" }, [thead, tbody]);
}

/** 状态徽标：online/offline/unknown 等映射到配色。 */
export function statusBadge(status: string): HTMLElement {
  const kind = /online|connected|running|enabled|ok/i.test(status)
    ? "ok"
    : /offline|error|disabled|unknown/i.test(status)
      ? "bad"
      : "muted";
  return el("span", { class: `badge badge-${kind}`, text: status });
}
