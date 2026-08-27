//! Route 页面（T-24/§24）：列表 + 创建/编辑/删除 + 启用/停用。

import {
  api,
  errMessage,
  type CreateRouteRequest,
  type Node,
  type Route,
  type RouteType,
  type TlsMode,
} from "../api/client";
import { el, formData, select, statusBadge, table, toast } from "../components/ui";
import { go } from "../routes/router";

function targetLabel(r: Route): string {
  return `${r.target_host}:${r.target_port}`;
}

function typeLabel(r: Route): string {
  if (r.type === "http" || r.type === "https") return `${r.type} · ${r.hostname ?? ""}`;
  return `${r.type} · ${r.listen_host ?? "0.0.0.0"}:${r.listen_port ?? "?"}`;
}

function buildRouteInput(d: Record<string, string>): CreateRouteRequest {
  const type = (d.type ?? "tcp") as RouteType;
  const tcpUdp = type === "tcp" || type === "udp";
  const base = {
    name: d.name ?? "",
    node_id: d.node_id ?? "",
    type,
    enabled: d.enabled === "true",
    target_host: d.target_host ?? "",
    target_port: Number(d.target_port),
    tls_mode: (d.tls_mode || "disabled") as TlsMode,
  };
  if (tcpUdp) {
    return {
      ...base,
      listen_host: d.listen_host || "0.0.0.0",
      listen_port: d.listen_port ? Number(d.listen_port) : null,
      hostname: null,
    };
  }
  return {
    ...base,
    listen_host: null,
    listen_port: null,
    hostname: d.hostname || null,
  };
}

function actionButton(label: string, className: string, onClick: () => void): HTMLElement {
  const b = el("button", { class: `btn btn-sm ${className}`, type: "button", text: label });
  b.addEventListener("click", onClick);
  return b;
}

function routeRows(routes: Route[], reload: () => void): Array<Array<string | HTMLElement>> {
  return routes.map((r) => {
    const actions = el("div", { class: "row-actions" }, [
      actionButton(r.enabled ? "停用" : "启用", "", () => {
        const p = r.enabled ? api.disableRoute(r.id) : api.enableRoute(r.id);
        void p.then(reload).catch((e) => toast(errMessage(e), "error"));
      }),
      el("a", { href: `#/routes/${r.id}/edit`, class: "btn btn-sm", text: "编辑" }),
      actionButton("删除", "btn-danger", () => {
        if (window.confirm(`删除路由 ${r.name}？`)) {
          void api.deleteRoute(r.id).then(reload).catch((e) => toast(errMessage(e), "error"));
        }
      }),
    ]);
    return [
      el("a", { href: `#/routes/${r.id}`, class: "mono", text: r.name }),
      r.type,
      typeLabel(r),
      targetLabel(r),
      statusBadge(r.enabled ? "enabled" : "disabled"),
      actions,
    ];
  });
}

async function loadRoutes(host: HTMLElement): Promise<void> {
  try {
    const routes = await api.listRoutes();
    const render = (): void => {
      host.replaceChildren(
        table(
          ["Name", "Type", "入口", "Target", "状态", "操作"],
          routeRows(routes, () => void loadRoutes(host)),
          "暂无路由，点击右上角「Create Route」添加",
        ),
      );
    };
    render();
  } catch (err) {
    toast(errMessage(err), "error");
    host.replaceChildren(el("p", { class: "muted", text: "加载失败" }));
  }
}

export async function routesPage(): Promise<HTMLElement> {
  const head = el("div", { class: "page-head" }, [
    el("h1", { text: "Routes" }),
    el("a", { href: "#/routes/new", class: "btn btn-primary", text: "Create Route" }),
  ]);
  const body = el("div");
  const page = el("div", { class: "page" }, [head, body]);
  await loadRoutes(body);
  return page;
}

async function routeForm(existing?: Route): Promise<HTMLFormElement> {
  let nodes: Node[] = [];
  try {
    nodes = await api.listNodes();
  } catch {
    nodes = [];
  }

  const nodeSelect = select(
    "node_id",
    nodes.map((n) => ({ value: n.id, label: n.name, selected: n.id === existing?.node_id })),
    { disabled: nodes.length === 0 },
  );

  const typeSelect = select("type", [
    { value: "tcp", label: "TCP", selected: (existing?.type ?? "tcp") === "tcp" },
    { value: "udp", label: "UDP", selected: existing?.type === "udp" },
    { value: "http", label: "HTTP", selected: existing?.type === "http" },
    { value: "https", label: "HTTPS", selected: existing?.type === "https" },
  ]);

  const tlsSelect = select("tls_mode", [
    { value: "disabled", label: "disabled", selected: (existing?.tls_mode ?? "disabled") === "disabled" },
    { value: "terminate", label: "terminate", selected: existing?.tls_mode === "terminate" },
    { value: "passthrough", label: "passthrough", selected: existing?.tls_mode === "passthrough" },
  ]);

  const listenFields = el("div", { class: "field-group", id: "listen-fields" }, [
    el("label", { text: "监听地址 (listen_host)" }),
    el("input", {
      type: "text",
      name: "listen_host",
      value: existing?.listen_host ?? "0.0.0.0",
      placeholder: "0.0.0.0",
    }),
    el("label", { text: "监听端口 (listen_port)" }),
    el("input", {
      type: "number",
      name: "listen_port",
      value: existing?.listen_port != null ? String(existing.listen_port) : "",
      min: "1",
      max: "65535",
      placeholder: "tcp/udp 必填",
    }),
  ]);

  const hostnameField = el("div", { class: "field-group", id: "hostname-field" }, [
    el("label", { text: "Hostname" }),
    el("input", {
      type: "text",
      name: "hostname",
      value: existing?.hostname ?? "",
      placeholder: "http/https 必填，如 app.example.com",
    }),
  ]);

  const enabledCheckbox = el("input", { type: "checkbox", name: "enabled" });
  enabledCheckbox.checked = existing ? existing.enabled : true;

  const syncVisibility = (): void => {
    const tcpUdp = typeSelect.value === "tcp" || typeSelect.value === "udp";
    listenFields.style.display = tcpUdp ? "" : "none";
    hostnameField.style.display = tcpUdp ? "none" : "";
  };
  typeSelect.addEventListener("change", syncVisibility);
  syncVisibility();

  const nodeHint =
    nodes.length === 0
      ? el("p", { class: "error", text: "尚无可用节点，请先创建 Node。" })
      : null;

  const form = el("form", { class: "card form-card" }, [
    el("label", { text: "名称" }),
    el("input", { type: "text", name: "name", required: true, value: existing?.name ?? "", placeholder: "web-app" }),
    el("label", { text: "节点" }),
    nodeSelect,
    nodeHint,
    el("label", { text: "类型" }),
    typeSelect,
    el("label", { text: "启用" }),
    enabledCheckbox,
    el("label", { text: "目标地址 (target_host)" }),
    el("input", { type: "text", name: "target_host", required: true, value: existing?.target_host ?? "", placeholder: "127.0.0.1" }),
    el("label", { text: "目标端口 (target_port)" }),
    el("input", {
      type: "number",
      name: "target_port",
      required: true,
      value: existing ? String(existing.target_port) : "",
      min: "1",
      max: "65535",
    }),
    listenFields,
    hostnameField,
    el("label", { text: "TLS 模式" }),
    tlsSelect,
    el("div", { class: "form-actions" }, [
      el("a", { href: "#/routes", class: "btn btn-ghost", text: "取消" }),
      el("button", { class: "btn btn-primary", type: "submit", text: existing ? "保存" : "创建" }),
    ]),
  ]);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const payload = buildRouteInput(formData(form));
    const btn = form.querySelector("button");
    btn?.setAttribute("disabled", "");
    const action = existing ? api.updateRoute(existing.id, payload) : api.createRoute(payload);
    void action
      .then(() => {
        toast(existing ? "已保存" : "已创建", "success");
        go("/routes");
      })
      .catch((err) => toast(errMessage(err), "error"))
      .finally(() => btn?.removeAttribute("disabled"));
  });

  return form;
}

export async function routeCreatePage(): Promise<HTMLElement> {
  const form = await routeForm();
  return el("div", { class: "page" }, [el("h1", { text: "Create Route" }), form]);
}

export async function routeEditPage(params: Record<string, string>): Promise<HTMLElement> {
  const id = params.id ?? "";
  try {
    const routes = await api.listRoutes();
    const existing = routes.find((r) => r.id === id);
    if (!existing) {
      return el("div", { class: "page" }, [el("h1", { text: "Route 不存在" })]);
    }
    const form = await routeForm(existing);
    return el("div", { class: "page" }, [el("h1", { text: "Edit Route" }), form]);
  } catch (err) {
    return el("div", { class: "page" }, [el("h1", { text: "加载失败" }), el("pre", { class: "error", text: errMessage(err) })]);
  }
}
