//! Node 页面（T-24/§24）：列表 + 创建 + 签发运行时凭据 + 删除。
//! 创建 node 一次性展示 bootstrap token（§4/§94）；列表可为 node 签发运行时 token 或删除。

import { api, errMessage, type Node } from "../api/client";
import { button, el, formData, statusBadge, table, toast } from "../components/ui";

function actionButton(label: string, className: string, onClick: () => void): HTMLElement {
  const b = el("button", { class: `btn btn-sm ${className}`, type: "button", text: label });
  b.addEventListener("click", onClick);
  return b;
}

function nodeRows(
  nodes: Node[],
  reload: () => void,
  issue: (n: Node) => void,
): Array<Array<string | HTMLElement>> {
  return nodes.map((n) => {
    const actions = el("div", { class: "row-actions" }, [
      actionButton("签发 Token", "", () => issue(n)),
      actionButton("删除", "btn-danger", () => {
        if (window.confirm(`删除节点 ${n.name}？\n该节点的路由不会被自动删除。`)) {
          void api.deleteNode(n.id).then(reload).catch((e) => toast(errMessage(e), "error"));
        }
      }),
    ]);
    return [
      el("a", { href: `#/nodes/${n.id}`, class: "mono", text: n.name }),
      statusBadge(n.status),
      n.hostname ?? "—",
      n.agent_version ?? "—",
      n.last_seen_at ?? "—",
      n.remote_addr ?? "—",
      actions,
    ];
  });
}

async function loadNodes(host: HTMLElement, issue: (n: Node) => void): Promise<void> {
  try {
    const nodes = await api.listNodes();
    host.replaceChildren(
      table(
        ["Name", "Status", "Hostname", "Agent", "Last Seen", "Remote", "操作"],
        nodeRows(nodes, () => void loadNodes(host, issue), issue),
        "暂无节点，点击右上角「Create Node」添加",
      ),
    );
  } catch (err) {
    toast(errMessage(err), "error");
    host.replaceChildren(el("p", { class: "muted", text: "加载失败" }));
  }
}

export async function nodesPage(): Promise<HTMLElement> {
  const head = el("div", { class: "page-head" }, [
    el("h1", { text: "Nodes" }),
    el("a", { href: "#/nodes/new", class: "btn btn-primary", text: "Create Node" }),
  ]);
  const credentialResult = el("div");
  const body = el("div");

  // 签发运行时 token（type=token，§5/§71），一次性展示明文；填到 agent 的 [auth].token。
  const issue = (n: Node): void => {
    void api
      .createCredential(n.id, { type: "token" })
      .then((res) => {
        const tokenBox = el("code", { class: "token-box", text: res.token });
        credentialResult.replaceChildren(
          el("div", { class: "card result-ok" }, [
            el("h3", { text: `已为节点 ${n.name} 签发运行时 token` }),
            el("p", {
              text: "这是 Agent 数据面认证用的运行时 token（填到 agent 的 [auth].token），仅显示这一次：",
            }),
            tokenBox,
            el("div", { class: "form-actions" }, [
              button("复制", {
                className: "btn btn-ghost",
                onClick: () => {
                  void navigator.clipboard
                    .writeText(res.token)
                    .then(() => toast("已复制", "success"));
                },
              }),
              button("关闭", {
                className: "btn btn-ghost",
                onClick: () => credentialResult.replaceChildren(),
              }),
            ]),
          ]),
        );
      })
      .catch((err) => toast(errMessage(err), "error"));
  };

  const page = el("div", { class: "page" }, [head, credentialResult, body]);
  await loadNodes(body, issue);
  return page;
}

export function nodeCreatePage(): HTMLElement {
  const form = el("form", { class: "card form-card" }, [
    el("h2", { text: "Create Node" }),
    el("label", { text: "名称" }),
    el("input", { type: "text", name: "name", required: true, placeholder: "home-nas" }),
    el("label", { text: "描述" }),
    el("input", { type: "text", name: "description", placeholder: "可选" }),
    el("div", { class: "form-actions" }, [
      el("a", { href: "#/nodes", class: "btn btn-ghost", text: "取消" }),
      el("button", { class: "btn btn-primary", type: "submit", text: "创建" }),
    ]),
    el("div", { id: "create-result" }),
  ]);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const btn = form.querySelector("button");
    btn?.setAttribute("disabled", "");
    void api
      .createNode({ name: d.name ?? "", description: d.description || null })
      .then((res) => showBootstrapToken(res.bootstrap_token, res.node.name))
      .catch((err) => toast(errMessage(err), "error"))
      .finally(() => btn?.removeAttribute("disabled"));
  });

  return el("div", { class: "page" }, [form]);
}

function showBootstrapToken(token: string, nodeName: string): void {
  const result = document.getElementById("create-result");
  if (!result) return;

  const tokenBox = el("code", { class: "token-box", text: token });
  const copy = el("button", { class: "btn btn-ghost", type: "button", text: "复制" });
  copy.addEventListener("click", () => {
    void navigator.clipboard.writeText(token).then(() => toast("已复制", "success"));
  });

  result.replaceChildren(
    el("div", { class: "card result-ok" }, [
      el("h3", { text: `节点 ${nodeName} 已创建` }),
      el("p", { text: "bootstrap token 仅显示这一次，请立即保存（用于 Agent enroll）：" }),
      tokenBox,
      el("div", { class: "form-actions" }, [
        copy,
        el("a", { href: "#/nodes", class: "btn btn-primary", text: "返回列表" }),
      ]),
    ]),
  );
}
