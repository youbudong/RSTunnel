//! Node 页面（T-24/§24）：列表 + 创建。创建后一次性展示 bootstrap token（§4/§94）。

import { api, errMessage, type Node } from "../api/client";
import { el, formData, statusBadge, table, toast } from "../components/ui";
import { go } from "../routes/router";

function nodeRows(nodes: Node[]): Array<Array<string | HTMLElement>> {
  return nodes.map((n) => [
    el("a", { href: `#/nodes/${n.id}`, class: "mono", text: n.name }),
    statusBadge(n.status),
    n.hostname ?? "—",
    n.agent_version ?? "—",
    n.last_seen_at ?? "—",
    n.remote_addr ?? "—",
  ]);
}

async function loadNodes(host: HTMLElement): Promise<void> {
  try {
    const nodes = await api.listNodes();
    host.replaceChildren(
      table(
        ["Name", "Status", "Hostname", "Agent", "Last Seen", "Remote"],
        nodeRows(nodes),
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
  const body = el("div");
  const page = el("div", { class: "page" }, [head, body]);
  await loadNodes(body);
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
