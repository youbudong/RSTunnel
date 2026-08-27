//! Dashboard（T-24/§24）：节点/路由概览卡片。T-25 起订阅 `/ws` 推送的
//! node/route/config 事件，实时刷新 online/offline 与路由启用数。

import { api, errMessage } from "../api/client";
import { el, toast } from "../components/ui";
import { onEvent } from "../websocket/ws";

/** 上次挂载时注册的取消订阅函数（导航离开后下一次挂载前清理）。 */
let unsubscribe: (() => void) | null = null;

export async function dashboardPage(): Promise<HTMLElement> {
  const page = el("div", { class: "page" }, [el("h1", { text: "Dashboard" })]);
  const grid = el("div", { class: "cards" });
  page.append(grid);

  const stats = new Map<string, HTMLElement>();
  const cards: Array<[string, string, string]> = [
    ["nodes-online", "Nodes Online", "在线节点"],
    ["nodes-total", "Total Nodes", "全部节点"],
    ["routes-enabled", "Enabled Routes", "已启用路由"],
    ["routes-total", "Total Routes", "全部路由"],
  ];
  for (const [key, title, hint] of cards) {
    const value = el("div", { class: "stat-value", text: "—" });
    stats.set(key, value);
    grid.append(
      el("div", { class: "card stat" }, [
        el("div", { class: "stat-label", text: title }),
        value,
        el("div", { class: "stat-hint", text: hint }),
      ]),
    );
  }

  const setStat = (key: string, v: number): void => {
    const node = stats.get(key);
    if (node) node.textContent = String(v);
  };

  const refresh = async (): Promise<void> => {
    if (!page.isConnected) return; // 页面已被替换（导航离开），跳过。
    try {
      const [nodes, routes] = await Promise.all([api.listNodes(), api.listRoutes()]);
      setStat("nodes-online", nodes.filter((n) => n.status === "online").length);
      setStat("nodes-total", nodes.length);
      setStat("routes-enabled", routes.filter((r) => r.enabled).length);
      setStat("routes-total", routes.length);
    } catch (err) {
      toast(errMessage(err), "error");
    }
  };

  await refresh();

  // 订阅事件总线，node/route/config 变更即刷新统计。
  unsubscribe?.();
  unsubscribe = onEvent((ev) => {
    if (
      ev.type.startsWith("node.") ||
      ev.type.startsWith("route.") ||
      ev.type.startsWith("config.")
    ) {
      void refresh();
    }
  });

  return page;
}
