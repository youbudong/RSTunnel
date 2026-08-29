//! 哈希路由（T-24）：`#/nodes`、`#/routes/:id/edit` 等，含登录守卫。

import { ensureSetupStatus, isAuthenticated } from "../auth/auth";
import { el } from "../components/ui";
import { errMessage } from "../api/client";
import { connectEvents } from "../websocket/ws";

type Handler = (params: Record<string, string>) => Promise<HTMLElement> | HTMLElement;

interface RouteDef {
  pattern: string;
  handler: Handler;
}

const routes: RouteDef[] = [];

export function route(pattern: string, handler: Handler): void {
  routes.push({ pattern, handler });
}

function match(path: string): { handler: Handler; params: Record<string, string> } | null {
  const pathParts = path.split("/").filter(Boolean);
  for (const r of routes) {
    const rParts = r.pattern.split("/").filter(Boolean);
    if (rParts.length !== pathParts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < rParts.length; i++) {
      const rp = rParts[i]!;
      const pp = pathParts[i]!;
      if (rp.startsWith(":")) params[rp.slice(1)] = decodeURIComponent(pp);
      else if (rp !== pp) {
        ok = false;
        break;
      }
    }
    if (ok) return { handler: r.handler, params };
  }
  return null;
}

export function currentPath(): string {
  const h = window.location.hash.replace(/^#/, "");
  return h === "" ? "/" : h;
}

export function go(path: string): void {
  window.location.hash = path;
}

export async function startRouter(): Promise<void> {
  const render = async (): Promise<void> => {
    const view = document.getElementById("view");
    if (!view) return;

    const path = currentPath();
    // 未登录：按「是否已初始化」分流到 setup（首次引导）或 login。
    if (!isAuthenticated()) {
      if (path === "/setup") {
        if (await ensureSetupStatus()) {
          go("/login");
          return;
        }
      } else if (path === "/login") {
        if (!(await ensureSetupStatus())) {
          go("/setup");
          return;
        }
      } else {
        go((await ensureSetupStatus()) ? "/login" : "/setup");
        return;
      }
    }
    // 已登录访问登录/引导页 → 回首页。
    if (isAuthenticated() && (path === "/login" || path === "/setup")) {
      go("/");
      return;
    }
    // 已登录：确保事件连接在（覆盖首次加载与登录后跳转；重复调用为空操作）。
    if (isAuthenticated()) connectEvents();

    view.replaceChildren();
    const m = match(path);
    if (!m) {
      view.append(el("div", { class: "page" }, [el("h1", { text: "404" }), el("p", { text: `未找到页面：${path}` })]));
      return;
    }
    try {
      view.append(await m.handler(m.params));
    } catch (err) {
      view.append(
        el("div", { class: "page" }, [
          el("h1", { text: "出错了" }),
          el("pre", { class: "error", text: errMessage(err) }),
        ]),
      );
    }
  };

  window.addEventListener("hashchange", () => void render());
  await render();
}
