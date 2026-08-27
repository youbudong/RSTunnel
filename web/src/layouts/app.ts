//! 应用壳（T-24）：左侧导航 + 顶部状态条 + 内容区（§65/§66）。

import { el } from "../components/ui";
import { logout } from "../auth/auth";
import { store } from "../stores/store";
import { go } from "../routes/router";
import { stopEvents } from "../websocket/ws";

const NAV = [
  { path: "/", label: "Dashboard" },
  { path: "/nodes", label: "Nodes" },
  { path: "/routes", label: "Routes" },
];

export function renderApp(): HTMLElement {
  const brand = el("div", { class: "brand" }, [el("span", { text: "Rust Tunnel" })]);

  const nav = el("nav", { class: "nav" });
  for (const item of NAV) {
    nav.append(el("a", { href: `#${item.path}`, class: "nav-link", text: item.label }));
  }
  // 高亮当前项。
  const markActive = (): void => {
    const path = currentPathForNav();
    nav.querySelectorAll("a").forEach((a) => {
      a.classList.toggle("active", a.getAttribute("href") === `#${path}`);
    });
  };
  window.addEventListener("hashchange", markActive);
  markActive();

  const logoutBtn = el("button", { class: "btn btn-ghost", type: "button", text: "Logout" });
  logoutBtn.addEventListener("click", () => {
    stopEvents();
    void logout().then(() => go("/login"));
  });

  const user = store.user;
  const topbar = el("div", { class: "topbar" }, [
    el("span", { class: "topbar-status" }, [el("span", { class: "dot dot-ok" }), " connected"]),
    el("span", { class: "spacer" }),
    user
      ? el("span", { class: "topbar-user", text: `${user.username}${user.role ? ` · ${user.role}` : ""}` })
      : null,
    logoutBtn,
  ]);

  const sidebar = el("aside", { class: "sidebar" }, [brand, nav]);
  const main = el("main", { class: "content" }, [
    topbar,
    el("div", { id: "view" }),
  ]);
  const toasts = el("div", { id: "toast", class: "toasts" });

  return el("div", { class: "layout" }, [sidebar, main, toasts]);
}

/** 导航高亮用：把 `/nodes/new` 归到 `/nodes`、`/routes/:id/edit` 归到 `/routes`。 */
function currentPathForNav(): string {
  const p = window.location.hash.replace(/^#/, "");
  if (p.startsWith("/nodes")) return "/nodes";
  if (p.startsWith("/routes")) return "/routes";
  return p === "" ? "/" : p;
}
