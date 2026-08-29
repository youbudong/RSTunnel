//! 入口（T-24）：挂载应用壳、注册路由、启动哈希路由；已登录则恢复用户画像。

import "./style.css";
import { me } from "./auth/auth";
import { isAuthenticated } from "./auth/auth";
import { renderApp } from "./layouts/app";
import { loginPage } from "./pages/login";
import { setupPage } from "./pages/setup";
import { dashboardPage } from "./pages/dashboard";
import { nodesPage, nodeCreatePage } from "./pages/nodes";
import { routesPage, routeCreatePage, routeEditPage } from "./pages/routes";
import { route, startRouter } from "./routes/router";
import { setUser } from "./stores/store";

route("/login", () => loginPage());
route("/setup", () => setupPage());
route("/", () => dashboardPage());
route("/nodes", () => nodesPage());
route("/nodes/new", () => nodeCreatePage());
route("/routes", () => routesPage());
route("/routes/new", () => routeCreatePage());
route("/routes/:id/edit", (p) => routeEditPage(p));

document.querySelector("#app")?.replaceChildren(renderApp());

// 已登录：启动时回填当前用户（会话 cookie 缺失或 token 过期则落到登录页）。
if (isAuthenticated()) {
  void me()
    .then(setUser)
    .catch(() => {
      /* 由路由守卫重定向到登录页 */
    });
}

void startRouter();
