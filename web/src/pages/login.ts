//! 登录页（T-24/§24）：`/login`。

import { login } from "../auth/auth";
import { el, formData, toast } from "../components/ui";
import { errMessage } from "../api/client";
import { setUser } from "../stores/store";
import { go } from "../routes/router";

export function loginPage(): HTMLElement {
  const form = el("form", { class: "card login-card" }, [
    el("h1", { text: "Rust Tunnel" }),
    el("p", { class: "muted", text: "登录管理后台" }),
    el("label", { text: "用户名" }),
    el("input", { type: "text", name: "username", autocomplete: "username", required: true }),
    el("label", { text: "密码" }),
    el("input", { type: "password", name: "password", autocomplete: "current-password", required: true }),
    el("button", { class: "btn btn-primary btn-block", type: "submit", text: "登录" }),
  ]);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const btn = form.querySelector("button");
    btn?.setAttribute("disabled", "");
    void login(d.username ?? "", d.password ?? "")
      .then((user) => {
        setUser(user);
        go("/");
      })
      .catch((err) => toast(errMessage(err), "error"))
      .finally(() => btn?.removeAttribute("disabled"));
  });

  return el("div", { class: "login-wrap" }, [form]);
}
