//! 首次引导页（T-20）：`users` 表为空时创建初始管理员账户，成功后直接进入登录态。

import { setup } from "../auth/auth";
import { el, formData, toast } from "../components/ui";
import { errMessage } from "../api/client";
import { setUser } from "../stores/store";
import { go } from "../routes/router";

export function setupPage(): HTMLElement {
  const form = el("form", { class: "card login-card" }, [
    el("h1", { text: "初始化管理员账户" }),
    el("p", { class: "muted", text: "首次使用：创建管理员账户" }),
    el("label", { text: "用户名" }),
    el("input", { type: "text", name: "username", autocomplete: "username", required: true }),
    el("label", { text: "邮箱（可选）" }),
    el("input", { type: "email", name: "email", autocomplete: "email" }),
    el("label", { text: "密码（至少 8 位）" }),
    el("input", {
      type: "password",
      name: "password",
      autocomplete: "new-password",
      required: true,
      minlength: "8",
    }),
    el("label", { text: "确认密码" }),
    el("input", {
      type: "password",
      name: "confirm",
      autocomplete: "new-password",
      required: true,
    }),
    el("button", { class: "btn btn-primary btn-block", type: "submit", text: "创建管理员" }),
  ]);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const password = d.password ?? "";
    if (password !== (d.confirm ?? "")) {
      toast("两次输入的密码不一致", "error");
      return;
    }
    const btn = form.querySelector("button");
    btn?.setAttribute("disabled", "");
    void setup(d.username ?? "", password, d.email ?? undefined)
      .then((user) => {
        setUser(user);
        go("/");
      })
      .catch((err) => toast(errMessage(err), "error"))
      .finally(() => btn?.removeAttribute("disabled"));
  });

  return el("div", { class: "login-wrap" }, [form]);
}
