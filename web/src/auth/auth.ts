//! 会话封装（T-24）：token 存 localStorage，登录/登出/当前用户。

import {
  api,
  clearToken,
  getToken,
  setToken,
  type User,
} from "../api/client";

export function isAuthenticated(): boolean {
  return getToken() !== null;
}

export async function login(username: string, password: string): Promise<User> {
  const res = await api.login({ username, password });
  setToken(res.access_token);
  return res.user;
}

/** 首次引导：创建初始管理员并直接进入登录态。 */
export async function setup(
  username: string,
  password: string,
  email?: string,
): Promise<User> {
  const res = await api.setup({ username, password, email });
  setToken(res.access_token);
  return res.user;
}

// setup 状态缓存（首次查询后复用），避免路由守卫反复请求后端。
let setupState: boolean | null = null;

/** 系统是否已初始化（存在至少一个用户）。首次调用请求后端并缓存。 */
export async function ensureSetupStatus(): Promise<boolean> {
  if (setupState !== null) return setupState;
  const res = await api.setupStatus();
  setupState = res.initialized;
  return setupState;
}

export async function me(): Promise<User> {
  return (await api.me()).user;
}

export async function logout(): Promise<void> {
  try {
    await api.logout();
  } catch {
    // 登出失败不阻塞本地清理。
  }
  clearToken();
}
