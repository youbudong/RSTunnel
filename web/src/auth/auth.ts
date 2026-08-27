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
