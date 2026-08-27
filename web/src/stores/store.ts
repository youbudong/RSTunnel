//! 极简全局状态（T-24）：当前用户。页面数据各自按需拉取，不做深度响应式。

import type { User } from "../api/client";

export interface AppState {
  user: User | null;
}

export const store: AppState = {
  user: null,
};

export function setUser(user: User | null): void {
  store.user = user;
}
