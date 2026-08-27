//! WebSocket 实时状态客户端（T-25，§23）：订阅 `/ws` 推送的 `node.*` / `route.*` /
//! `config.*` 事件。认证依赖登录时设置的 HttpOnly `sid` cookie（浏览器自动携带，
//! 无需在 URL/消息中透传 token）。断线自动重连，订阅者只处理感兴趣的事件。

import { isAuthenticated } from "../auth/auth";

/** 服务端 `BusEvent` 的消息格式（§23：`{ type, data }`）。 */
export interface BusEvent {
  type: string;
  data: Record<string, unknown>;
}

type Listener = (event: BusEvent) => void;

const RECONNECT_DELAY_MS = 3000;

let socket: WebSocket | null = null;
let stopped = false;
let retryTimer: number | undefined;
const listeners = new Set<Listener>();

function wsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws`;
}

function open(): void {
  if (socket || stopped) return;
  const ws = new WebSocket(wsUrl());
  socket = ws;

  ws.addEventListener("message", (ev) => {
    let parsed: BusEvent;
    try {
      parsed = JSON.parse(String(ev.data)) as BusEvent;
    } catch {
      return; // 忽略无法解析的帧。
    }
    for (const fn of listeners) fn(parsed);
  });
  ws.addEventListener("error", () => {
    ws.close();
  });
  ws.addEventListener("close", () => {
    socket = null;
    if (!stopped) scheduleReconnect();
  });
}

function scheduleReconnect(): void {
  if (retryTimer !== undefined) return;
  retryTimer = window.setTimeout(() => {
    retryTimer = undefined;
    open();
  }, RECONNECT_DELAY_MS);
}

/** 建立（或恢复）事件连接。未登录或已连接时为空操作。 */
export function connectEvents(): void {
  stopped = false;
  if (!isAuthenticated() || socket) return;
  open();
}

/** 断开并停止自动重连（登出时调用）。 */
export function stopEvents(): void {
  stopped = true;
  if (retryTimer !== undefined) {
    window.clearTimeout(retryTimer);
    retryTimer = undefined;
  }
  const ws = socket;
  socket = null;
  ws?.close();
}

/** 订阅事件，返回取消订阅函数（页面卸载/重建时调用以避免监听器泄漏）。 */
export function onEvent(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
