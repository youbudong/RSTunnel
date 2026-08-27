//! 类型化 REST 客户端（T-24）。请求/响应类型复用 T-23 生成的 `api-types.d.ts`
//! （§132：避免前后端手写重复类型），运行时通过 `fetch` 走同源代理。

import type { components } from "../types/api-types";

export type Schemas = components["schemas"];
export type Node = Schemas["Node"];
export type Route = Schemas["Route"];
export type User = Schemas["User"];
export type CreateNodeRequest = Schemas["CreateNodeRequest"];
export type CreateNodeResponse = Schemas["CreateNodeResponse"];
export type UpdateNodeRequest = Schemas["UpdateNodeRequest"];
export type CreateRouteRequest = Schemas["CreateRouteRequest"];
export type UpdateRouteRequest = Schemas["UpdateRouteRequest"];
export type LoginResponse = Schemas["LoginResponse"];
export type MeResponse = Schemas["MeResponse"];
export type CredentialResponse = Schemas["CredentialResponse"];
export type RouteType = Schemas["RouteType"];
export type TlsMode = Schemas["TlsMode"];

const TOKEN_KEY = "rstunnel.token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/** REST 错误：服务端统一返回 `{ error: { code, message, request_id } }`。 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  const res = await fetch(path, init);
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const data = text ? (JSON.parse(text) as Record<string, unknown>) : null;

  if (!res.ok) {
    const err = (data?.error ?? {}) as { code?: string; message?: string };
    throw new ApiError(
      res.status,
      err.code ?? "HTTP_ERROR",
      err.message ?? `请求失败（HTTP ${res.status}）`,
    );
  }
  return data as T;
}

export const api = {
  login: (body: { username: string; password: string }) =>
    request<LoginResponse>("POST", "/auth/login", body),
  logout: () => request<void>("POST", "/auth/logout"),
  me: () => request<MeResponse>("GET", "/auth/me"),

  listNodes: () => request<Node[]>("GET", "/api/v1/nodes"),
  createNode: (body: CreateNodeRequest) =>
    request<CreateNodeResponse>("POST", "/api/v1/nodes", body),
  updateNode: (id: string, body: UpdateNodeRequest) =>
    request<Node>("PATCH", `/api/v1/nodes/${id}`, body),
  deleteNode: (id: string) => request<void>("DELETE", `/api/v1/nodes/${id}`),
  createCredential: (id: string, body: { type?: string; expires_at?: string | null }) =>
    request<CredentialResponse>("POST", `/api/v1/nodes/${id}/credentials`, body),

  listRoutes: () => request<Route[]>("GET", "/api/v1/routes"),
  createRoute: (body: CreateRouteRequest) =>
    request<Route>("POST", "/api/v1/routes", body),
  updateRoute: (id: string, body: UpdateRouteRequest) =>
    request<Route>("PATCH", `/api/v1/routes/${id}`, body),
  deleteRoute: (id: string) => request<void>("DELETE", `/api/v1/routes/${id}`),
  enableRoute: (id: string) => request<Route>("POST", `/api/v1/routes/${id}/enable`),
  disableRoute: (id: string) => request<Route>("POST", `/api/v1/routes/${id}/disable`),
};
