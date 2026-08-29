//! HTTP 数据面入口（T-26）：在 `http.bind` 上接受连接，解析 HTTP/1.x 请求头，
//! 按 `Host` 匹配 Route（[`HostTable`]），经 Node 的 QUIC 连接打开双向流（复用 OPEN_TCP），
//! 注入/覆盖 `X-Forwarded-*` 后透传字节（设计文档 §52/§110，协议 §202）。
//!
//! 服务端只做 Host 路由与 header 注入，Agent 侧仍按 OPEN_TCP 连 `target_host:target_port`
//! 并透传后续字节，无需解析 HTTP。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::acl_store::AclStore;
use crate::conn_limiter::ConnLimiter;
use crate::conn_registry::ConnRegistry;
use crate::frame_io::read_frame;
use crate::route::HostTable;
use crate::tcp_proxy::{copy_duplex, send_message};
use tunnel_protocol::{Message, OpenTcpPayload};

/// 请求头最大字节数（超出视为恶意/异常，直接 400）。
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// 请求行/头无法解析或 Host 缺失时返回的最小响应。
const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const TOO_MANY: &[u8] =
    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 等 Agent 回 OPEN_OK/OPEN_FAIL 的超时（略大于 agent 侧 connect 超时，留出回帧余量）。
/// 目标黑洞式不可达或 agent 无响应时，若无此兜底 server 会无限挂起，前端反代超时后替我们回 503。
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Host 路由的 HTTP 反向入口（单监听，按 Host 分发到不同 Node/Route）。
pub struct HttpProxy {
    host_table: Arc<HostTable>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
    addr: SocketAddr,
    listener: Arc<TcpListener>,
}

impl HttpProxy {
    /// 绑定 `addr` 并准备接受连接（`run` 才进入接受循环）。
    pub async fn bind(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
    ) -> Result<Self> {
        Self::bind_with_acl(addr, host_table, conns, Arc::new(AclStore::new())).await
    }

    /// 同上，并共享数据面 ACL 判定器（T-34：deny 源返回 403）。
    pub async fn bind_with_acl(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
        acl: Arc<AclStore>,
    ) -> Result<Self> {
        Self::bind_with_acl_and_limiter(addr, host_table, conns, acl, Arc::new(ConnLimiter::new()))
            .await
    }

    /// 同上，并共享数据面 ACL 判定器与按 Route 的连接限速器（生产 main 用）。
    pub async fn bind_with_acl_and_limiter(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
        acl: Arc<AclStore>,
        conn_limiter: Arc<ConnLimiter>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind HTTP listener {addr}"))?;
        let addr = listener.local_addr()?;
        Ok(Self {
            host_table,
            conns,
            acl,
            conn_limiter,
            addr,
            listener: Arc::new(listener),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// 启动接受循环（每连接一个任务），直到进程退出。
    pub fn run(&self) {
        let listener = Arc::clone(&self.listener);
        let host_table = Arc::clone(&self.host_table);
        let conns = Arc::clone(&self.conns);
        let acl = Arc::clone(&self.acl);
        let conn_limiter = Arc::clone(&self.conn_limiter);
        tokio::spawn(async move {
            accept_loop(listener, host_table, conns, acl, conn_limiter).await;
        });
    }
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    host_table: Arc<HostTable>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if let Some(c) = tunnel_metrics::connections_total() {
                    c.inc();
                }
                let host_table = Arc::clone(&host_table);
                let conns = Arc::clone(&conns);
                let acl = Arc::clone(&acl);
                let conn_limiter = Arc::clone(&conn_limiter);
                tokio::spawn(async move {
                    handle_http(stream, host_table, conns, acl, conn_limiter, peer, "http").await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "http accept error");
                break;
            }
        }
    }
}

/// 处理单条入向连接：读请求头 → Host 路由 → OPEN_TCP → 注入 header → 透传字节。
///
/// 对 `S` 泛化以复用同一套 Host 路由/header 注入逻辑：明文 HTTP 传 [`tokio::net::TcpStream`]，
/// TLS 终止后的流（`tokio_rustls::server::TlsStream`）传 `proto="https"`（T-27）。
pub(crate) async fn handle_http<S>(
    mut stream: S,
    host_table: Arc<HostTable>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
    peer: SocketAddr,
    proto: &'static str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. 读请求头（缓冲区可能已含部分 body 字节，稍后继续转发）。
    let mut buf = Vec::with_capacity(4096);
    let head_end = match read_head(&mut stream, &mut buf).await {
        Ok(Some(n)) => n,
        Ok(None) => return, // 未发完整请求即关闭
        Err(e) => {
            tracing::debug!(%peer, error = %e, "read request head failed");
            return;
        }
    };

    // 2. 解析请求行与头（`httparse` 为 hyper 内部使用的成熟 HTTP/1.x parser）。
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let Ok(httparse::Status::Complete(_)) = req.parse(&buf[..head_end]) else {
        tracing::debug!(%peer, "unparseable HTTP request");
        let _ = stream.write_all(BAD_REQUEST).await;
        return;
    };
    let (Some(method), Some(path)) = (req.method, req.path) else {
        let _ = stream.write_all(BAD_REQUEST).await;
        return;
    };
    let version = req.version.unwrap_or(1);

    // 3. Host → Route（Host 头大小写不敏感，容忍带端口）。
    let host = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| String::from_utf8_lossy(h.value).into_owned())
        .unwrap_or_default();
    let Some(route) = host_table.lookup(host_for_lookup(&host)) else {
        tracing::debug!(%peer, host, "no route for host");
        if let Some(c) = tunnel_metrics::route_errors_total() {
            c.inc();
        }
        let _ = stream.write_all(NOT_FOUND).await;
        return;
    };

    // T-34：数据面 ACL——deny 的源返回 403（未配置则放行）。
    if !acl.allows(route.id, &peer, &route.target_host, route.target_port) {
        tracing::info!(route = %route.name, %peer, "http connection denied by ACL");
        let _ = stream.write_all(FORBIDDEN).await;
        return;
    }

    // T-35：单 Route 连接数上限（limits.max_connections，None = 不限）。守卫随连接存续。
    let _conn_guard = match route.limits.as_ref().and_then(|l| l.max_connections) {
        Some(max) => match conn_limiter.try_acquire(route.id, max) {
            Some(g) => Some(g),
            None => {
                tracing::info!(
                    route = %route.name,
                    max_connections = max,
                    %peer,
                    "route at connection limit"
                );
                let _ = stream.write_all(TOO_MANY).await;
                return;
            }
        },
        None => None,
    };

    // 4. Node 连接 + 打开双向流（复用 OPEN_TCP，见协议 §202）。
    let Some(conn) = conns.get(route.node_id) else {
        tracing::warn!(route = %route.name, node = %route.node_id, "node offline");
        if let Some(c) = tunnel_metrics::connections_failed() {
            c.inc();
        }
        if let Some(c) = tunnel_metrics::route_errors_total() {
            c.inc();
        }
        let _ = stream.write_all(BAD_GATEWAY).await;
        return;
    };
    let (mut qsend, mut qrecv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(route = %route.name, error = %e, "open bidi stream failed");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            let _ = stream.write_all(BAD_GATEWAY).await;
            return;
        }
    };
    let msg = Message::OpenTcp(OpenTcpPayload {
        route_id: route.id,
        target_host: route.target_host.clone(),
        target_port: route.target_port,
        client_addr: Some(peer.to_string()),
    });
    if send_message(&mut qsend, msg, 0).await.is_err() {
        if let Some(c) = tunnel_metrics::connections_failed() {
            c.inc();
        }
        return;
    }
    let frame = match tokio::time::timeout(OPEN_TIMEOUT, read_frame(&mut qrecv)).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => {
            tracing::warn!(route = %route.name, error = %e, "read OPEN result failed");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            let _ = stream.write_all(BAD_GATEWAY).await;
            return;
        }
        Err(_elapsed) => {
            tracing::warn!(route = %route.name, timeout = ?OPEN_TIMEOUT, "agent did not answer OPEN_TCP in time");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            let _ = stream.write_all(BAD_GATEWAY).await;
            return;
        }
    };
    let Some(frame) = frame else {
        if let Some(c) = tunnel_metrics::connections_failed() {
            c.inc();
        }
        let _ = stream.write_all(BAD_GATEWAY).await;
        return;
    };
    match Message::from_frame(&frame) {
        Ok(Message::OpenOk(_)) => {}
        Ok(Message::OpenFail(p)) => {
            tracing::warn!(route = %route.name, code = %p.code, "agent failed to open target");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            if let Some(c) = tunnel_metrics::route_errors_total() {
                c.inc();
            }
            let _ = stream.write_all(BAD_GATEWAY).await;
            return;
        }
        _ => {
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            let _ = stream.write_all(BAD_GATEWAY).await;
            return;
        }
    }

    // 5. 注入/覆盖 X-Forwarded-* 并写出请求头；随后补发已缓冲的 body 尾随字节。
    let head = build_head(method, path, version, req.headers, peer, proto);
    if qsend.write_all(&head).await.is_err() {
        return;
    }
    if head_end < buf.len() && qsend.write_all(&buf[head_end..]).await.is_err() {
        return;
    }

    // 6. 剩余字节双向透传（含半关闭）。
    copy_duplex(stream, qsend, qrecv).await;
}

/// 从流读取到 `\r\n\r\n`（或 `\n\n`）为止，返回头部结束位置（含终止符）。
/// 可能多读的 body 字节保留在 `buf` 中由调用方继续转发。
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Result<Option<usize>> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(pos) = find_header_end(buf) {
            return Ok(Some(pos));
        }
        if buf.len() >= MAX_HEAD_BYTES {
            anyhow::bail!("request head exceeds {MAX_HEAD_BYTES} bytes");
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

/// 从 Host 头剥离端口（`example.com:8080` → `example.com`），非数字端口部分不剥离。
fn host_for_lookup(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => host,
    }
}

/// 重建请求行 + 头，覆盖不可信客户端的 `X-Forwarded-For/Proto/Host`（§110）。
///
/// `Host` 等其余头原样保留；`X-Forwarded-For` 覆盖为真实客户端 IP（不追加，杜绝伪造）。
fn build_head(
    method: &str,
    path: &str,
    version: u8,
    headers: &[httparse::Header<'_>],
    peer: SocketAddr,
    proto: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.");
    out.push(b'0' + version);
    out.extend_from_slice(b"\r\n");

    let mut host: &[u8] = b"";
    for h in headers {
        match h.name.to_ascii_lowercase().as_str() {
            // 覆盖项：统一由下方注入，忽略客户端原值。
            "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" => continue,
            "host" => {
                host = h.value;
                out.extend_from_slice(b"Host: ");
                out.extend_from_slice(h.value);
                out.extend_from_slice(b"\r\n");
            }
            _ => {
                out.extend_from_slice(h.name.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(h.value);
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    out.extend_from_slice(b"X-Forwarded-For: ");
    out.extend_from_slice(peer.ip().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"X-Forwarded-Proto: ");
    out.extend_from_slice(proto.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"X-Forwarded-Host: ");
    out.extend_from_slice(host);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn build_head_injects_and_overrides_forwarded_headers() {
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"app.example.com",
            },
            httparse::Header {
                name: "X-Forwarded-For",
                value: b"1.2.3.4",
            },
            httparse::Header {
                name: "User-Agent",
                value: b"curl/8",
            },
        ];
        let peer: SocketAddr = "203.0.113.9:51234".parse().unwrap();
        let head = build_head("GET", "/x?q=1", 1, &headers, peer, "http");
        let s = String::from_utf8(head).unwrap();

        assert!(s.starts_with("GET /x?q=1 HTTP/1.1\r\n"), "head: {s:?}");
        assert!(s.contains("Host: app.example.com\r\n"));
        assert!(s.contains("User-Agent: curl/8\r\n"));
        assert!(s.contains("X-Forwarded-For: 203.0.113.9\r\n"));
        assert!(s.contains("X-Forwarded-Proto: http\r\n"));
        assert!(s.contains("X-Forwarded-Host: app.example.com\r\n"));
        // 客户端伪造的 X-Forwarded-For 被覆盖，不出现原值。
        assert!(!s.contains("1.2.3.4"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn host_for_lookup_strips_numeric_port_only() {
        assert_eq!(host_for_lookup("app.example.com"), "app.example.com");
        assert_eq!(host_for_lookup("app.example.com:8080"), "app.example.com");
        // 非数字端口不剥离。
        assert_eq!(
            host_for_lookup("app.example.com:http"),
            "app.example.com:http"
        );
    }

    #[test]
    fn find_header_end_detects_crlf_and_bare_lf() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Some(27)
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\nHost: a\n\n"), Some(24));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: a\r\n"), None);
    }
}
