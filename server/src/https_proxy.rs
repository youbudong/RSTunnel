//! HTTPS 数据面入口（T-27/T-28）：在 `https.bind` 上接受 TLS。
//!
//! 先窥探 ClientHello 的 SNI 判定：
//! - 匹配到 `tls_mode = 'passthrough'` 的 HTTPS 路由 → 不解密，按 SNI 透传原始 TLS（T-28）；
//! - 否则按 SNI 选证书（[`CertResolver`]）终止 TLS，把解密流交给 [`handle_http`]
//!   （Host 路由 + `X-Forwarded-*` 注入 + OPEN_TCP 透传），`X-Forwarded-Proto` 置为 `https`（T-27）。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::acl_store::AclStore;
use crate::certificate::{server_config, CertResolver, CertStore};
use crate::conn_limiter::ConnLimiter;
use crate::conn_registry::ConnRegistry;
use crate::http_proxy::handle_http;
use crate::route::HostTable;
use crate::tls_passthrough::{forward_passthrough, peek_sni, Prefixed};

/// 按 SNI 终止 TLS 的 HTTPS 反向入口（单监听，解密后按 Host 分发）。
pub struct HttpsProxy {
    acceptor: TlsAcceptor,
    host_table: Arc<HostTable>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
    addr: SocketAddr,
    listener: Arc<TcpListener>,
}

impl HttpsProxy {
    /// 绑定 `addr` 并构建 SNI 证书解析器（`run` 才进入接受循环）。
    pub async fn bind(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
        cert_store: Arc<CertStore>,
    ) -> Result<Self> {
        Self::bind_with_acl(
            addr,
            host_table,
            conns,
            cert_store,
            Arc::new(AclStore::new()),
        )
        .await
    }

    /// 同上，并共享数据面 ACL 判定器（T-34）。
    pub async fn bind_with_acl(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
        cert_store: Arc<CertStore>,
        acl: Arc<AclStore>,
    ) -> Result<Self> {
        Self::bind_with_acl_and_limiter(
            addr,
            host_table,
            conns,
            cert_store,
            acl,
            Arc::new(ConnLimiter::new()),
        )
        .await
    }

    /// 同上，并共享数据面 ACL 判定器与按 Route 的连接限速器（生产 main 用）。
    pub async fn bind_with_acl_and_limiter(
        addr: SocketAddr,
        host_table: Arc<HostTable>,
        conns: Arc<ConnRegistry>,
        cert_store: Arc<CertStore>,
        acl: Arc<AclStore>,
        conn_limiter: Arc<ConnLimiter>,
    ) -> Result<Self> {
        let resolver = CertResolver::new(cert_store);
        let acceptor = TlsAcceptor::from(Arc::new(server_config(resolver)));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind HTTPS listener {addr}"))?;
        let addr = listener.local_addr()?;
        Ok(Self {
            acceptor,
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
        let acceptor = self.acceptor.clone();
        let host_table = Arc::clone(&self.host_table);
        let conns = Arc::clone(&self.conns);
        let acl = Arc::clone(&self.acl);
        let conn_limiter = Arc::clone(&self.conn_limiter);
        tokio::spawn(async move {
            accept_loop(listener, acceptor, host_table, conns, acl, conn_limiter).await;
        });
    }
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    acceptor: TlsAcceptor,
    host_table: Arc<HostTable>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
) {
    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                let acceptor = acceptor.clone();
                let host_table = Arc::clone(&host_table);
                let conns = Arc::clone(&conns);
                let acl = Arc::clone(&acl);
                let conn_limiter = Arc::clone(&conn_limiter);
                tokio::spawn(async move {
                    // 窥探 ClientHello 的 SNI，判定透传还是终止（前缀字节必须原样重放）。
                    let (sni, prefix) = match peek_sni(&mut stream).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(%peer, error = %e, "peek tls clienthello failed");
                            return;
                        }
                    };
                    // T-28：匹配到 passthrough 路由 → 不解密透传。
                    if let Some(route) = sni
                        .as_deref()
                        .and_then(|s| host_table.lookup(s))
                        .filter(|r| r.tls_passthrough())
                    {
                        // T-34：passthrough 同样受数据面 ACL 约束（deny 源直接丢连接）。
                        if !acl.allows(route.id, &peer, &route.target_host, route.target_port) {
                            tracing::info!(route = %route.name, %peer, "https passthrough denied by ACL");
                            return;
                        }
                        let Some(conn) = conns.get(route.node_id) else {
                            tracing::warn!(route = %route.name, node = %route.node_id, "node offline");
                            return;
                        };
                        // T-35：passthrough 同样受连接数上限约束（守卫随连接存续）。
                        let _conn_guard =
                            match route.limits.as_ref().and_then(|l| l.max_connections) {
                                Some(max) => match conn_limiter.try_acquire(route.id, max) {
                                    Some(g) => Some(g),
                                    None => {
                                        tracing::info!(
                                            route = %route.name,
                                            max_connections = max,
                                            %peer,
                                            "route at connection limit"
                                        );
                                        return;
                                    }
                                },
                                None => None,
                            };
                        forward_passthrough(Prefixed::new(prefix, stream), conn, route, peer).await;
                        return;
                    }
                    // T-27：终止 TLS 后按 Host 路由。
                    match acceptor.accept(Prefixed::new(prefix, stream)).await {
                        Ok(tls) => {
                            handle_http(tls, host_table, conns, acl, conn_limiter, peer, "https")
                                .await
                        }
                        Err(e) => {
                            // 无匹配证书（未知 SNI）或握手失败——丢弃连接。
                            tracing::debug!(%peer, error = %e, "tls handshake failed");
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "https accept error");
                break;
            }
        }
    }
}
