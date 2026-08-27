//! TCP 数据面入口（T-14/T-15/T-19）：按 Route 的 `listen_host:listen_port` 绑定监听，接受连接后
//! 匹配到对应 Route，通过该 Node 的 QUIC 连接打开双向流，正向发送 OPEN_TCP 帧，随后双向转发
//! 原始字节（设计文档 §8.2/§82/§84）。
//!
//! 热更新（T-19）：[`TcpProxy::reconcile`] 按新路由表增删监听——改 target/node 对已建立连接
//! 透明（它们持有各自打开的流），新连接经 [`RouteTable`] 每次接受时查最新路由；删除/禁用走
//! drain（停接受 → 等活跃连接归零 → 解绑，设计文档 §139）。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::acl_store::AclStore;
use crate::conn_limiter::ConnLimiter;
use crate::conn_registry::ConnRegistry;
use crate::frame_io::{read_frame, write_frame};
use crate::route::{RouteTable, ServerRoute};
use tunnel_core::RouteId;
use tunnel_protocol::{Message, OpenTcpPayload, RouteType};

/// drain 等待活跃连接归零的最大时长；超时则强制解绑（记录告警）。
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// 一条已绑定监听：实际绑定地址、drain 信号与活动连接计数。
struct BoundListener {
    route_id: RouteId,
    addr: SocketAddr,
    listener: Arc<TcpListener>,
    /// drain 信号：置 `true` 时接受循环停止（停止接受新连接）。
    drain_tx: watch::Sender<bool>,
    /// 该监听上仍活跃的连接数（drain 时等它归零）。
    active: Arc<AtomicU64>,
}

/// 连接活动计数守卫：`drop` 时递减，用于 drain 时等待活跃连接归零。
struct ActiveGuard(Arc<AtomicU64>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
        // T-38：活跃数据面流数随连接结束递减。
        if let Some(g) = tunnel_metrics::streams_active() {
            g.dec();
        }
    }
}

/// 接受循环的共享上下文（TcpProxy 级，跨监听共享）。
struct AcceptContext {
    routes: Arc<RouteTable>,
    accepted: Arc<AtomicU64>,
    conns: Arc<ConnRegistry>,
    acl: Arc<AclStore>,
    conn_limiter: Arc<ConnLimiter>,
}

/// 聚合所有 Route 的 TCP 监听。接受连接后经 Node 的 QUIC 连接转发到内网目标。
pub struct TcpProxy {
    routes: Arc<RouteTable>,
    listeners: DashMap<SocketAddr, BoundListener>,
    accepted: Arc<AtomicU64>,
    conns: Arc<ConnRegistry>,
    /// 数据面 ACL 判定器（空 = 放行所有连接）。
    acl: Arc<AclStore>,
    /// 按 Route 的并发连接限速器（T-35：`limits.max_connections`）。
    conn_limiter: Arc<ConnLimiter>,
}

impl TcpProxy {
    /// 从 Route 表绑定全部「启用的 TCP」监听（使用独立的空连接注册表与空 ACL，见 [`Self::bind_with_conns`]）。
    pub async fn bind(routes: Arc<RouteTable>) -> Result<Self> {
        Self::bind_with_conns(routes, Arc::new(ConnRegistry::new())).await
    }

    /// 从 Route 表绑定全部「启用的 TCP」监听，并用共享的 [`ConnRegistry`] 解析 Node 连接。
    /// 重复监听冲突已由 [`RouteTable::insert`] 拦截。
    pub async fn bind_with_conns(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
    ) -> Result<Self> {
        Self::bind_with_conns_and_acl(routes, conns, Arc::new(AclStore::new())).await
    }

    /// 同上，并共享数据面 ACL 判定器（T-34：deny 源在转发前被拒）。
    pub async fn bind_with_conns_and_acl(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
        acl: Arc<AclStore>,
    ) -> Result<Self> {
        Self::bind_with_conns_acl_and_limiter(routes, conns, acl, Arc::new(ConnLimiter::new()))
            .await
    }

    /// 同上，并共享数据面 ACL 判定器与按 Route 的连接限速器（生产 main 用）。
    pub async fn bind_with_conns_acl_and_limiter(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
        acl: Arc<AclStore>,
        conn_limiter: Arc<ConnLimiter>,
    ) -> Result<Self> {
        let listeners = DashMap::new();
        for route in routes
            .routes()
            .into_iter()
            .filter(|r| r.enabled && r.route_type == RouteType::Tcp)
        {
            let bound = bind_listener((*route).clone()).await?;
            listeners.insert(bound.addr, bound);
        }
        Ok(Self {
            routes,
            listeners,
            accepted: Arc::new(AtomicU64::new(0)),
            conns,
            acl,
            conn_limiter,
        })
    }

    /// 各 Route 的实际绑定地址（供测试/日志观察）。
    pub fn local_addrs(&self) -> Vec<(RouteId, SocketAddr)> {
        self.listeners
            .iter()
            .map(|b| (b.value().route_id, b.value().addr))
            .collect()
    }

    /// 已接受且匹配到 Route 的连接数。
    pub fn accepted_count(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// 启动接受循环（每 Route 一个任务），直到进程退出。
    pub fn run(&self) {
        for bound in self.listeners.iter() {
            self.spawn_accept_loop(bound.value());
        }
    }

    /// 热更新（T-19）：按新路由表 reconcile 监听——新增绑定、删除/禁用走 drain、改动更新路由表条目。
    ///
    /// `new_routes` 为该 Server 的全量期望路由（含禁用）；仅「启用的 TCP」会绑定监听。
    pub async fn reconcile(&self, new_routes: &[ServerRoute]) -> Result<()> {
        let mut desired: HashMap<SocketAddr, ServerRoute> = HashMap::new();
        for r in new_routes
            .iter()
            .filter(|r| r.enabled && r.route_type == RouteType::Tcp)
        {
            let addr = r.listen_addr()?;
            desired.insert(addr, r.clone());
        }

        let current: HashSet<SocketAddr> = self.listeners.iter().map(|e| *e.key()).collect();
        let desired_set: HashSet<SocketAddr> = desired.keys().copied().collect();

        let to_remove: Vec<SocketAddr> = current.difference(&desired_set).copied().collect();
        let to_update: Vec<SocketAddr> = current.intersection(&desired_set).copied().collect();
        let to_add: Vec<SocketAddr> = desired_set.difference(&current).copied().collect();

        // 1. 删除/禁用：停止接受新连接 → 等活跃连接归零 → 解绑并移除路由条目。
        for addr in to_remove {
            self.drain_listener(addr).await?;
            self.routes.remove(&addr);
        }

        // 2. 改动（listen 不变，target/node 等变化）：替换路由表条目，新建接即用新配置。
        for addr in to_update {
            if let Some(new_route) = desired.get(&addr) {
                self.routes.remove(&addr);
                if let Err(e) = self.routes.insert(new_route.clone()) {
                    tracing::warn!(%addr, error = %e, "update route table entry failed");
                }
            }
        }

        // 3. 新增：绑定监听并启动接受循环。
        for addr in to_add {
            let route = desired
                .get(&addr)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing desired route {addr}"))?;
            self.routes
                .insert(route.clone())
                .map_err(|e| anyhow::anyhow!("insert route {addr}: {e}"))?;
            let bound = bind_listener(route).await?;
            self.spawn_accept_loop(&bound);
            let addr = bound.addr;
            self.listeners.insert(addr, bound);
        }

        Ok(())
    }

    /// 停止某监听的接受循环，等待其活跃连接归零（drain），并解绑。
    async fn drain_listener(&self, addr: SocketAddr) -> Result<()> {
        let Some((_, bound)) = self.listeners.remove(&addr) else {
            return Ok(());
        };
        // 停止接受新连接。
        let _ = bound.drain_tx.send(true);
        // 等活跃连接归零（超时则强制解绑）。
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        while bound.active.load(Ordering::Relaxed) > 0 {
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    %addr,
                    active = bound.active.load(Ordering::Relaxed),
                    "drain timed out; force-unbinding listener"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tracing::info!(%addr, "listener drained");
        Ok(())
    }

    /// 为一条已绑定监听启动接受循环。
    fn spawn_accept_loop(&self, bound: &BoundListener) {
        let listener = Arc::clone(&bound.listener);
        let addr = bound.addr;
        let active = Arc::clone(&bound.active);
        let ctx = AcceptContext {
            routes: Arc::clone(&self.routes),
            accepted: Arc::clone(&self.accepted),
            conns: Arc::clone(&self.conns),
            acl: Arc::clone(&self.acl),
            conn_limiter: Arc::clone(&self.conn_limiter),
        };
        // 克隆 sender 并随任务存活：drain 只能由显式 `drain_listener` 触发，而非监听器
        //（或整个 proxy）被 drop 时 sender 销毁导致 `changed()` 返回 Err、接受循环意外退出。
        let drain_tx = bound.drain_tx.clone();
        let drain_rx = drain_tx.subscribe();
        tokio::spawn(async move {
            let _drain_tx = drain_tx;
            accept_loop(listener, addr, active, drain_rx, ctx).await;
        });
    }
}

/// 绑定单个 Route 的监听并构造 [`BoundListener`]。
async fn bind_listener(route: ServerRoute) -> Result<BoundListener> {
    let addr = route.listen_addr()?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind TCP listener for route {}", route.name))?;
    let addr = listener.local_addr()?;
    let (drain_tx, _) = watch::channel(false);
    Ok(BoundListener {
        route_id: route.id,
        addr,
        listener: Arc::new(listener),
        drain_tx,
        active: Arc::new(AtomicU64::new(0)),
    })
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    addr: SocketAddr,
    active: Arc<AtomicU64>,
    mut drain_rx: watch::Receiver<bool>,
    ctx: AcceptContext,
) {
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        // 每次接受都查最新路由（热更新：改 target/node 对新建接生效）。
                        let Some(route) = ctx.routes.lookup(&addr) else {
                            tracing::debug!(%addr, %peer, "route removed; dropping inbound connection");
                            if let Some(c) = tunnel_metrics::route_errors_total() {
                                c.inc();
                            }
                            drop(stream);
                            continue;
                        };
                        // T-34：数据面 ACL——deny 的源在转发前被拒（未配置则放行）。
                        if !ctx.acl.allows(route.id, &peer, &route.target_host, route.target_port) {
                            tracing::info!(
                                route = %route.name,
                                %peer,
                                "tcp connection denied by ACL"
                            );
                            drop(stream);
                            continue;
                        }
                        tracing::info!(
                            route = %route.name,
                            target = %format!("{}:{}", route.target_host, route.target_port),
                            %peer,
                            "tcp connection matched route"
                        );
                        ctx.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Some(c) = tunnel_metrics::connections_total() {
                            c.inc();
                        }

                        let Some(conn) = ctx.conns.get(route.node_id) else {
                            tracing::warn!(
                                route = %route.name,
                                node = %route.node_id,
                                "node offline; dropping inbound connection"
                            );
                            if let Some(c) = tunnel_metrics::connections_failed() {
                                c.inc();
                            }
                            if let Some(c) = tunnel_metrics::route_errors_total() {
                                c.inc();
                            }
                            drop(stream);
                            continue;
                        };

                        // T-35：单 Route 连接数上限（limits.max_connections，None = 不限）。
                        let conn_guard = match route.limits.as_ref().and_then(|l| l.max_connections) {
                            Some(max) => match ctx.conn_limiter.try_acquire(route.id, max) {
                                Some(g) => Some(g),
                                None => {
                                    tracing::warn!(
                                        route = %route.name,
                                        max_connections = max,
                                        %peer,
                                        "route at connection limit; dropping inbound connection"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            },
                            None => None,
                        };

                        active.fetch_add(1, Ordering::Relaxed);
                        if let Some(g) = tunnel_metrics::streams_active() {
                            g.inc();
                        }
                        let active = Arc::clone(&active);
                        tokio::spawn(async move {
                            let _guard = ActiveGuard(active);
                            // 连接存续期间持有额度；连接结束（task 退出）自动释放。
                            let _conn_guard = conn_guard;
                            forward_tcp(stream, conn, route, peer).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%addr, error = %e, "tcp accept error");
                        break;
                    }
                }
            }
            _ = drain_rx.changed() => {
                tracing::debug!(%addr, "drain signal received; stopping accept loop");
                break;
            }
        }
    }
}

/// 单条入向 TCP 连接的转发：打开双向流 → 发 OPEN_TCP → 读 OPEN_OK/OPEN_FAIL → 双向拷贝。
async fn forward_tcp(
    tcp: tokio::net::TcpStream,
    conn: quinn::Connection,
    route: Arc<ServerRoute>,
    peer: SocketAddr,
) {
    let (mut qsend, mut qrecv) = match conn.open_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::warn!(route = %route.name, error = %e, "open bidi stream failed");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            return;
        }
    };

    // 1. 正向 OPEN_TCP（携带目标地址与客户端来源）。
    let msg = Message::OpenTcp(OpenTcpPayload {
        route_id: route.id,
        target_host: route.target_host.clone(),
        target_port: route.target_port,
        client_addr: Some(peer.to_string()),
    });
    if let Err(e) = send_message(&mut qsend, msg, 0).await {
        tracing::warn!(route = %route.name, error = %e, "send OPEN_TCP failed");
        if let Some(c) = tunnel_metrics::connections_failed() {
            c.inc();
        }
        return;
    }

    // 2. 读首帧：OPEN_OK 继续，OPEN_FAIL（目标不可达等）终止。
    match read_frame(&mut qrecv).await {
        Ok(Some(frame)) => match Message::from_frame(&frame) {
            Ok(Message::OpenOk(_)) => {}
            Ok(Message::OpenFail(p)) => {
                tracing::warn!(
                    route = %route.name,
                    code = %p.code,
                    message = %p.message,
                    "agent failed to open target"
                );
                if let Some(c) = tunnel_metrics::connections_failed() {
                    c.inc();
                }
                if let Some(c) = tunnel_metrics::route_errors_total() {
                    c.inc();
                }
                return;
            }
            Ok(other) => {
                tracing::warn!(route = %route.name, frame = ?other, "unexpected first data frame");
                if let Some(c) = tunnel_metrics::connections_failed() {
                    c.inc();
                }
                return;
            }
            Err(e) => {
                tracing::warn!(route = %route.name, error = %e, "decode first data frame");
                if let Some(c) = tunnel_metrics::connections_failed() {
                    c.inc();
                }
                return;
            }
        },
        Ok(None) => {
            tracing::debug!(route = %route.name, "data stream closed before OPEN_OK");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            return;
        }
        Err(e) => {
            tracing::warn!(route = %route.name, error = %e, "read OPEN_OK/OPEN_FAIL");
            if let Some(c) = tunnel_metrics::connections_failed() {
                c.inc();
            }
            return;
        }
    }

    // 3. 双向拷贝（含半关闭：读毕即 finish/关闭写端）。
    copy_duplex(tcp, qsend, qrecv).await;
}

/// 双向转发：客户端流 ↔ QUIC 流，读毕即向对端传达半关闭。
///
/// 对 `S` 泛化：TCP 数据面传 [`tokio::net::TcpStream`]，HTTP/TLS 数据面复用
/// （`TcpStream` 或 `tokio_rustls::server::TlsStream`）。
pub(crate) async fn copy_duplex<S>(
    stream: S,
    mut qsend: quinn::SendStream,
    mut qrecv: quinn::RecvStream,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut r, mut w) = tokio::io::split(stream);

    let to_quic = async move {
        let n = tokio::io::copy(&mut r, &mut qsend).await;
        // 客户端读毕（FIN）：finish 通知 Agent 本次发送结束。
        let _ = qsend.finish();
        n
    };
    let from_quic = async move {
        let n = tokio::io::copy(&mut qrecv, &mut w).await;
        // QUIC 读毕（Agent finish/关闭）：关闭客户端写端。
        let _ = w.shutdown().await;
        n
    };

    let (a, b) = tokio::join!(to_quic, from_quic);
    // T-38：字节计数——客户端→Server（received）与 Server→客户端（sent）。
    match a {
        Ok(n) => {
            if let Some(c) = tunnel_metrics::bytes_received_total() {
                c.inc_by(n);
            }
        }
        Err(e) => tracing::debug!(error = %e, "stream->quic copy error"),
    }
    match b {
        Ok(n) => {
            if let Some(c) = tunnel_metrics::bytes_sent_total() {
                c.inc_by(n);
            }
        }
        Err(e) => tracing::debug!(error = %e, "quic->stream copy error"),
    }
}

/// 组帧并写入数据流。
pub(crate) async fn send_message(
    send: &mut quinn::SendStream,
    msg: Message,
    request_id: u64,
) -> Result<()> {
    let frame = msg.into_frame(request_id)?;
    write_frame(send, &frame).await
}
