//! UDP 数据面入口（T-30）：按 Route 的 `listen_host:listen_port` 绑定 UDP 监听，收到客户端
//! datagram 后按 `(client_addr, route_id)` 建立逻辑 UDP 会话（分配 `udp_session_id`，经控制流
//! 发 `UDP_OPEN` 通知 Agent），再把每个 UDP 包封装进 QUIC Datagram 转发；反向（Agent→客户端）
//! 由每连接一个的 datagram 读取任务解封装后写回对应客户端 socket。空闲会话超时回收并 `UDP_CLOSE`
//! （设计文档 §5/§13/§54）。
//!
//! 源地址欺骗/反射防护的限速（T-31）与超大包计数（T-32 部分）在同一数据面落地：超过
//! `max_datagram_size`（默认 1200，含 10 字节头）的 UDP 包在此丢弃并计数，不静默截断。

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use tunnel_core::RouteId;
use tunnel_protocol::{
    decode_udp_datagram, encode_udp_datagram, Message, RouteType, UdpClosePayload, UdpOpenPayload,
    UDP_DATAGRAM_HEADER_LEN,
};

use crate::config_sync::ConfigSync;
use crate::conn_registry::ConnRegistry;
use crate::route::{RouteTable, ServerRoute};

/// 单个 UDP 会话的空闲超时（设计文档 §3462：UDP idle timeout 60s）。
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 会话回收扫描周期。
const REAP_INTERVAL: Duration = Duration::from_secs(10);
/// v1 不做分片：UDP payload 超过该上限即丢弃并计数（设计文档 §5，`max_datagram_size` 默认 1200）。
const MAX_UDP_PAYLOAD: usize = 1200;

/// T-32：计算单个 UDP 包允许的最大 payload 字节数。
///
/// 取「对端 `max_datagram_size − 10 字节头」与默认上限 1200 的较小者；对端未告知
/// （`None`）时返回 0，即拒绝转发任何 payload。
fn max_payload(peer_max: Option<usize>) -> usize {
    peer_max
        .map(|m| {
            m.saturating_sub(UDP_DATAGRAM_HEADER_LEN)
                .min(MAX_UDP_PAYLOAD)
        })
        .unwrap_or(0)
}

/// UDP 反射/源地址欺骗防护限速参数（T-31，设计文档 §17/§54）。
///
/// 公网 UDP 监听可被用于反射放大：伪造源 IP 发包让 Server→Agent→内网目标回包打到受害者。
/// 对「每个源 IP」独立限速，超限丢弃并计数，阻断无界会话/转发。
#[derive(Debug, Clone, Copy)]
pub struct UdpRateLimits {
    /// 单源 IP 最大并发逻辑会话数。
    pub max_sessions_per_ip: u32,
    /// 单源 IP 最大发包速率（包/秒）。
    pub max_packets_per_sec: u64,
    /// 单源 IP 最大字节速率（字节/秒）。
    pub max_bytes_per_sec: u64,
}

impl Default for UdpRateLimits {
    fn default() -> Self {
        Self {
            max_sessions_per_ip: 64,
            max_packets_per_sec: 1_000,
            max_bytes_per_sec: 1_000_000,
        }
    }
}

/// 简单令牌桶：`capacity` 为桶深，`refill_per_sec` 为每秒补充速率。按需补充后尝试扣除 `n` 个令牌。
struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last: Instant::now(),
        }
    }

    /// 尝试扣 `n` 个令牌；成功返回 true。补充量随 `now` 单调递增累积（`saturating` 防回拨 panic）。
    fn try_take(&mut self, n: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// 单源 IP 的限速状态：并发会话数 + 发包/字节令牌桶（T-31）。
struct SourceRateState {
    sessions: AtomicU32,
    packets: Mutex<TokenBucket>,
    bytes: Mutex<TokenBucket>,
}

impl SourceRateState {
    fn new(limits: &UdpRateLimits) -> Self {
        Self {
            sessions: AtomicU32::new(0),
            packets: Mutex::new(TokenBucket::new(
                limits.max_packets_per_sec as f64,
                limits.max_packets_per_sec as f64,
            )),
            bytes: Mutex::new(TokenBucket::new(
                limits.max_bytes_per_sec as f64,
                limits.max_bytes_per_sec as f64,
            )),
        }
    }
}

/// 会话键：`(客户端地址, 路由)` —— 同一客户端对同一 UDP 路由复用一个逻辑会话（§54）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    client: SocketAddr,
    route: RouteId,
}

/// 一条逻辑 UDP 会话：Server 分配的 `session_id` 关联「客户端 socket」与「Agent 的 QUIC datagram」。
struct UdpSession {
    session_id: u64,
    route: Arc<ServerRoute>,
    client: SocketAddr,
    socket: Arc<UdpSocket>,
    last_active: Mutex<Instant>,
}

impl UdpSession {
    fn touch(&self) {
        if let Ok(mut g) = self.last_active.lock() {
            *g = Instant::now();
        }
    }

    /// 距 `now` 已空闲的时长（供超时回收判断；`last_active` 恒为过去，故用 `saturating` 防 panic）。
    fn idle_for(&self, now: Instant) -> Option<Duration> {
        self.last_active
            .lock()
            .ok()
            .map(|g| now.saturating_duration_since(*g))
    }
}

/// 一条已绑定的 UDP 监听（实际绑定地址 + socket）。
struct BoundListener {
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
}

/// 聚合所有 Route 的 UDP 监听与逻辑会话。客户端 datagram ↔ QUIC datagram 转发。
pub struct UdpProxy {
    routes: Arc<RouteTable>,
    conns: Arc<ConnRegistry>,
    config_sync: Arc<ConfigSync>,
    listeners: DashMap<SocketAddr, BoundListener>,
    /// 正向映射：`(client, route) → session`（收包时查/建会话）。
    sessions: DashMap<SessionKey, Arc<UdpSession>>,
    /// 反向映射：`session_id → session`（datagram 读取任务按此分发到客户端）。
    by_id: DashMap<u64, Arc<UdpSession>>,
    next_session_id: AtomicU64,
    /// 因超过 `max_datagram_size` 被丢弃的 UDP 包计数（T-32）。
    dropped_oversized: AtomicU64,
    /// T-31：因发包/字节速率超限被丢弃的包计数。
    dropped_rate_limited: AtomicU64,
    /// T-31：因源 IP 会话数超限被丢弃的包计数。
    dropped_session_limited: AtomicU64,
    /// T-31：单源 IP 限速参数。
    rate_limits: UdpRateLimits,
    /// T-31：按源 IP 的限速状态（会话计数 + 令牌桶）。
    sources: DashMap<IpAddr, SourceRateState>,
    idle_timeout: Duration,
}

impl UdpProxy {
    /// 从 Route 表绑定全部「启用的 UDP」监听（默认空闲超时）。
    pub async fn bind(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
        config_sync: Arc<ConfigSync>,
    ) -> Result<Self> {
        Self::bind_with_timeout(routes, conns, config_sync, UDP_IDLE_TIMEOUT).await
    }

    /// 同上，但可覆盖空闲超时（测试用短超时验证会话回收）。
    pub async fn bind_with_timeout(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
        config_sync: Arc<ConfigSync>,
        idle_timeout: Duration,
    ) -> Result<Self> {
        Self::bind_with_limits(
            routes,
            conns,
            config_sync,
            idle_timeout,
            UdpRateLimits::default(),
        )
        .await
    }

    /// 完整构造：可覆盖空闲超时与限速参数（T-31 测试用极小限速验证丢弃/计数）。
    pub async fn bind_with_limits(
        routes: Arc<RouteTable>,
        conns: Arc<ConnRegistry>,
        config_sync: Arc<ConfigSync>,
        idle_timeout: Duration,
        rate_limits: UdpRateLimits,
    ) -> Result<Self> {
        let listeners = DashMap::new();
        for route in routes
            .routes()
            .into_iter()
            .filter(|r| r.enabled && r.route_type == RouteType::Udp)
        {
            let addr = route.listen_addr()?;
            let socket = UdpSocket::bind(addr)
                .await
                .with_context(|| format!("bind UDP listener for route {}", route.name))?;
            let addr = socket.local_addr()?;
            listeners.insert(
                addr,
                BoundListener {
                    addr,
                    socket: Arc::new(socket),
                },
            );
        }
        Ok(Self {
            routes,
            conns,
            config_sync,
            listeners,
            sessions: DashMap::new(),
            by_id: DashMap::new(),
            next_session_id: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_session_limited: AtomicU64::new(0),
            rate_limits,
            sources: DashMap::new(),
            idle_timeout,
        })
    }

    /// 各 Route 的实际绑定地址（供测试/日志观察）。
    pub fn local_addrs(&self) -> Vec<(RouteId, SocketAddr)> {
        // 绑定地址按 route 排序以便确定性输出；route id 由 sessions 之外的单例 routes 反查。
        let mut addrs: Vec<(RouteId, SocketAddr)> = self
            .listeners
            .iter()
            .filter_map(|b| {
                let route = self.routes.lookup(&b.value().addr)?;
                Some((route.id, b.value().addr))
            })
            .collect();
        addrs.sort_by_key(|(id, _)| *id);
        addrs
    }

    /// 已丢弃的超大 UDP 包计数（T-32 观测）。
    pub fn dropped_oversized(&self) -> u64 {
        self.dropped_oversized.load(Ordering::Relaxed)
    }

    /// 因发包/字节速率超限被丢弃的包计数（T-31 观测）。
    pub fn dropped_rate_limited(&self) -> u64 {
        self.dropped_rate_limited.load(Ordering::Relaxed)
    }

    /// 因源 IP 会话数超限被丢弃的包计数（T-31 观测）。
    pub fn dropped_session_limited(&self) -> u64 {
        self.dropped_session_limited.load(Ordering::Relaxed)
    }

    /// 当前活跃逻辑会话数（供测试/日志观察）。
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// 启动收包循环（每监听一个任务）+ 会话回收任务，直到进程退出。
    pub fn run(self: &Arc<Self>) {
        for bound in self.listeners.iter() {
            let this = Arc::clone(self);
            let socket = Arc::clone(&bound.value().socket);
            let addr = bound.value().addr;
            tokio::spawn(async move {
                this.recv_loop(socket, addr).await;
            });
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.reap_loop().await;
        });
    }

    /// 为一条 Agent QUIC 连接启动 datagram 读取任务（Agent→客户端方向）。连接关闭时 `read_datagram`
    /// 返回错误，循环自然退出。
    pub fn spawn_datagram_reader(self: &Arc<Self>, conn: quinn::Connection) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(bytes) => this.handle_datagram(&bytes).await,
                    Err(e) => {
                        tracing::debug!(error = %e, "datagram read closed");
                        return;
                    }
                }
            }
        });
    }

    /// 单监听收包循环：客户端 datagram → 建/查会话 → 封装 → QUIC datagram。
    async fn recv_loop(&self, socket: Arc<UdpSocket>, addr: SocketAddr) {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, client) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "udp recv error");
                    return;
                }
            };
            self.forward_to_agent(&socket, addr, client, &buf[..n])
                .await;
        }
    }

    /// 把一段客户端 UDP 载荷转发到 Agent。
    async fn forward_to_agent(
        &self,
        socket: &Arc<UdpSocket>,
        addr: SocketAddr,
        client: SocketAddr,
        payload: &[u8],
    ) {
        // 每次收包都查最新路由（热更新：改 target/node 对新建会话生效）。
        let Some(route) = self.routes.lookup(&addr) else {
            tracing::debug!(%addr, %client, "route removed; dropping udp packet");
            return;
        };
        let Some(conn) = self.conns.get(route.node_id) else {
            tracing::warn!(route = %route.name, node = %route.node_id, "node offline; dropping udp packet");
            return;
        };
        // T-32：超大包判定——超过「对端可用 datagram 上限 − 头」与默认 1200 的较小者即丢弃。
        // 放在限速/建会话之前，避免为注定丢弃的包建会话或消耗限速令牌。
        let cap = max_payload(conn.max_datagram_size());
        if payload.len() > cap {
            self.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                route = %route.name,
                len = payload.len(),
                cap,
                "udp packet exceeds max_datagram_size; dropped"
            );
            return;
        }
        // T-31：反射防护——先按源 IP 限速/限会话；超限（含未建会话的伪造源）在此丢弃并计数，
        // 不建会话、不转发。
        if !self.admit_packet(&route, client, payload.len()) {
            return;
        }
        let session = self.get_or_create_session(socket, &route, client);

        let data = encode_udp_datagram(session.session_id, payload);
        if let Err(e) = conn.send_datagram(data.into()) {
            tracing::debug!(session = session.session_id, error = %e, "send datagram failed");
            return;
        }
        // T-38：成功转发到 Agent 的 UDP 包计数。
        if let Some(c) = tunnel_metrics::udp_packets_total() {
            c.inc();
        }
        session.touch();
    }

    /// T-31 反射防护：按源 IP 做会话数 / 发包速率 / 字节速率限速。返回 false 表示已丢弃
    /// （调用方不再建会话、不再转发），并已计入对应计数器。
    ///
    /// 会话数上限只约束「将新建会话」的包（已建会话的包不受限，避免长连接被误杀）；发包与
    /// 字节速率对每个包（含已建会话）都生效，从总量上压制反射放大。
    fn admit_packet(
        &self,
        route: &Arc<ServerRoute>,
        client: SocketAddr,
        payload_len: usize,
    ) -> bool {
        let limits = self.rate_limits;
        let now = Instant::now();
        let ip = client.ip();

        // 会话数限速：仅对「无对应会话」的包生效。
        let key = SessionKey {
            client,
            route: route.id,
        };
        if !self.sessions.contains_key(&key) {
            let sessions = self
                .sources
                .get(&ip)
                .map(|s| s.sessions.load(Ordering::Relaxed))
                .unwrap_or(0);
            if sessions >= limits.max_sessions_per_ip {
                self.dropped_session_limited.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%ip, sessions, max = limits.max_sessions_per_ip, "udp session limit exceeded; dropping packet");
                return false;
            }
        }

        // 发包速率 + 字节速率：任一超限即丢（令牌桶；锁中毒时 fail-closed 视为超限）。
        let state = self
            .sources
            .entry(ip)
            .or_insert_with(|| SourceRateState::new(&limits));
        let pps_ok = state
            .packets
            .lock()
            .map(|mut b| b.try_take(1.0, now))
            .unwrap_or(false);
        let bps_ok = state
            .bytes
            .lock()
            .map(|mut b| b.try_take(payload_len as f64, now))
            .unwrap_or(false);
        if !pps_ok || !bps_ok {
            self.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%ip, route = %route.name, "udp rate limit exceeded; dropping packet");
            return false;
        }

        true
    }

    /// 取 `(client, route)` 对应会话，不存在则分配 `session_id` 并 `UDP_OPEN` 通知 Agent。
    fn get_or_create_session(
        &self,
        socket: &Arc<UdpSocket>,
        route: &Arc<ServerRoute>,
        client: SocketAddr,
    ) -> Arc<UdpSession> {
        let key = SessionKey {
            client,
            route: route.id,
        };
        if let Some(s) = self.sessions.get(&key) {
            return s.value().clone();
        }
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(UdpSession {
            session_id,
            route: Arc::clone(route),
            client,
            socket: Arc::clone(socket),
            last_active: Mutex::new(Instant::now()),
        });
        self.sessions.insert(key, session.clone());
        self.by_id.insert(session_id, session.clone());
        // T-31：递增该源 IP 的会话计数（若在 admit 与 create 之间被 reap 回收则重建，计数仍正确）。
        let limits = self.rate_limits;
        self.sources
            .entry(client.ip())
            .or_insert_with(|| SourceRateState::new(&limits))
            .sessions
            .fetch_add(1, Ordering::Relaxed);
        // 控制流通知 Agent 建会话（复用配置推送通道，按序送达）。
        self.config_sync.push_message(
            route.node_id,
            Message::UdpOpen(UdpOpenPayload {
                route_id: route.id,
                udp_session_id: session_id,
                client_addr: client.to_string(),
            }),
        );
        session
    }

    /// 处理一条来自 Agent 的 datagram（Agent→客户端）：解封装 → 写回客户端 socket。
    async fn handle_datagram(&self, data: &[u8]) {
        let Some(dg) = decode_udp_datagram(data) else {
            tracing::debug!("undecodable udp datagram");
            return;
        };
        let Some(session) = self.by_id.get(&dg.session_id).map(|e| e.value().clone()) else {
            tracing::debug!(session = dg.session_id, "unknown udp session");
            return;
        };
        if session
            .socket
            .send_to(dg.payload, session.client)
            .await
            .is_err()
        {
            tracing::debug!(session = dg.session_id, client = %session.client, "send to client failed");
        }
        session.touch();
    }

    /// 周期回收空闲会话（`UDP_CLOSE` 通知 Agent 关闭其本地 socket）。
    async fn reap_loop(&self) {
        loop {
            tokio::time::sleep(REAP_INTERVAL).await;
            self.reap_expired();
        }
    }

    fn reap_expired(&self) {
        let now = Instant::now();
        let mut expired: Vec<Arc<UdpSession>> = Vec::new();
        for entry in self.sessions.iter() {
            let s = entry.value();
            if let Some(idle) = s.idle_for(now) {
                if idle > self.idle_timeout {
                    expired.push(s.clone());
                }
            }
        }
        for s in expired {
            let key = SessionKey {
                client: s.client,
                route: s.route.id,
            };
            self.sessions.remove(&key);
            self.by_id.remove(&s.session_id);
            // T-31：递减该源 IP 的会话计数（`checked_sub` 防下溢，仅在极端竞态时保守不动作）。
            if let Some(state) = self.sources.get(&s.client.ip()) {
                let _ = state
                    .sessions
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
            }
            self.config_sync.push_message(
                s.route.node_id,
                Message::UdpClose(UdpClosePayload {
                    udp_session_id: s.session_id,
                }),
            );
            tracing::info!(session = s.session_id, client = %s.client, "udp session expired");
        }

        // T-31：回收「无活跃会话」的源 IP 状态，防止伪造源 IP 无限累积（有会话的保留）。
        self.sources
            .retain(|_, state| state.sessions.load(Ordering::Relaxed) > 0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn route(id: u128, listen: &str, port: u16) -> ServerRoute {
        ServerRoute {
            id: RouteId::from_u128(id),
            name: format!("udp-{id}"),
            route_type: RouteType::Udp,
            enabled: true,
            node_id: tunnel_core::NodeId::from_u128(id + 1000),
            listen_host: listen.to_string(),
            listen_port: port,
            target_host: "192.168.1.100".to_string(),
            target_port: 53,
            hostname: None,
            tls_mode: None,
            limits: None,
        }
    }

    /// 构造一个不带监听的 `UdpProxy`（测试直接操作会话表，不跑真实收包）。
    fn proxy_with_limits(idle_timeout: Duration, rate_limits: UdpRateLimits) -> Arc<UdpProxy> {
        Arc::new(UdpProxy {
            routes: Arc::new(RouteTable::new()),
            conns: Arc::new(ConnRegistry::new()),
            config_sync: Arc::new(ConfigSync::new()),
            listeners: DashMap::new(),
            sessions: DashMap::new(),
            by_id: DashMap::new(),
            next_session_id: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_session_limited: AtomicU64::new(0),
            rate_limits,
            sources: DashMap::new(),
            idle_timeout,
        })
    }

    fn proxy_with_timeout(idle_timeout: Duration) -> Arc<UdpProxy> {
        proxy_with_limits(idle_timeout, UdpRateLimits::default())
    }

    /// 手工插入一条会话，`last_active` 由调用方指定（供回收逻辑验证）。
    async fn insert_session(
        proxy: &UdpProxy,
        session_id: u64,
        route: Arc<ServerRoute>,
        last_active: Instant,
    ) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let session = Arc::new(UdpSession {
            session_id,
            route: Arc::clone(&route),
            client: "127.0.0.1:9000".parse().unwrap(),
            socket,
            last_active: Mutex::new(last_active),
        });
        let key = SessionKey {
            client: "127.0.0.1:9000".parse().unwrap(),
            route: route.id,
        };
        proxy.sessions.insert(key, session.clone());
        proxy.by_id.insert(session_id, session);
    }

    #[tokio::test]
    async fn reap_expired_removes_stale_session() {
        let proxy = proxy_with_timeout(Duration::from_secs(60));
        let route = Arc::new(route(1, "127.0.0.1", 5353));
        insert_session(&proxy, 1, route, Instant::now() - Duration::from_secs(120)).await;
        assert_eq!(proxy.session_count(), 1);

        proxy.reap_expired();

        assert_eq!(proxy.session_count(), 0);
        assert!(proxy.by_id.is_empty());
    }

    #[tokio::test]
    async fn reap_keeps_fresh_session() {
        let proxy = proxy_with_timeout(Duration::from_secs(60));
        let route = Arc::new(route(1, "127.0.0.1", 5353));
        // 通过插入 fresh 会话（last_active = now）验证不回收。
        insert_session(&proxy, 2, route, Instant::now()).await;
        assert_eq!(proxy.session_count(), 1);

        proxy.reap_expired();

        assert_eq!(proxy.session_count(), 1);
    }

    #[test]
    fn max_payload_caps_at_default_and_header() {
        // 对端未告知 datagram 上限 → 0，任何 payload 都被拒。
        assert_eq!(max_payload(None), 0);
        // 对端上限充足 → 取默认 1200 上限。
        assert_eq!(max_payload(Some(65527)), MAX_UDP_PAYLOAD);
        // 对端上限恰好 1200 → 减 10 字节头后 1190。
        assert_eq!(max_payload(Some(1200)), 1200 - UDP_DATAGRAM_HEADER_LEN);
        // 对端上限小于头（饱和减法防下溢）→ 0。
        assert_eq!(max_payload(Some(5)), 0);
    }

    #[tokio::test]
    async fn session_limit_drops_new_sessions() {
        let limits = UdpRateLimits {
            max_sessions_per_ip: 1,
            ..Default::default()
        };
        let proxy = proxy_with_limits(Duration::from_secs(60), limits);
        let route = Arc::new(route(1, "127.0.0.1", 5353));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // 同源 IP 的第二个端口（将新建会话）会触发会话数上限；首个端口放行并建会话。
        let client1 = "10.0.0.1:1000".parse().unwrap();
        let client2 = "10.0.0.1:2000".parse().unwrap();

        assert!(proxy.admit_packet(&route, client1, 4));
        proxy.get_or_create_session(&socket, &route, client1);
        assert_eq!(proxy.session_count(), 1);

        assert!(!proxy.admit_packet(&route, client2, 4));
        assert_eq!(proxy.dropped_session_limited(), 1);
        assert_eq!(proxy.session_count(), 1);

        // 已建会话的包不受会话数上限约束，仍放行。
        assert!(proxy.admit_packet(&route, client1, 4));
    }

    #[tokio::test]
    async fn rate_limit_drops_excess_packets() {
        let limits = UdpRateLimits {
            max_packets_per_sec: 1,
            ..Default::default()
        };
        let proxy = proxy_with_limits(Duration::from_secs(60), limits);
        let route = Arc::new(route(1, "127.0.0.1", 5353));
        let client = "10.0.0.2:1000".parse().unwrap();

        // 每秒 1 包的令牌桶：首个放行，随后立即的第二个被丢弃并计数。
        assert!(proxy.admit_packet(&route, client, 4));
        assert!(!proxy.admit_packet(&route, client, 4));
        assert_eq!(proxy.dropped_rate_limited(), 1);
        assert_eq!(proxy.dropped_session_limited(), 0);
    }

    #[tokio::test]
    async fn byte_rate_limit_drops_packet() {
        let limits = UdpRateLimits {
            max_bytes_per_sec: 3,
            ..Default::default()
        };
        let proxy = proxy_with_limits(Duration::from_secs(60), limits);
        let route = Arc::new(route(1, "127.0.0.1", 5353));
        let client = "10.0.0.3:1000".parse().unwrap();

        // 字节桶容量 3，4 字节的包直接超限丢弃并计数。
        assert!(!proxy.admit_packet(&route, client, 4));
        assert_eq!(proxy.dropped_rate_limited(), 1);
    }
}
