//! Agent 持久会话：连接 + 认证后持有控制流，运行心跳循环（设计文档 §35）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tunnel_core::frame_io::{read_frame, write_frame};
use tunnel_core::NodeId;
use tunnel_metrics::agent_rtt_seconds;
use tunnel_protocol::{
    AuthPayload, ConfigAckPayload, ConfigResyncPayload, ConfigUpdatePayload, HelloPayload, Message,
    PingPayload, RouteConfig, RouteDelta, RouteType,
};

use tunnel_config::SecurityConfig;

use crate::agent::Agent;
use crate::udp::UdpSessions;

/// 心跳参数（设计文档 §35：interval 15s / timeout 45s）。
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            timeout: Duration::from_secs(45),
        }
    }
}

/// 会话退出原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// 控制流或连接被对端关闭。
    Closed,
    /// 超过 `timeout` 未收到 PONG。
    Timeout,
}

/// 数据面接受任务守卫：`AgentSession::run` 返回时中止数据面任务，释放连接句柄。
struct DataTaskGuard(tokio::task::JoinHandle<()>);

impl Drop for DataTaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 依次尝试多个服务器端点（T-43/§50 故障转移）：返回第一个成功认证的会话。
///
/// `endpoints` 为 `(addr, server_name)` 列表，顺序即优先级（primary 在前）。某端点连接或认证
/// 失败即记日志并尝试下一个；全部失败返回最后一个错误。主 Server 停后据此自动切到备，
/// 主恢复后（下一轮重连从 primary 开始）自动回切。
pub async fn connect_any(
    agent: &Agent,
    endpoints: &[(SocketAddr, String)],
    hello: HelloPayload,
    auth: AuthPayload,
    security: Arc<SecurityConfig>,
) -> Result<AgentSession> {
    let mut last_err = None;
    for (index, (addr, server_name)) in endpoints.iter().enumerate() {
        tracing::info!(%addr, %server_name, endpoint_index = index, "trying server endpoint");
        match AgentSession::connect_to(
            agent,
            *addr,
            server_name,
            hello.clone(),
            auth.clone(),
            Arc::clone(&security),
        )
        .await
        {
            Ok(session) => {
                tracing::info!(%addr, endpoint_index = index, "connected to server endpoint");
                return Ok(session);
            }
            Err(e) => {
                tracing::warn!(
                    %addr,
                    %server_name,
                    endpoint_index = index,
                    error = %e,
                    "endpoint failed; trying next"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no server endpoint to try")))
}

/// 认证成功后的持久控制流会话。
pub struct AgentSession {
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    node_id: NodeId,
    /// 当前已应用（并 ACK 给 Server）的配置版本（设计文档 §10）。
    applied_version: u64,
    /// 本地运行时路由配置（空快照/增量更新在此落地，供后续数据面使用）。
    routes: Vec<RouteConfig>,
    /// 本地目标安全策略（T-34f：`allow_targets`/`deny_targets`），供数据面出站校验。
    security: Arc<SecurityConfig>,
}

impl AgentSession {
    /// 连接 + 认证，返回持有控制流的会话（使用 `Agent` 固定的 SNI）。失败时回 AUTH_FAIL 并报错。
    pub async fn connect(
        agent: &Agent,
        addr: SocketAddr,
        hello: HelloPayload,
        auth: AuthPayload,
        security: Arc<SecurityConfig>,
    ) -> Result<Self> {
        let conn = agent.connect(addr).await?;
        Self::finish_connect(conn, hello, auth, security).await
    }

    /// 连接 + 认证，`server_name` 为该端点 SNI（T-43 故障转移：不同服务器可不同 SNI）。
    pub async fn connect_to(
        agent: &Agent,
        addr: SocketAddr,
        server_name: &str,
        hello: HelloPayload,
        auth: AuthPayload,
        security: Arc<SecurityConfig>,
    ) -> Result<Self> {
        let conn = agent.connect_to(addr, server_name).await?;
        Self::finish_connect(conn, hello, auth, security).await
    }

    /// 建连后完成控制流握手：HELLO→AUTH→读 AUTH_OK→读 CONFIG_SNAPSHOT→回 ACK。
    async fn finish_connect(
        conn: quinn::Connection,
        hello: HelloPayload,
        auth: AuthPayload,
        security: Arc<SecurityConfig>,
    ) -> Result<Self> {
        let (mut send, mut recv) = conn.open_bi().await.context("open control stream")?;

        let hello_frame = Message::Hello(hello).into_frame(1)?;
        write_frame(&mut send, &hello_frame).await?;
        let auth_frame = Message::Auth(auth).into_frame(2)?;
        write_frame(&mut send, &auth_frame).await?;

        let frame = read_frame(&mut recv)
            .await?
            .context("server closed before AUTH response")?;
        let node_id = match Message::from_frame(&frame)? {
            Message::AuthOk(p) => p.node_id,
            Message::AuthFail(p) => bail!("auth failed: {} ({})", p.code, p.message),
            other => bail!("unexpected response frame: {other:?}"),
        };

        // T-13：认证成功后 Server 会紧随 AUTH_OK 下发 CONFIG_SNAPSHOT，落地本地运行时配置并回 ACK。
        let snapshot_frame = read_frame(&mut recv)
            .await?
            .context("server closed before CONFIG_SNAPSHOT")?;
        let (applied_version, routes) = match Message::from_frame(&snapshot_frame)? {
            Message::ConfigSnapshot(p) => (p.config_version, p.routes),
            other => bail!("expected CONFIG_SNAPSHOT, got {other:?}"),
        };
        send_config_ack(&mut send, applied_version, snapshot_frame.request_id).await?;

        Ok(Self {
            conn,
            send,
            recv,
            node_id,
            applied_version,
            routes,
            security,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// 当前已应用的配置版本（供测试/日志观察）。
    pub fn applied_version(&self) -> u64 {
        self.applied_version
    }

    /// 心跳循环：每 `interval` 发 PING；`timeout` 内无 PONG 判定超时。返回退出原因。
    ///
    /// 同时处理 Server 下发的 CONFIG_UPDATE / CONFIG_SNAPSHOT：版本连续则应用并回 ACK，
    /// 不连续（漏了中间版本）则回 CONFIG_RESYNC 请求完整快照（设计文档 §10）。
    pub async fn run(self, heartbeat: HeartbeatConfig) -> Result<RunOutcome> {
        let Self {
            conn,
            mut send,
            mut recv,
            node_id,
            mut applied_version,
            mut routes,
            security,
        } = self;

        // T-15：数据面——接受 Server 打开的双向流并转发到内网目标。
        // T-34f：共享本地目标策略，出站前校验（拒绝 loopback/link-local 等未授权目标）。
        // 守卫在 `run` 返回（含提前 return）时中止该任务，释放连接句柄。
        let _data_guard = DataTaskGuard(tokio::spawn(crate::data_plane::accept_data_streams(
            conn.clone(),
            security,
        )));

        // T-30：UDP 数据面——会话注册表 + 连接级 datagram 读取任务（Server→目标方向）。
        // 守卫在 `run` 返回时中止读取任务；会话表 drop 时关闭全部 UDP 会话。
        let udp = Arc::new(UdpSessions::new());
        let _udp_guard = DataTaskGuard({
            let conn = conn.clone();
            let udp = Arc::clone(&udp);
            tokio::spawn(async move {
                while let Ok(bytes) = conn.read_datagram().await {
                    udp.handle_datagram(&bytes).await;
                }
            })
        });

        let mut next_ping = tokio::time::Instant::now() + heartbeat.interval;
        let mut last_pong = tokio::time::Instant::now();
        let mut request_id = 3u64; // 1/2 已被 HELLO/AUTH 使用

        loop {
            let deadline = last_pong + heartbeat.timeout;
            tokio::select! {
                _ = tokio::time::sleep_until(next_ping) => {
                    let ts = now_micros();
                    let msg = Message::Ping(PingPayload { ts });
                    if write_frame(&mut send, &msg.into_frame(request_id)?).await.is_err() {
                        tracing::debug!(%node_id, "send ping failed");
                        return Ok(RunOutcome::Closed);
                    }
                    request_id += 1;
                    next_ping = tokio::time::Instant::now() + heartbeat.interval;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    tracing::warn!(%node_id, "heartbeat timeout");
                    return Ok(RunOutcome::Timeout);
                }
                frame = read_frame(&mut recv) => {
                    match frame {
                        Ok(Some(f)) => {
                            match Message::from_frame(&f) {
                                Ok(Message::Pong(p)) => {
                                    let rtt = Duration::from_micros((now_micros() - p.ts).max(0) as u64);
                                    record_rtt(node_id, rtt);
                                    last_pong = tokio::time::Instant::now();
                                }
                                Ok(Message::ConfigSnapshot(snapshot)) => {
                                    applied_version = snapshot.config_version;
                                    routes = snapshot.routes;
                                    if let Err(e) = send_config_ack(&mut send, applied_version, f.request_id).await {
                                        tracing::warn!(%node_id, error = %e, "send CONFIG_ACK failed");
                                        return Ok(RunOutcome::Closed);
                                    }
                                }
                                Ok(Message::ConfigUpdate(update)) => {
                                    match apply_config_update(&mut routes, applied_version, &update) {
                                        Ok(v) => {
                                            applied_version = v;
                                            if let Err(e) = send_config_ack(&mut send, v, f.request_id).await {
                                                tracing::warn!(%node_id, error = %e, "send CONFIG_ACK failed");
                                                return Ok(RunOutcome::Closed);
                                            }
                                        }
                                        Err(last_applied) => {
                                            tracing::warn!(%node_id, incoming = update.config_version, last_applied, "config version gap, requesting resync");
                                            if let Err(e) = send_config_resync(&mut send, last_applied, f.request_id).await {
                                                tracing::warn!(%node_id, error = %e, "send CONFIG_RESYNC failed");
                                                return Ok(RunOutcome::Closed);
                                            }
                                        }
                                    }
                                }
                                Ok(Message::UdpOpen(p)) => {
                                    // T-30：按 route_id 找到本地 UDP 路由，建会话并开始转发。
                                    match routes
                                        .iter()
                                        .find(|r| r.id == p.route_id && r.route_type == RouteType::Udp)
                                        .cloned()
                                    {
                                        Some(route) => udp.open(&conn, p.udp_session_id, &route).await,
                                        None => tracing::warn!(route_id = %p.route_id, "UDP_OPEN for unknown route"),
                                    }
                                }
                                Ok(Message::UdpClose(p)) => {
                                    udp.close(p.udp_session_id);
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::debug!(%node_id, error = %e, "decode control frame");
                                }
                            }
                        }
                        Ok(None) => return Ok(RunOutcome::Closed),
                        Err(e) => {
                            tracing::debug!(%node_id, error = %e, "control stream closed");
                            return Ok(RunOutcome::Closed);
                        }
                    }
                }
            }
        }
    }
}

/// 回一帧 CONFIG_ACK（`applied = true`，成功落地）。
async fn send_config_ack(
    send: &mut quinn::SendStream,
    config_version: u64,
    request_id: u64,
) -> Result<()> {
    let msg = Message::ConfigAck(ConfigAckPayload {
        config_version,
        applied: true,
        error: None,
    });
    write_frame(send, &msg.into_frame(request_id)?).await
}

/// 回一帧 CONFIG_RESYNC，携带最后成功应用的版本。
async fn send_config_resync(
    send: &mut quinn::SendStream,
    last_applied_version: u64,
    request_id: u64,
) -> Result<()> {
    let msg = Message::ConfigResync(ConfigResyncPayload {
        last_applied_version,
    });
    write_frame(send, &msg.into_frame(request_id)?).await
}

/// 应用一次增量配置更新。
///
/// 版本必须连续（`update.config_version == applied_version + 1`），否则说明中间有版本
/// 丢失，返回 `Err(last_applied_version)` 表示需要 Server 重发完整快照（设计文档 §10）。
fn apply_config_update(
    routes: &mut Vec<RouteConfig>,
    applied_version: u64,
    update: &ConfigUpdatePayload,
) -> Result<u64, u64> {
    if update.config_version != applied_version + 1 {
        return Err(applied_version);
    }
    apply_route_delta(routes, &update.routes);
    Ok(update.config_version)
}

/// 将路由增量（added/updated/removed）应用到本地路由表。
fn apply_route_delta(routes: &mut Vec<RouteConfig>, delta: &RouteDelta) {
    for added in &delta.added {
        if !routes.iter().any(|r| r.id == added.id) {
            routes.push(added.clone());
        }
    }
    for updated in &delta.updated {
        match routes.iter_mut().find(|r| r.id == updated.id) {
            Some(existing) => *existing = updated.clone(),
            None => routes.push(updated.clone()),
        }
    }
    routes.retain(|r| !delta.removed.contains(&r.id));
}

/// 记录 RTT 到指标与日志。
fn record_rtt(node_id: NodeId, rtt: Duration) {
    if let Some(g) = agent_rtt_seconds() {
        g.set(rtt.as_secs_f64());
    }
    tracing::debug!(%node_id, rtt_ms = rtt.as_millis(), "heartbeat pong");
}

/// 当前 unix 微秒时间戳（`PingPayload.ts` 的单位，精度足够测量本机 RTT）。
fn now_micros() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_micros() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use tunnel_core::NodeId;
    use tunnel_protocol::RouteType;

    fn route(id: u128, name: &str) -> RouteConfig {
        RouteConfig {
            id: NodeId::from_u128(id),
            name: name.to_string(),
            route_type: RouteType::Tcp,
            enabled: true,
            target_host: "127.0.0.1".to_string(),
            target_port: 8080,
            hostname: None,
            limits: None,
        }
    }

    #[test]
    fn apply_update_contiguous_applies_delta() {
        let mut routes = vec![route(1, "a")];
        let delta = RouteDelta {
            added: vec![route(2, "b")],
            updated: vec![route(1, "a2")],
            removed: Vec::new(),
        };
        let update = ConfigUpdatePayload {
            config_version: 8,
            routes: delta,
            limits: None,
        };
        assert_eq!(apply_config_update(&mut routes, 7, &update), Ok(8));
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].name, "a2");
        assert_eq!(routes[1].name, "b");
    }

    #[test]
    fn apply_update_discontinuous_requests_resync() {
        let mut routes = vec![route(1, "a")];
        let update = ConfigUpdatePayload {
            config_version: 9,
            routes: RouteDelta::default(),
            limits: None,
        };
        // 9 != 7 + 1，应返回 Err(最后已应用版本) 且不改动本地路由。
        assert_eq!(apply_config_update(&mut routes, 7, &update), Err(7));
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn apply_delta_removes_and_dedups_added() {
        let mut routes = vec![route(1, "a"), route(2, "b")];
        let delta = RouteDelta {
            added: vec![route(1, "a")], // 已存在的 id 不应重复追加
            updated: Vec::new(),
            removed: vec![NodeId::from_u128(2)],
        };
        apply_route_delta(&mut routes, &delta);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].name, "a");
    }
}
