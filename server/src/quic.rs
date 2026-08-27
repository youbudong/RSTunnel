//! Server 的 QUIC 端点：接受 Agent 连接，识别控制流，完成 HELLO→AUTH 握手并维护上线状态。
//!
//! 握手成功后进入控制流循环：处理 PING→PONG 心跳，超过 `heartbeat_timeout` 未收到 PING
//! 判定离线（设计文档 §35）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tunnel_core::auth::{authenticate, AuthDecision, SUPPORTED_PROTOCOL_MAJOR};
use tunnel_core::session::{NodeSession, SessionManager};
use tunnel_core::NodeId;
use tunnel_db::Db;
use tunnel_protocol::{
    AuthFailPayload, AuthOkPayload, ConfigSnapshotPayload, Limits, Message, PingPayload,
};

use tunnel_common::TraceId;

use crate::config_sync::ConfigSync;
use crate::conn_registry::ConnRegistry;
use crate::event::{EventBus, NODE_OFFLINE, NODE_ONLINE};
use crate::frame_io::{read_frame, write_frame};
use crate::route::ServerRoute;
use crate::udp_proxy::UdpProxy;

/// 默认心跳超时：超过该时长未收到 PING 判定离线（设计文档 §35）。
const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

pub struct QuicServer {
    endpoint: quinn::Endpoint,
    db: Db,
    sessions: Arc<SessionManager>,
    conns: Arc<ConnRegistry>,
    config_sync: Arc<ConfigSync>,
    events: Arc<EventBus>,
    heartbeat_timeout: Duration,
    /// UDP 数据面（可选）：设置后为每条 Agent 连接启动 datagram 读取任务。
    udp: OnceLock<Arc<UdpProxy>>,
}

impl QuicServer {
    /// 绑定 UDP 地址并创建端点。套接字立即开始收包，`run` 才进入接受循环。
    pub fn bind(
        addr: SocketAddr,
        server_config: quinn::ServerConfig,
        db: Db,
        sessions: Arc<SessionManager>,
    ) -> Result<Self> {
        Self::bind_with_events(
            addr,
            server_config,
            db,
            sessions,
            Arc::new(EventBus::new(EventBus::DEFAULT_CAPACITY)),
        )
    }

    /// 与 REST 管理面共享事件总线（生产 main 用），使 node online/offline
    /// 数据面事件能被 `/ws` 订阅。
    pub fn bind_with_events(
        addr: SocketAddr,
        server_config: quinn::ServerConfig,
        db: Db,
        sessions: Arc<SessionManager>,
        events: Arc<EventBus>,
    ) -> Result<Self> {
        Self::bind_with_heartbeat_timeout_and_events(
            addr,
            server_config,
            db,
            sessions,
            DEFAULT_HEARTBEAT_TIMEOUT,
            events,
        )
    }

    /// 同上，但可覆盖心跳超时（测试用短超时验证离线判定）。
    pub fn bind_with_heartbeat_timeout(
        addr: SocketAddr,
        server_config: quinn::ServerConfig,
        db: Db,
        sessions: Arc<SessionManager>,
        heartbeat_timeout: Duration,
    ) -> Result<Self> {
        Self::bind_with_heartbeat_timeout_and_events(
            addr,
            server_config,
            db,
            sessions,
            heartbeat_timeout,
            Arc::new(EventBus::new(EventBus::DEFAULT_CAPACITY)),
        )
    }

    fn bind_with_heartbeat_timeout_and_events(
        addr: SocketAddr,
        server_config: quinn::ServerConfig,
        db: Db,
        sessions: Arc<SessionManager>,
        heartbeat_timeout: Duration,
        events: Arc<EventBus>,
    ) -> Result<Self> {
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .with_context(|| format!("bind QUIC endpoint on {addr}"))?;
        Ok(Self {
            endpoint,
            db,
            sessions,
            conns: Arc::new(ConnRegistry::new()),
            config_sync: Arc::new(ConfigSync::new()),
            events,
            heartbeat_timeout,
            udp: OnceLock::new(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// 共享的连接注册表（数据面 TCP Proxy 据此打开双向流）。
    pub fn conns(&self) -> Arc<ConnRegistry> {
        Arc::clone(&self.conns)
    }

    /// 共享的配置同步器（路由变更后据此向在线 Node 推送 CONFIG_UPDATE）。
    pub fn config_sync(&self) -> Arc<ConfigSync> {
        Arc::clone(&self.config_sync)
    }

    /// 挂接 UDP 数据面（T-30）：设置后，每条新 Agent 连接都会启动 datagram 读取任务。
    /// 需在 `run` 接受连接前调用（生产 main 在启动监听前设置）。
    pub fn set_udp_proxy(&self, udp: Arc<UdpProxy>) {
        let _ = self.udp.set(udp);
    }

    /// 优雅关闭：关闭端点与所有连接，`run` 的接受循环随即返回。
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"server shutdown");
    }

    /// 接受循环，直到端点关闭（`accept` 返回 `None`）。
    pub async fn run(&self) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            match incoming.await {
                Ok(conn) => {
                    let shared = ConnectionShared {
                        sessions: Arc::clone(&self.sessions),
                        conns: Arc::clone(&self.conns),
                        config_sync: Arc::clone(&self.config_sync),
                        events: Arc::clone(&self.events),
                        udp: self.udp.get().cloned(),
                    };
                    tokio::spawn(handle_connection(
                        conn,
                        self.db.clone(),
                        shared,
                        self.heartbeat_timeout,
                    ));
                }
                Err(e) => tracing::warn!(%e, "connection handshake failed"),
            }
        }
        tracing::info!("QUIC endpoint closed");
        Ok(())
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    db: Db,
    shared: ConnectionShared,
    heartbeat_timeout: Duration,
) {
    let ConnectionShared {
        sessions,
        conns,
        config_sync,
        events,
        udp,
    } = shared;
    let trace_id = TraceId::new();
    let remote = conn.remote_address();
    tracing::info!(%trace_id, %remote, "agent connection established");

    // 第一个双向流作为控制流（HELLO→AUTH 在此完成）。
    let (send, recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::warn!(%trace_id, %e, "failed to accept control stream");
            return;
        }
    };

    // 握手；返回 (是否上线及 node_id, 控制流读写句柄)。
    let (online, send, recv) = match handshake(send, recv, &db, &sessions, &events, remote).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(%trace_id, %e, "control stream error");
            return;
        }
    };

    let Some(node_id) = online else {
        // 认证失败或流在握手期间关闭；等连接关闭即可。
        let _ = conn.closed().await;
        return;
    };

    // 数据面：把连接句柄登记到注册表，TCP Proxy 据此打开双向流。
    conns.register(node_id, conn.clone());

    // T-30：UDP 数据面——为连接启动 datagram 读取任务（Agent→客户端方向）。
    if let Some(udp) = udp {
        udp.spawn_datagram_reader(conn.clone());
    }

    // 配置下发：登记该 Node 的推送通道，路由变更时由 ConfigSync 主动推 CONFIG_UPDATE。
    let push_rx = config_sync.register(node_id);

    // 控制流循环 + 心跳超时 + 配置同步。
    serve_control_stream(
        ControlCtx {
            conn: &conn,
            db: &db,
            sessions: &sessions,
            heartbeat_timeout,
        },
        send,
        recv,
        node_id,
        push_rx,
    )
    .await;

    // 摘除配置推送通道、数据面连接句柄、会话并持久化离线状态。
    config_sync.unregister(node_id);
    conns.unregister(node_id);
    let _ = sessions.unregister(node_id);
    // T-38：Node 离线，同步递减在线数与活跃会话数。
    if let Some(g) = tunnel_metrics::nodes_online() {
        g.dec();
    }
    if let Some(g) = tunnel_metrics::sessions_active() {
        g.dec();
    }
    let now = OffsetDateTime::now_utc();
    if let Err(e) = db
        .set_node_offline(&node_id.to_string(), &now.to_string())
        .await
    {
        tracing::warn!(%node_id, error = %e, "failed to persist offline");
    }
    events.publish(
        NODE_OFFLINE,
        json!({ "node_id": node_id.to_string(), "status": "offline" }),
    );
    tracing::info!(%trace_id, %node_id, "node offline");
}

/// HELLO→AUTH 握手：读 HELLO → 读 AUTH → 校验 → 回 AUTH_OK / AUTH_FAIL，成功后下发配置快照。
///
/// 返回 `(Some(node_id), send, recv)` 表示认证成功且已注册在线会话，
/// 并归还控制流句柄供后续心跳/配置使用；`(None, send, recv)` 表示认证失败（已回 AUTH_FAIL）。
async fn handshake(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    db: &Db,
    sessions: &SessionManager,
    events: &EventBus,
    remote: SocketAddr,
) -> Result<(Option<NodeId>, quinn::SendStream, quinn::RecvStream)> {
    // 1. HELLO
    let Some(hello_frame) = read_frame(&mut recv).await? else {
        return Ok((None, send, recv)); // 对端未发 HELLO 即关闭
    };
    let hello = match Message::from_frame(&hello_frame) {
        Ok(Message::Hello(h)) => h,
        Ok(_) => {
            reply_auth_fail(
                &mut send,
                hello_frame.request_id,
                "PROTOCOL_ERROR",
                "first frame must be HELLO",
            )
            .await?;
            return Ok((None, send, recv));
        }
        Err(e) => return Err(e).context("decode HELLO"),
    };
    if hello.protocol_version.major != SUPPORTED_PROTOCOL_MAJOR {
        reply_auth_fail(
            &mut send,
            hello_frame.request_id,
            "PROTOCOL_ERROR",
            "unsupported protocol major version",
        )
        .await?;
        return Ok((None, send, recv));
    }
    tracing::info!(
        agent = %hello.agent_version,
        major = hello.protocol_version.major,
        "agent hello"
    );

    // 2. AUTH
    let Some(auth_frame) = read_frame(&mut recv).await? else {
        return Ok((None, send, recv)); // 对端在 HELLO 后未发 AUTH 即关闭
    };
    let auth = match Message::from_frame(&auth_frame) {
        Ok(Message::Auth(a)) => a,
        Ok(_) => {
            reply_auth_fail(
                &mut send,
                auth_frame.request_id,
                "PROTOCOL_ERROR",
                "second frame must be AUTH",
            )
            .await?;
            return Ok((None, send, recv));
        }
        Err(e) => return Err(e).context("decode AUTH"),
    };

    // 3. 校验凭据 → 回 AUTH_OK / AUTH_FAIL。
    let now = OffsetDateTime::now_utc();
    match authenticate(db, &auth, now).await {
        AuthDecision::Success(s) => {
            let msg = Message::AuthOk(AuthOkPayload {
                node_id: s.node_id,
                config_version: s.config_version,
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                server_time: now.to_string(),
            });
            send_message(&mut send, msg, auth_frame.request_id).await?;

            // T-13/T-18：AUTH_OK 后下发该 Node 的全量配置快照（含路由），供 Agent 建立基线。
            send_snapshot(db, &mut send, s.node_id, s.config_version).await?;

            let _ = sessions.register(NodeSession::new(s.node_id, remote.to_string(), now));
            // T-38：在线 Node 数与活跃 QUIC 会话数（一 Node 一连接，同步增减）。
            if let Some(g) = tunnel_metrics::nodes_online() {
                g.inc();
            }
            if let Some(g) = tunnel_metrics::sessions_active() {
                g.inc();
            }
            if let Err(e) = db
                .set_node_online(
                    &s.node_id.to_string(),
                    &remote.to_string(),
                    &hello.agent_version,
                    &now.to_string(),
                )
                .await
            {
                tracing::warn!(node_id = %s.node_id, error = %e, "failed to persist online");
            }
            tracing::info!(node_id = %s.node_id, agent = %hello.agent_version, "node online");
            events.publish(
                NODE_ONLINE,
                json!({ "node_id": s.node_id.to_string(), "status": "online" }),
            );
            Ok((Some(s.node_id), send, recv))
        }
        AuthDecision::Failure { code, message } => {
            reply_auth_fail(&mut send, auth_frame.request_id, code, &message).await?;
            Ok((None, send, recv))
        }
    }
}

/// `serve_control_stream` 所需的共享上下文（避免参数过多）。
struct ControlCtx<'a> {
    conn: &'a quinn::Connection,
    db: &'a Db,
    sessions: &'a SessionManager,
    heartbeat_timeout: Duration,
}

/// 连接级共享句柄（数据面注册表、配置同步、事件总线、UDP 数据面），随连接生命周期存续。
struct ConnectionShared {
    sessions: Arc<SessionManager>,
    conns: Arc<ConnRegistry>,
    config_sync: Arc<ConfigSync>,
    events: Arc<EventBus>,
    udp: Option<Arc<UdpProxy>>,
}

/// 控制流循环：PING→PONG 心跳 + 配置同步（CONFIG_ACK / CONFIG_RESYNC / 主动 CONFIG_UPDATE），
/// 超时/流关闭/连接关闭即退出。
async fn serve_control_stream(
    ctx: ControlCtx<'_>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    node_id: NodeId,
    mut push_rx: mpsc::UnboundedReceiver<Message>,
) {
    let ControlCtx {
        conn,
        db,
        sessions,
        heartbeat_timeout,
    } = ctx;
    let mut deadline = tokio::time::Instant::now() + heartbeat_timeout;

    loop {
        tokio::select! {
            frame = read_frame(&mut recv) => {
                match frame {
                    Ok(Some(f)) => {
                        match Message::from_frame(&f) {
                            Ok(Message::Ping(p)) => {
                                let now = OffsetDateTime::now_utc();
                                if let Some(s) = sessions.get(node_id) {
                                    s.record_ping(now);
                                }
                                let pong = Message::Pong(PingPayload { ts: p.ts });
                                if let Err(e) = send_message(&mut send, pong, f.request_id).await {
                                    tracing::warn!(%node_id, error = %e, "failed to send PONG");
                                    break;
                                }
                                if let Some(s) = sessions.get(node_id) {
                                    s.record_pong(now);
                                }
                            }
                            Ok(Message::ConfigAck(ack)) => {
                                if let Some(s) = sessions.get(node_id) {
                                    s.record_config_ack(ack.config_version);
                                }
                                // 持久化：应用成功 → synced；失败 → failed（设计文档 §28）。
                                let now = OffsetDateTime::now_utc().to_string();
                                if ack.applied {
                                    if let Err(e) = db
                                        .set_node_applied_config(
                                            &node_id.to_string(),
                                            ack.config_version as i64,
                                            &now,
                                        )
                                        .await
                                    {
                                        tracing::warn!(%node_id, error = %e, "persist applied config failed");
                                    }
                                } else if let Err(e) = db
                                    .set_node_config_failed(&node_id.to_string(), &now)
                                    .await
                                {
                                    tracing::warn!(%node_id, error = %e, "persist config failed status failed");
                                }
                                tracing::info!(%node_id, version = ack.config_version, applied = ack.applied, "config ack");
                            }
                            Ok(Message::ConfigResync(resync)) => {
                                tracing::info!(%node_id, last_applied = resync.last_applied_version, "config resync requested");
                                // 重新读当前版本（连接存续期间可能又变了），下发完整快照兜底。
                                match db.get_config_version(&node_id.to_string()).await {
                                    Ok(v) => {
                                        if let Err(e) = send_snapshot(db, &mut send, node_id, v.max(0) as u64).await {
                                            tracing::warn!(%node_id, error = %e, "failed to resend CONFIG_SNAPSHOT");
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(%node_id, error = %e, "read config version for resync");
                                        break;
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                tracing::debug!(%node_id, error = %e, "decode control frame");
                            }
                        }
                        deadline = tokio::time::Instant::now() + heartbeat_timeout;
                    }
                    Ok(None) => {
                        tracing::debug!(%node_id, "control stream closed");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(%node_id, error = %e, "control stream error");
                        break;
                    }
                }
            }
            msg = push_rx.recv() => {
                match msg {
                    Some(m) => {
                        if let Err(e) = send_message(&mut send, m, 0).await {
                            tracing::warn!(%node_id, error = %e, "failed to push config message");
                            break;
                        }
                    }
                    None => {
                        tracing::debug!(%node_id, "config push channel closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!(%node_id, "heartbeat timeout");
                break;
            }
            reason = conn.closed() => {
                tracing::debug!(%node_id, ?reason, "connection closed");
                break;
            }
        }
    }
}

/// 下发一帧 CONFIG_SNAPSHOT：加载该 Node 的全量路由（`RouteConfig`），供 Agent 建立基线。
///
/// `config_version` 由调用方提供（握手时来自认证，重同步时重新读库）。
async fn send_snapshot(
    db: &Db,
    send: &mut quinn::SendStream,
    node_id: NodeId,
    config_version: u64,
) -> Result<()> {
    let routes = db
        .list_routes_for_node(&node_id.to_string())
        .await
        .context("list routes for node")?
        .into_iter()
        .map(ServerRoute::try_from)
        .map(|r| r.map(|s| s.to_route_config()))
        .collect::<Result<Vec<_>>>()
        .context("parse node routes")?;
    let msg = Message::ConfigSnapshot(ConfigSnapshotPayload {
        config_version,
        routes,
        acl: Vec::new(),
        limits: Limits::default(),
    });
    send_message(send, msg, 0).await
}

/// 回一帧 AUTH_FAIL。
async fn reply_auth_fail(
    send: &mut quinn::SendStream,
    request_id: u64,
    code: &str,
    message: &str,
) -> Result<()> {
    let msg = Message::AuthFail(AuthFailPayload {
        code: code.to_string(),
        message: message.to_string(),
    });
    send_message(send, msg, request_id).await
}

/// 组帧并写入控制流。
async fn send_message(send: &mut quinn::SendStream, msg: Message, request_id: u64) -> Result<()> {
    let frame = msg.into_frame(request_id)?;
    write_frame(send, &frame).await
}
