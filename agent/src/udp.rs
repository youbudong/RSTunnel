//! Agent 侧 UDP 数据面（T-30）：收到 Server 的 `UDP_OPEN` 后，绑定本地 UDP socket 并 `connect`
//! 到内网 UDP 目标，把「目标回包 → QUIC datagram」的转发任务登记进 [`UdpSessions`]；连接级
//! datagram 读取任务把 Server 来的 datagram 解封装后写回目标。`UDP_CLOSE`（或连接结束）关闭会话。
//!
//! UDP 无连接语义：目标回包按 `session_id` 关联，datagram 头格式见 `docs/protocol.md §5`。

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::UdpSocket;

use tunnel_protocol::{decode_udp_datagram, encode_udp_datagram, RouteConfig};

/// 一条到内网 UDP 目标的会话：socket 已 `connect` 目标（用 `send`/`recv` 收发），
/// `task` 是「目标回包 → datagram」转发任务。
struct UdpHandle {
    socket: Arc<UdpSocket>,
    task: tokio::task::JoinHandle<()>,
}

/// 会话注册表：`udp_session_id → UdpHandle`，由控制流（建/关会话）与 datagram 读取任务（分发）共享。
#[derive(Default)]
pub struct UdpSessions {
    by_id: DashMap<u64, UdpHandle>,
}

impl UdpSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// 建会话：解析并 `connect` 目标 → 派生回传任务 → 登记。已存在则忽略（幂等）。
    pub async fn open(&self, conn: &quinn::Connection, session_id: u64, route: &RouteConfig) {
        if self.by_id.contains_key(&session_id) {
            return;
        }
        let target = format!("{}:{}", route.target_host, route.target_port);
        let Some(addr) = resolve_udp(&route.target_host, route.target_port).await else {
            tracing::warn!(%target, "udp target resolution failed");
            return;
        };
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%target, error = %e, "udp socket bind failed");
                return;
            }
        };
        if let Err(e) = socket.connect(addr).await {
            tracing::warn!(%target, error = %e, "udp connect failed");
            return;
        }
        let socket = Arc::new(socket);
        let task = tokio::spawn(recv_loop(
            Arc::clone(&socket),
            conn.clone(),
            session_id,
            target,
        ));
        self.by_id.insert(session_id, UdpHandle { socket, task });
        tracing::debug!(session = session_id, "udp session opened");
    }

    /// 关会话：摘除并中止其回传任务（drop socket 即关闭本地 UDP socket）。
    pub fn close(&self, session_id: u64) {
        if let Some((_, handle)) = self.by_id.remove(&session_id) {
            handle.task.abort();
            tracing::debug!(session = session_id, "udp session closed");
        }
    }

    /// 分发一条来自 Server 的 datagram（Server→目标）：解封装 → 写回目标 socket。
    pub async fn handle_datagram(&self, data: &[u8]) {
        let Some(dg) = decode_udp_datagram(data) else {
            return;
        };
        let socket = match self.by_id.get(&dg.session_id) {
            Some(entry) => entry.value().socket.clone(),
            None => return,
        };
        let _ = socket.send(dg.payload).await;
    }

    /// 关闭全部会话（连接结束时清理，见 [`Drop`]）。
    fn close_all(&self) {
        let ids: Vec<u64> = self.by_id.iter().map(|e| *e.key()).collect();
        for id in ids {
            self.close(id);
        }
    }
}

impl Drop for UdpSessions {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// 目标回包转发循环：`recv` 目标 → 封装 datagram → 回传 Server。连接/目标关闭即退出。
async fn recv_loop(
    socket: Arc<UdpSocket>,
    conn: quinn::Connection,
    session_id: u64,
    target: String,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(%target, error = %e, "udp target recv closed");
                return;
            }
        };
        let data = encode_udp_datagram(session_id, &buf[..n]);
        if conn.send_datagram(data.into()).is_err() {
            tracing::debug!(%target, session = session_id, "send datagram to server failed");
            return;
        }
    }
}

/// 解析 UDP 目标地址（`target_host` 可为 IP 或主机名）。
async fn resolve_udp(host: &str, port: u16) -> Option<SocketAddr> {
    tokio::net::lookup_host((host, port)).await.ok()?.next()
}
