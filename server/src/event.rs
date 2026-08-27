//! 服务端事件总线（T-25，§134）：QUIC 连接/心跳与 REST CRUD 发布事件，
//! `/ws` 端点订阅并推送给浏览器（§23）。基于 `tokio::sync::broadcast`，
//! 无订阅者时 `publish` 为 no-op，订阅者落后仅丢失历史（不阻塞生产者）。

use serde::Serialize;
use tokio::sync::broadcast;

/// 事件类型（§23）：`node.*` / `route.*` / `config.*`。
pub const NODE_ONLINE: &str = "node.online";
pub const NODE_OFFLINE: &str = "node.offline";
pub const NODE_CREATED: &str = "node.created";
pub const NODE_UPDATED: &str = "node.updated";
pub const ROUTE_CREATED: &str = "route.created";
pub const ROUTE_UPDATED: &str = "route.updated";
pub const ROUTE_DELETED: &str = "route.deleted";
pub const CONFIG_UPDATED: &str = "config.updated";

/// 一条可序列化的事件（§23 消息格式 `{ "type", "data" }`）。
#[derive(Debug, Clone, Serialize)]
pub struct BusEvent {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub data: serde_json::Value,
}

/// 广播通道封装。`Sender` 已 `Clone`，可直接放入 `Arc` 共享。
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<BusEvent>,
}

impl EventBus {
    /// 默认容量：容纳约 256 条未消费事件，超过后最旧事件被丢弃（`Lagged`）。
    pub const DEFAULT_CAPACITY: usize = 256;

    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// 发布一条事件。无订阅者或接收端已关闭时静默忽略。
    pub fn publish(&self, event_type: &'static str, data: serde_json::Value) {
        let _ = self.tx.send(BusEvent { event_type, data });
    }

    /// 新订阅者：只接收订阅之后发布的事件（不含历史）。
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.tx.subscribe()
    }
}
