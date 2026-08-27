//! 配置下发（T-18）：`ConfigSync` 维护「在线 Node → 推送通道」映射。
//!
//! 路由变更后调用 [`ConfigSync::notify_routes_changed`]：`config_version + 1` → 计算增量
//! → 推送给在线 Agent（离线则仅版本 +1，`config_status = 'pending'`，待上线走快照收敛）。
//! 设计文档 §10/§28。

use anyhow::Result;
use dashmap::DashMap;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tunnel_core::compute_route_delta;
use tunnel_core::NodeId;
use tunnel_db::Db;
use tunnel_protocol::{ConfigUpdatePayload, Message, RouteConfig};

/// 配置同步器：按 Node 建立无界推送通道，向在线 Agent 的控制流主动下发消息。
#[derive(Debug, Default)]
pub struct ConfigSync {
    push: DashMap<NodeId, mpsc::UnboundedSender<Message>>,
}

impl ConfigSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册某个在线 Node 的推送通道，返回接收端供控制流 `select!` 消费。
    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.push.insert(node_id, tx);
        rx
    }

    /// 摘除推送通道（连接关闭时调用）。
    pub fn unregister(&self, node_id: NodeId) {
        self.push.remove(&node_id);
    }

    /// 路由变更后的下发入口（T-21 REST 将调用）：
    /// 版本 +1 → 计算增量 → 推送给在线 Agent；离线 Node 仅版本 +1（`config_status=pending`）。
    ///
    /// 返回新的 `config_version`。
    pub async fn notify_routes_changed(
        &self,
        db: &Db,
        node_id: NodeId,
        old_routes: &[RouteConfig],
        new_routes: &[RouteConfig],
    ) -> Result<u64> {
        let now = OffsetDateTime::now_utc().to_string();
        let version = db.bump_config_version(&node_id.to_string(), &now).await?;
        let delta = compute_route_delta(old_routes, new_routes);
        self.push(
            node_id,
            Message::ConfigUpdate(ConfigUpdatePayload {
                config_version: version as u64,
                routes: delta,
                limits: None,
            }),
        );
        Ok(version as u64)
    }

    /// 向在线 Node 的控制流推送一帧消息；离线则忽略（版本已落在 DB 中）。
    fn push(&self, node_id: NodeId, msg: Message) {
        if let Some(tx) = self.push.get(&node_id) {
            // 无界通道 send 不阻塞；接收端（控制流）已退出时返回 Err，忽略。
            let _ = tx.send(msg);
        }
    }

    /// 向在线 Node 的控制流推送一条数据面控制消息（UDP_OPEN/UDP_CLOSE 等）。
    /// 与配置消息共用同一推送通道，按序送达控制流；离线则忽略。
    pub fn push_message(&self, node_id: NodeId, msg: Message) {
        self.push(node_id, msg);
    }
}
