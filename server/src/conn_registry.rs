//! 连接注册表：维护「Node ID → QUIC 连接」映射，供数据面（TCP Proxy）在收到入向连接时
//! 打开新的双向流（设计文档 §82/§84）。`quinn::Connection` 是廉价句柄，可安全 Clone。

use dashmap::DashMap;
use tunnel_core::NodeId;

#[derive(Debug, Default)]
pub struct ConnRegistry {
    conns: DashMap<NodeId, quinn::Connection>,
}

impl ConnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册/更新一个 Node 的连接（同 Node 重连时替换旧连接）。
    pub fn register(&self, node_id: NodeId, conn: quinn::Connection) {
        self.conns.insert(node_id, conn);
    }

    /// 摘除一个 Node 的连接。
    pub fn unregister(&self, node_id: NodeId) {
        self.conns.remove(&node_id);
    }

    /// 取 Node 的当前连接（若在线）。
    pub fn get(&self, node_id: NodeId) -> Option<quinn::Connection> {
        self.conns.get(&node_id).map(|r| r.value().clone())
    }
}
