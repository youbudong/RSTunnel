//! Session Manager：内存中维护「在线 Node → Session」映射（设计文档 §35/§151）。
//!
//! 只存元数据，不持有传输句柄（QUIC 连接由 server 管理）；连接关闭时由 server 调用
//! [`SessionManager::unregister`] 摘除并持久化离线状态。心跳字段用原子量原地更新，
//! 避免为每次 PING/PONG 加锁或替换整个会话。

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// 一个在线 Node 的会话元数据。
#[derive(Debug)]
pub struct NodeSession {
    pub node_id: Uuid,
    pub remote_addr: String,
    pub connected_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    /// 最近一次收到 PING 的 unix 秒时间戳（0 = 从未）。
    last_ping_at_secs: AtomicI64,
    /// 最近一次回 PONG 的 unix 秒时间戳（0 = 从未）。
    last_pong_at_secs: AtomicI64,
    /// 最近一次 Agent 回报「已应用」的配置版本（0 = 从未 ACK）。
    applied_config_version: AtomicU64,
}

impl NodeSession {
    pub fn new(node_id: Uuid, remote_addr: String, now: OffsetDateTime) -> Self {
        Self {
            node_id,
            remote_addr,
            connected_at: now,
            last_seen_at: now,
            last_ping_at_secs: AtomicI64::new(0),
            last_pong_at_secs: AtomicI64::new(0),
            applied_config_version: AtomicU64::new(0),
        }
    }

    /// 记录收到一次 PING（原地更新）。
    pub fn record_ping(&self, now: OffsetDateTime) {
        self.last_ping_at_secs
            .store(now.unix_timestamp(), Ordering::Relaxed);
    }

    /// 记录回了一次 PONG（原地更新）。
    pub fn record_pong(&self, now: OffsetDateTime) {
        self.last_pong_at_secs
            .store(now.unix_timestamp(), Ordering::Relaxed);
    }

    /// 记录 Agent 回报已应用的配置版本。
    pub fn record_config_ack(&self, version: u64) {
        self.applied_config_version
            .store(version, Ordering::Relaxed);
    }

    pub fn applied_config_version(&self) -> u64 {
        self.applied_config_version.load(Ordering::Relaxed)
    }

    pub fn last_ping_at(&self) -> Option<OffsetDateTime> {
        secs_to_dt(self.last_ping_at_secs.load(Ordering::Relaxed))
    }

    pub fn last_pong_at(&self) -> Option<OffsetDateTime> {
        secs_to_dt(self.last_pong_at_secs.load(Ordering::Relaxed))
    }
}

fn secs_to_dt(secs: i64) -> Option<OffsetDateTime> {
    if secs == 0 {
        None
    } else {
        OffsetDateTime::from_unix_timestamp(secs).ok()
    }
}

/// Session Manager（[`DashMap`] 实现，读多写少，无全局锁）。
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: DashMap<Uuid, Arc<NodeSession>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册/上线一个会话。同 node 已存在时替换并返回旧会话（旧连接应由调用方关闭）。
    pub fn register(&self, session: NodeSession) -> Option<Arc<NodeSession>> {
        self.sessions.insert(session.node_id, Arc::new(session))
    }

    /// 摘除并返回会话（若存在）。
    pub fn unregister(&self, node_id: Uuid) -> Option<Arc<NodeSession>> {
        self.sessions.remove(&node_id).map(|(_, v)| v)
    }

    /// 取会话快照（`Arc` clone）。
    pub fn get(&self, node_id: Uuid) -> Option<Arc<NodeSession>> {
        self.sessions.get(&node_id).map(|r| r.clone())
    }

    /// 是否在线。
    pub fn is_online(&self, node_id: Uuid) -> bool {
        self.sessions.contains_key(&node_id)
    }

    /// 当前在线节点数。
    pub fn online_count(&self) -> usize {
        self.sessions.len()
    }

    /// 全部在线会话快照。
    pub fn list(&self) -> Vec<Arc<NodeSession>> {
        self.sessions.iter().map(|r| r.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn ts() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn register_and_query() {
        let m = SessionManager::new();
        let id = Uuid::new_v4();
        assert!(!m.is_online(id));
        assert_eq!(m.online_count(), 0);
        assert!(m
            .register(NodeSession::new(id, "1.2.3.4:5".into(), ts()))
            .is_none());
        assert!(m.is_online(id));
        assert_eq!(m.online_count(), 1);
        let s = m.get(id).unwrap();
        assert_eq!(s.node_id, id);
        assert_eq!(s.remote_addr, "1.2.3.4:5");
    }

    #[test]
    fn unregister() {
        let m = SessionManager::new();
        let id = Uuid::new_v4();
        m.register(NodeSession::new(id, "x".into(), ts()));
        let removed = m.unregister(id).unwrap();
        assert_eq!(removed.node_id, id);
        assert!(!m.is_online(id));
        assert_eq!(m.online_count(), 0);
    }

    #[test]
    fn re_register_replaces() {
        let m = SessionManager::new();
        let id = Uuid::new_v4();
        m.register(NodeSession::new(id, "a".into(), ts()));
        let old = m.register(NodeSession::new(id, "b".into(), ts())).unwrap();
        assert_eq!(old.remote_addr, "a");
        assert_eq!(m.get(id).unwrap().remote_addr, "b");
        assert_eq!(m.online_count(), 1);
    }

    #[test]
    fn list_returns_all() {
        let m = SessionManager::new();
        m.register(NodeSession::new(Uuid::new_v4(), "a".into(), ts()));
        m.register(NodeSession::new(Uuid::new_v4(), "b".into(), ts()));
        assert_eq!(m.list().len(), 2);
    }

    #[test]
    fn heartbeat_recording() {
        let s = NodeSession::new(Uuid::new_v4(), "x".into(), ts());
        assert_eq!(s.last_ping_at(), None);
        assert_eq!(s.last_pong_at(), None);
        let t = ts();
        s.record_ping(t);
        s.record_pong(t);
        assert_eq!(s.last_ping_at(), Some(t));
        assert_eq!(s.last_pong_at(), Some(t));
    }
}
