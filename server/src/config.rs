//! 配置管理器（T-17）：`ArcSwap<ConfigSnapshot>` 无锁读、原子替换，
//! `load → validate → atomic replace → broadcast`（设计文档 §28/§78）。

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::broadcast;
use tunnel_db::Db;

use crate::route::ServerRoute;
use tunnel_protocol::RouteType;

/// Server 侧不可变配置快照。读端无锁（`ArcSwap`），替换原子。
#[derive(Debug, Default, Clone)]
pub struct ConfigSnapshot {
    /// 全量路由（已校验：监听地址可解析且无重复）。
    pub routes: Vec<ServerRoute>,
}

/// 配置管理器：`ArcSwap<ConfigSnapshot>` + `load → validate → atomic replace → broadcast`。
#[derive(Debug)]
pub struct ConfigManager {
    snapshot: ArcSwap<ConfigSnapshot>,
    /// 每次 replace 后广播一帧，订阅方据此热更新（T-18/T-19）。
    tx: broadcast::Sender<()>,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            snapshot: ArcSwap::new(Arc::new(ConfigSnapshot::default())),
            tx,
        }
    }

    /// 无锁读取当前快照（返回独立 `Arc`，与后续替换互不影响）。
    pub fn snapshot(&self) -> Arc<ConfigSnapshot> {
        self.snapshot.load_full()
    }

    /// 订阅配置变更广播（每次 replace 后收到一帧）。
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// 从数据库加载全量路由并原子替换快照：`load → validate → atomic replace → broadcast`。
    pub async fn reload(&self, db: &Db) -> Result<()> {
        let routes = Self::load(db).await?;
        Self::validate(&routes)?;
        self.replace(ConfigSnapshot { routes });
        Ok(())
    }

    /// 原子替换快照并广播。
    pub fn replace(&self, snapshot: ConfigSnapshot) {
        self.snapshot.store(Arc::new(snapshot));
        // 无订阅方时 send 返回 Err，忽略（快照已替换，仅广播不到）。
        let _ = self.tx.send(());
    }

    /// 从数据库加载全量路由（解析为 [`ServerRoute`]）。
    async fn load(db: &Db) -> Result<Vec<ServerRoute>> {
        db.list_routes()
            .await
            .context("list routes")?
            .into_iter()
            .map(ServerRoute::try_from)
            .collect::<Result<Vec<_>>>()
            .context("parse routes")
    }

    /// 校验：TCP/UDP 路由监听地址可解析且无重复；HTTP/HTTPS 路由 hostname 存在且无重复
    /// （其余校验在 API 层，见设计文档 §57）。
    fn validate(routes: &[ServerRoute]) -> Result<()> {
        let mut seen_listen = HashSet::new();
        let mut seen_host = HashSet::new();
        for route in routes {
            match route.route_type {
                // HTTP/HTTPS 路由按 Host 路由（共享 `http.bind`，无独立监听），校验 hostname。
                RouteType::Http | RouteType::Https => {
                    let host = route
                        .host_key()
                        .with_context(|| format!("route {} has no hostname", route.name))?;
                    if !seen_host.insert(host.clone()) {
                        bail!("duplicate hostname {host} (route {})", route.name);
                    }
                }
                _ => {
                    let addr = route.listen_addr().with_context(|| {
                        format!("route {} has invalid listen address", route.name)
                    })?;
                    if !seen_listen.insert(addr) {
                        bail!("duplicate listen address {addr} (route {})", route.name);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::route::ServerRoute;
    use tunnel_core::{NodeId, RouteId};
    use tunnel_protocol::RouteType;

    fn route(id: u128, listen: &str, port: u16) -> ServerRoute {
        ServerRoute {
            id: RouteId::from_u128(id),
            name: format!("route-{id}"),
            route_type: RouteType::Tcp,
            enabled: true,
            node_id: NodeId::from_u128(id + 1000),
            listen_host: listen.to_string(),
            listen_port: port,
            target_host: "192.168.1.100".to_string(),
            target_port: 22,
            hostname: None,
            tls_mode: None,
            limits: None,
        }
    }

    #[test]
    fn replace_is_atomic_and_read_lock_free() {
        let mgr = ConfigManager::new();
        let before = mgr.snapshot();
        assert!(before.routes.is_empty());

        // 读者拿到旧快照后，替换不影响其已持有的 Arc。
        mgr.replace(ConfigSnapshot {
            routes: vec![route(1, "127.0.0.1", 8080)],
        });
        let after = mgr.snapshot();
        assert_eq!(after.routes.len(), 1);
        assert!(before.routes.is_empty(), "old snapshot must be unchanged");
    }

    #[test]
    fn validate_rejects_duplicate_listen() {
        let routes = vec![route(1, "127.0.0.1", 8080), route(2, "127.0.0.1", 8080)];
        let err = ConfigManager::validate(&routes).unwrap_err();
        assert!(err.to_string().contains("duplicate listen"), "got: {err}");
    }

    #[test]
    fn validate_rejects_invalid_listen_host() {
        let routes = vec![route(1, "not-an-ip", 8080)];
        assert!(ConfigManager::validate(&routes).is_err());
    }

    #[test]
    fn validate_accepts_distinct_listens() {
        let routes = vec![route(1, "127.0.0.1", 8080), route(2, "127.0.0.1", 8081)];
        ConfigManager::validate(&routes).unwrap();
    }

    fn http_route(id: u128, hostname: &str) -> ServerRoute {
        ServerRoute {
            id: RouteId::from_u128(id),
            name: format!("http-{id}"),
            route_type: RouteType::Http,
            enabled: true,
            node_id: NodeId::from_u128(id + 1000),
            listen_host: "0.0.0.0".to_string(),
            listen_port: 0,
            target_host: "192.168.1.100".to_string(),
            target_port: 80,
            hostname: Some(hostname.to_string()),
            tls_mode: None,
            limits: None,
        }
    }

    #[test]
    fn validate_accepts_http_routes_by_hostname() {
        // HTTP 路由无独立监听（listen_port=0），两个不同 hostname 不冲突。
        let routes = vec![
            http_route(1, "app.example.com"),
            http_route(2, "other.example.com"),
        ];
        ConfigManager::validate(&routes).unwrap();
    }

    #[test]
    fn validate_rejects_duplicate_hostname() {
        let routes = vec![
            http_route(1, "app.example.com"),
            http_route(2, "APP.EXAMPLE.COM"),
        ];
        let err = ConfigManager::validate(&routes).unwrap_err();
        assert!(err.to_string().contains("duplicate hostname"), "got: {err}");
    }

    #[test]
    fn validate_rejects_http_route_without_hostname() {
        let mut r = http_route(1, "app.example.com");
        r.hostname = None;
        assert!(ConfigManager::validate(&[r]).is_err());
    }

    #[test]
    fn broadcast_notifies_subscriber() {
        let mgr = ConfigManager::new();
        let mut rx = mgr.subscribe();
        mgr.replace(ConfigSnapshot {
            routes: vec![route(1, "127.0.0.1", 8080)],
        });
        assert!(rx.try_recv().is_ok(), "subscriber should receive broadcast");
    }
}
