//! Route 模型与 listen → route 查找表（设计文档 §11/§83）。
//!
//! `ServerRoute` 是 Server 侧的 Route 视图（含 listen 地址与 node_id，区别于 Agent 侧的
//! [`tunnel_protocol::RouteConfig`]）。[`RouteTable`] 维护 `listen 地址 → Route` 映射，
//! 并在插入时校验重复监听冲突（T-14）。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use thiserror::Error;
use tunnel_core::{NodeId, RouteId};
use tunnel_db::RouteRow;
use tunnel_protocol::{Limits, RouteConfig, RouteType};

/// Server 侧的 Route 视图。
#[derive(Debug, Clone)]
pub struct ServerRoute {
    pub id: RouteId,
    pub name: String,
    pub route_type: RouteType,
    pub enabled: bool,
    pub node_id: NodeId,
    pub listen_host: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub hostname: Option<String>,
    pub tls_mode: Option<String>,
    pub limits: Option<Limits>,
}

impl ServerRoute {
    /// 监听地址（`listen_host:listen_port`）。`listen_host` 为 IP 字面量。
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        let ip: IpAddr = self
            .listen_host
            .parse()
            .with_context(|| format!("invalid listen_host {:?}", self.listen_host))?;
        Ok(SocketAddr::new(ip, self.listen_port))
    }

    /// 转成下发 Agent 的 wire 视图 [`RouteConfig`]（不含 server 侧专用的 listen/node 字段）。
    pub fn to_route_config(&self) -> RouteConfig {
        RouteConfig {
            id: self.id,
            name: self.name.clone(),
            route_type: self.route_type,
            enabled: self.enabled,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            hostname: self.hostname.clone(),
            limits: self.limits.clone(),
        }
    }

    /// HTTP/HTTPS 路由的 Host 键（小写归一化，Host 头大小写不敏感）；非 HTTP 路由返回 `None`。
    pub fn host_key(&self) -> Option<String> {
        match self.route_type {
            RouteType::Http | RouteType::Https => {
                self.hostname.as_ref().map(|h| h.to_ascii_lowercase())
            }
            _ => None,
        }
    }

    /// 是否 TLS 透传：HTTPS 路由且 `tls_mode = 'passthrough'`（Server 仅按 SNI 路由，不解密）。
    pub fn tls_passthrough(&self) -> bool {
        self.route_type == RouteType::Https && self.tls_mode.as_deref() == Some("passthrough")
    }
}

impl TryFrom<RouteRow> for ServerRoute {
    type Error = anyhow::Error;

    fn try_from(r: RouteRow) -> Result<Self> {
        let route_type = match r.route_type.as_str() {
            "tcp" => RouteType::Tcp,
            "udp" => RouteType::Udp,
            "http" => RouteType::Http,
            "https" => RouteType::Https,
            other => bail!("unknown route type {other:?}"),
        };
        let listen_host = r.listen_host.unwrap_or_else(|| "0.0.0.0".to_string());
        // HTTP/HTTPS 路由无独立监听（共享 `http.bind`），`listen_port` 置 0；TCP/UDP 必须提供。
        let listen_port = match route_type {
            RouteType::Http | RouteType::Https => 0,
            _ => r
                .listen_port
                .context("route has no listen_port")?
                .try_into()
                .context("listen_port out of range")?,
        };
        let target_port = r
            .target_port
            .try_into()
            .context("target_port out of range")?;
        let limits = match r.limits {
            Some(s) if !s.is_empty() => {
                Some(serde_json::from_str(&s).context("parse route limits")?)
            }
            _ => None,
        };
        Ok(Self {
            id: RouteId::parse_str(&r.id).context("invalid route id")?,
            name: r.name,
            route_type,
            enabled: r.enabled,
            node_id: NodeId::parse_str(&r.node_id).context("invalid node id")?,
            listen_host,
            listen_port,
            target_host: r.target_host,
            target_port,
            hostname: r.hostname,
            tls_mode: r.tls_mode,
            limits,
        })
    }
}

/// 插入 Route 失败的原因。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteTableError {
    #[error("invalid listen address: {0}")]
    InvalidListenAddr(String),
    #[error("duplicate listen {addr}: routes {existing} and {incoming}")]
    DuplicateListen {
        addr: SocketAddr,
        existing: RouteId,
        incoming: RouteId,
    },
}

/// listen 地址 → Route 查找表（[`DashMap`] 实现，读多写少）。
#[derive(Debug, Default)]
pub struct RouteTable {
    by_listen: DashMap<SocketAddr, Arc<ServerRoute>>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条 Route，检测重复监听冲突。成功后以 `listen_addr` 为键。
    pub fn insert(&self, route: ServerRoute) -> Result<(), RouteTableError> {
        let addr = route
            .listen_addr()
            .map_err(|e| RouteTableError::InvalidListenAddr(e.to_string()))?;
        if let Some(existing) = self.by_listen.get(&addr) {
            return Err(RouteTableError::DuplicateListen {
                addr,
                existing: existing.value().id,
                incoming: route.id,
            });
        }
        self.by_listen.insert(addr, Arc::new(route));
        Ok(())
    }

    /// 按监听地址查找 Route。
    pub fn lookup(&self, addr: &SocketAddr) -> Option<Arc<ServerRoute>> {
        self.by_listen.get(addr).map(|r| r.value().clone())
    }

    /// 移除并返回某监听地址对应的 Route（热更新删除/禁用时使用）。
    pub fn remove(&self, addr: &SocketAddr) -> Option<Arc<ServerRoute>> {
        self.by_listen.remove(addr).map(|(_, v)| v)
    }

    /// 全部 Route 快照。
    pub fn routes(&self) -> Vec<Arc<ServerRoute>> {
        self.by_listen.iter().map(|r| r.value().clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.by_listen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_listen.is_empty()
    }
}

/// 插入 Host 路由失败的原因。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostTableError {
    #[error("duplicate hostname {host}: routes {existing} and {incoming}")]
    DuplicateHostname {
        host: String,
        existing: RouteId,
        incoming: RouteId,
    },
}

/// Host → Route 查找表（HTTP/HTTPS 路由按 Host 而非 listen 地址路由，设计文档 §52）。
///
/// 键为小写归一化的 hostname；非 HTTP 路由（无 hostname）在插入时被忽略。
#[derive(Debug, Default)]
pub struct HostTable {
    by_host: DashMap<String, Arc<ServerRoute>>,
}

impl HostTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条 HTTP/HTTPS 路由，检测重复 hostname 冲突；非 HTTP 路由忽略（返回 Ok）。
    pub fn insert(&self, route: ServerRoute) -> Result<(), HostTableError> {
        let Some(host) = route.host_key() else {
            return Ok(());
        };
        if let Some(existing) = self.by_host.get(&host) {
            return Err(HostTableError::DuplicateHostname {
                host,
                existing: existing.value().id,
                incoming: route.id,
            });
        }
        self.by_host.insert(host, Arc::new(route));
        Ok(())
    }

    /// 按 Host 查找路由（大小写不敏感）。
    pub fn lookup(&self, host: &str) -> Option<Arc<ServerRoute>> {
        self.by_host
            .get(&host.to_ascii_lowercase())
            .map(|r| r.value().clone())
    }

    /// 移除并返回某 hostname 对应的路由（热更新删除/禁用时使用）。
    pub fn remove(&self, host: &str) -> Option<Arc<ServerRoute>> {
        self.by_host
            .remove(&host.to_ascii_lowercase())
            .map(|(_, v)| v)
    }

    /// 热更新（T-19）：按全量路由重建 Host 表（仅启用的 HTTP/HTTPS 路由）。
    /// 与启动时构建一致；删除/禁用/改动主机名的路由随全量重建自然移除或更新。
    pub fn reconcile(&self, routes: &[ServerRoute]) {
        self.by_host.clear();
        for route in routes.iter().filter(|r| r.enabled) {
            if let Some(host) = route.host_key() {
                self.by_host.insert(host, Arc::new(route.clone()));
            }
        }
    }

    /// 全部 Host 路由快照。
    pub fn routes(&self) -> Vec<Arc<ServerRoute>> {
        self.by_host.iter().map(|r| r.value().clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn route(id: u128, name: &str, listen: &str, port: u16) -> ServerRoute {
        ServerRoute {
            id: RouteId::from_u128(id),
            name: name.to_string(),
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
    fn insert_and_lookup() {
        let t = RouteTable::new();
        t.insert(route(1, "a", "127.0.0.1", 8080)).unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let found = t.lookup(&addr).unwrap();
        assert_eq!(found.name, "a");
        assert_eq!(found.node_id, NodeId::from_u128(1001));
    }

    #[test]
    fn duplicate_listen_is_rejected() {
        let t = RouteTable::new();
        t.insert(route(1, "a", "127.0.0.1", 8080)).unwrap();
        let err = t.insert(route(2, "b", "127.0.0.1", 8080)).unwrap_err();
        match err {
            RouteTableError::DuplicateListen {
                existing, incoming, ..
            } => {
                assert_eq!(existing, RouteId::from_u128(1));
                assert_eq!(incoming, RouteId::from_u128(2));
            }
            other => panic!("expected DuplicateListen, got {other:?}"),
        }
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn invalid_listen_host_is_rejected() {
        let t = RouteTable::new();
        let err = t.insert(route(1, "a", "not-an-ip", 8080)).unwrap_err();
        assert!(matches!(err, RouteTableError::InvalidListenAddr(_)));
    }

    #[test]
    fn try_from_http_route_allows_missing_listen_port() {
        let row = RouteRow {
            id: "11111111-1111-4111-8111-111111111111".to_string(),
            name: "web".to_string(),
            node_id: "22222222-2222-4222-8222-222222222222".to_string(),
            route_type: "http".to_string(),
            enabled: true,
            listen_host: None,
            listen_port: None,
            hostname: Some("app.example.com".to_string()),
            target_host: "192.168.1.100".to_string(),
            target_port: 80,
            tls_mode: None,
            limits: None,
        };
        let r = ServerRoute::try_from(row).unwrap();
        assert_eq!(r.route_type, RouteType::Http);
        // 无独立监听：listen_host 缺省 0.0.0.0，listen_port 置 0。
        assert_eq!(r.listen_host, "0.0.0.0");
        assert_eq!(r.listen_port, 0);
        assert_eq!(r.host_key(), Some("app.example.com".to_string()));
    }

    #[test]
    fn try_from_route_row_parses_fields() {
        let row = RouteRow {
            id: "11111111-1111-4111-8111-111111111111".to_string(),
            name: "ssh".to_string(),
            node_id: "22222222-2222-4222-8222-222222222222".to_string(),
            route_type: "tcp".to_string(),
            enabled: true,
            listen_host: Some("127.0.0.1".to_string()),
            listen_port: Some(2222),
            hostname: None,
            target_host: "192.168.1.100".to_string(),
            target_port: 22,
            tls_mode: None,
            limits: None,
        };
        let r = ServerRoute::try_from(row).unwrap();
        assert_eq!(r.route_type, RouteType::Tcp);
        assert!(r.enabled);
        assert_eq!(r.listen_addr().unwrap(), "127.0.0.1:2222".parse().unwrap());
        assert_eq!(r.target_port, 22);
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
    fn host_key_lowercases_and_is_http_only() {
        assert_eq!(
            http_route(1, "App.Example.COM").host_key(),
            Some("app.example.com".to_string())
        );
        // TCP 路由无 hostname，host_key 为 None。
        assert_eq!(route(1, "a", "127.0.0.1", 8080).host_key(), None);
    }

    #[test]
    fn host_table_lookup_is_case_insensitive() {
        let t = HostTable::new();
        t.insert(http_route(1, "App.Example.COM")).unwrap();
        let found = t.lookup("APP.example.com").unwrap();
        assert_eq!(found.id, RouteId::from_u128(1));
    }

    #[test]
    fn host_table_ignores_non_http_routes() {
        let t = HostTable::new();
        t.insert(route(1, "a", "127.0.0.1", 8080)).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn host_table_rejects_duplicate_hostname() {
        let t = HostTable::new();
        t.insert(http_route(1, "app.example.com")).unwrap();
        let err = t.insert(http_route(2, "APP.EXAMPLE.COM")).unwrap_err();
        let HostTableError::DuplicateHostname {
            host,
            existing,
            incoming,
        } = err;
        assert_eq!(host, "app.example.com");
        assert_eq!(existing, RouteId::from_u128(1));
        assert_eq!(incoming, RouteId::from_u128(2));
        assert_eq!(t.len(), 1);
    }
}
