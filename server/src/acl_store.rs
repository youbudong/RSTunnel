//! 数据面 ACL 存储（T-34）：从 DB 加载 `acl_rules`，为每条入向连接提供 [`AclStore::allows`] 判定。
//!
//! 设计（§30/§1400）：全局规则（`route_id = NULL`）作用于所有 Route；Route 专属规则仅作用于该 Route。
//! 快照用 [`arc_swap::ArcSwap`] 无锁读 + 原子替换（REST 变更后调用 [`AclStore::reload`] 热生效）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tunnel_core::{evaluate_acl, RouteId};
use tunnel_db::{AclRuleRow, Db};
use tunnel_protocol::{AclAction, AclRule};

/// ACL 快照：全局规则 + 按 Route 分组的规则。
#[derive(Debug, Default)]
struct AclSnapshot {
    global: Vec<AclRule>,
    by_route: HashMap<RouteId, Vec<AclRule>>,
}

/// 数据面 ACL 判定器。空（未配置任何规则）时对所有连接放行。
#[derive(Debug, Default)]
pub struct AclStore {
    snapshot: ArcSwap<AclSnapshot>,
}

impl AclStore {
    pub fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(AclSnapshot::default()),
        }
    }

    /// 从 DB 重新加载全部规则并原子替换快照。加载失败保留旧快照并告警（不 panic）。
    pub async fn reload(&self, db: &Db) {
        let rows = match db.list_acl_rules().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "reload ACL rules failed; keeping previous snapshot");
                return;
            }
        };
        let mut snap = AclSnapshot::default();
        for row in rows {
            let Some(rule) = row_to_rule(&row) else {
                continue;
            };
            match row.route_id.as_deref() {
                Some(rid) => match RouteId::parse_str(rid) {
                    Ok(rid) => snap.by_route.entry(rid).or_default().push(rule),
                    Err(_) => tracing::debug!(rid, "skip ACL rule with invalid route_id"),
                },
                None => snap.global.push(rule),
            }
        }
        self.snapshot.store(Arc::new(snap));
    }

    /// 判定一条入向连接是否放行。
    ///
    /// - 全局规则 + 该 Route 专属规则均参与匹配；
    /// - 两者皆空 → 放行（未配置 ACL 的 Route 保持开放）；
    /// - 否则交 [`evaluate_acl`]（deny 优先、默认 deny）。
    pub fn allows(
        &self,
        route_id: RouteId,
        source: &SocketAddr,
        target_host: &str,
        target_port: u16,
    ) -> bool {
        let snap = self.snapshot.load();
        let route_rules = snap.by_route.get(&route_id);
        if snap.global.is_empty() && route_rules.is_none_or(|r| r.is_empty()) {
            return true;
        }
        let mut merged = Vec::with_capacity(snap.global.len() + route_rules.map_or(0, |r| r.len()));
        merged.extend(snap.global.iter().cloned());
        if let Some(r) = route_rules {
            merged.extend(r.iter().cloned());
        }
        evaluate_acl(&merged, source, target_host, target_port)
    }
}

/// `AclRuleRow` → wire `AclRule`。非法 action / 越界 port 视为无效规则（保守跳过）。
fn row_to_rule(row: &AclRuleRow) -> Option<AclRule> {
    let action = match row.action.as_str() {
        "allow" => AclAction::Allow,
        "deny" => AclAction::Deny,
        _ => return None,
    };
    Some(AclRule {
        action,
        source_cidr: row.source_cidr.clone(),
        source_port: row.source_port.and_then(|p| u16::try_from(p).ok()),
        target_host: row.target_host.clone(),
        target_port: row.target_port.and_then(|p| u16::try_from(p).ok()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn src(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::V4(std::net::SocketAddrV4::new(ip.parse().unwrap(), port))
    }

    fn rule(action: AclAction, cidr: Option<&str>) -> AclRule {
        AclRule {
            action,
            source_cidr: cidr.map(str::to_string),
            source_port: None,
            target_host: None,
            target_port: None,
        }
    }

    #[test]
    fn empty_store_allows_all() {
        let store = AclStore::new();
        let route = RouteId::from_u128(1);
        assert!(store.allows(route, &src("10.0.0.1", 1234), "h", 80));
        assert!(store.allows(route, &src("8.8.8.8", 1), "h", 80));
    }

    #[test]
    fn global_deny_applies_to_any_route() {
        let mut snap = AclSnapshot::default();
        snap.global.push(rule(AclAction::Deny, Some("0.0.0.0/0")));
        let store = AclStore {
            snapshot: ArcSwap::from_pointee(snap),
        };
        assert!(!store.allows(RouteId::from_u128(1), &src("10.0.0.1", 1), "h", 80));
        assert!(!store.allows(RouteId::from_u128(2), &src("192.168.1.1", 1), "h", 80));
    }

    #[test]
    fn route_scoped_rule_only_affects_that_route() {
        let mut snap = AclSnapshot::default();
        snap.by_route
            .entry(RouteId::from_u128(1))
            .or_default()
            .push(rule(AclAction::Deny, Some("0.0.0.0/0")));
        let store = AclStore {
            snapshot: ArcSwap::from_pointee(snap),
        };
        // route 1 被 deny；route 2 无规则 → 放行。
        assert!(!store.allows(RouteId::from_u128(1), &src("10.0.0.1", 1), "h", 80));
        assert!(store.allows(RouteId::from_u128(2), &src("10.0.0.1", 1), "h", 80));
    }

    #[test]
    fn row_to_rule_converts_and_rejects_invalid() {
        let ok = AclRuleRow {
            id: "1".into(),
            tenant_id: "default".into(),
            route_id: None,
            action: "allow".into(),
            source_cidr: Some("10.0.0.0/8".into()),
            source_port: Some(8080),
            target_host: None,
            target_port: None,
            created_at: "t".into(),
        };
        let r = row_to_rule(&ok).unwrap();
        assert_eq!(r.action, AclAction::Allow);
        assert_eq!(r.source_port, Some(8080));

        let bad = AclRuleRow {
            action: "bogus".into(),
            ..ok
        };
        assert!(row_to_rule(&bad).is_none());
    }
}
