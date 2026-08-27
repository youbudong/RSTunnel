//! 配置同步纯函数（T-18）：路由增量计算，无 IO，可被 cargo-fuzz 直接调用。
//!
//! 与 Agent 侧 `apply_route_delta` 对称：Server 用 [`compute_route_delta`] 由旧/新
//! 路由表算出增量，Agent 用 `apply_route_delta` 把增量落回本地（设计文档 §10）。

use tunnel_protocol::{RouteConfig, RouteDelta};

/// 计算旧 → 新的路由增量（按 `RouteConfig.id` 比对）。
///
/// - `added`：新有旧无；
/// - `updated`：两侧都有但内容不同；
/// - `removed`：旧有新无（仅存 id）。
pub fn compute_route_delta(old: &[RouteConfig], new: &[RouteConfig]) -> RouteDelta {
    use std::collections::HashMap;

    let old_by_id: HashMap<_, &RouteConfig> = old.iter().map(|r| (r.id, r)).collect();
    let new_by_id: HashMap<_, &RouteConfig> = new.iter().map(|r| (r.id, r)).collect();

    let mut added = Vec::new();
    let mut updated = Vec::new();
    for (id, new_route) in &new_by_id {
        match old_by_id.get(id) {
            None => added.push((*new_route).clone()),
            Some(old_route) if *old_route != *new_route => updated.push((*new_route).clone()),
            Some(_) => {}
        }
    }

    let removed: Vec<_> = old
        .iter()
        .filter(|r| !new_by_id.contains_key(&r.id))
        .map(|r| r.id)
        .collect();

    RouteDelta {
        added,
        updated,
        removed,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tunnel_protocol::RouteType;
    use uuid::Uuid;

    fn route(id: u128, name: &str, target_port: u16) -> RouteConfig {
        RouteConfig {
            id: Uuid::from_u128(id),
            name: name.to_string(),
            route_type: RouteType::Tcp,
            enabled: true,
            target_host: "192.168.1.100".to_string(),
            target_port,
            hostname: None,
            limits: None,
        }
    }

    #[test]
    fn identical_lists_yield_empty_delta() {
        let routes = vec![route(1, "a", 22), route(2, "b", 80)];
        let delta = compute_route_delta(&routes, &routes);
        assert!(delta.added.is_empty());
        assert!(delta.updated.is_empty());
        assert!(delta.removed.is_empty());
    }

    #[test]
    fn added_updated_removed_are_detected() {
        let old = vec![route(1, "a", 22), route(2, "b", 80)];
        let new = vec![route(1, "a", 2222), route(3, "c", 443)];
        let delta = compute_route_delta(&old, &new);

        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].id, Uuid::from_u128(3));

        assert_eq!(delta.updated.len(), 1);
        assert_eq!(delta.updated[0].id, Uuid::from_u128(1));
        assert_eq!(delta.updated[0].target_port, 2222);

        assert_eq!(delta.removed, vec![Uuid::from_u128(2)]);
    }

    #[test]
    fn reorder_only_is_not_an_update() {
        // 仅顺序不同、内容相同 → 无更新（按 id 对齐，顺序不敏感）。
        let a = vec![route(1, "a", 22), route(2, "b", 80)];
        let b = vec![route(2, "b", 80), route(1, "a", 22)];
        let delta = compute_route_delta(&a, &b);
        assert!(delta.added.is_empty());
        assert!(delta.updated.is_empty());
        assert!(delta.removed.is_empty());
    }
}
