//! ACL 评估（T-34，设计文档 §30/§1400）：`acl_rules` 匹配（CIDR/port/hostname），默认 deny。
//!
//! 纯函数、无 IO，供 Server 数据面在每条入向连接上调用；`AclRule` 复用 [`tunnel_protocol::AclRule`]。
//!
//! 语义：
//! - 规则按 `(source_cidr, source_port, target_host, target_port)` 四维匹配，`None` 字段表示「任意」；
//! - `deny` 规则一旦命中立即拒绝（deny 优先，即使前面有 allow）；
//! - 无任何 `allow` 命中 → 拒绝（**默认 deny**；空规则集也拒绝，由调用方决定是否对「未配置 ACL 的
//!   route」提前放行）。

use std::net::{IpAddr, SocketAddr};

use tunnel_common::cidr::cidr_matches;
use tunnel_protocol::{AclAction, AclRule};

/// 该规则是否命中给定的连接四元组（源 IP/port + 目标 host/port）。
///
/// 每个 `Some` 字段都需匹配才视为命中；`None` 字段为「任意」。`target_host` 匹配大小写不敏感
/// （hostname 语义），`source_cidr` 用 [`cidr_matches`]（非法 CIDR 不命中，保守拒绝）。
pub fn rule_matches(
    rule: &AclRule,
    source_ip: IpAddr,
    source_port: u16,
    target_host: &str,
    target_port: u16,
) -> bool {
    if let Some(cidr) = &rule.source_cidr {
        if !cidr_matches(cidr, source_ip) {
            return false;
        }
    }
    if let Some(port) = rule.source_port {
        if port != source_port {
            return false;
        }
    }
    if let Some(host) = &rule.target_host {
        if !host.eq_ignore_ascii_case(target_host) {
            return false;
        }
    }
    if let Some(port) = rule.target_port {
        if port != target_port {
            return false;
        }
    }
    true
}

/// 评估一组 ACL 规则对一条连接是否放行。
///
/// 返回 `true` = 放行，`false` = 拒绝。规则通常已按 route 作用域过滤（调用方合并全局 + 本 route
/// 规则后传入）；空规则集返回 `false`（默认 deny），调用方应在前置判断「route 无 ACL 则放行」。
pub fn evaluate_acl(
    rules: &[AclRule],
    source: &SocketAddr,
    target_host: &str,
    target_port: u16,
) -> bool {
    let mut allowed = false;
    for rule in rules {
        if rule_matches(rule, source.ip(), source.port(), target_host, target_port) {
            match rule.action {
                AclAction::Deny => return false,
                AclAction::Allow => allowed = true,
            }
        }
    }
    allowed
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::SocketAddrV4;

    fn allow_cidr(cidr: &str) -> AclRule {
        AclRule {
            action: AclAction::Allow,
            source_cidr: Some(cidr.to_string()),
            source_port: None,
            target_host: None,
            target_port: None,
        }
    }

    fn deny_cidr(cidr: &str) -> AclRule {
        AclRule {
            action: AclAction::Deny,
            source_cidr: Some(cidr.to_string()),
            source_port: None,
            target_host: None,
            target_port: None,
        }
    }

    fn src(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(ip.parse().unwrap(), port))
    }

    #[test]
    fn empty_rules_default_deny() {
        assert!(!evaluate_acl(&[], &src("10.0.0.1", 1234), "host", 80));
    }

    #[test]
    fn single_allow_matches() {
        let rules = vec![allow_cidr("10.0.0.0/8")];
        assert!(evaluate_acl(&rules, &src("10.1.2.3", 1234), "host", 80));
        // 源不在 allow 范围内 → 默认 deny。
        assert!(!evaluate_acl(&rules, &src("192.168.1.1", 1234), "host", 80));
    }

    #[test]
    fn deny_overrides_allow() {
        // allow 10/8 但 deny 10.1.0.0/16 → 命中 deny，拒绝。
        let rules = vec![allow_cidr("10.0.0.0/8"), deny_cidr("10.1.0.0/16")];
        assert!(!evaluate_acl(&rules, &src("10.1.2.3", 1234), "host", 80));
        // 10.2.x 命中 allow 不命中 deny → 放行。
        assert!(evaluate_acl(&rules, &src("10.2.0.1", 1234), "host", 80));
    }

    #[test]
    fn source_port_matching() {
        let rules = vec![AclRule {
            action: AclAction::Allow,
            source_cidr: None,
            source_port: Some(8080),
            target_host: None,
            target_port: None,
        }];
        assert!(evaluate_acl(&rules, &src("1.2.3.4", 8080), "h", 80));
        assert!(!evaluate_acl(&rules, &src("1.2.3.4", 8081), "h", 80));
    }

    #[test]
    fn target_host_and_port_matching() {
        let rules = vec![AclRule {
            action: AclAction::Allow,
            source_cidr: None,
            source_port: None,
            target_host: Some("db.internal".to_string()),
            target_port: Some(5432),
        }];
        // hostname 大小写不敏感。
        assert!(evaluate_acl(
            &rules,
            &src("1.2.3.4", 1),
            "DB.Internal",
            5432
        ));
        assert!(!evaluate_acl(
            &rules,
            &src("1.2.3.4", 1),
            "db.internal",
            5433
        ));
        assert!(!evaluate_acl(
            &rules,
            &src("1.2.3.4", 1),
            "web.internal",
            5432
        ));
    }

    #[test]
    fn catch_all_deny_rejects_everything() {
        let rules = vec![allow_cidr("10.0.0.0/8"), deny_cidr("0.0.0.0/0")];
        // 0.0.0.0/0 命中所有 IPv4 → 即使 10.x 命中 allow 也被 deny 覆盖。
        assert!(!evaluate_acl(&rules, &src("10.5.5.5", 1), "h", 80));
    }
}
