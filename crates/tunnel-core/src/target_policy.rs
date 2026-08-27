//! Agent 本地目标策略（T-34f/§33）：`allow_targets` / `deny_targets` 的纯函数判定。
//!
//! 与数据面 ACL（[`crate::acl`]）不同，这里约束的是 Agent 出站目标 IP：`allow` 为白名单、
//! `deny` 为黑名单；显式 `allow` 优先于 `deny`（允许管理员放行 localhost/link-local）。
//! 非法 CIDR 不匹配（对 `deny` 而言偏宽松，应在配置层 `validate` 预先拦截非法 CIDR）。

use std::net::IpAddr;

use tunnel_common::cidr::cidr_matches;

/// 判定目标 IP 是否放行。
///
/// 语义：
/// 1. 命中 `allow` → 放行（显式允许优先于 deny）；
/// 2. 命中 `deny` → 拒绝；
/// 3. `allow` 非空（白名单模式）→ 其余一律拒绝；
/// 4. 默认放行。
pub fn target_allowed(allow: &[String], deny: &[String], ip: IpAddr) -> bool {
    if allow.iter().any(|c| cidr_matches(c, ip)) {
        return true;
    }
    if deny.iter().any(|c| cidr_matches(c, ip)) {
        return false;
    }
    allow.is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::IpAddr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn default_deny_blocks_loopback_and_link_local() {
        let allow: Vec<String> = Vec::new();
        let deny = vec!["127.0.0.0/8".to_string(), "169.254.0.0/16".to_string()];
        assert!(!target_allowed(&allow, &deny, v4("127.0.0.1")));
        assert!(!target_allowed(&allow, &deny, v4("169.254.169.254")));
        // 其它地址默认放行。
        assert!(target_allowed(&allow, &deny, v4("192.168.1.5")));
    }

    #[test]
    fn explicit_allow_overrides_deny() {
        let allow = vec!["127.0.0.0/8".to_string()];
        let deny = vec!["127.0.0.0/8".to_string(), "169.254.0.0/16".to_string()];
        assert!(target_allowed(&allow, &deny, v4("127.0.0.1")));
        // 未显式允许的 deny 仍拒绝。
        assert!(!target_allowed(&allow, &deny, v4("169.254.169.254")));
    }

    #[test]
    fn non_empty_allow_acts_as_allowlist() {
        let allow = vec!["192.168.1.0/24".to_string()];
        let deny: Vec<String> = Vec::new();
        assert!(target_allowed(&allow, &deny, v4("192.168.1.42")));
        // 白名单外的地址（即便不在 deny）也被拒绝。
        assert!(!target_allowed(&allow, &deny, v4("10.0.0.1")));
    }

    #[test]
    fn invalid_cidr_never_matches() {
        let allow: Vec<String> = Vec::new();
        let deny = vec!["bogus".to_string()];
        // 非法 deny 不命中 → 默认放行（配置层应已校验）。
        assert!(target_allowed(&allow, &deny, v4("10.0.0.1")));
    }

    #[test]
    fn ipv6_loopback_covered_by_full_prefix() {
        let allow: Vec<String> = Vec::new();
        let deny = vec!["::1/128".to_string()];
        assert!(!target_allowed(
            &allow,
            &deny,
            "::1".parse::<IpAddr>().unwrap()
        ));
        assert!(target_allowed(
            &allow,
            &deny,
            "2001:db8::1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn ipv4_bare_ip_is_exact_match() {
        let allow: Vec<String> = Vec::new();
        let deny = vec!["10.0.0.1".to_string()];
        assert!(!target_allowed(&allow, &deny, v4("10.0.0.1")));
        assert!(target_allowed(&allow, &deny, v4("10.0.0.2")));
    }
}
