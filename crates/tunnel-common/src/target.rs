//! 目标地址 SSRF 校验（T-37/§106）：纯函数，判断一个 IP 是否属于禁止作为 Tunnel
//! 目标的地址类别——loopback / link-local / multicast / metadata（云厂商元数据端点）。
//!
//! 与 Agent 侧 `allow/deny_targets`（CIDR）不同，这里是 Server 在配置 Route 时的静态
//! IP 字面量检查：目标写成 `127.0.0.1`、`169.254.169.254` 这类地址时直接拒绝，除非
//! 管理员显式放行（`security.allow_unsafe_targets`）。私有地址（10/8、172.16/12、
//! 192.168/16、fc00::/7）是内网穿透的合法目标，**不**在拒绝之列。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cidr::cidr_matches;

/// 返回禁止目标地址的类别名（如 `loopback`）；若 `ip` 可作为目标返回 `None`。
pub fn forbidden_target_category(ip: IpAddr) -> Option<&'static str> {
    // IPv4-mapped IPv6（`::ffff:a.b.c.d`）按内嵌 IPv4 处理，避免绕过 v4 规则。
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(ip) => forbidden_v4(ip),
        IpAddr::V6(ip) => forbidden_v6(ip),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<&'static str> {
    // 云厂商元数据端点（169.254.169.254）虽落在 link-local 内，单列以给出更明确报错。
    if ip == Ipv4Addr::new(169, 254, 169, 254) {
        return Some("metadata");
    }
    let ip = IpAddr::V4(ip);
    if cidr_matches("127.0.0.0/8", ip) {
        Some("loopback")
    } else if cidr_matches("169.254.0.0/16", ip) {
        Some("link-local")
    } else if cidr_matches("224.0.0.0/4", ip) {
        Some("multicast")
    } else {
        None
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let ip = IpAddr::V6(ip);
    if cidr_matches("::1", ip) {
        Some("loopback")
    } else if cidr_matches("fe80::/10", ip) {
        Some("link-local")
    } else if cidr_matches("ff00::/8", ip) {
        Some("multicast")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::IpAddr;

    fn cat(s: &str) -> Option<&'static str> {
        forbidden_target_category(s.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn rejects_loopback() {
        assert_eq!(cat("127.0.0.1"), Some("loopback"));
        assert_eq!(cat("127.8.9.10"), Some("loopback"));
        assert_eq!(cat("::1"), Some("loopback"));
    }

    #[test]
    fn rejects_link_local() {
        assert_eq!(cat("169.254.1.2"), Some("link-local"));
        assert_eq!(cat("fe80::1"), Some("link-local"));
    }

    #[test]
    fn rejects_multicast() {
        assert_eq!(cat("224.0.0.1"), Some("multicast"));
        assert_eq!(cat("239.255.255.255"), Some("multicast"));
        assert_eq!(cat("ff02::1"), Some("multicast"));
    }

    #[test]
    fn rejects_metadata_service() {
        assert_eq!(cat("169.254.169.254"), Some("metadata"));
    }

    #[test]
    fn allows_private_and_public() {
        // 私有地址是内网穿透的合法目标。
        assert_eq!(cat("192.168.1.100"), None);
        assert_eq!(cat("10.0.0.5"), None);
        assert_eq!(cat("172.16.0.1"), None);
        assert_eq!(cat("fd12::1"), None);
        // 公网地址放行。
        assert_eq!(cat("8.8.8.8"), None);
        assert_eq!(cat("203.0.113.10"), None);
        assert_eq!(cat("2001:db8::1"), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_checked_as_v4() {
        assert_eq!(cat("::ffff:169.254.169.254"), Some("metadata"));
        assert_eq!(cat("::ffff:127.0.0.1"), Some("loopback"));
        assert_eq!(cat("::ffff:192.168.1.1"), None);
    }
}
