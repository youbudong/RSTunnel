//! CIDR / IP 前缀匹配（T-34/§106）：纯函数，无 IO，供 Server ACL 与 Agent 目标校验复用。
//!
//! 支持 IPv4 与 IPv6 的 CIDR（`a.b.c.d/n`、`::/n`）及裸 IP（等价于全前缀，如 `10.0.0.1`
//! 视作 `/32`、`::1` 视作 `/128`）。输入非法时 [`cidr_matches`] 返回 `false`（保守拒绝），
//! [`parse_cidr`] 返回 `None`。

use std::net::IpAddr;

/// 解析 `a.b.c.d/n` 或裸 IP 为 `(网络地址, 前缀长度)`。
///
/// - 裸 IP 的 prefix 按地址族全宽（v4=32，v6=128）；
/// - 非法 IP / 越界前缀 / 多余字段返回 `None`。
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (host, prefix) = match s.split_once('/') {
        Some((h, p)) => {
            if p.is_empty() || p.contains('/') {
                return None;
            }
            let prefix: u8 = p.parse().ok()?;
            (h, prefix)
        }
        None => {
            // 裸 IP：前缀按地址族全宽。
            let ip: IpAddr = s.parse().ok()?;
            let full = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            return Some((ip, full));
        }
    };

    let ip: IpAddr = host.parse().ok()?;
    // 前缀越界即非法（v4 与 v6 各自校验）。
    let full = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > full {
        return None;
    }
    Some((ip, prefix))
}

/// 判断 `ip` 是否落在 CIDR 范围内。非法 CIDR 返回 `false`（保守拒绝）。
pub fn cidr_matches(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, prefix)) = parse_cidr(cidr) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            // 将 prefix 右移为掩码；prefix 已在 parse 阶段校验 ≤ 32。
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let net = u32::from(net) & mask;
            let ip = u32::from(ip) & mask;
            net == ip
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let net = u128::from(net) & mask;
            let ip = u128::from(ip) & mask;
            net == ip
        }
        // 地址族不一致：不匹配。
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::IpAddr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn parses_cidr_and_bare_ip() {
        let (ip, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(ip, v4("10.0.0.0"));
        assert_eq!(prefix, 8);

        let (ip, prefix) = parse_cidr("192.168.1.5").unwrap();
        assert_eq!(ip, v4("192.168.1.5"));
        assert_eq!(prefix, 32);

        let (ip, prefix) = parse_cidr("::/0").unwrap();
        assert_eq!(ip, v6("::"));
        assert_eq!(prefix, 0);
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("::/129").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/8/extra").is_none());
        assert!(parse_cidr("").is_none());
    }

    #[test]
    fn ipv4_cidr_matching() {
        assert!(cidr_matches("10.0.0.0/8", v4("10.1.2.3")));
        assert!(!cidr_matches("10.0.0.0/8", v4("11.0.0.1")));
        assert!(cidr_matches("192.168.1.0/24", v4("192.168.1.42")));
        assert!(!cidr_matches("192.168.1.0/24", v4("192.168.2.1")));
        // /0 匹配全部 IPv4。
        assert!(cidr_matches("0.0.0.0/0", v4("203.0.113.7")));
        // 裸 IP 精确匹配。
        assert!(cidr_matches("10.0.0.1", v4("10.0.0.1")));
        assert!(!cidr_matches("10.0.0.1", v4("10.0.0.2")));
    }

    #[test]
    fn ipv6_cidr_matching() {
        assert!(cidr_matches("fd00::/8", v6("fd12:3456::1")));
        assert!(!cidr_matches("fd00::/8", v6("fe80::1")));
        assert!(cidr_matches("::/0", v6("2001:db8::1")));
    }

    #[test]
    fn address_family_mismatch_never_matches() {
        assert!(!cidr_matches("10.0.0.0/8", v6("::1")));
        assert!(!cidr_matches("::/0", v4("10.0.0.1")));
    }

    #[test]
    fn invalid_cidr_is_conservatively_rejected() {
        assert!(!cidr_matches("bogus", v4("10.0.0.1")));
    }
}
