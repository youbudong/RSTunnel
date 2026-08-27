//! Prometheus 指标（设计文档 §38）：Server 数据面/管理面指标 + Agent 心跳/重连指标。
//!
//! 全部通过 [`prometheus::default_registry`] 注册，`/metrics` 端点用 [`TextEncoder`]
//! 渲染（M10，T-38）。每个指标用 [`OnceLock`] 惰性注册，保证同一进程只注册一次
//! （默认 registry 重复注册会 panic）。

use std::sync::OnceLock;

use prometheus::{Gauge, IntCounter};

pub use prometheus::default_registry;

/// 定义并惰性注册一个指标，返回 `Option<&'static T>`（同名已注册/构造失败时 `None`）。
macro_rules! metric {
    ($name:ident, $ty:ty, $metric:literal, $help:literal) => {
        pub fn $name() -> Option<&'static $ty> {
            static CELL: OnceLock<Option<$ty>> = OnceLock::new();
            CELL.get_or_init(|| {
                let Ok(m) = <$ty>::new($metric, $help) else {
                    return None;
                };
                if default_registry().register(Box::new(m.clone())).is_err() {
                    return None;
                }
                Some(m)
            })
            .as_ref()
        }
    };
}

// ---- Agent 侧（T-11/T-12）----
metric!(
    agent_rtt_seconds,
    Gauge,
    "tunnel_agent_rtt_seconds",
    "Agent 心跳往返时间（秒）"
);
metric!(
    agent_reconnect_total,
    IntCounter,
    "tunnel_agent_reconnect_total",
    "Agent 自动重连次数"
);

// ---- Server 侧（T-38/§38）----
metric!(
    nodes_online,
    Gauge,
    "tunnel_nodes_online",
    "当前在线 Node 数"
);
metric!(nodes_total, Gauge, "tunnel_nodes_total", "已注册 Node 总数");
metric!(
    sessions_active,
    Gauge,
    "tunnel_sessions_active",
    "当前活跃 QUIC 会话数"
);
metric!(
    streams_active,
    Gauge,
    "tunnel_streams_active",
    "当前活跃数据面流数"
);
metric!(
    connections_total,
    IntCounter,
    "tunnel_connections_total",
    "数据面接受连接总数"
);
metric!(
    connections_failed,
    IntCounter,
    "tunnel_connections_failed",
    "数据面失败连接总数"
);
metric!(
    bytes_received_total,
    IntCounter,
    "tunnel_bytes_received_total",
    "Server 收到字节总数"
);
metric!(
    bytes_sent_total,
    IntCounter,
    "tunnel_bytes_sent_total",
    "Server 发送字节总数"
);
metric!(
    udp_packets_total,
    IntCounter,
    "tunnel_udp_packets_total",
    "UDP 数据包总数"
);
metric!(
    route_errors_total,
    IntCounter,
    "tunnel_route_errors_total",
    "Route 查找/转发错误总数"
);

/// 注册 §38 全部指标（T-38）。幂等：重复调用安全（`OnceLock` 只注册一次）。
pub fn register_all() -> prometheus::Result<()> {
    let _ = nodes_online();
    let _ = nodes_total();
    let _ = sessions_active();
    let _ = streams_active();
    let _ = connections_total();
    let _ = connections_failed();
    let _ = bytes_received_total();
    let _ = bytes_sent_total();
    let _ = udp_packets_total();
    let _ = route_errors_total();
    let _ = agent_rtt_seconds();
    let _ = agent_reconnect_total();
    Ok(())
}

/// 渲染默认 registry 为 Prometheus 文本格式（供 `/metrics` 端点，T-38）。
pub fn render() -> String {
    prometheus::TextEncoder::new()
        .encode_to_string(&default_registry().gather())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn register_all_is_idempotent_and_renders_names() {
        register_all().unwrap();
        register_all().unwrap();
        let text = render();
        for name in [
            "tunnel_nodes_online",
            "tunnel_nodes_total",
            "tunnel_sessions_active",
            "tunnel_streams_active",
            "tunnel_connections_total",
            "tunnel_connections_failed",
            "tunnel_bytes_received_total",
            "tunnel_bytes_sent_total",
            "tunnel_udp_packets_total",
            "tunnel_route_errors_total",
            "tunnel_agent_reconnect_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
    }

    #[test]
    fn counters_and_gauges_update() {
        register_all().unwrap();
        nodes_online().unwrap().set(3.0);
        connections_total().unwrap().inc();
        connections_total().unwrap().inc();
        let text = render();
        assert!(text.contains("tunnel_nodes_online 3"));
        assert!(text.contains("tunnel_connections_total 2"));
    }
}
