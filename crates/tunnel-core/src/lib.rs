//! 共享类型与抽象。
//!
//! 复用 `tunnel-protocol` 的 wire 类型（`RouteConfig` 等）；本 crate 提供领域别名与
//! 高层抽象。核心 trait（`TunnelTransport`/`RouteHandler`/`TargetConnector`）在 M2/M4
//! 接入传输层后落地。

pub use tunnel_protocol::{AclAction, AclRule, Limits, RouteConfig, RouteType};

pub mod acl;
pub mod auth;
pub mod config_sync;
pub mod frame_io;
pub mod session;
pub mod target_policy;

pub use acl::evaluate_acl;
pub use auth::{authenticate, AuthDecision, AuthSuccess, SUPPORTED_PROTOCOL_MAJOR};
pub use config_sync::compute_route_delta;
pub use frame_io::{read_frame, write_frame};
pub use session::{NodeSession, SessionManager};
pub use target_policy::target_allowed;

pub type NodeId = uuid::Uuid;
pub type RouteId = uuid::Uuid;
pub type ConnectionId = uuid::Uuid;

/// 数据面目标（Agent 要连的内网地址）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}
