//! 各消息的 JSON payload 结构。见 docs/protocol.md §4。

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub tcp: bool,
    pub udp: bool,
    pub http: bool,
    pub websocket: bool,
    pub quic: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            tcp: true,
            udp: true,
            http: true,
            websocket: true,
            quic: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloPayload {
    pub protocol_version: ProtocolVersion,
    pub agent_version: String,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthOkPayload {
    pub node_id: Uuid,
    pub config_version: u64,
    pub server_version: String,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthFailPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PingPayload {
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// 配置（wire 类型，也供 core / agent 复用）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    Tcp,
    Udp,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclRule {
    pub action: AclAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connection_rate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bandwidth: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub route_type: RouteType,
    pub enabled: bool,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigSnapshotPayload {
    pub config_version: u64,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub acl: Vec<AclRule>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDelta {
    #[serde(default)]
    pub added: Vec<RouteConfig>,
    #[serde(default)]
    pub updated: Vec<RouteConfig>,
    #[serde(default)]
    pub removed: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigUpdatePayload {
    pub config_version: u64,
    pub routes: RouteDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigAckPayload {
    pub config_version: u64,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigResyncPayload {
    pub last_applied_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpOpenPayload {
    pub route_id: Uuid,
    pub udp_session_id: u64,
    pub client_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpClosePayload {
    pub udp_session_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatsPayload {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_streams: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthPayload {
    pub applied_config_version: u64,
    pub status: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenTcpPayload {
    pub route_id: Uuid,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenOkPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenFailPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}
