//! 公共基础设施：错误类型、关联 ID、日志初始化。
//!
//! 本 crate 是叶子依赖，不依赖任何内部 crate。

pub mod cidr;
pub mod target;

use thiserror::Error;

/// 全局错误类型。
///
/// 跨 crate 边界统一使用本类型；[`Error::code`] 映射到协议层错误码（docs/protocol.md §8）。
/// 变体携带 `String` 而非外部错误类型，避免把 sqlx/io 等依赖引入叶子 crate。
#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("config: {0}")]
    Config(String),
    #[error("route: {0}")]
    Route(String),
    #[error("target: {0}")]
    Target(String),
    #[error("resource limit: {0}")]
    ResourceLimit(String),
    #[error("db: {0}")]
    Db(String),
    #[error("io: {0}")]
    Io(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// 协议层错误码（见 docs/protocol.md §8）。
    pub fn code(&self) -> &'static str {
        match self {
            Error::Protocol(_) => "PROTOCOL_ERROR",
            Error::Auth(_) => "AUTH_FAILED",
            Error::Config(_) => "CONFIG_INVALID",
            Error::Route(_) => "ROUTE_NOT_FOUND",
            Error::Target(_) => "TARGET_UNREACHABLE",
            Error::ResourceLimit(_) => "RESOURCE_LIMIT",
            Error::Db(_) | Error::Io(_) | Error::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// 跨组件关联 ID（设计文档 §87），随请求/连接在 Web→Server→Agent→Target 间传播。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId(pub uuid::Uuid);

impl TraceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 初始化结构化日志（JSON 输出，默认 `info`，可用 `RUST_LOG` 覆盖）。
///
/// 幂等：重复调用（如测试）安全。
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}
