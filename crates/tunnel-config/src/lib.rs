//! Server / Agent 的 bootstrap 启动配置（TOML）。
//!
//! 对应 docs/rust-tunnel-design.md §44/§45/§160。业务 Tunnel 配置**不**在此（存 DB）。

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid config: {0}")]
    Invalid(String),
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub http: HttpConfig,
    pub https: HttpsConfig,
    pub quic: QuicConfig,
    pub internal: InternalConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub security: ServerSecurityConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub bind: String,
}

/// TLS 终止入口（T-27）：在 `https.bind` 上接受 TLS，按 SNI 选证书，解密后转 HTTP 数据面。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsConfig {
    pub bind: String,
}

/// QUIC 自签名证书参数（开发/演示用；生产由 T-27 从 ACME/配置加载）。
///
/// `subjects` 为证书 SAN（须包含 Agent 所连接的服务器主机名，否则握手失败）；
/// `cert_der_path` 非空时把生成的证书 DER 落盘，供 Agent 作为 `[server].ca` 信任。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    #[serde(default = "default_subjects")]
    pub subjects: Vec<String>,
    pub cert_der_path: Option<String>,
    /// 服务端私钥 DER 落盘路径。与 `cert_der_path` 同时配置时，服务端复用已落盘证书
    /// （跨重启稳定身份），否则每次启动新生成（开发/测试）。
    pub key_der_path: Option<String>,
}

fn default_subjects() -> Vec<String> {
    vec!["localhost".into()]
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            subjects: default_subjects(),
            cert_der_path: None,
            key_der_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    pub bind: String,
    pub max_concurrent_bidi_streams: u64,
    pub max_concurrent_uni_streams: u64,
    pub idle_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConfig {
    pub bind: String,
    /// Web 管理后台静态目录（`web/dist` 构建产物，T-24/§153）。`None` 时 internal 端口
    /// 仅提供 REST API / Swagger / `/ws`，不同源托管前端（前端需另跑 `vite` 代理）。
    #[serde(default)]
    pub web_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

/// Server 安全配置（T-35/T-37，§160）：登录防暴力破解限速 + SSRF 目标校验开关。
///
/// 字段级 `#[serde(default = ...)]` 保证 `[security]` 表部分缺省时仍取合理缺省
/// （例如仅覆盖 `login_window_seconds` 时 `max_login_attempts` 不会退化为 0）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSecurityConfig {
    /// 窗口内连续失败达到该次数后，该用户名被锁定（登录返回 429）。
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    /// 失败统计窗口（秒）。
    #[serde(default = "default_login_window_seconds")]
    pub login_window_seconds: u64,
    /// 管理员显式允许将 Route 目标指向 loopback/link-local/multicast/metadata 等
    /// 危险地址（T-37，默认拒绝）。置 `true` 即跳过 SSRF 目标校验。
    #[serde(default)]
    pub allow_unsafe_targets: bool,
}

fn default_max_login_attempts() -> u32 {
    5
}

fn default_login_window_seconds() -> u64 {
    300
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self {
            max_login_attempts: default_max_login_attempts(),
            login_window_seconds: default_login_window_seconds(),
            allow_unsafe_targets: false,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:443".into(),
        }
    }
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:443".into(),
        }
    }
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:443".into(),
            max_concurrent_bidi_streams: 10_000,
            max_concurrent_uni_streams: 1_000,
            idle_timeout_seconds: 60,
        }
    }
}

impl Default for InternalConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            web_dir: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://tunnel.db".into(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl ServerConfig {
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Invalid(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for bind in [
            &self.http.bind,
            &self.https.bind,
            &self.quic.bind,
            &self.internal.bind,
        ] {
            if bind.is_empty() {
                return Err(ConfigError::Invalid("empty bind address".into()));
            }
        }
        if self.database.url.is_empty() {
            return Err(ConfigError::Invalid("empty database url".into()));
        }
        // T-35：阈值 0 会把所有登录（含管理员）都锁定，属于明显误配。
        if self.security.max_login_attempts == 0 {
            return Err(ConfigError::Invalid(
                "max_login_attempts must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// 多服务器故障转移列表（T-43/§50）：`[[servers]]` 数组，顺序即优先级（首个为 primary，
    /// 其后为 fallback）。非空时优先于 `[server].endpoints`。
    pub servers: Vec<ServerEntry>,
    pub server: ServerListConfig,
    pub auth: AuthConfig,
    pub agent: AgentInfoConfig,
    pub data: DataConfig,
    pub health: HealthConfig,
    pub security: SecurityConfig,
}

/// 单个服务器条目（T-43/§50）：`[[servers]]` 中的一行，仅 `address = "host:port"`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub address: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerListConfig {
    /// 旧式平铺端点列表（§45，向后兼容）：`[server].endpoints = ["host:port", ...]`。
    /// 配置了 `[[servers]]` 时被忽略。
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// 服务端证书/CA 路径（DER 编码；信任自签名/私有 CA）。缺省 = 不信任（系统根待 T-30 接入）。
    #[serde(default)]
    pub ca: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfoConfig {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataConfig {
    pub directory: String,
}

/// Agent 本地健康探针（T-39/§97）：`GET /health` 返回 `{ "status": "ok" }`。
/// 仅监听回环，供编排器/`systemctl` 探活。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub bind: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9090".into(),
        }
    }
}

/// Agent 本地目标安全策略（T-34f/§33）：约束 Agent 出站目标 IP。
///
/// `allow_targets` 为白名单（非空时仅这些目标放行），`deny_targets` 为黑名单；
/// 默认拒绝 loopback 与 link-local，防止把 Tunnel 变成任意内网扫描器。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 白名单（CIDR）。显式允许优先于 deny；非空时其余地址一律拒绝。
    #[serde(default)]
    pub allow_targets: Vec<String>,
    /// 黑名单（CIDR）。默认拒绝 `127.0.0.0/8` 与 `169.254.0.0/16`。
    #[serde(default = "default_deny_targets")]
    pub deny_targets: Vec<String>,
}

fn default_deny_targets() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "169.254.0.0/16".into()]
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_targets: Vec::new(),
            deny_targets: default_deny_targets(),
        }
    }
}

impl SecurityConfig {
    /// 放行所有目标（测试/开发用；生产请显式配置 deny/allow）。
    pub fn allow_all() -> Self {
        Self {
            allow_targets: Vec::new(),
            deny_targets: Vec::new(),
        }
    }
}

impl Default for AgentInfoConfig {
    fn default() -> Self {
        Self {
            name: "agent".into(),
        }
    }
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            directory: "/var/lib/tunnel-agent".into(),
        }
    }
}

impl AgentConfig {
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Invalid(e.to_string()))
    }

    /// 故障转移顺序的服务器地址列表（T-43）：优先 `[[servers]]`，空则回退 `[server].endpoints`。
    pub fn server_addresses(&self) -> Vec<String> {
        if !self.servers.is_empty() {
            self.servers.iter().map(|s| s.address.clone()).collect()
        } else {
            self.server.endpoints.clone()
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let addresses = self.server_addresses();
        if addresses.is_empty() {
            return Err(ConfigError::Invalid("no server endpoints".into()));
        }
        if addresses.iter().any(|a| a.trim().is_empty()) {
            return Err(ConfigError::Invalid("empty server address".into()));
        }
        if self.auth.token.is_empty() {
            return Err(ConfigError::Invalid("empty auth token".into()));
        }
        if self.agent.name.is_empty() {
            return Err(ConfigError::Invalid("empty agent name".into()));
        }
        if self.health.bind.is_empty() {
            return Err(ConfigError::Invalid("empty health bind address".into()));
        }
        // T-34f：deny/allow 目标 CIDR 非法即启动失败（避免 deny 拼写错误导致静默放行）。
        for cidr in self
            .security
            .allow_targets
            .iter()
            .chain(&self.security.deny_targets)
        {
            if tunnel_common::cidr::parse_cidr(cidr).is_none() {
                return Err(ConfigError::Invalid(format!("invalid target CIDR: {cidr}")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn server_defaults_from_empty_toml() {
        let cfg = ServerConfig::from_toml("").unwrap();
        assert_eq!(cfg.http.bind, "0.0.0.0:443");
        assert_eq!(cfg.https.bind, "0.0.0.0:443");
        assert_eq!(cfg.quic.max_concurrent_bidi_streams, 10_000);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_rejects_empty_bind() {
        let mut cfg = ServerConfig::default();
        cfg.http.bind = String::new();
        assert!(cfg.validate().is_err());
        let mut cfg = ServerConfig::default();
        cfg.https.bind = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn server_security_defaults_from_empty_toml() {
        let cfg = ServerConfig::from_toml("").unwrap();
        assert_eq!(cfg.security.max_login_attempts, 5);
        assert_eq!(cfg.security.login_window_seconds, 300);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_security_partial_override_keeps_defaults() {
        // 仅覆盖 login_window_seconds：max_login_attempts 不应退化为 0。
        let cfg = ServerConfig::from_toml(
            r#"
[security]
login_window_seconds = 60
"#,
        )
        .unwrap();
        assert_eq!(cfg.security.max_login_attempts, 5);
        assert_eq!(cfg.security.login_window_seconds, 60);
    }

    #[test]
    fn server_security_allow_unsafe_targets_defaults_false() {
        let cfg = ServerConfig::from_toml("").unwrap();
        assert!(!cfg.security.allow_unsafe_targets);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_security_allow_unsafe_targets_override() {
        let cfg = ServerConfig::from_toml(
            r#"
[security]
allow_unsafe_targets = true
"#,
        )
        .unwrap();
        assert!(cfg.security.allow_unsafe_targets);
        // 其余安全项保持缺省。
        assert_eq!(cfg.security.max_login_attempts, 5);
        assert_eq!(cfg.security.login_window_seconds, 300);
    }

    #[test]
    fn server_rejects_zero_login_attempts() {
        let cfg = ServerConfig::from_toml(
            r#"
[security]
max_login_attempts = 0
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn server_tls_defaults_to_localhost_and_no_path() {
        let cfg = ServerConfig::from_toml("").unwrap();
        assert_eq!(cfg.tls.subjects, vec!["localhost".to_string()]);
        assert_eq!(cfg.tls.cert_der_path, None);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_tls_override_subjects_and_path() {
        let cfg = ServerConfig::from_toml(
            r#"
[tls]
subjects = ["server", "localhost"]
cert_der_path = "/etc/tunnel/certs/server.der"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.tls.subjects,
            vec!["server".to_string(), "localhost".to_string()]
        );
        assert_eq!(
            cfg.tls.cert_der_path,
            Some("/etc/tunnel/certs/server.der".to_string())
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_tls_partial_override_keeps_subject_default() {
        // 仅覆盖 cert_der_path：subjects 不应退化为空（空 SAN 证书无法握手）。
        let cfg = ServerConfig::from_toml(
            r#"
[tls]
cert_der_path = "/tmp/server.der"
"#,
        )
        .unwrap();
        assert_eq!(cfg.tls.subjects, vec!["localhost".to_string()]);
        assert_eq!(cfg.tls.cert_der_path, Some("/tmp/server.der".to_string()));
    }

    #[test]
    fn server_internal_web_dir_defaults_none() {
        let cfg = ServerConfig::from_toml("").unwrap();
        assert_eq!(cfg.internal.bind, "127.0.0.1:8080");
        assert_eq!(cfg.internal.web_dir, None);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_internal_web_dir_override() {
        let cfg = ServerConfig::from_toml(
            r#"
[internal]
bind = "127.0.0.1:8080"
web_dir = "/app/web/dist"
"#,
        )
        .unwrap();
        assert_eq!(cfg.internal.web_dir, Some("/app/web/dist".to_string()));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_internal_web_dir_omitted_keeps_bind_required() {
        // `[internal]` 存在但只写 bind：web_dir 缺省为 None（T-24 前后向兼容）。
        let cfg = ServerConfig::from_toml(
            r#"
[internal]
bind = "10.0.0.1:9000"
"#,
        )
        .unwrap();
        assert_eq!(cfg.internal.bind, "10.0.0.1:9000");
        assert_eq!(cfg.internal.web_dir, None);
    }

    #[test]
    fn agent_requires_token_and_endpoints() {
        assert!(AgentConfig::default().validate().is_err());
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn security_defaults_deny_loopback_and_link_local() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.security.deny_targets,
            vec!["127.0.0.0/8".to_string(), "169.254.0.0/16".to_string()]
        );
        assert!(cfg.security.allow_targets.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn security_overrides_deny_and_allow() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"

[security]
allow_targets = ["192.168.1.0/24"]
deny_targets = ["10.0.0.0/8"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.security.allow_targets, vec!["192.168.1.0/24"]);
        assert_eq!(cfg.security.deny_targets, vec!["10.0.0.0/8"]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn security_rejects_invalid_cidr() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"

[security]
deny_targets = ["not-a-cidr"]
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn agent_health_defaults_to_loopback() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(cfg.health.bind, "127.0.0.1:9090");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn agent_health_override() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"

[health]
bind = "127.0.0.1:9091"
"#,
        )
        .unwrap();
        assert_eq!(cfg.health.bind, "127.0.0.1:9091");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn agent_rejects_empty_health_bind() {
        let mut cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["tunnel.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        cfg.health.bind = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn agent_parses_servers_array_and_orders_them() {
        let cfg = AgentConfig::from_toml(
            r#"
[[servers]]
address = "a.example.com:443"

[[servers]]
address = "b.example.com:443"

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.server_addresses(),
            vec!["a.example.com:443", "b.example.com:443"]
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn agent_servers_take_precedence_over_legacy_endpoints() {
        let cfg = AgentConfig::from_toml(
            r#"
[[servers]]
address = "a.example.com:443"

[server]
endpoints = ["legacy.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(cfg.server_addresses(), vec!["a.example.com:443"]);
    }

    #[test]
    fn agent_falls_back_to_legacy_endpoints_when_no_servers() {
        let cfg = AgentConfig::from_toml(
            r#"
[server]
endpoints = ["legacy.example.com:443"]

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(cfg.server_addresses(), vec!["legacy.example.com:443"]);
    }

    #[test]
    fn agent_rejects_empty_servers_and_endpoints() {
        let cfg = AgentConfig::from_toml(
            r#"
[[servers]]
address = ""

[auth]
token = "secret"
"#,
        )
        .unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].address, "");
        assert!(cfg.validate().is_err());
    }
}
