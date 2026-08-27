//! tunnel-agent 库目标：QUIC 客户端、TLS、控制流认证。二进制入口见 `src/main.rs`。
//!
//! 拆成 lib 以便集成测试（`tests/`）直接驱动 Agent 客户端连向服务端。

pub mod agent;
pub mod data_plane;
pub mod health;
pub mod reconnect;
pub mod session;
pub mod tls;
pub mod udp;

pub use agent::{Agent, AuthOutcome};
pub use reconnect::{run_with_reconnect, Backoff, ReconnectConfig};
pub use session::{connect_any, AgentSession, HeartbeatConfig, RunOutcome};
