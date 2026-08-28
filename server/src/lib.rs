//! tunnel-server 库目标：QUIC 端点、TLS、帧 IO。二进制入口见 `src/main.rs`。
//!
//! 拆成 lib 以便集成测试（`tests/`）直接驱动服务端组件。

pub mod acl_store;
pub mod api;
pub mod certificate;
pub mod config;
pub mod config_sync;
pub mod conn_limiter;
pub mod conn_registry;
pub mod event;
pub mod frame_io;
pub mod http_proxy;
pub mod https_proxy;
pub mod login_limiter;
pub mod quic;
pub mod readiness;
pub mod route;
pub mod session;
pub mod tcp_proxy;
pub mod tls;
pub mod tls_passthrough;
pub mod udp_proxy;
pub mod web;
