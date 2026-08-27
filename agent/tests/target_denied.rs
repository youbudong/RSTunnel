//! 集成测试（T-34f）：Agent 按本地 `[security]` 目标策略拒绝未授权目标（loopback/link-local），
//! 回 OPEN_FAIL(TARGET_DENIED)（设计文档 §33）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use tunnel_agent::{data_plane::handle_data_stream, tls};
use tunnel_config::SecurityConfig;
use tunnel_core::frame_io::{read_frame, write_frame};
use tunnel_core::RouteId;
use tunnel_protocol::{Message, OpenTcpPayload};
use tunnel_server::tls as server_tls;

const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";

/// 一个当前无进程监听的端口（连接会得到 ECONNREFUSED）。
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// 用 mock server 打开一条双向流并正向发送 OPEN_TCP 到 `target_host:target_port`，
/// 返回 Agent 回的 OPEN_FAIL 错误码。
async fn run_target_and_get_fail_code(
    security: SecurityConfig,
    target_host: &str,
    target_port: u16,
) -> String {
    let target_host = target_host.to_string();
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = server_tls::server_config(&cert).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let open = Message::OpenTcp(OpenTcpPayload {
            route_id: RouteId::parse_str(ROUTE_ID).unwrap(),
            target_host,
            target_port,
            client_addr: Some("1.2.3.4:5678".to_string()),
        });
        write_frame(&mut send, &open.into_frame(0).unwrap())
            .await
            .unwrap();

        let frame = read_frame(&mut recv).await.unwrap().unwrap();
        match Message::from_frame(&frame).unwrap() {
            Message::OpenFail(p) => p.code,
            other => panic!("expected OpenFail, got {other:?}"),
        }
    });

    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (send, recv) = conn.accept_bi().await.unwrap();
    handle_data_stream(send, recv, Arc::new(security)).await;

    server_task.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_security_denies_loopback_target() {
    // 默认 deny `127.0.0.0/8` → 连 127.0.0.1 被本地策略拒绝。
    let code = run_target_and_get_fail_code(SecurityConfig::default(), "127.0.0.1", 8080).await;
    assert_eq!(code, "TARGET_DENIED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_security_denies_link_local_target() {
    // 默认 deny `169.254.0.0/16` → 连云元数据地址被拒（SSRF 防护）。
    let code = run_target_and_get_fail_code(SecurityConfig::default(), "169.254.169.254", 80).await;
    assert_eq!(code, "TARGET_DENIED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_allow_overrides_default_deny() {
    // 管理员显式放行 loopback 后，127.0.0.1 不再被本地策略拒绝（连接失败转成 UNREACHABLE）。
    let port = free_port().await;
    let security = SecurityConfig {
        allow_targets: vec!["127.0.0.0/8".to_string()],
        deny_targets: SecurityConfig::default().deny_targets,
    };
    let code = run_target_and_get_fail_code(security, "127.0.0.1", port).await;
    assert_eq!(code, "TARGET_UNREACHABLE");
}
