//! 集成测试（T-16）：目标不可达时 Agent 回 OPEN_FAIL(TARGET_UNREACHABLE)（设计文档 §56）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use tunnel_agent::{data_plane::handle_data_stream, tls};
use tunnel_config::SecurityConfig;
use tunnel_core::frame_io::{read_frame, write_frame};
use tunnel_core::RouteId;
use tunnel_protocol::{Message, OpenTcpPayload};
use tunnel_server::tls as server_tls;

const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_replies_open_fail_for_unreachable_target() {
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = server_tls::server_config(&cert).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    // 一个当前没有进程监听的端口（连接将得到 ECONNREFUSED）。
    let unreachable_port = free_port().await;

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // 服务端打开一个双向流，正向 OPEN_TCP（目标 = 不可达端口）。
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let open = Message::OpenTcp(OpenTcpPayload {
            route_id: RouteId::parse_str(ROUTE_ID).unwrap(),
            target_host: "127.0.0.1".to_string(),
            target_port: unreachable_port,
            client_addr: Some("1.2.3.4:5678".to_string()),
        });
        write_frame(&mut send, &open.into_frame(0).unwrap())
            .await
            .unwrap();

        // 期望 Agent 回 OPEN_FAIL(TARGET_UNREACHABLE)。
        let frame = read_frame(&mut recv).await.unwrap().unwrap();
        match Message::from_frame(&frame).unwrap() {
            Message::OpenFail(p) => assert_eq!(p.code, "TARGET_UNREACHABLE"),
            other => panic!("expected OpenFail, got {other:?}"),
        }
        conn.close(0u32.into(), b"done");
    });

    // Agent 侧：连接 mock server，accept 到该双向流，交给数据面处理器。
    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (send, recv) = conn.accept_bi().await.unwrap();
    handle_data_stream(send, recv, Arc::new(SecurityConfig::allow_all())).await;

    server_task.await.unwrap();
}
