//! 集成测试（T-11）：Agent 心跳循环发送 PING 并记录 RTT。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tunnel_agent::{tls, Agent, AgentSession, HeartbeatConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion};
use tunnel_server::{quic::QuicServer, tls as server_tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const NOW: &str = "2026-08-27T00:00:00Z";

/// 建内存库 + 迁移 + 种入一个 node 及 credential。
async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    tunnel_db::sqlx::query(
        "INSERT INTO nodes (id, name, config_version, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(NODE_ID)
    .bind("node-a")
    .bind(7i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    tunnel_db::sqlx::query(
        "INSERT INTO credentials (id, node_id, type, secret_hash, created_at) \
         VALUES (?, ?, 'token', ?, ?)",
    )
    .bind("22222222-2222-4222-8222-222222222222")
    .bind(NODE_ID)
    .bind(hash_token("secret-token"))
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_heartbeat_records_rtt() {
    let db = seeded_db().await;
    let sessions = Arc::new(SessionManager::new());
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = server_tls::server_config(&cert).unwrap();
    let server =
        QuicServer::bind("127.0.0.1:0".parse().unwrap(), server_cfg, db, sessions).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();

    let session = AgentSession::connect(
        &agent,
        addr,
        HelloPayload {
            protocol_version: ProtocolVersion { major: 1, minor: 0 },
            agent_version: "test-agent".into(),
            capabilities: Capabilities::default(),
        },
        AuthPayload {
            node_id: None,
            credential: Some("secret-token".into()),
        },
        Arc::new(SecurityConfig::allow_all()),
    )
    .await
    .unwrap();

    // 重置指标，跑短间隔心跳，断言 RTT 被记录。
    let gauge = tunnel_metrics::agent_rtt_seconds().unwrap();
    gauge.set(0.0);

    let session_task = tokio::spawn(async move {
        let _ = session
            .run(HeartbeatConfig {
                interval: Duration::from_millis(50),
                timeout: Duration::from_secs(5),
            })
            .await;
    });

    // 等几轮 PING/PONG。
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(gauge.get() > 0.0, "expected rtt > 0, got {}", gauge.get());

    session_task.abort();
    server_task.abort();
}
