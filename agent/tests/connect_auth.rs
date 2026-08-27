//! 集成测试（T-10）：Agent 通过 QUIC 连接 Server 并完成 HELLO→AUTH，收到 AUTH_OK / AUTH_FAIL。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use tunnel_agent::{tls, Agent, AuthOutcome};
use tunnel_auth::hash_token;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion};
use tunnel_server::{quic::QuicServer, tls as server_tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const NOW: &str = "2026-08-27T00:00:00Z";

/// 建内存库 + 迁移 + 种入一个 node（config_version=7）及 credential（token "secret-token"）。
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

/// 起 server（自签名证书），用 Agent 客户端 + 给定 token 做一次认证往返。
async fn agent_auth_roundtrip(token: &str) -> AuthOutcome {
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

    // Agent 客户端：信任服务端自签名证书，SNI = localhost。
    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
    let conn = agent.connect(addr).await.unwrap();

    let outcome = agent
        .authenticate(
            &conn,
            HelloPayload {
                protocol_version: ProtocolVersion { major: 1, minor: 0 },
                agent_version: "test-agent".into(),
                capabilities: Capabilities::default(),
            },
            AuthPayload {
                node_id: None,
                credential: Some(token.to_string()),
            },
        )
        .await
        .unwrap();

    conn.close(0u32.into(), b"done");
    server_task.abort();
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_connects_and_gets_auth_ok() {
    match agent_auth_roundtrip("secret-token").await {
        AuthOutcome::Ok(p) => {
            assert_eq!(p.node_id.to_string(), NODE_ID);
            assert_eq!(p.config_version, 7);
            assert!(!p.server_version.is_empty());
            assert!(!p.server_time.is_empty());
        }
        AuthOutcome::Fail(p) => {
            panic!("expected AUTH_OK, got AUTH_FAIL {} ({})", p.code, p.message)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_receives_auth_fail_on_bad_token() {
    match agent_auth_roundtrip("wrong-token").await {
        AuthOutcome::Fail(p) => assert_eq!(p.code, "AUTH_FAILED"),
        AuthOutcome::Ok(p) => panic!("expected AUTH_FAIL, got AUTH_OK for {}", p.node_id),
    }
}
