//! 集成测试（T-08/T-09）：Agent 通过 QUIC 控制流完成 HELLO→AUTH→AUTH_OK / AUTH_FAIL，
//! 并在认证成功后上线（online）与断开后下线（offline）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use tunnel_auth::hash_token;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, Message, ProtocolVersion};
use tunnel_server::{frame_io::read_frame, quic::QuicServer, tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const NOW: &str = "2026-08-27T00:00:00Z";

fn client_config(cert: &CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let crypto = QuicClientConfig::try_from(rustls_cfg).unwrap();
    quinn::ClientConfig::new(Arc::new(crypto))
}

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

async fn node_status(db: &Db) -> String {
    tunnel_db::sqlx::query_scalar::<_, String>("SELECT status FROM nodes WHERE id = ?")
        .bind(NODE_ID)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// 起 server、建连、发 HELLO+AUTH、读回一帧并解码。
async fn auth_roundtrip(token: &str) -> Message {
    let db = seeded_db().await;
    let sessions = Arc::new(SessionManager::new());
    let cert = tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = tls::server_config(&cert).unwrap();
    let server =
        QuicServer::bind("127.0.0.1:0".parse().unwrap(), server_cfg, db, sessions).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config(&cert.cert_der));
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let hello = Message::Hello(HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "test-agent".into(),
        capabilities: Capabilities::default(),
    });
    send.write_all(&hello.into_frame(1).unwrap().encode())
        .await
        .unwrap();
    let auth = Message::Auth(AuthPayload {
        node_id: None,
        credential: Some(token.to_string()),
    });
    send.write_all(&auth.into_frame(2).unwrap().encode())
        .await
        .unwrap();
    send.finish().unwrap();

    let frame = read_frame(&mut recv).await.unwrap().unwrap();
    let msg = Message::from_frame(&frame).unwrap();

    conn.close(0u32.into(), b"done");
    server_task.abort();
    msg
}

/// 轮询直到 `cond` 为真，否则超时 panic。
async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_token_returns_auth_ok() {
    match auth_roundtrip("secret-token").await {
        Message::AuthOk(p) => {
            assert_eq!(p.node_id.to_string(), NODE_ID);
            assert_eq!(p.config_version, 7);
            assert!(!p.server_version.is_empty());
            assert!(!p.server_time.is_empty());
        }
        other => panic!("expected AuthOk, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_token_returns_auth_fail() {
    match auth_roundtrip("wrong-token").await {
        Message::AuthFail(p) => assert_eq!(p.code, "AUTH_FAILED"),
        other => panic!("expected AuthFail, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_goes_online_then_offline() {
    let db = seeded_db().await;
    let sessions = Arc::new(SessionManager::new());
    let cert = tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = tls::server_config(&cert).unwrap();
    let server = QuicServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_cfg,
        db.clone(),
        Arc::clone(&sessions),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config(&cert.cert_der));
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let hello = Message::Hello(HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "test-agent".into(),
        capabilities: Capabilities::default(),
    });
    send.write_all(&hello.into_frame(1).unwrap().encode())
        .await
        .unwrap();
    let auth = Message::Auth(AuthPayload {
        node_id: None,
        credential: Some("secret-token".into()),
    });
    send.write_all(&auth.into_frame(2).unwrap().encode())
        .await
        .unwrap();
    // 保持控制流发送侧打开（真实 agent 会持续发 PING）；离线由 conn.close() 触发。

    let frame = read_frame(&mut recv).await.unwrap().unwrap();
    let node_id = match Message::from_frame(&frame).unwrap() {
        Message::AuthOk(p) => p.node_id,
        other => panic!("expected AuthOk, got {other:?}"),
    };

    // 上线：Session Manager 有该 node，DB status = online。
    wait_until(|| sessions.is_online(node_id)).await;
    assert_eq!(node_status(&db).await, "online");

    conn.close(0u32.into(), b"done");

    // 下线：Session Manager 摘除，DB status = offline。
    wait_until(|| !sessions.is_online(node_id)).await;
    // DB 持久化紧跟 unregister（异步落库），轮询直到确认 offline 再断言。
    for _ in 0..100 {
        if node_status(&db).await == "offline" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(node_status(&db).await, "offline");

    server_task.abort();
}
