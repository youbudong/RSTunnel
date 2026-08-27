//! 集成测试（T-11）：Server 控制流处理 PING→PONG，心跳超时判定离线。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use tunnel_auth::hash_token;
use tunnel_core::NodeId;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{
    AuthPayload, Capabilities, HelloPayload, Message, PingPayload, ProtocolVersion,
};
use tunnel_server::{
    frame_io::{read_frame, write_frame},
    quic::QuicServer,
    tls,
};

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

/// 起 server（可指定心跳超时），连接 + 认证，返回控制流句柄与上线 node_id。
async fn connect_authenticated(
    heartbeat_timeout: Duration,
) -> (
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    NodeId,
    Arc<SessionManager>,
    Db,
) {
    let db = seeded_db().await;
    let sessions = Arc::new(SessionManager::new());
    let cert = tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server_cfg = tls::server_config(&cert).unwrap();
    let server = QuicServer::bind_with_heartbeat_timeout(
        "127.0.0.1:0".parse().unwrap(),
        server_cfg,
        db.clone(),
        Arc::clone(&sessions),
        heartbeat_timeout,
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
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
    write_frame(&mut send, &hello.into_frame(1).unwrap())
        .await
        .unwrap();
    let auth = Message::Auth(AuthPayload {
        node_id: None,
        credential: Some("secret-token".into()),
    });
    write_frame(&mut send, &auth.into_frame(2).unwrap())
        .await
        .unwrap();

    let frame = read_frame(&mut recv).await.unwrap().unwrap();
    let node_id = match Message::from_frame(&frame).unwrap() {
        Message::AuthOk(p) => p.node_id,
        other => panic!("expected AuthOk, got {other:?}"),
    };

    // T-13：AUTH_OK 后 server 会紧跟下发 CONFIG_SNAPSHOT，消费掉并校验版本。
    let snap = read_frame(&mut recv).await.unwrap().unwrap();
    match Message::from_frame(&snap).unwrap() {
        Message::ConfigSnapshot(p) => assert_eq!(p.config_version, 7),
        other => panic!("expected ConfigSnapshot, got {other:?}"),
    };

    (conn, send, recv, node_id, sessions, db)
}

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
async fn server_responds_to_ping() {
    let (conn, mut send, mut recv, node_id, sessions, _db) =
        connect_authenticated(Duration::from_secs(45)).await;

    let ping = Message::Ping(PingPayload { ts: 12_345 });
    write_frame(&mut send, &ping.into_frame(10).unwrap())
        .await
        .unwrap();

    let frame = read_frame(&mut recv).await.unwrap().unwrap();
    match Message::from_frame(&frame).unwrap() {
        Message::Pong(p) => assert_eq!(p.ts, 12_345),
        other => panic!("expected Pong, got {other:?}"),
    }

    // 会话记录了 last_ping / last_pong。
    let s = sessions.get(node_id).unwrap();
    assert!(s.last_ping_at().is_some());
    assert!(s.last_pong_at().is_some());

    conn.close(0u32.into(), b"done");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_timeout_marks_offline() {
    let (conn, _send, _recv, node_id, sessions, db) =
        connect_authenticated(Duration::from_millis(300)).await;

    // 不发送 PING，等待心跳超时 → 离线。
    wait_until(|| !sessions.is_online(node_id)).await;
    // DB 持久化紧跟 unregister（异步落库），轮询直到确认 offline 再断言。
    for _ in 0..100 {
        if node_status(&db).await == "offline" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(node_status(&db).await, "offline");

    conn.close(0u32.into(), b"done");
}
