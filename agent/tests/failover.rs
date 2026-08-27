//! 集成测试（T-43）：多服务器故障转移。
//!
//! 验证 `connect_any` 按 `endpoints` 顺序（primary 在前）依次尝试，主不可达/主停机后
//! 自动切到备用服务器，Agent 在备用 Server 重新上线。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tunnel_agent::{connect_any, run_with_reconnect, tls, Agent, HeartbeatConfig, ReconnectConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::{NodeId, SessionManager};
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

async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met within timeout");
}

/// 短 QUIC idle 超时的客户端配置：让「连向已停机 primary」的握手快速失败（而非默认 30s），
/// 从而在测试里确定性触发故障转移。
fn client_config(cert: &server_tls::SelfSignedCert) -> quinn::ClientConfig {
    let mut cfg = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(2)).unwrap(),
    ));
    cfg.transport_config(Arc::new(transport));
    cfg
}

fn hello() -> HelloPayload {
    HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "test-agent".into(),
        capabilities: Capabilities::default(),
    }
}

fn auth() -> AuthPayload {
    AuthPayload {
        node_id: None,
        credential: Some("secret-token".into()),
    }
}

/// 冷启动故障转移：primary 端口不可达（已释放），Agent 首次连接即切到备用 Server 上线。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_any_skips_unreachable_primary_and_connects_backup() {
    let db = seeded_db().await;
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let node_id = NodeId::parse_str(NODE_ID).unwrap();

    // primary：bind 后立即 drop，释放端口 → 对 Agent 而言不可达（ICMP 拒绝）。
    let primary_addr = {
        let primary = QuicServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_tls::server_config(&cert).unwrap(),
            db.clone(),
            Arc::new(SessionManager::new()),
        )
        .unwrap();
        primary.local_addr().unwrap()
    };

    // backup：真实在跑。
    let sessions2 = Arc::new(SessionManager::new());
    let server2 = Arc::new(
        QuicServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_tls::server_config(&cert).unwrap(),
            db.clone(),
            Arc::clone(&sessions2),
        )
        .unwrap(),
    );
    let addr2 = server2.local_addr().unwrap();
    let s2 = Arc::clone(&server2);
    let server2_task = tokio::spawn(async move {
        let _ = s2.run().await;
    });

    let client_config = client_config(&cert);
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
    let endpoints = vec![
        (primary_addr, "localhost".to_string()),
        (addr2, "localhost".to_string()),
    ];

    let session = connect_any(
        &agent,
        &endpoints,
        hello(),
        auth(),
        Arc::new(SecurityConfig::allow_all()),
    )
    .await
    .unwrap();

    assert_eq!(session.node_id(), node_id);
    assert!(sessions2.is_online(node_id), "should be online on backup");

    server2_task.abort();
}

/// 主备切换：Agent 先连 primary 上线，主停机后自动切到备用 Server 重新上线。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_fails_over_to_backup_after_primary_stops() {
    let db = seeded_db().await;
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let node_id = NodeId::parse_str(NODE_ID).unwrap();

    // primary
    let sessions1 = Arc::new(SessionManager::new());
    let server1 = Arc::new(
        QuicServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_tls::server_config(&cert).unwrap(),
            db.clone(),
            Arc::clone(&sessions1),
        )
        .unwrap(),
    );
    let addr1 = server1.local_addr().unwrap();
    let s1 = Arc::clone(&server1);
    let server1_task = tokio::spawn(async move {
        let _ = s1.run().await;
    });

    // backup
    let sessions2 = Arc::new(SessionManager::new());
    let server2 = Arc::new(
        QuicServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_tls::server_config(&cert).unwrap(),
            db.clone(),
            Arc::clone(&sessions2),
        )
        .unwrap(),
    );
    let addr2 = server2.local_addr().unwrap();
    let s2 = Arc::clone(&server2);
    let server2_task = tokio::spawn(async move {
        let _ = s2.run().await;
    });

    let client_config = client_config(&cert);
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
    let endpoints = vec![
        (addr1, "localhost".to_string()),
        (addr2, "localhost".to_string()),
    ];

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let reconnect_task = tokio::spawn(async move {
        run_with_reconnect(
            {
                let agent = &agent;
                let endpoints = &endpoints;
                let security = Arc::new(SecurityConfig::allow_all());
                move || connect_any(agent, endpoints, hello(), auth(), Arc::clone(&security))
            },
            HeartbeatConfig {
                interval: Duration::from_millis(50),
                timeout: Duration::from_millis(500),
            },
            ReconnectConfig {
                cap: Duration::from_millis(200),
                max_reconnects: None,
            },
            cancel_rx,
        )
        .await;
    });

    // 首次连上 primary。
    wait_until(|| sessions1.is_online(node_id)).await;
    assert!(
        !sessions2.is_online(node_id),
        "backup should stay idle while primary is up"
    );

    // 主停机：close 结束 accept 循环，等待 task 退出后 drop 掉最后一个 Arc 释放端口。
    server1.close();
    let _ = server1_task.await;
    drop(server1);

    // Agent 检测到断开后按顺序重试：primary 不可达 → 切到 backup 上线。
    wait_until(|| sessions2.is_online(node_id)).await;

    cancel_tx.send(true).unwrap();
    reconnect_task.abort();
    server2_task.abort();
}
