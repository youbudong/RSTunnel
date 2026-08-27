//! 集成测试（T-12）：Server 断开后 Agent 按指数退避自动重连上线，reconnect_total 递增。
//!
//! 通过优雅关闭 Server1 使 Agent 现有连接断开，同时把重连目标切到已就绪的 Server2
//! （不同端口），避免进程内 UDP 端口无法立即释放的问题，同时验证「断开 → 重连 → 上线」。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tunnel_agent::{
    run_with_reconnect, tls, Agent, AgentSession, HeartbeatConfig, ReconnectConfig,
};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_reconnects_after_server_restart() {
    let db = seeded_db().await;
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let node_id = NodeId::parse_str(NODE_ID).unwrap();

    // Server1：独立 SessionManager，验证首次上线。
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

    // Agent：连接目标可切换（Mutex），用于在 Server1 关闭后指向 Server2。
    let target = Arc::new(Mutex::new(addr1));
    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
    let hello = HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "test-agent".into(),
        capabilities: Capabilities::default(),
    };
    let auth = AuthPayload {
        node_id: None,
        credential: Some("secret-token".into()),
    };
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let reconnect_task = {
        let target = Arc::clone(&target);
        tokio::spawn(async move {
            run_with_reconnect(
                || {
                    let addr = *target.lock().unwrap();
                    AgentSession::connect(
                        &agent,
                        addr,
                        hello.clone(),
                        auth.clone(),
                        Arc::new(SecurityConfig::allow_all()),
                    )
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
        })
    };

    // 首次上线。
    wait_until(|| sessions1.is_online(node_id)).await;

    // Server2 就绪（新端口 + 新 SessionManager），随后把重连目标切过去并关闭 Server1。
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

    *target.lock().unwrap() = addr2;
    server1.close();

    // Agent 检测到断开后自动重连到 Server2，重新上线；reconnect_total 递增。
    wait_until(|| sessions2.is_online(node_id)).await;
    wait_until(|| tunnel_metrics::agent_reconnect_total().unwrap().get() > 0).await;
    assert!(
        tunnel_metrics::agent_reconnect_total().unwrap().get() > 0,
        "reconnect_total should have incremented"
    );

    // 清理。
    cancel_tx.send(true).unwrap();
    reconnect_task.abort();
    server2_task.abort();
    server1_task.abort();
}
