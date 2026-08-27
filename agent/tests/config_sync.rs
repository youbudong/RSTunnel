//! 集成测试（T-18）：配置版本与下发——改 Route → 对应 Node 版本 +1 → 推 CONFIG_UPDATE →
//! Agent 应用并 ACK → Server 持久化 `applied_config_version`/`config_status='synced'`；
//! 离线 Node 则仅版本 +1，`config_status` 保持 `pending`（设计文档 §10/§28）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tunnel_agent::{tls, Agent, AgentSession, HeartbeatConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{
    AuthPayload, Capabilities, HelloPayload, ProtocolVersion, RouteConfig, RouteType,
};
use tunnel_server::config_sync::ConfigSync;
use tunnel_server::{quic::QuicServer, tls as server_tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";
const NOW: &str = "2026-08-27T00:00:00Z";

fn hello() -> HelloPayload {
    HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "test-agent".into(),
        capabilities: Capabilities::default(),
    }
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

fn route(target_port: u16) -> RouteConfig {
    RouteConfig {
        id: tunnel_core::RouteId::parse_str(ROUTE_ID).unwrap(),
        name: "echo".to_string(),
        route_type: RouteType::Tcp,
        enabled: true,
        target_host: "127.0.0.1".to_string(),
        target_port,
        hostname: None,
        limits: None,
    }
}

/// 建内存库 + 迁移 + node（config_version=7）+ credential + 一条 TCP Route。
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
    tunnel_db::sqlx::query(
        "INSERT INTO routes \
         (id, name, node_id, type, enabled, listen_host, listen_port, target_host, target_port, \
          status, created_at, updated_at) \
         VALUES (?, 'echo', ?, 'tcp', 1, '127.0.0.1', 8080, '127.0.0.1', 8080, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind(NODE_ID)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

/// 读取 Node 的 `(config_version, applied_config_version, config_status)`。
async fn node_state(db: &Db) -> (i64, i64, String) {
    tunnel_db::sqlx::query_as(
        "SELECT config_version, applied_config_version, config_status FROM nodes WHERE id = ?",
    )
    .bind(NODE_ID)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

struct Tunnel {
    server: Arc<QuicServer>,
    server_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.server.close();
        self.server_task.abort();
        self.agent_task.abort();
    }
}

async fn spawn_tunnel(db: Db) -> Tunnel {
    let sessions = Arc::new(SessionManager::new());
    let cert = server_tls::generate_self_signed(&["localhost".to_string()]).unwrap();
    let server = Arc::new(
        QuicServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_tls::server_config(&cert).unwrap(),
            db.clone(),
            Arc::clone(&sessions),
        )
        .unwrap(),
    );
    let quic_addr = server.local_addr().unwrap();
    let s = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = s.run().await;
    });

    let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
    let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
    let auth = AuthPayload {
        node_id: None,
        credential: Some("secret-token".into()),
    };
    let session = AgentSession::connect(
        &agent,
        quic_addr,
        hello(),
        auth,
        Arc::new(SecurityConfig::allow_all()),
    )
    .await
    .unwrap();
    let node_id = session.node_id();
    let agent_task = tokio::spawn(async move {
        let _ = session
            .run(HeartbeatConfig {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(30),
            })
            .await;
    });

    // 等 Agent 连接登记（控制流循环已就绪）。
    wait_until(|| server.conns().get(node_id).is_some()).await;

    Tunnel {
        server,
        server_task,
        agent_task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_change_bumps_version_and_agent_acks() {
    let db = seeded_db().await;
    let tunnel = spawn_tunnel(db.clone()).await;

    // 1. 初始快照（version 7）被 Agent ACK，落库 synced。
    let mut initial = (0i64, 0i64, String::new());
    for _ in 0..400 {
        initial = node_state(&db).await;
        if initial.1 == 7 && initial.2 == "synced" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        initial,
        (7, 7, "synced".to_string()),
        "initial snapshot not ACKed"
    );

    // 2. 改 Route（target_port 8080 → 9090）→ 版本 +1 并推 CONFIG_UPDATE。
    let old_routes = vec![route(8080)];
    let new_routes = vec![route(9090)];
    let node_id = tunnel_core::NodeId::parse_str(NODE_ID).unwrap();
    let version = tunnel
        .server
        .config_sync()
        .notify_routes_changed(&db, node_id, &old_routes, &new_routes)
        .await
        .unwrap();
    assert_eq!(version, 8);

    // 3. Agent 应用增量并 ACK → Server 落库 applied_config_version=8、synced。
    for _ in 0..400 {
        let (v, applied, status) = node_state(&db).await;
        if v == 8 && applied == 8 && status == "synced" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(node_state(&db).await, (8, 8, "synced".to_string()));

    drop(tunnel);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_node_keeps_pending() {
    let db = seeded_db().await;
    let sync = ConfigSync::new();
    let node_id = tunnel_core::NodeId::parse_str(NODE_ID).unwrap();

    // 无在线 Agent（未 register 任何推送通道）：版本 +1，但无人 ACK，保持 pending。
    let version = sync
        .notify_routes_changed(&db, node_id, &[route(8080)], &[route(9090)])
        .await
        .unwrap();
    assert_eq!(version, 8);
    assert_eq!(node_state(&db).await, (8, 0, "pending".to_string()));
}
