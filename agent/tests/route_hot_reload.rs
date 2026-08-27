//! 集成测试（T-19）：路由热更新——改 target 不影响已建立连接，新连接用新配置；
//! 删 Route 走 drain（停接受 → 等活跃连接归零 → 解绑，新连接被拒绝）（设计文档 §139）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tunnel_agent::{tls, Agent, AgentSession, HeartbeatConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::{NodeId, RouteId, SessionManager};
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion, RouteType};
use tunnel_server::route::{RouteTable, ServerRoute};
use tunnel_server::tcp_proxy::TcpProxy;
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

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
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

fn server_route(listen_port: u16, target_port: u16) -> ServerRoute {
    ServerRoute {
        id: RouteId::parse_str(ROUTE_ID).unwrap(),
        name: "echo".to_string(),
        route_type: RouteType::Tcp,
        enabled: true,
        node_id: NodeId::parse_str(NODE_ID).unwrap(),
        listen_host: "127.0.0.1".to_string(),
        listen_port,
        target_host: "127.0.0.1".to_string(),
        target_port,
        hostname: None,
        tls_mode: None,
        limits: None,
    }
}

/// 建内存库 + 迁移 + node + credential + 一条 TCP Route（listen → target）。
async fn seeded_db(listen_port: u16, target_port: u16) -> Db {
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
         VALUES (?, 'echo', ?, 'tcp', 1, '127.0.0.1', ?, '127.0.0.1', ?, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind(NODE_ID)
    .bind(listen_port as i64)
    .bind(target_port as i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

/// 内网目标 A：pingpong 服务器（读到多少就回多少，无需 EOF，连接可长存）。
async fn spawn_pingpong_target() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, task)
}

/// 内网目标 B：连上即写一个固定字节并关闭（用于区分「到达了哪个目标」）。
async fn spawn_identity_target(byte: u8) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = sock.write_all(&[byte]).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, task)
}

struct Tunnel {
    server: Arc<QuicServer>,
    proxy: Arc<TcpProxy>,
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

    // 加载路由 + 启动 TCP 数据面监听（与 QUIC 共享连接注册表）。
    let table = Arc::new(RouteTable::new());
    for row in db.list_routes().await.unwrap() {
        table.insert(ServerRoute::try_from(row).unwrap()).unwrap();
    }
    let proxy = Arc::new(
        TcpProxy::bind_with_conns(table, server.conns())
            .await
            .unwrap(),
    );
    proxy.run();

    // Agent 连接 + 认证 + 启动心跳/数据面。
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

    // 等 Agent 连接登记（数据面可用）。
    wait_until(|| server.conns().get(node_id).is_some()).await;

    Tunnel {
        server,
        proxy,
        server_task,
        agent_task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn change_target_preserves_existing_and_routes_new() {
    let (port_a, task_a) = spawn_pingpong_target().await;
    let (port_b, task_b) = spawn_identity_target(b'B').await;
    let listen_port = free_port().await;
    let db = seeded_db(listen_port, port_a).await;
    let tunnel = spawn_tunnel(db).await;

    // 现有连接到达 A（pingpong 回显）。
    let mut conn1 = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    conn1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    conn1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // 热更新：target A → B（listen 不变）。
    tunnel
        .proxy
        .reconcile(&[server_route(listen_port, port_b)])
        .await
        .unwrap();

    // 新连接到达 B（identity 写 'B'）。
    let mut conn2 = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut b = [0u8; 1];
    conn2.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"B");

    // 现有连接仍可用（仍与 A 的 pingpong 通信，未被热更新打断）。
    conn1.write_all(b"alive").await.unwrap();
    let mut buf5 = [0u8; 5];
    conn1.read_exact(&mut buf5).await.unwrap();
    assert_eq!(&buf5, b"alive");

    drop(conn1);
    drop(conn2);
    drop(tunnel);
    task_a.abort();
    task_b.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_route_drains_and_rejects_new() {
    let (port_a, task_a) = spawn_pingpong_target().await;
    let listen_port = free_port().await;
    let db = seeded_db(listen_port, port_a).await;
    let tunnel = spawn_tunnel(db).await;

    // 现有连接存活。
    let mut conn1 = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    conn1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    conn1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // 删 Route：reconcile 空表 → drain（停接受 → 等活跃连接归零 → 解绑）。
    let p = Arc::clone(&tunnel.proxy);
    let reconcile_task = tokio::spawn(async move { p.reconcile(&[]).await });

    // 关闭现有连接，令活跃连接归零，drain 随之完成并解绑监听。
    drop(conn1);
    reconcile_task.await.unwrap().unwrap();

    // 新连接被拒绝（监听已解绑）。
    let err = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);

    drop(tunnel);
    task_a.abort();
}
