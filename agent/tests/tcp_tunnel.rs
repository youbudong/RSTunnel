//! 集成测试（T-15/T-16）：端到端 TCP 数据面——客户端连 Server 的 Route 监听，经 Node 的 QUIC
//! 连接 OPEN_TCP → 内网目标，双向转发原始字节；含半关闭（half-close）不丢数据验证。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tunnel_agent::{tls, Agent, AgentSession, HeartbeatConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion};
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

/// 建内存库 + 迁移 + node（config_version=7）+ credential + 一条 TCP Route
/// （listen 127.0.0.1:<listen_port> → target 127.0.0.1:<target_port>）。
/// `limits` 为 `limits` 列的 JSON 字符串（`None` = 不限）。
async fn seeded_db(listen_port: u16, target_port: u16, limits: Option<&str>) -> Db {
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
    let limits = limits.map(str::to_string);
    tunnel_db::sqlx::query(
        "INSERT INTO routes \
         (id, name, node_id, type, enabled, listen_host, listen_port, target_host, target_port, \
          limits, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'tcp', 1, '127.0.0.1', ?, '127.0.0.1', ?, ?, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("echo")
    .bind(NODE_ID)
    .bind(listen_port as i64)
    .bind(target_port as i64)
    .bind(limits)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

/// 内网目标：echo 服务器（读多少回多少）。
async fn spawn_echo_target() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (port, task)
}

/// 完整隧道：Server（QUIC + TCP 监听）+ Agent（连接 + 认证 + 数据面）。
struct Tunnel {
    listen_port: u16,
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

async fn spawn_tunnel(target_port: u16, limits: Option<&str>) -> Tunnel {
    // `free_port()` 绑定→取端口→释放，到 `TcpProxy` 重新绑定同一端口之间存在 TOCTOU 窗口；
    // 与本文件另一测试或其它测试二进制并行时端口可能被抢，命中 AddrInUse 即换端口重试
    // （QUIC server 与 echo 目标均绑 `:0`，不会冲突，唯一会 AddrInUse 的是 TCP 监听）。
    for _ in 0..8 {
        let listen_port = free_port().await;
        let db = seeded_db(listen_port, target_port, limits).await;
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

        // 加载路由 + 绑定 TCP 数据面监听（唯一可能 AddrInUse 的步骤，失败即换端口重试）。
        let table = Arc::new(RouteTable::new());
        for row in db.list_routes().await.unwrap() {
            table.insert(ServerRoute::try_from(row).unwrap()).unwrap();
        }
        let proxy = match TcpProxy::bind_with_conns(table, server.conns()).await {
            Ok(p) => p,
            Err(e) if format!("{e:#}").contains("Address already in use") => continue,
            Err(e) => panic!("bind TCP proxy: {e:#}"),
        };
        proxy.run();

        let s = Arc::clone(&server);
        let server_task = tokio::spawn(async move {
            let _ = s.run().await;
        });

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

        // 等 Agent 的连接登记进注册表（数据面可用）。
        wait_until(|| server.conns().get(node_id).is_some()).await;

        return Tunnel {
            listen_port,
            server,
            server_task,
            agent_task,
        };
    }
    panic!("could not bind a free TCP port after retries");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_reaches_intranet_service() {
    let (target_port, target_task) = spawn_echo_target().await;
    let tunnel = spawn_tunnel(target_port, None).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    client.shutdown().await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    drop(client);
    drop(tunnel);
    target_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_does_not_lose_data() {
    let (target_port, target_task) = spawn_echo_target().await;
    let tunnel = spawn_tunnel(target_port, None).await;

    // 大 payload（远大于单次 copy 缓冲）验证半关闭不丢数据：写毕即 shutdown（FIN），
    // 仍应完整读回目标回声。
    let payload: Vec<u8> = (0..256_000u32).map(|i| (i % 251) as u8).collect();
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut got = Vec::with_capacity(payload.len());
    let mut chunk = [0u8; 8192];
    loop {
        let n = client.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(got, payload);

    drop(client);
    drop(tunnel);
    target_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_max_connections_rejects_excess() {
    // T-35：单 Route 超过 limits.max_connections=1 后，第二条入向连接被拒（服务器关闭连接）。
    let (target_port, target_task) = spawn_echo_target().await;
    let tunnel = spawn_tunnel(target_port, Some(r#"{"max_connections":1}"#)).await;

    // 第一条连接占用唯一额度并保持打开。
    let mut a = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();
    a.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    // 第二条连接：超限被拒——服务器接受后立即 drop，客户端读到 EOF（或 RST）。
    let mut b = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(5), b.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {} // RST 也是「被拒」的一种表现
        Ok(Ok(n)) => panic!("excess connection should be closed, but read {n} bytes"),
        Err(_) => panic!("second connection was not rejected within timeout"),
    }

    // 第一条连接仍可用（额度未受影响）。
    a.write_all(b"again").await.unwrap();
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"again");

    drop(a);
    drop(tunnel);
    target_task.abort();
}
