//! 集成测试（T-30）：端到端 UDP 数据面——客户端发 datagram 到 Server 的 UDP 监听，经 Node 的
//! QUIC datagram 转发到内网 UDP 目标并回显。首个包负责建会话（`UDP_OPEN` 经控制流到达 Agent
//! 前，首个 datagram 可能因会话未建而被丢弃），故发两次：第一次建会话，第二次验证回显。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use tunnel_agent::{tls, Agent, AgentSession, HeartbeatConfig};
use tunnel_auth::hash_token;
use tunnel_config::SecurityConfig;
use tunnel_core::SessionManager;
use tunnel_db::Db;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion};
use tunnel_server::route::{RouteTable, ServerRoute};
use tunnel_server::udp_proxy::UdpProxy;
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

async fn free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
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

/// 建内存库 + 迁移 + node + credential + 一条 UDP Route
/// （listen 127.0.0.1:<listen_port> → target 127.0.0.1:<target_port>）。
async fn seeded_udp_db(listen_port: u16, target_port: u16) -> Db {
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
         VALUES (?, ?, ?, 'udp', 1, '127.0.0.1', ?, '127.0.0.1', ?, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("dns")
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

/// 内网 UDP 目标：回显服务器（收多少回多少）。
async fn spawn_udp_echo_target() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], src).await;
        }
    });
    (port, task)
}

/// 完整 UDP 隧道：Server（QUIC + UDP 监听）+ Agent（连接 + 认证 + UDP 数据面）。
struct UdpTunnel {
    listen_port: u16,
    server: Arc<QuicServer>,
    udp: Arc<UdpProxy>,
    server_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.server.close();
        self.server_task.abort();
        self.agent_task.abort();
    }
}

async fn spawn_tunnel(target_port: u16) -> UdpTunnel {
    // `free_udp_port()` 绑定→取端口→释放，到 `UdpProxy::bind` 重新绑定之间存在 TOCTOU 窗口；
    // 并行测试可能抢走端口，命中 AddrInUse 即换端口重试（QUIC server 与 echo 目标均绑 `:0`）。
    for _ in 0..8 {
        let listen_port = free_udp_port().await;
        let db = seeded_udp_db(listen_port, target_port).await;
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

        // 加载路由 + 绑定 UDP 数据面（唯一可能 AddrInUse 的步骤，失败即换端口重试）。
        // 须在 `run` 接受连接前挂接。
        let table = Arc::new(RouteTable::new());
        for row in db.list_routes().await.unwrap() {
            table.insert(ServerRoute::try_from(row).unwrap()).unwrap();
        }
        let udp =
            match UdpProxy::bind(Arc::clone(&table), server.conns(), server.config_sync()).await {
                Ok(p) => Arc::new(p),
                Err(e) if format!("{e:#}").contains("Address already in use") => continue,
                Err(e) => panic!("bind UDP proxy: {e:#}"),
            };
        server.set_udp_proxy(Arc::clone(&udp));
        udp.run();

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

        wait_until(|| server.conns().get(node_id).is_some()).await;

        return UdpTunnel {
            listen_port,
            server,
            udp,
            server_task,
            agent_task,
        };
    }
    panic!("could not bind a free UDP port after retries");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_client_reaches_intranet_target() {
    let (target_port, target_task) = spawn_udp_echo_target().await;
    let tunnel = spawn_tunnel(target_port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();

    let msg = b"ping-udp";
    // 首个包建会话（UDP_OPEN 经控制流落地前，其 datagram 可能被丢弃）；第二次验证端到端回显。
    client.send(msg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    client.send(msg).await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], msg);

    drop(client);
    drop(tunnel);
    target_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_packet_is_dropped_and_counted() {
    let (target_port, target_task) = spawn_udp_echo_target().await;
    let tunnel = spawn_tunnel(target_port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(("127.0.0.1", tunnel.listen_port))
        .await
        .unwrap();

    // 先发小包建会话，再发超过 1200 默认上限的大包；大包应被明确丢弃并计数，不转发、不截断。
    client.send(b"warm").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let before = tunnel.udp.dropped_oversized();
    let big = vec![0xABu8; 2048];
    client.send(&big).await.unwrap();
    wait_until(|| tunnel.udp.dropped_oversized() > before).await;

    drop(client);
    drop(tunnel);
    target_task.abort();
}
