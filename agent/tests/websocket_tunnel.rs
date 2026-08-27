//! 集成测试（T-29）：WebSocket 经 HTTP 隧道可用——客户端发 `Upgrade: websocket`，Server 按
//! Host 路由并透传（`handle_http` 保留 `Upgrade`/`Connection` 头，`copy_duplex` 双向透传），
//! 目标回 `101 Switching Protocols` 后进入全双工回显。断言握手与后续双向字节均正确转发。

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
use tunnel_server::http_proxy::HttpProxy;
use tunnel_server::route::{HostTable, ServerRoute};
use tunnel_server::{quic::QuicServer, tls as server_tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";
const HOSTNAME: &str = "app.example.com";
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

/// 建内存库 + 迁移 + node + credential + 一条 HTTP Route（hostname → target）。
async fn seeded_http_db(target_port: u16) -> Db {
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
         (id, name, node_id, type, enabled, listen_host, listen_port, hostname, \
          target_host, target_port, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'http', 1, NULL, NULL, ?, '127.0.0.1', ?, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("web")
    .bind(NODE_ID)
    .bind(HOSTNAME)
    .bind(target_port as i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

/// WebSocket 目标：读到升级请求头后回 `101 Switching Protocols`，随后全双工回显（读到即写回）。
async fn spawn_ws_target() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // 读到请求头为止（升级请求无 body）。
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                // 回 101，进入 WebSocket 数据阶段。
                let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                            Connection: Upgrade\r\nSec-WebSocket-Accept: dummy\r\n\r\n";
                if sock.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // 全双工回显直到对端关闭。
                loop {
                    let mut data = [0u8; 4096];
                    let n = sock.read(&mut data).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    if sock.write_all(&data[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, task)
}

/// 完整 HTTP 隧道（同 http_tunnel：Server QUIC + HTTP Host 入口 + Agent）。
struct HttpTunnel {
    http_addr: std::net::SocketAddr,
    server: Arc<QuicServer>,
    server_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpTunnel {
    fn drop(&mut self) {
        self.server.close();
        self.server_task.abort();
        self.agent_task.abort();
    }
}

async fn spawn_http_tunnel(db: Db) -> HttpTunnel {
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

    let host_table = Arc::new(HostTable::new());
    for row in db.list_routes().await.unwrap() {
        host_table
            .insert(ServerRoute::try_from(row).unwrap())
            .unwrap();
    }
    let http_proxy = HttpProxy::bind("127.0.0.1:0".parse().unwrap(), host_table, server.conns())
        .await
        .unwrap();
    let http_addr = http_proxy.local_addr();
    http_proxy.run();

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

    HttpTunnel {
        http_addr,
        server,
        server_task,
        agent_task,
    }
}

/// 读取直到 `\r\n\r\n`（返回该段字节）。
async fn read_head(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = sock.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_upgrade_and_echo_roundtrip() {
    let (target_port, target_task) = spawn_ws_target().await;
    let db = seeded_http_db(target_port).await;
    let tunnel = spawn_http_tunnel(db).await;

    let mut client = tokio::net::TcpStream::connect(tunnel.http_addr)
        .await
        .unwrap();
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {HOSTNAME}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    // 1. 升级握手：目标回 101，且 Upgrade 头被原样保留。
    let head = read_head(&mut client).await;
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "got: {head}"
    );
    assert!(
        head.to_ascii_lowercase().contains("upgrade: websocket"),
        "got: {head}"
    );

    // 2. 升级后全双工回显：连续两条消息都原样往返，证明长连接双向透传。
    for msg in ["hello-websocket", "second-frame"] {
        client.write_all(msg.as_bytes()).await.unwrap();
        let mut data = [0u8; 128];
        let n = client.read(&mut data).await.unwrap();
        assert_eq!(&data[..n], msg.as_bytes());
    }

    drop(client);
    drop(tunnel);
    target_task.abort();
}
