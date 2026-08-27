//! 集成测试（T-26）：端到端 HTTP 数据面——客户端连 Server 的 `http.bind` 入口，
//! 按 `Host` 路由到 HTTP Route，经 Node 的 QUIC 连接 OPEN_TCP → 内网目标；
//! 校验 Host 正确转发、客户端伪造的 `X-Forwarded-For` 被覆盖为真实来源 IP。

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

/// 建内存库 + 迁移 + node + credential + 一条 HTTP Route
/// （hostname → target 127.0.0.1:<target_port>，无独立监听）。
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

/// 内网目标：解析请求头，回显 `host` 与 `x-forwarded-for` 的值（供断言 Host 路由与 XFF 覆盖）。
async fn spawn_http_target() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let head = String::from_utf8_lossy(&buf);
                let host = header_value(&head, "host").unwrap_or_default();
                let xff = header_value(&head, "x-forwarded-for").unwrap_or_default();
                let body = format!("host={host}\nxff={xff}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, task)
}

/// 大小写不敏感地提取单个请求头值。
fn header_value(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// 完整 HTTP 隧道：Server（QUIC + HTTP Host 入口）+ Agent（连接 + 认证 + 数据面）。
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

async fn spawn_http_tunnel(target_port: u16) -> HttpTunnel {
    let db = seeded_http_db(target_port).await;
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

    // 加载 HTTP 路由到 HostTable，绑定 Host 路由入口（与 QUIC 共享连接注册表）。
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

    HttpTunnel {
        http_addr,
        server,
        server_task,
        agent_task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_routes_and_overrides_forged_xff() {
    let (target_port, target_task) = spawn_http_target().await;
    let tunnel = spawn_http_tunnel(target_port).await;

    let mut client = tokio::net::TcpStream::connect(tunnel.http_addr)
        .await
        .unwrap();
    let req = format!(
        "GET /hello HTTP/1.1\r\nHost: {HOSTNAME}\r\nX-Forwarded-For: 1.2.3.4\r\nConnection: close\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let mut resp = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = client.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8(resp).unwrap();

    // Host 正确转发到目标。
    assert!(body.contains(&format!("host={HOSTNAME}")), "body: {body}");
    // 客户端伪造的 XFF 被覆盖为真实来源 IP（127.0.0.1），而非 1.2.3.4。
    assert!(body.contains("xff=127.0.0.1"), "body: {body}");
    assert!(
        !body.contains("1.2.3.4"),
        "forged XFF must be overwritten: {body}"
    );

    drop(client);
    drop(tunnel);
    target_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_host_returns_404() {
    let (target_port, target_task) = spawn_http_target().await;
    let tunnel = spawn_http_tunnel(target_port).await;

    let mut client = tokio::net::TcpStream::connect(tunnel.http_addr)
        .await
        .unwrap();
    let req = "GET / HTTP/1.1\r\nHost: unknown.example.com\r\nConnection: close\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let mut resp = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = client.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&resp);
    assert!(head.starts_with("HTTP/1.1 404 Not Found"), "got: {head}");

    drop(client);
    drop(tunnel);
    target_task.abort();
}
