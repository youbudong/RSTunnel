//! 集成测试（T-27）：端到端 HTTPS 数据面——客户端连 Server 的 `https.bind` 入口，按 SNI 选证书，
//! 终止 TLS 后复用 HTTP 数据面（Host 路由 + `X-Forwarded-*` 注入）；校验
//! `X-Forwarded-Proto=https` 与客户端伪造的 `X-Forwarded-For` 被覆盖。

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
use tunnel_server::certificate::CertStore;
use tunnel_server::https_proxy::HttpsProxy;
use tunnel_server::route::{HostTable, ServerRoute};
use tunnel_server::{quic::QuicServer, tls as server_tls};

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";
const CERT_ID: &str = "55555555-5555-4555-8555-555555555555";
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

/// 建内存库 + 迁移 + node + credential + 一条 HTTP Route + 一张覆盖 HOSTNAME 的手动证书。
/// 返回 `(db, cert_der)`：`cert_der` 供测试客户端信任该自签名证书。
async fn seeded_https_db(target_port: u16) -> (Db, rustls::pki_types::CertificateDer<'static>) {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let certified = rcgen::generate_simple_self_signed(vec![HOSTNAME.to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let cert_der = certified.cert.der().clone();

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
    tunnel_db::sqlx::query(
        "INSERT INTO certificates \
         (id, name, hostnames, certificate, private_key_encrypted, expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
    )
    .bind(CERT_ID)
    .bind("app-cert")
    .bind("[\"app.example.com\"]")
    .bind(cert_pem)
    .bind(key_pem)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();

    (db, cert_der)
}

/// 内网目标：回显 `host`、`x-forwarded-for`、`x-forwarded-proto`（供断言 Host 路由、
/// XFF 覆盖与 TLS 终止后的 proto 标识）。
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
                let proto = header_value(&head, "x-forwarded-proto").unwrap_or_default();
                let body = format!("host={host}\nxff={xff}\nproto={proto}");
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

/// 完整 HTTPS 隧道：Server（QUIC + HTTPS SNI 入口）+ Agent（连接 + 认证 + 数据面）。
struct HttpsTunnel {
    https_addr: std::net::SocketAddr,
    server: Arc<QuicServer>,
    server_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpsTunnel {
    fn drop(&mut self) {
        self.server.close();
        self.server_task.abort();
        self.agent_task.abort();
    }
}

async fn spawn_https_tunnel(db: Db) -> HttpsTunnel {
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

    // 加载 HTTP 路由到 HostTable + 证书到 CertStore，绑定 SNI 终止入口。
    let host_table = Arc::new(HostTable::new());
    for row in db.list_routes().await.unwrap() {
        host_table
            .insert(ServerRoute::try_from(row).unwrap())
            .unwrap();
    }
    let cert_store =
        Arc::new(CertStore::from_rows(&db.list_certificates().await.unwrap()).unwrap());
    let https_proxy = HttpsProxy::bind(
        "127.0.0.1:0".parse().unwrap(),
        host_table,
        server.conns(),
        cert_store,
    )
    .await
    .unwrap();
    let https_addr = https_proxy.local_addr();
    https_proxy.run();

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

    HttpsTunnel {
        https_addr,
        server,
        server_task,
        agent_task,
    }
}

/// 用信任自签名证书的 rustls 客户端连 HTTPS 入口并返回响应体（含握手成功与否）。
async fn https_get(
    https_addr: std::net::SocketAddr,
    cert_der: rustls::pki_types::CertificateDer<'static>,
) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(HOSTNAME).unwrap();
    let tcp = tokio::net::TcpStream::connect(https_addr).await.unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let req = format!(
        "GET /secure HTTP/1.1\r\nHost: {HOSTNAME}\r\nX-Forwarded-For: 1.2.3.4\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.shutdown().await.unwrap();

    let mut resp = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = tls.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(resp).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_terminates_and_marks_proto_https() {
    let (target_port, target_task) = spawn_http_target().await;
    let (db, cert_der) = seeded_https_db(target_port).await;
    let tunnel = spawn_https_tunnel(db).await;

    let body = https_get(tunnel.https_addr, cert_der).await;

    // Host 正确转发到目标。
    assert!(body.contains(&format!("host={HOSTNAME}")), "body: {body}");
    // TLS 终止后的流按 https 注入 X-Forwarded-Proto。
    assert!(body.contains("proto=https"), "body: {body}");
    // 客户端伪造的 XFF 被覆盖为真实来源 IP（127.0.0.1）。
    assert!(body.contains("xff=127.0.0.1"), "body: {body}");
    assert!(
        !body.contains("1.2.3.4"),
        "forged XFF must be overwritten: {body}"
    );

    drop(tunnel);
    target_task.abort();
}
