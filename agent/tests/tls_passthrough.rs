//! 集成测试（T-28）：端到端 TLS 透传——客户端连 Server 的 `https.bind` 入口，Server 仅按 SNI
//! 路由、不解密，原始 TLS 字节经 QUIC 透传到内网 TLS 目标，客户端与目标直连完成握手。
//! 断言：客户端握手成功、读到的是**目标**发来的数据（即 Server 未终止 TLS）。

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
const HOSTNAME: &str = "app.example.com";
const NOW: &str = "2026-08-27T00:00:00Z";
const TARGET_MESSAGE: &str = "HELLO-TLS-TARGET";

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

/// 建内存库 + 迁移 + node + credential + 一条 HTTPS 透传路由（`tls_mode='passthrough'`）。
async fn seeded_passthrough_db(target_port: u16) -> Db {
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
          target_host, target_port, tls_mode, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'https', 1, NULL, NULL, ?, '127.0.0.1', ?, 'passthrough', 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("web-tls")
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

/// 内网 TLS 目标：自签名证书（SAN=HOSTNAME），握手后发送一段已知字节再关闭。
/// 返回 `(port, target_cert_der, task)`；`target_cert_der` 供客户端信任（证明端到端直连）。
async fn spawn_tls_target() -> (
    u16,
    rustls::pki_types::CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
) {
    let certified = rcgen::generate_simple_self_signed(vec![HOSTNAME.to_string()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let _ = tls.write_all(TARGET_MESSAGE.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, cert_der, task)
}

/// 完整 TLS 透传隧道：Server（QUIC + HTTPS SNI 入口）+ Agent（连接 + 认证 + 数据面）。
struct PassthroughTunnel {
    https_addr: std::net::SocketAddr,
    server: Arc<QuicServer>,
    server_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}

impl Drop for PassthroughTunnel {
    fn drop(&mut self) {
        self.server.close();
        self.server_task.abort();
        self.agent_task.abort();
    }
}

async fn spawn_passthrough_tunnel(db: Db) -> PassthroughTunnel {
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

    // 透传不需要终止证书；空 CertStore 仅使终止路径无证书可选。
    let host_table = Arc::new(HostTable::new());
    for row in db.list_routes().await.unwrap() {
        host_table
            .insert(ServerRoute::try_from(row).unwrap())
            .unwrap();
    }
    let https_proxy = HttpsProxy::bind(
        "127.0.0.1:0".parse().unwrap(),
        host_table,
        server.conns(),
        Arc::new(CertStore::new()),
    )
    .await
    .unwrap();
    let https_addr = https_proxy.local_addr();
    https_proxy.run();

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

    PassthroughTunnel {
        https_addr,
        server,
        server_task,
        agent_task,
    }
}

/// 用信任**目标**证书的 rustls 客户端连 Server 的 HTTPS 入口，读回目标发来的字节。
/// 若 Server 终止了 TLS，客户端会拿到 Server 自己的证书导致握手失败；因此成功 + 读到
/// `TARGET_MESSAGE` 即证明全程透传、Server 未解密。
async fn tls_client(
    addr: std::net::SocketAddr,
    cert_der: rustls::pki_types::CertificateDer<'static>,
) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(HOSTNAME).unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let mut out = String::new();
    let mut buf = [0u8; 64];
    loop {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.push_str(std::str::from_utf8(&buf[..n]).unwrap());
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_handshakes_with_target_through_passthrough() {
    let (target_port, target_cert, target_task) = spawn_tls_target().await;
    let db = seeded_passthrough_db(target_port).await;
    let tunnel = spawn_passthrough_tunnel(db).await;

    let msg = tls_client(tunnel.https_addr, target_cert).await;
    // 客户端用目标证书完成握手，且读到的正是目标发来的字节——Server 未解密。
    assert_eq!(msg, TARGET_MESSAGE);

    drop(tunnel);
    target_task.abort();
}
