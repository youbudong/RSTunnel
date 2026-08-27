//! 基准测试（T-46/§149/§61）。
//!
//! 独立 crate（同 fuzz/，非 workspace 成员），三个子命令：
//!   bench agents <N>        —— N 个 Agent 并发「连接 + 认证 + 快照」上线（1→10k 连接规模）
//!   bench throughput <MB>   —— 单条 TCP 隧道 echo 吞吐（MB/s）
//!   bench tcp <N>           —— N 条并发 TCP 连接穿过同一条隧道（1→10k 并发连接）
//!
//! 服务端与客户端同进程、同 tokio runtime（multi_thread）运行，回环网络测量。
//! 结果打印为 `key=value`，便于写入报告。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures_util::future::join_all;
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

const NOW: &str = "2026-08-27T00:00:00Z";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";

fn hello() -> HelloPayload {
    HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: "bench-agent".into(),
        capabilities: Capabilities::default(),
    }
}

fn auth(credential: &str) -> AuthPayload {
    AuthPayload {
        node_id: None,
        credential: Some(credential.to_string()),
    }
}

/// 当前进程 RSS（KB）。Linux 专用（`/proc/self/status` 的 VmRSS）。
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                let mut it = l.split_whitespace();
                if it.next() == Some("VmRSS:") {
                    it.next().and_then(|v| v.parse().ok())
                } else {
                    None
                }
            })
        })
        .unwrap_or(0)
}

/// 内存库 + 迁移 + 种入 `count` 个 node + credential（token-{i}）。
/// node/credential id 用 `{:08x}` 拼成合法 UUID 字符串（NodeId::parse_str 可解析）。
async fn seed_agent_nodes(db: &Db, count: usize) -> Result<()> {
    for i in 0..count {
        let node_id = format!("{i:08x}-0000-4000-8000-000000000000");
        let cred_id = format!("{i:08x}-0000-4000-8000-000000000001");
        let name = format!("node-{i}");
        let token = format!("token-{i}");

        tunnel_db::sqlx::query(
            "INSERT INTO nodes (id, name, config_version, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&node_id)
        .bind(&name)
        .bind(7i64)
        .bind(NOW)
        .bind(NOW)
        .execute(db.pool())
        .await?;

        tunnel_db::sqlx::query(
            "INSERT INTO credentials (id, node_id, type, secret_hash, created_at) \
             VALUES (?, ?, 'token', ?, ?)",
        )
        .bind(&cred_id)
        .bind(&node_id)
        .bind(hash_token(&token))
        .bind(NOW)
        .execute(db.pool())
        .await?;
    }
    Ok(())
}

/// `bench agents <N>`：N 个 Agent 并发完成 QUIC 握手 + token 认证 + 配置快照拉取并保持在线。
/// 统计墙钟时间、建立速率、内存增量、单连接建立延迟分布。
async fn bench_agents(count: usize) -> Result<()> {
    let db = Db::connect_memory().await?;
    db.migrate().await?;
    seed_agent_nodes(&db, count).await?;

    let sessions = Arc::new(SessionManager::new());
    let cert = server_tls::generate_self_signed(&["localhost".to_string()])?;
    let server = Arc::new(QuicServer::bind(
        "127.0.0.1:0".parse()?,
        server_tls::server_config(&cert)?,
        db.clone(),
        Arc::clone(&sessions),
    )?);
    let addr = server.local_addr()?;
    let s = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = s.run().await;
    });

    let client_config = tls::client_config_with_cert(&cert.cert_der)?;
    let agent = Agent::new(client_config, "localhost".to_string())?;
    let security = Arc::new(SecurityConfig::allow_all());

    let before = rss_kb();
    let start = Instant::now();
    let results = join_all((0..count).map(|i| {
        let agent = &agent;
        let security = Arc::clone(&security);
        let token = format!("token-{i}");
        async move {
            let t0 = Instant::now();
            let res = AgentSession::connect(agent, addr, hello(), auth(&token), security).await;
            let lat = t0.elapsed();
            (res, lat)
        }
    }))
    .await;
    let elapsed = start.elapsed();
    let after = rss_kb();

    let mut lats: Vec<Duration> = Vec::with_capacity(count);
    let mut sessions: Vec<AgentSession> = Vec::with_capacity(count);
    for (res, lat) in results {
        match res {
            Ok(s) => {
                sessions.push(s);
                lats.push(lat);
            }
            Err(e) => eprintln!("connect failed: {e:#}"),
        }
    }
    let ok = sessions.len();

    let delta = after.saturating_sub(before);
    println!(
        "bench=agents count={count} ok={ok} elapsed_ms={} setup_rate_per_s={:.1} \
         rss_before_kb={before} rss_after_kb={after} rss_delta_kb={delta}",
        elapsed.as_millis(),
        ok as f64 / elapsed.as_secs_f64(),
    );
    println!("rss_per_conn_kb={:.2}", delta as f64 / ok.max(1) as f64);

    // 单连接建立延迟分布：min / p50 / p90 / p99 / max。
    if !lats.is_empty() {
        lats.sort_unstable();
        let p = |q: f64| {
            let idx = ((lats.len() - 1) as f64 * q) as usize;
            lats[idx].as_millis()
        };
        println!(
            "connect_latency_ms min={} p50={} p90={} p99={} max={}",
            lats[0].as_millis(),
            p(0.50),
            p(0.90),
            p(0.99),
            lats[lats.len() - 1].as_millis(),
        );
    }

    // 保持在线一小段时间，再清理。
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(sessions);
    server.close();
    server_task.abort();
    Ok(())
}

/// 内存库 + 迁移 + node + credential + 一条 TCP Route（listen 127.0.0.1:<listen> → target）。
async fn seeded_route_db(listen_port: u16, target_port: u16) -> Result<Db> {
    let db = Db::connect_memory().await?;
    db.migrate().await?;
    let node_id = "11111111-1111-4111-8111-111111111111";
    tunnel_db::sqlx::query(
        "INSERT INTO nodes (id, name, config_version, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(node_id)
    .bind("node-a")
    .bind(7i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await?;
    tunnel_db::sqlx::query(
        "INSERT INTO credentials (id, node_id, type, secret_hash, created_at) \
         VALUES (?, ?, 'token', ?, ?)",
    )
    .bind("22222222-2222-4222-8222-222222222222")
    .bind(node_id)
    .bind(hash_token("secret-token"))
    .bind(NOW)
    .execute(db.pool())
    .await?;
    tunnel_db::sqlx::query(
        "INSERT INTO routes \
         (id, name, node_id, type, enabled, listen_host, listen_port, target_host, target_port, \
          limits, status, created_at, updated_at) \
         VALUES (?, ?, ?, 'tcp', 1, '127.0.0.1', ?, '127.0.0.1', ?, NULL, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("echo")
    .bind(node_id)
    .bind(listen_port as i64)
    .bind(target_port as i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await?;
    Ok(db)
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

/// 完整隧道（Server + TCP 监听 + Agent 数据面）。
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

async fn spawn_tunnel(target_port: u16) -> Tunnel {
    for _ in 0..8 {
        let listen_port = free_port().await;
        let db = seeded_route_db(listen_port, target_port).await.unwrap();
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

        let client_config = tls::client_config_with_cert(&cert.cert_der).unwrap();
        let agent = Agent::new(client_config, "localhost".to_string()).unwrap();
        let session = AgentSession::connect(
            &agent,
            quic_addr,
            hello(),
            auth("secret-token"),
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

        return Tunnel {
            listen_port,
            server,
            server_task,
            agent_task,
        };
    }
    panic!("could not bind a free TCP port after retries");
}

/// `bench throughput <MB>`：单条 TCP 隧道 echo 吞吐。客户端并发「写 + 读」（读边写边收），
/// 写 MB MiB、读回 MB MiB，报单方向等效 MB/s。
async fn bench_throughput(mb: usize) -> Result<()> {
    let (target_port, target_task) = spawn_echo_target().await;
    let tunnel = spawn_tunnel(target_port).await;

    let total = mb * 1024 * 1024;
    let client = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.listen_port)).await?;
    let (mut r, mut w) = tokio::io::split(client);

    let start = Instant::now();
    let writer = async {
        let chunk = vec![0u8; 65536];
        let mut written = 0usize;
        while written < total {
            let n = (total - written).min(chunk.len());
            w.write_all(&chunk[..n]).await?;
            written += n;
        }
        w.shutdown().await?;
        Ok::<usize, anyhow::Error>(written)
    };
    let reader = async {
        let mut got = 0usize;
        let mut buf = vec![0u8; 65536];
        while got < total {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok::<usize, anyhow::Error>(got)
    };
    let (written, echoed) = tokio::join!(writer, reader);
    let (written, echoed) = (written?, echoed?);
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();

    println!(
        "bench=throughput mb={mb} written={written} echoed={echoed} elapsed_ms={} one_way_mib_per_s={:.2}",
        elapsed.as_millis(),
        mb as f64 / secs,
    );

    drop(tunnel);
    target_task.abort();
    Ok(())
}

/// `bench tcp <N>`：N 条并发 TCP 连接穿过同一条隧道，各自 echo 固定 payload。
/// 统计总墙钟、成功数、聚合吞吐。
async fn bench_tcp(count: usize) -> Result<()> {
    let payload: Vec<u8> = vec![0xAB; 65536]; // 64 KiB
    let payload_len = payload.len();
    let (target_port, target_task) = spawn_echo_target().await;
    let tunnel = spawn_tunnel(target_port).await;
    let port = tunnel.listen_port;

    let start = Instant::now();
    let results = join_all((0..count).map(|_| {
        let payload = payload.clone();
        async move {
            let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            c.write_all(&payload).await?;
            c.shutdown().await?;
            let mut got = 0usize;
            let mut buf = vec![0u8; 65536];
            while got < payload.len() {
                let n = c.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            Ok::<usize, anyhow::Error>(got)
        }
    }))
    .await;
    let elapsed = start.elapsed();

    let ok = results.iter().filter(|r| r.is_ok()).count();
    let echoed: usize = results.iter().filter_map(|r| r.as_ref().ok()).sum();
    let secs = elapsed.as_secs_f64();
    println!(
        "bench=tcp count={count} ok={ok} elapsed_ms={} agg_mib_per_s={:.2} per_conn={}B",
        elapsed.as_millis(),
        (echoed as f64 / (1024.0 * 1024.0)) / secs,
        payload_len,
    );

    drop(tunnel);
    target_task.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (mode, n) = (
        args.get(1).map(String::as_str),
        args.get(2).and_then(|s| s.parse::<usize>().ok()),
    );
    match mode {
        Some("agents") => bench_agents(n.unwrap_or(1000)).await,
        Some("throughput") => bench_throughput(n.unwrap_or(64)).await,
        Some("tcp") => bench_tcp(n.unwrap_or(1000)).await,
        _ => {
            eprintln!("usage: bench <agents|throughput|tcp> [N]");
            Ok(())
        }
    }
}
