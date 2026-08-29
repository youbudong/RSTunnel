//! tunnel-server 二进制入口：加载配置 → 构建 TLS → 启动 QUIC 接受循环。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tunnel_config::ServerConfig;
use tunnel_core::SessionManager;
use tunnel_server::acl_store::AclStore;
use tunnel_server::certificate::CertStore;
use tunnel_server::config::ConfigManager;
use tunnel_server::conn_limiter::ConnLimiter;
use tunnel_server::http_proxy::HttpProxy;
use tunnel_server::https_proxy::HttpsProxy;
use tunnel_server::login_limiter::LoginLimiter;
use tunnel_server::route::{HostTable, RouteTable};
use tunnel_server::tcp_proxy::TcpProxy;
use tunnel_server::udp_proxy::UdpProxy;
use tunnel_server::{quic, tls};

#[derive(Parser)]
#[command(name = "tunnel-server", version, about = "Rust Tunnel 服务端")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "config/server.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    tunnel_common::init_logging();
    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server exited with error");
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read config {}", args.config.display()))?;
    let cfg = ServerConfig::from_toml(&text)?;
    cfg.validate()?;

    // T-38：注册全部 Prometheus 指标（幂等；`/metrics` 与数据面内联计数共享 default registry）。
    tunnel_metrics::register_all().context("register metrics")?;

    // T-39：就绪状态——随启动流程逐组件置位，`/ready` 据此判定（§98）。
    let readiness = Arc::new(tunnel_server::readiness::Readiness::new());

    let db = tunnel_db::Db::connect(&cfg.database.url)
        .await
        .context("connect database")?;
    db.migrate().await.context("run migrations")?;
    readiness.mark_db();

    let quic_addr: SocketAddr = cfg.quic.bind.parse().context("parse quic bind address")?;
    // TODO(T-27): 从 ACME/配置加载证书；开发/演示用自签名（SAN 取自 [tls].subjects）。
    // 配置 cert_der_path + key_der_path 时复用已落盘证书（跨重启稳定身份），否则每次启动新生成。
    let cert = tls::load_or_generate(
        cfg.tls.cert_der_path.as_deref().map(Path::new),
        cfg.tls.key_der_path.as_deref().map(Path::new),
        &cfg.tls.subjects,
    )?;
    let server_config = tls::server_config(&cert)?;
    let sessions = Arc::new(SessionManager::new());
    // T-25：数据面（QUIC）与管理面（REST）共享事件总线，`/ws` 订阅其上的 node/route/config 事件。
    let events = Arc::new(tunnel_server::event::EventBus::new(
        tunnel_server::event::EventBus::DEFAULT_CAPACITY,
    ));
    let server = quic::QuicServer::bind_with_events(
        quic_addr,
        server_config,
        db.clone(),
        sessions,
        Arc::clone(&events),
    )?;
    let addr = server.local_addr()?;
    tracing::info!(%addr, "QUIC listener started");
    readiness.mark_quic();

    // T-17：配置管理器从数据库加载并校验路由快照（ArcSwap 无锁读、原子替换）。
    let config = ConfigManager::new();
    config.reload(&db).await.context("load config")?;
    readiness.mark_config();

    // T-34：数据面 ACL——加载 `acl_rules` 快照，与 Tcp/Http/Https proxy 及 REST 共享。
    let acl = Arc::new(AclStore::new());
    acl.reload(&db).await;

    // T-35：按 Route 的连接限速器（limits.max_connections），跨 Tcp/Http/Https 数据面共享。
    let conn_limiter = Arc::new(ConnLimiter::new());

    // T-14/T-15：由快照构建 Route 表并启动 TCP 数据面监听（经各 Node 的 QUIC 连接转发）。
    // T-26：HTTP/HTTPS 路由按 Host 路由（共享 `http.bind`），独立构建 HostTable。
    let routes = Arc::new(RouteTable::new());
    let host_table = Arc::new(HostTable::new());
    for route in &config.snapshot().routes {
        match route.route_type {
            tunnel_protocol::RouteType::Http | tunnel_protocol::RouteType::Https => {
                host_table
                    .insert(route.clone())
                    .context("insert host route")?;
            }
            _ => {
                routes.insert(route.clone()).context("insert route")?;
            }
        }
    }
    let proxy = TcpProxy::bind_with_conns_acl_and_limiter(
        Arc::clone(&routes),
        server.conns(),
        Arc::clone(&acl),
        Arc::clone(&conn_limiter),
    )
    .await
    .context("bind tcp proxy")?;
    let n_listeners = proxy.local_addrs().len();
    tracing::info!(listeners = n_listeners, "TCP listeners started");
    proxy.run();

    // T-30：UDP 数据面——按 Route 绑定 UDP 监听，客户端 datagram ↔ QUIC datagram 转发。
    let udp_proxy = Arc::new(
        UdpProxy::bind(Arc::clone(&routes), server.conns(), server.config_sync())
            .await
            .context("bind udp proxy")?,
    );
    let n_udp = udp_proxy.local_addrs().len();
    if n_udp > 0 {
        tracing::info!(listeners = n_udp, "UDP listeners started");
    }
    server.set_udp_proxy(Arc::clone(&udp_proxy));
    udp_proxy.run();

    // T-26：HTTP 数据面入口——解析 Host → 匹配 HTTP/HTTPS Route → 注入 X-Forwarded-* → OPEN_TCP 透传。
    let http_addr: SocketAddr = cfg.http.bind.parse().context("parse http bind address")?;
    let http_proxy = HttpProxy::bind_with_acl_and_limiter(
        http_addr,
        Arc::clone(&host_table),
        server.conns(),
        Arc::clone(&acl),
        Arc::clone(&conn_limiter),
    )
    .await
    .context("bind http proxy")?;
    tracing::info!(addr = %http_proxy.local_addr(), "HTTP listener started");
    http_proxy.run();
    readiness.mark_http();

    // T-27：从数据库加载手动证书，按 SNI 终止 TLS；解密后复用 HTTP 数据面（X-Forwarded-Proto=https）。
    let cert_store = Arc::new(CertStore::from_rows(&db.list_certificates().await?)?);
    if !cert_store.is_empty() {
        tracing::info!(certificates = cert_store.len(), "TLS certificates loaded");
    }
    let warn_before = time::Duration::days(30);
    for (hostnames, expires_at) in cert_store.expiring(time::OffsetDateTime::now_utc(), warn_before)
    {
        tracing::warn!(hostnames, %expires_at, "certificate expired or expiring soon");
    }
    let https_addr: SocketAddr = cfg.https.bind.parse().context("parse https bind address")?;
    let https_proxy = HttpsProxy::bind_with_acl_and_limiter(
        https_addr,
        host_table,
        server.conns(),
        cert_store,
        Arc::clone(&acl),
        Arc::clone(&conn_limiter),
    )
    .await
    .context("bind https proxy")?;
    tracing::info!(addr = %https_proxy.local_addr(), "HTTPS listener started");
    https_proxy.run();

    // T-20：REST API（管理面）监听 internal 地址（回环，不对外发布；§75 生产走 443 HTTPS 入口）。
    let internal_addr: SocketAddr = cfg
        .internal
        .bind
        .parse()
        .context("parse internal bind address")?;
    let listener = tokio::net::TcpListener::bind(internal_addr)
        .await
        .with_context(|| format!("bind admin API listener {internal_addr}"))?;
    // T-35：登录防暴力破解限速器（阈值/窗口来自 `[security]` 配置）。
    let login_limiter = Arc::new(LoginLimiter::new(
        cfg.security.max_login_attempts,
        cfg.security.login_window_seconds,
    ));
    // T-24/§153：配置了 `[internal].web_dir` 时，从 internal 端口同源托管 Web 管理后台。
    let web_dir = cfg.internal.web_dir.clone().map(PathBuf::from);
    if let Some(dir) = &web_dir {
        tracing::info!(dir = %dir.display(), "serving Web admin from internal listener");
    }
    let app = tunnel_server::api::router(
        tunnel_server::api::AppState::new_with_events_acl_and_login(
            db.clone(),
            events,
            acl,
            login_limiter,
        )
        .with_allow_unsafe_targets(cfg.security.allow_unsafe_targets)
        .with_readiness(Arc::clone(&readiness))
        .with_web_dir(web_dir)
        .with_config_sync(server.config_sync()),
    );
    tracing::info!(%internal_addr, "admin API listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "admin API server error");
        }
    });

    tokio::select! {
        res = server.run() => res,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
            Ok(())
        }
    }
}
