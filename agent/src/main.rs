//! tunnel-agent 入口：加载 bootstrap → 解析 endpoints → QUIC 连接 → HELLO/AUTH → 心跳循环。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tunnel_config::AgentConfig;
use tunnel_protocol::{AuthPayload, Capabilities, HelloPayload, ProtocolVersion};

use tunnel_agent::{connect_any, run_with_reconnect, tls, Agent, HeartbeatConfig, ReconnectConfig};

#[derive(Parser)]
#[command(name = "tunnel-agent", version, about = "Rust Tunnel 内网代理")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "config/agent.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    tunnel_common::init_logging();
    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "agent exited with error");
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read config {}", args.config.display()))?;
    let cfg = AgentConfig::from_toml(&text)?;
    cfg.validate()?;

    // T-43：多服务器故障转移。`server_addresses()` 顺序即优先级（primary 在前）。
    let addresses = cfg.server_addresses();
    let endpoints = resolve_endpoints(&addresses).await?;
    for (i, (addr, server_name)) in endpoints.iter().enumerate() {
        tracing::info!(%addr, %server_name, endpoint_index = i, name = %cfg.agent.name, "server endpoint");
    }

    let client_config = build_client_config(cfg.server.ca.as_deref())?;
    // `server_name` 仅作默认 SNI；故障转移循环按每个端点各自的 SNI 连。
    let agent = Agent::new(client_config, endpoints[0].1.clone())?;

    let hello = HelloPayload {
        protocol_version: ProtocolVersion { major: 1, minor: 0 },
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: Capabilities::default(),
    };
    let auth = AuthPayload {
        node_id: None,
        credential: Some(cfg.auth.token.clone()),
    };

    // T-34f：本地目标策略（allow/deny_targets）贯穿整个连接生命周期，供数据面出站校验。
    let security = Arc::new(cfg.security.clone());

    // T-39：本地存活探针（[health].bind，默认 127.0.0.1:9090/health），供编排器探活。
    let health_addr: SocketAddr = cfg
        .health
        .bind
        .parse()
        .with_context(|| format!("parse health bind address {}", cfg.health.bind))?;
    let health_listener = tokio::net::TcpListener::bind(health_addr)
        .await
        .with_context(|| format!("bind health listener {health_addr}"))?;
    tracing::info!(%health_addr, "agent health endpoint listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(health_listener, tunnel_agent::health::router()).await {
            tracing::error!(error = %e, "agent health server error");
        }
    });

    // 连接 + 认证 + 心跳，断开后按指数退避自动重连（T-12）。
    // 取消信号未使用——Agent 作为常驻进程运行至被外部终止。
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    run_with_reconnect(
        {
            let agent = &agent;
            let endpoints = &endpoints;
            move || {
                connect_any(
                    agent,
                    endpoints,
                    hello.clone(),
                    auth.clone(),
                    Arc::clone(&security),
                )
            }
        },
        HeartbeatConfig::default(),
        ReconnectConfig::default(),
        cancel_rx,
    )
    .await;

    Ok(())
}

/// 解析 `host:port` → (SocketAddr, host)。host 用作 TLS SNI。
async fn resolve_endpoint(endpoint: &str) -> Result<(SocketAddr, String)> {
    let (host, _port) = endpoint
        .rsplit_once(':')
        .context("endpoint must be host:port")?;
    let addr = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve endpoint {endpoint}"))?
        .next()
        .context("endpoint resolved to no address")?;
    Ok((addr, host.to_string()))
}

/// 解析所有服务器端点（T-43）。单个端点解析失败仅记警告并跳过（主备可能并非全部可达）；
/// 全部失败则报错。
async fn resolve_endpoints(endpoints: &[String]) -> Result<Vec<(SocketAddr, String)>> {
    let mut resolved = Vec::new();
    for endpoint in endpoints {
        match resolve_endpoint(endpoint).await {
            Ok(pair) => resolved.push(pair),
            Err(e) => tracing::warn!(%endpoint, error = %e, "skip unresolvable server endpoint"),
        }
    }
    if resolved.is_empty() {
        anyhow::bail!("no server endpoint could be resolved");
    }
    Ok(resolved)
}

fn build_client_config(ca: Option<&str>) -> Result<quinn::ClientConfig> {
    match ca {
        Some(path) => {
            let der = std::fs::read(path).with_context(|| format!("read CA {path}"))?;
            tls::client_config_from_der(der)
        }
        None => {
            tracing::warn!(
                "no [server].ca configured; server cert is not trusted (system roots land in T-30)"
            );
            tls::client_config_without_roots()
        }
    }
}
