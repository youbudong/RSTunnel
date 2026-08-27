//! tunnel-cli：管理引导工具。提供 token / 密码哈希生成、演示数据种入，
//! 以及配置快照的导出/导入与备份/恢复（T-42，docs §99/§100）。

mod snapshot;

use std::process::ExitCode;

use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};

use snapshot::Snapshot;

#[derive(Parser)]
#[command(name = "tunnel-cli", version, about = "Rust Tunnel 管理 CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 生成一个新的 agent 凭据 token（明文仅显示一次）
    Token,
    /// 生成密码的 Argon2id 哈希（用于 seed 管理员用户）
    HashPassword { password: String },
    /// 种入演示 Node + 凭据 + HTTP Route（Docker compose / 本地演示用）
    Seed(SeedArgs),
    /// 全量备份（含凭据哈希与证书）到 YAML，用于灾难恢复
    Backup(BackupArgs),
    /// 从全量备份恢复（默认预览，需 --yes 落库）
    Restore(RestoreArgs),
    /// 导出控制面配置（nodes/routes/domains/acl，不含凭据）到 YAML
    Export(ExportArgs),
    /// 导入控制面配置（默认预览，需 --yes 落库）
    Import(ImportArgs),
}

#[derive(Args)]
struct SeedArgs {
    /// 数据库 URL（SQLite）
    #[arg(long, default_value = "sqlite:///data/tunnel.db")]
    db: String,
    /// Agent 凭据 token（明文仅此处使用；库里只存 SHA-256 哈希）
    #[arg(long)]
    token: String,
    /// 演示 Route 的目标主机（target 服务名/IP）
    #[arg(long, default_value = "target")]
    target_host: String,
    /// 演示 Route 的目标端口
    #[arg(long, default_value_t = 5678)]
    target_port: u16,
    /// 演示 Route 的 Host（HTTP Host 路由匹配）
    #[arg(long, default_value = "app.example.com")]
    hostname: String,
}

#[derive(Args)]
struct BackupArgs {
    #[arg(long, default_value = "sqlite:///data/tunnel.db")]
    db: String,
    #[arg(long, default_value = "tunnel-backup.yaml")]
    output: String,
}

#[derive(Args)]
struct RestoreArgs {
    #[arg(long, default_value = "sqlite:///data/tunnel.db")]
    db: String,
    #[arg(long)]
    input: String,
    /// 确认落库（缺省仅校验 + 预览，不改库）
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct ExportArgs {
    #[arg(long, default_value = "sqlite:///data/tunnel.db")]
    db: String,
    #[arg(long, default_value = "tunnel-config.yaml")]
    output: String,
}

#[derive(Args)]
struct ImportArgs {
    #[arg(long, default_value = "sqlite:///data/tunnel.db")]
    db: String,
    #[arg(long)]
    input: String,
    /// 确认落库（缺省仅校验 + 预览，不改库）
    #[arg(long)]
    yes: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Token => {
            let token = tunnel_auth::generate_token();
            println!("token: {token}");
            println!("hash:  {}", tunnel_auth::hash_token(&token));
            Ok(())
        }
        Command::HashPassword { password } => {
            match tunnel_auth::hash_password(&password) {
                Ok(h) => println!("{h}"),
                Err(e) => return exit_err(&format!("{e}")),
            }
            Ok(())
        }
        Command::Seed(args) => seed(args).await,
        Command::Backup(args) => backup(args).await,
        Command::Restore(args) => restore(args).await,
        Command::Export(args) => export(args).await,
        Command::Import(args) => import(args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => exit_err(&format!("{e:#}")),
    }
}

fn exit_err(msg: &str) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::FAILURE
}

/// 种入一个演示拓扑：Node `demo-node` + 运行时凭据（`token`）+ 一条 HTTP Route。
///
/// 幂等：`demo-node` 已存在则跳过（重置演示需清空数据目录）。凭据以 `type='token'`
/// 入库，Agent 数据面 AUTH 据此通过；明文 token 不落库。
async fn seed(args: SeedArgs) -> anyhow::Result<()> {
    const NODE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa01";
    const CRED_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa02";
    const ROUTE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa03";

    let db = tunnel_db::Db::connect(&args.db)
        .await
        .context("connect database")?;
    db.migrate().await.context("run migrations")?;

    if db.node_name_exists("demo-node", None).await? {
        eprintln!("demo-node already seeded; skipping (clear the data dir to reset)");
        return Ok(());
    }

    let ts = time::OffsetDateTime::now_utc().to_string();
    db.create_node(NODE_ID, "demo-node", None, &ts).await?;
    db.create_credential(
        CRED_ID,
        NODE_ID,
        "token",
        &tunnel_auth::hash_token(&args.token),
        None,
        &ts,
    )
    .await?;
    db.create_route(
        ROUTE_ID,
        "demo-web",
        NODE_ID,
        "http",
        true,
        None,
        None,
        Some(&args.hostname),
        &args.target_host,
        args.target_port as i64,
        "none",
        None,
        &ts,
    )
    .await?;

    println!(
        "seeded node=demo-node route=demo-web hostname={} target={}:{}",
        args.hostname, args.target_host, args.target_port
    );
    Ok(())
}

/// 全量备份（含凭据哈希与证书）。
async fn backup(args: BackupArgs) -> anyhow::Result<()> {
    let db = connect(&args.db).await?;
    let snap = Snapshot::from_db(&db, true).await?;
    std::fs::write(&args.output, snap.to_yaml()?)
        .with_context(|| format!("write {}", args.output))?;
    println!(
        "已备份到 {}（nodes={} routes={} domains={} acl={} credentials={} certificates={}）",
        args.output,
        snap.nodes.len(),
        snap.routes.len(),
        snap.domains.len(),
        snap.acl_rules.len(),
        snap.credentials.len(),
        snap.certificates.len()
    );
    Ok(())
}

/// 控制面配置导出（不含凭据与证书）。
async fn export(args: ExportArgs) -> anyhow::Result<()> {
    let db = connect(&args.db).await?;
    let snap = Snapshot::from_db(&db, false).await?;
    std::fs::write(&args.output, snap.to_yaml()?)
        .with_context(|| format!("write {}", args.output))?;
    println!(
        "已导出到 {}（nodes={} routes={} domains={} acl={}；不含凭据/证书）",
        args.output,
        snap.nodes.len(),
        snap.routes.len(),
        snap.domains.len(),
        snap.acl_rules.len()
    );
    Ok(())
}

/// 从全量备份恢复。
async fn restore(args: RestoreArgs) -> anyhow::Result<()> {
    do_restore(&args.db, &args.input, args.yes, true).await
}

/// 从控制面配置导入（§100：拒绝含凭据的备份文件）。
async fn import(args: ImportArgs) -> anyhow::Result<()> {
    do_restore(&args.db, &args.input, args.yes, false).await
}

async fn do_restore(
    db_url: &str,
    input: &str,
    yes: bool,
    allow_secrets: bool,
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(input).with_context(|| format!("read {input}"))?;
    let snap = Snapshot::from_yaml(&text)?;
    if !allow_secrets && (!snap.credentials.is_empty() || !snap.certificates.is_empty()) {
        bail!("{input} 含凭据/证书（全量备份），请用 `restore` 而非 `import`");
    }
    snap.validate().context("snapshot 校验失败")?;

    let db = connect(db_url).await?;
    let report = snapshot::restore(&db, &snap, yes).await?;
    if yes {
        println!("已恢复：\n{}", report.render());
    } else {
        println!("预览（加 --yes 落库）：\n{}", report.render());
    }
    Ok(())
}

async fn connect(db_url: &str) -> anyhow::Result<tunnel_db::Db> {
    let db = tunnel_db::Db::connect(db_url)
        .await
        .context("connect database")?;
    db.migrate().await.context("run migrations")?;
    Ok(db)
}
