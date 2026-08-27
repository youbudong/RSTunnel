//! 导出 OpenAPI 文档为 JSON 文件（T-23/§132）。
//!
//! 用法：`cargo run -p tunnel-server --example dump_openapi -- <output.json>`
//!
//! 由 `#[derive(OpenApi)]` 的 [`ApiDoc`] 单一事实来源生成，供 `web/` 用
//! `openapi-typescript` 生成 TS 类型，避免前后端手写重复类型。

use std::env;
use std::fs;
use std::path::PathBuf;

use utoipa::OpenApi;

use tunnel_server::api::openapi::ApiDoc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("openapi.json"));

    let json = ApiDoc::openapi().to_pretty_json()?;
    fs::write(&path, json)?;
    println!("wrote {}", path.display());
    Ok(())
}
