//! Web 管理后台静态托管（T-24/§153）：把 `web/dist` 构建产物作为 SPA 从 internal 端口
//! 同源提供。
//!
//! 前端用哈希路由（`#/nodes`、`#/routes/:id/edit`），服务端仅需应答 `/`（`index.html`）
//! 与 `/assets/*`；`not_found_service` 回退到 `index.html`，兼顾未来路径路由/直接刷新。

use std::path::Path;

use axum::http::StatusCode;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_status::SetStatus;

/// 构建 SPA 静态文件服务：目录请求回退 `index.html`，未命中路径同样回退 `index.html`
/// （200 而非 404），使 `axum::Router::fallback_service` 能正确托管单页应用。
pub fn spa_fallback(dir: &Path) -> ServeDir<SetStatus<ServeFile>> {
    let index = dir.join("index.html");
    ServeDir::new(dir)
        .append_index_html_on_directories(true)
        .fallback(SetStatus::new(ServeFile::new(index), StatusCode::OK))
}
