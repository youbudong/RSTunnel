//! 集成测试（T-24/§153）：`[internal].web_dir` 配置后，internal 端口把 `web/dist` 作为 SPA
//! 同源托管——`/` 与 `/assets/*` 命中静态文件，未命中路径回退 `index.html`（200），
//! 且 API 路由优先于静态兜底（不被吞掉）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use tunnel_db::Db;
use tunnel_server::api::AppState;

async fn migrated_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    db
}

/// 在系统临时目录创建一个最小 SPA：`index.html` + `assets/app.js`。
fn write_spa() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rstunnel-web-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(dir.join("assets")).unwrap();
    fs::write(dir.join("index.html"), "<html>app shell</html>").unwrap();
    fs::write(dir.join("assets/app.js"), "console.log('hi')").unwrap();
    dir
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn root_serves_index_html() {
    let dir = write_spa();
    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_web_dir(Some(dir)));
    let (status, body) = get(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("app shell"), "got: {body}");
}

#[tokio::test]
async fn assets_are_served() {
    let dir = write_spa();
    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_web_dir(Some(dir)));
    let (status, body) = get(&app, "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "console.log('hi')");
}

#[tokio::test]
async fn unknown_path_falls_back_to_index_html() {
    let dir = write_spa();
    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_web_dir(Some(dir)));
    // `/nodes` 是前端哈希路由里的客户端路径，服务端无此 API 路由 → SPA 回退。
    let (status, body) = get(&app, "/nodes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("app shell"), "got: {body}");
}

#[tokio::test]
async fn api_routes_take_precedence_over_spa_fallback() {
    let dir = write_spa();
    let app =
        tunnel_server::api::router(AppState::new(migrated_db().await).with_web_dir(Some(dir)));
    // `/health` 是已注册的 API 路由，不应被静态兜底吞掉。
    let (status, body) = get(&app, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"status\":\"ok\""), "got: {body}");
}

#[tokio::test]
async fn no_web_dir_disables_spa() {
    // 默认 `AppState::new` 的 web_dir 为 None：`/` 无兜底，返回 404。
    let app = tunnel_server::api::router(AppState::new(migrated_db().await));
    let (status, _) = get(&app, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
