//! 集成测试（T-23）：`/openapi.json` 与 `/docs`（Swagger UI）。
//!
//! 验收：`/openapi.json` 为合法 OpenAPI 3.x，覆盖全部 API 路径，且 components.schemas
//! 含 §132 要求的 `Node`/`Route`/`User` 类型；`/docs` 返回 Swagger UI HTML。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use tunnel_db::Db;
use tunnel_server::api::AppState;

async fn app() -> axum::Router {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    tunnel_server::api::router(AppState::new(db))
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn openapi_json_is_valid_and_covers_routes_and_schemas() {
    let app = app().await;

    let (status, headers, body) = get(&app, "/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false),
        "openapi.json should be application/json"
    );

    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let version = doc["openapi"].as_str().unwrap();
    assert!(version.starts_with("3."), "openapi version {version}");

    // 关键路径全部覆盖。
    for p in [
        "/auth/login",
        "/auth/me",
        "/enroll",
        "/api/v1/nodes",
        "/api/v1/nodes/{id}",
        "/api/v1/nodes/{id}/credentials",
        "/api/v1/routes",
        "/api/v1/routes/{id}",
        "/api/v1/routes/{id}/enable",
    ] {
        assert!(
            doc["paths"].get(p).is_some(),
            "missing path {p} in openapi.json"
        );
    }

    // §132 要求的核心类型（Node/Route/User）存在。
    let schemas = &doc["components"]["schemas"];
    for name in ["Node", "Route", "User"] {
        assert!(
            schemas.get(name).is_some(),
            "missing schema {name} in components.schemas"
        );
    }
}

#[tokio::test]
async fn docs_serves_swagger_ui_html() {
    let app = app().await;

    // `/docs` 重定向到 `/docs/`（Swagger UI 挂载约定）。
    let (status, headers, body) = get(&app, "/docs/").await;
    assert_eq!(status, StatusCode::OK);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/html"),
        "Swagger UI should be HTML, got {content_type}"
    );
    assert!(
        body.contains("swagger"),
        "Swagger UI HTML should mention swagger"
    );
}
