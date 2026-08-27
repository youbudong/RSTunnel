//! 集成测试（T-25）：事件总线（§134）+ `/ws` 端点（§23）。
//!
//! 覆盖：EventBus 按订阅顺序投递、订阅后事件可见性；`/ws` 未认证返回 401、
//! 携带有效 Bearer 的握手返回 101 并含 `Sec-WebSocket-Accept`。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use futures_util::StreamExt;
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tower::ServiceExt;

use tunnel_auth::hash_password;
use tunnel_db::Db;
use tunnel_server::api::AppState;
use tunnel_server::event::{EventBus, NODE_OFFLINE, NODE_ONLINE};

const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ROLE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NOW: &str = "2026-08-27T00:00:00Z";

async fn seeded_db() -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    tunnel_db::sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, disabled, created_at, updated_at) \
         VALUES (?, 'admin', 'admin@example.com', ?, 0, ?, ?)",
    )
    .bind(USER_ID)
    .bind(hash_password("hunter2").unwrap())
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();

    tunnel_db::sqlx::query("INSERT INTO roles (id, name) VALUES (?, 'admin')")
        .bind(ROLE_ID)
        .execute(db.pool())
        .await
        .unwrap();

    tunnel_db::sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(USER_ID)
        .bind(ROLE_ID)
        .execute(db.pool())
        .await
        .unwrap();

    db
}

fn app(db: Db) -> axum::Router {
    tunnel_server::api::router(AppState::new(db))
}

fn json_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// WebSocket 升级请求（RFC 6455 示例 nonce）。`token` 为 `None` 时不带认证头。
fn ws_req(token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("GET")
        .uri("/ws")
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==");
    if let Some(token) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(Body::empty()).unwrap()
}

async fn send(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value, HeaderMap) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, headers)
}

async fn login_token(app: &axum::Router) -> String {
    let (status, json, _) = send(
        app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login should succeed");
    json["access_token"].as_str().unwrap().to_string()
}

#[test]
fn event_bus_delivers_events_in_order_to_subscribers() {
    let bus = EventBus::new(8);
    let mut rx = bus.subscribe();

    bus.publish(NODE_ONLINE, json!({ "node_id": "a" }));
    bus.publish(NODE_OFFLINE, json!({ "node_id": "a" }));

    let e1 = rx.try_recv().unwrap();
    assert_eq!(e1.event_type, NODE_ONLINE);
    assert_eq!(e1.data["node_id"], "a");
    let e2 = rx.try_recv().unwrap();
    assert_eq!(e2.event_type, NODE_OFFLINE);
}

#[test]
fn subscriber_only_receives_events_after_subscription() {
    let bus = EventBus::new(8);
    // 订阅前发布：对新订阅者不可见。
    bus.publish(NODE_ONLINE, json!({ "node_id": "a" }));

    let mut rx = bus.subscribe();
    bus.publish(NODE_OFFLINE, json!({ "node_id": "a" }));

    let e = rx.try_recv().unwrap();
    assert_eq!(e.event_type, NODE_OFFLINE);
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn ws_without_auth_is_401() {
    let app = app(seeded_db().await);
    let (status, json, _) = send(&app, ws_req(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn ws_upgrades_and_pushes_events_with_bearer_token() {
    let events = Arc::new(EventBus::new(8));
    let app =
        tunnel_server::api::router(AppState::new_with_events(seeded_db().await, events.clone()));

    // 复用同一 app 的会话存储登录拿 Bearer token。
    let token = login_token(&app).await;

    // oneshot 无法提供 hyper 的升级状态，需走真实 TCP 服务器驱动 `on_upgrade`。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 携带 Bearer 的 WebSocket 握手（`IntoClientRequest` 自动补握手头与随机 key）。
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    // 触发事件并读取：`/ws` 的订阅可能晚于握手完成，故带重试避免竞态。
    let mut received: Option<WsMessage> = None;
    for _ in 0..20 {
        events.publish(NODE_ONLINE, json!({ "node_id": "a", "status": "online" }));
        match tokio::time::timeout(Duration::from_millis(200), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                received = Some(msg);
                break;
            }
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => continue,
        }
    }
    let msg = received.expect("no event received over websocket");
    let WsMessage::Text(text) = msg else {
        panic!("expected text frame, got {msg:?}");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "node.online");
    assert_eq!(v["data"]["node_id"], "a");
    assert_eq!(v["data"]["status"], "online");
}
