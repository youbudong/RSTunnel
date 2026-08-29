//! 集成测试（T-21）：`/api/v1/nodes`、`/api/v1/routes` 全套 CRUD + 创建校验（§57）+ 审计日志。
//!
//! 覆盖：Node/Route 增删改查、重复 listen/hostname 返回 409、node 不存在 404、端口非法 422、
//! 每个写操作落一条 `audit_logs`。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use tunnel_auth::hash_password;
use tunnel_db::Db;
use tunnel_server::api::AppState;

const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
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

    // admin 角色由迁移（0003_seed_roles）种入，按 name 复用。
    let role_id: String = tunnel_db::sqlx::query_scalar("SELECT id FROM roles WHERE name = 'admin'")
        .fetch_one(db.pool())
        .await
        .unwrap();

    tunnel_db::sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(USER_ID)
        .bind(&role_id)
        .execute(db.pool())
        .await
        .unwrap();

    db
}

fn app(db: Db) -> axum::Router {
    tunnel_server::api::router(AppState::new(db))
}

/// 显式放行危险目标（T-37：`security.allow_unsafe_targets = true`）。
fn app_with_unsafe_targets(db: Db) -> axum::Router {
    tunnel_server::api::router(AppState::new(db).with_allow_unsafe_targets(true))
}

fn json_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn bearer_req(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
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

async fn create_node(app: &axum::Router, token: &str, name: &str) -> serde_json::Value {
    let (status, json, _) = send(
        app,
        bearer_req(
            "POST",
            "/api/v1/nodes",
            token,
            &format!(r#"{{"name":"{name}","description":"test node"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create node failed: {json}");
    json["node"].clone()
}

async fn count_audit(db: &Db, action: &str) -> i64 {
    tunnel_db::sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = ?")
        .bind(action)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn node_crud_and_duplicate_name_conflict() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;

    // 未认证访问被拒。
    let (status, _, _) = send(&app, json_req("GET", "/api/v1/nodes", "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 创建。
    let node = create_node(&app, &token, "home").await;
    let id = node["id"].as_str().unwrap().to_string();
    assert_eq!(node["name"], "home");
    assert_eq!(node["status"], "pending");

    // 列表 + 详情。
    let (status, json, _) = send(&app, bearer_req("GET", "/api/v1/nodes", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json.as_array().unwrap().len(), 1);
    let (status, json, _) = send(
        &app,
        bearer_req("GET", &format!("/api/v1/nodes/{id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], id.as_str());

    // 改名。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "PATCH",
            &format!("/api/v1/nodes/{id}"),
            &token,
            r#"{"name":"nas"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "nas");

    // 重名 409。
    let (status, json, _) = send(
        &app,
        bearer_req("POST", "/api/v1/nodes", &token, r#"{"name":"nas"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"]["code"], "DUPLICATE_NAME");

    // 删除 + 再查 404。
    let (status, _, _) = send(
        &app,
        bearer_req("DELETE", &format!("/api/v1/nodes/{id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        bearer_req("GET", &format!("/api/v1/nodes/{id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 写操作各落一条审计。
    assert_eq!(count_audit(&db, "node.create").await, 1);
    assert_eq!(count_audit(&db, "node.update").await, 1);
    assert_eq!(count_audit(&db, "node.delete").await, 1);
}

#[tokio::test]
async fn route_crud_and_conflict_validation() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    let route_body = |name: &str, listen_port: u16| {
        format!(
            r#"{{"name":"{name}","node_id":"{node_id}","type":"tcp","listen_host":"0.0.0.0","listen_port":{listen_port},"target_host":"192.168.1.100","target_port":22}}"#
        )
    };

    // 创建。
    let (status, route, _) = send(
        &app,
        bearer_req("POST", "/api/v1/routes", &token, &route_body("ssh", 2222)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create route failed: {route}");
    let route_id = route["id"].as_str().unwrap().to_string();
    assert_eq!(route["type"], "tcp");
    assert_eq!(route["enabled"], true);
    assert_eq!(route["status"], "draft");
    assert_eq!(route["listen_port"], 2222);

    // 列表 + 详情。
    let (status, json, _) = send(&app, bearer_req("GET", "/api/v1/routes", &token, "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json.as_array().unwrap().len(), 1);
    let (status, json, _) = send(
        &app,
        bearer_req("GET", &format!("/api/v1/routes/{route_id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "ssh");

    // 重复 listen 409。
    let (status, json, _) = send(
        &app,
        bearer_req("POST", "/api/v1/routes", &token, &route_body("ssh2", 2222)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"]["code"], "DUPLICATE_LISTEN");

    // 重复 hostname 409（两条 http 路由同 hostname）。
    let http_route = |name: &str| {
        format!(
            r#"{{"name":"{name}","node_id":"{node_id}","type":"http","hostname":"app.example.com","target_host":"192.168.1.100","target_port":80}}"#
        )
    };
    let (status, _, _) = send(
        &app,
        bearer_req("POST", "/api/v1/routes", &token, &http_route("web")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, json, _) = send(
        &app,
        bearer_req("POST", "/api/v1/routes", &token, &http_route("web2")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"]["code"], "DUPLICATE_HOSTNAME");

    // PATCH 更新 target_port。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "PATCH",
            &format!("/api/v1/routes/{route_id}"),
            &token,
            r#"{"target_port":2222}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["target_port"], 2222);

    // 删除 + 再查 404。
    let (status, _, _) = send(
        &app,
        bearer_req("DELETE", &format!("/api/v1/routes/{route_id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        bearer_req("GET", &format!("/api/v1/routes/{route_id}"), &token, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_validation_node_not_found_and_invalid_port() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    // node 不存在 → 404。
    let ghost = "99999999-9999-4999-8999-999999999999";
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/routes",
            &token,
            &format!(
                r#"{{"name":"r","node_id":"{ghost}","type":"tcp","listen_port":1234,"target_host":"h","target_port":1}}"#
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"]["code"], "NODE_NOT_FOUND");

    // target_port = 0 → 422。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/routes",
            &token,
            &format!(
                r#"{{"name":"r","node_id":"{node_id}","type":"tcp","listen_port":1234,"target_host":"h","target_port":0}}"#
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "INVALID_PORT");

    // tcp 缺 listen_port → 422。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/routes",
            &token,
            &format!(
                r#"{{"name":"r","node_id":"{node_id}","type":"tcp","target_host":"h","target_port":1}}"#
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "INVALID_LISTEN");

    // http 缺 hostname → 422。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/routes",
            &token,
            &format!(
                r#"{{"name":"r","node_id":"{node_id}","type":"http","target_host":"h","target_port":80}}"#
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"]["code"], "INVALID_HOSTNAME");
}

#[tokio::test]
async fn route_enable_disable_and_audit() {
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    let body = format!(
        r#"{{"name":"ssh","node_id":"{node_id}","type":"tcp","listen_port":2222,"target_host":"h","target_port":22}}"#
    );
    let (status, route, _) = send(&app, bearer_req("POST", "/api/v1/routes", &token, &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let route_id = route["id"].as_str().unwrap().to_string();

    // disable → enabled=false。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            &format!("/api/v1/routes/{route_id}/disable"),
            &token,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["enabled"], false);

    // enable → enabled=true。
    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            &format!("/api/v1/routes/{route_id}/enable"),
            &token,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["enabled"], true);

    // 全生命周期审计：create/update(disable/enable 各算一次)/delete 之外，
    // enable/disable 也各写一条。
    assert_eq!(count_audit(&db, "route.create").await, 1);
    assert_eq!(count_audit(&db, "route.disable").await, 1);
    assert_eq!(count_audit(&db, "route.enable").await, 1);
}

#[tokio::test]
async fn route_rejects_ssrf_targets_by_default() {
    // T-37：默认拒绝 loopback/link-local/multicast/metadata 目标（§106）。
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    for (port, target) in [
        (1234, "169.254.169.254"),
        (1235, "127.0.0.1"),
        (1236, "169.254.1.2"),
        (1237, "224.0.0.1"),
        (1238, "::1"),
        (1239, "fe80::1"),
        (1240, "ff02::1"),
    ] {
        let (status, json, _) = send(
            &app,
            bearer_req(
                "POST",
                "/api/v1/routes",
                &token,
                &format!(
                    r#"{{"name":"r{port}","node_id":"{node_id}","type":"tcp","listen_port":{port},"target_host":"{target}","target_port":22}}"#
                ),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "target {target}: {json}"
        );
        assert_eq!(json["error"]["code"], "FORBIDDEN_TARGET");
    }
}

#[tokio::test]
async fn route_allows_private_and_hostname_targets() {
    // 私有地址与主机名是内网穿透的合法目标，不被 SSRF 校验拒绝（T-37 仅拦危险类别）。
    let db = seeded_db().await;
    let app = app(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    for (port, target) in [(1241, "192.168.1.100"), (1242, "db.internal")] {
        let (status, json, _) = send(
            &app,
            bearer_req(
                "POST",
                "/api/v1/routes",
                &token,
                &format!(
                    r#"{{"name":"r{port}","node_id":"{node_id}","type":"tcp","listen_port":{port},"target_host":"{target}","target_port":22}}"#
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "target {target}: {json}");
    }
}

#[tokio::test]
async fn route_allows_unsafe_targets_when_configured() {
    // 管理员显式放行（security.allow_unsafe_targets = true）后，元数据地址也可配置。
    let db = seeded_db().await;
    let app = app_with_unsafe_targets(db.clone());
    let token = login_token(&app).await;
    let node = create_node(&app, &token, "home").await;
    let node_id = node["id"].as_str().unwrap();

    let (status, json, _) = send(
        &app,
        bearer_req(
            "POST",
            "/api/v1/routes",
            &token,
            &format!(
                r#"{{"name":"meta","node_id":"{node_id}","type":"tcp","listen_port":1243,"target_host":"169.254.169.254","target_port":80}}"#
            ),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "override should allow metadata target: {json}"
    );
}
