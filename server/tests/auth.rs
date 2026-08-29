//! 集成测试（T-20）：REST 认证——登录校验 Argon2id 密码后发 HttpOnly Secure SameSite cookie
//! 会话 + 短时 Bearer token；/auth/me 接受 cookie 或 Bearer；登出吊销会话（设计文档 §21/§69）。

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
    let role_id: String =
        tunnel_db::sqlx::query_scalar("SELECT id FROM roles WHERE name = 'admin'")
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

fn json_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn cookie_req(method: &str, uri: &str, sid: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("sid={sid}"))
        .body(Body::empty())
        .unwrap()
}

fn bearer_req(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
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

fn session_id_from_set_cookie(headers: &HeaderMap) -> String {
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    cookie
        .split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("sid=")
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn login_success_sets_cookie_and_me_returns_user() {
    let app = app(seeded_db().await);

    let (status, json, headers) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["user"]["username"], "admin");
    assert_eq!(json["user"]["role"], "admin");
    assert_eq!(json["token_type"], "Bearer");
    let access_token = json["access_token"].as_str().unwrap().to_string();
    assert!(!access_token.is_empty());

    let set_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let sid = session_id_from_set_cookie(&headers);

    // cookie 认证。
    let (status, json, _) = send(&app, cookie_req("GET", "/auth/me", &sid)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["user"]["username"], "admin");

    // Bearer 认证。
    let (status, json, _) = send(&app, bearer_req("GET", "/auth/me", &access_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["user"]["id"], USER_ID);
}

#[tokio::test]
async fn login_wrong_password_is_401() {
    let app = app(seeded_db().await);

    let (status, json, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"wrong"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn unknown_user_is_401() {
    let app = app(seeded_db().await);

    let (status, _, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"ghost","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_lockout_returns_429_after_max_failures() {
    // 默认限速器：5 次失败后锁定（T-35）。第 6 次即使密码正确也返回 429。
    let app = app(seeded_db().await);

    for _ in 0..5 {
        let (status, _, _) = send(
            &app,
            json_req(
                "POST",
                "/auth/login",
                r#"{"username":"admin","password":"wrong"}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    let (status, json, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"]["code"], "LOGIN_LOCKED");
}

#[tokio::test]
async fn successful_login_resets_failure_count() {
    // 失败几次后再成功，失败计数清零，不锁定（T-35）。
    let app = app(seeded_db().await);

    for _ in 0..4 {
        let (status, _, _) = send(
            &app,
            json_req(
                "POST",
                "/auth/login",
                r#"{"username":"admin","password":"wrong"}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // 成功一次，清零。
    let (status, _, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 之后失败 4 次仍未锁定（不是累计 8 次）。
    for _ in 0..4 {
        let (status, _, _) = send(
            &app,
            json_req(
                "POST",
                "/auth/login",
                r#"{"username":"admin","password":"wrong"}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"wrong"}"#,
        ),
    )
    .await;
    // 第 5 次失败仍未锁定（429 只在达到阈值后）。
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_without_auth_is_401() {
    let app = app(seeded_db().await);
    let (status, json, _) = send(&app, json_req("GET", "/auth/me", "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn logout_revokes_session() {
    let app = app(seeded_db().await);

    let (_, _, headers) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    let sid = session_id_from_set_cookie(&headers);

    // 登出前 cookie 有效。
    let (status, _, _) = send(&app, cookie_req("GET", "/auth/me", &sid)).await;
    assert_eq!(status, StatusCode::OK);

    // 登出。
    let (status, _, _) = send(&app, cookie_req("POST", "/auth/logout", &sid)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 登出后 cookie 失效。
    let (status, _, _) = send(&app, cookie_req("GET", "/auth/me", &sid)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_issues_new_access_token() {
    let app = app(seeded_db().await);

    let (_, login_json, headers) = send(
        &app,
        json_req(
            "POST",
            "/auth/login",
            r#"{"username":"admin","password":"hunter2"}"#,
        ),
    )
    .await;
    let old_token = login_json["access_token"].as_str().unwrap().to_string();
    let sid = session_id_from_set_cookie(&headers);

    let (status, json, _) = send(&app, cookie_req("POST", "/auth/refresh", &sid)).await;
    assert_eq!(status, StatusCode::OK);
    let new_token = json["access_token"].as_str().unwrap().to_string();
    assert_ne!(new_token, old_token);

    // 新 token 可用。
    let (status, _, _) = send(&app, bearer_req("GET", "/auth/me", &new_token)).await;
    assert_eq!(status, StatusCode::OK);
}
