//! 管理端运维端点：`backup`/`restore`（灾难恢复，含凭据与证书）与
//! `export`/`import`（控制面配置迁移，不含凭据/证书）。
//!
//! 均为 admin-only（`settings.write` 权限）。`restore`/`import` 默认 dry-run，
//! `?apply=true` 才落库；按主键「不存在则插入、已存在则跳过」，永不覆盖现有行。
//! 快照逻辑见 [`crate::snapshot`]（T-42，docs §99/§100）。

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use super::auth::CurrentUser;
use super::rbac::{require_permission, Permission};
use super::{internal, write_audit, ApiError, AppState};
use crate::snapshot::{self, Snapshot};

/// restore/import 请求体上限（快照可能超过 axum 默认 2MB）。
const SNAPSHOT_BODY_LIMIT: usize = 10 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/backup", get(backup))
        .route("/export", get(export))
        .route("/restore", post(restore))
        .route("/import", post(import))
        .layer(DefaultBodyLimit::max(SNAPSHOT_BODY_LIMIT))
}

/// `?apply=true` 才落库；缺省仅校验 + 预览。
#[derive(Debug, Deserialize)]
struct ApplyQuery {
    #[serde(default)]
    apply: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/backup",
    responses(
        (status = 200, description = "Full snapshot YAML (includes credentials & certificates)", body = String, content_type = "application/yaml")
    ),
    tag = "admin"
)]
async fn backup(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::SettingsWrite)?;
    let snap = Snapshot::from_db(&state.db, true).await.map_err(internal)?;
    yaml_response(snap, "tunnel-backup.yaml")
}

#[utoipa::path(
    get,
    path = "/api/v1/export",
    responses(
        (status = 200, description = "Control-plane snapshot YAML (no credentials/certificates)", body = String, content_type = "application/yaml")
    ),
    tag = "admin"
)]
async fn export(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::SettingsWrite)?;
    let snap = Snapshot::from_db(&state.db, false)
        .await
        .map_err(internal)?;
    yaml_response(snap, "tunnel-config.yaml")
}

#[utoipa::path(
    post,
    path = "/api/v1/restore",
    params(("apply" = bool, Query, description = "Commit changes (default false = dry-run preview)")),
    responses((status = 200, description = "Restore report (inserted/skipped per table)")),
    tag = "admin"
)]
async fn restore(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Query(q): Query<ApplyQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::SettingsWrite)?;
    let snap = parse_snapshot(&body)?;
    let report = snapshot::restore(&state.db, &snap, q.apply)
        .await
        .map_err(internal)?;
    if q.apply {
        write_audit(
            &state,
            Some(&user.id),
            "restore",
            "snapshot",
            "restore",
            None,
        )
        .await?;
    }
    Ok(Json(report).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/import",
    params(("apply" = bool, Query, description = "Commit changes (default false = dry-run preview)")),
    responses((status = 200, description = "Import report (inserted/skipped per table)")),
    tag = "admin"
)]
async fn import(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Query(q): Query<ApplyQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_permission(&user, Permission::SettingsWrite)?;
    let snap = parse_snapshot(&body)?;
    if !snap.credentials.is_empty() || !snap.certificates.is_empty() {
        return Err(ApiError::unprocessable(
            "CONTAINS_SECRETS",
            "import rejects snapshots with credentials/certificates; use restore",
        ));
    }
    let report = snapshot::restore(&state.db, &snap, q.apply)
        .await
        .map_err(internal)?;
    if q.apply {
        write_audit(&state, Some(&user.id), "import", "snapshot", "import", None).await?;
    }
    Ok(Json(report).into_response())
}

/// 把 UTF-8 YAML 请求体解析为快照；非法输入返回 422。
fn parse_snapshot(body: &Bytes) -> Result<Snapshot, ApiError> {
    let yaml = std::str::from_utf8(body)
        .map_err(|_| ApiError::unprocessable("INVALID_BODY", "request body must be UTF-8 YAML"))?;
    Snapshot::from_yaml(yaml)
        .map_err(|e| ApiError::unprocessable("INVALID_SNAPSHOT", e.to_string()))
}

/// 序列化为 YAML 下载响应（`application/yaml` + 附件文件名）。
fn yaml_response(snap: Snapshot, filename: &str) -> Result<Response, ApiError> {
    let yaml = snap.to_yaml().map_err(internal)?;
    let mut resp = yaml.into_response();
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/yaml"));
    resp.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).map_err(internal)?,
    );
    Ok(resp)
}
