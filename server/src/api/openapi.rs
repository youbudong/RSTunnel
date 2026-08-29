//! OpenAPI（T-23，§131）：`/openapi.json` 与 `/docs`（Swagger UI）。
//!
//! 由各 handler 上的 `#[utoipa::path]` 与响应/请求结构体的 `#[derive(ToSchema)]`
//! 自动生成，单一事实来源（Rust 类型），供 Web 侧生成 TS 类型（§132）。

use axum::Router;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use super::AppState;

/// OpenAPI 文档：聚合全部 API 路径 + 可复用 schema（Node/Route/User/...）。
#[derive(OpenApi)]
#[openapi(
    paths(
        // auth（T-20）
        crate::api::auth::login,
        crate::api::auth::logout,
        crate::api::auth::refresh,
        crate::api::auth::me,
        // enroll（T-22）
        crate::api::enroll::enroll,
        // setup（T-20 首次引导）
        crate::api::setup::setup_status,
        crate::api::setup::setup,
        // nodes（T-21/T-22）
        crate::api::nodes::list_nodes,
        crate::api::nodes::get_node,
        crate::api::nodes::create_node,
        crate::api::nodes::update_node,
        crate::api::nodes::delete_node,
        crate::api::nodes::create_credential,
        crate::api::nodes::revoke_credential,
        // routes（T-21）
        crate::api::routes::list_routes,
        crate::api::routes::get_route,
        crate::api::routes::create_route,
        crate::api::routes::update_route,
        crate::api::routes::delete_route,
        crate::api::routes::enable_route,
        crate::api::routes::disable_route,
    ),
    components(schemas(
        crate::session::User,
        crate::api::auth::LoginRequest,
        crate::api::auth::LoginResponse,
        crate::api::auth::MeResponse,
        crate::api::auth::RefreshResponse,
        crate::api::enroll::EnrollRequest,
        crate::api::enroll::EnrollResponse,
        crate::api::setup::SetupRequest,
        crate::api::setup::SetupStatusResponse,
        crate::api::nodes::Node,
        crate::api::nodes::CreateNodeRequest,
        crate::api::nodes::UpdateNodeRequest,
        crate::api::nodes::CreateNodeResponse,
        crate::api::nodes::CreateCredentialRequest,
        crate::api::nodes::CredentialResponse,
        crate::api::routes::Route,
        crate::api::routes::CreateRouteRequest,
        crate::api::routes::UpdateRouteRequest,
        crate::api::routes::TlsMode,
        tunnel_protocol::RouteType,
        tunnel_protocol::Limits,
    )),
    tags(
        (name = "auth", description = "Authentication & sessions"),
        (name = "enroll", description = "Agent enrollment"),
        (name = "setup", description = "First-run setup"),
        (name = "nodes", description = "Node management"),
        (name = "routes", description = "Route management"),
    ),
    info(
        title = "Rust Tunnel API",
        version = "0.1.0",
        description = "RSTunnel 管理面 REST API（§21）"
    )
)]
pub struct ApiDoc;

/// 组装 `/docs`（Swagger UI）与 `/openapi.json`。`SwaggerUi` 自动路由 JSON 到
/// `.url()` 指定的路径，UI 到 `/docs`。
pub fn router() -> Router<AppState> {
    SwaggerUi::new("/docs")
        .url("/openapi.json", ApiDoc::openapi())
        .into()
}
