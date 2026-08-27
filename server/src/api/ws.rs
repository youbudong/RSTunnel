//! WebSocket 实时状态（T-25，§23）：`GET /ws` 升级后推送事件总线上的
//! `node.*` / `route.*` / `config.*` 事件。认证与 HTTP API 一致（Cookie 或 Bearer）。

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::sync::broadcast::error::RecvError;

use super::auth::CurrentUser;
use super::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(ws_handler))
}

/// 升级前先过 `CurrentUser`（未认证返回 401，不进入升级）。
async fn ws_handler(
    State(state): State<AppState>,
    _user: CurrentUser,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| forward_events(socket, state))
}

/// 订阅事件总线并把每条事件序列化为 JSON 文本帧推给客户端；连接关闭即退出。
async fn forward_events(mut socket: WebSocket, state: AppState) {
    let mut rx = state.events.subscribe();
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        // BusEvent 恒可序列化；失败即编程错误，跳过该帧继续。
                        let Ok(text) = serde_json::to_string(&ev) else { continue };
                        if socket.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    // 客户端落后：告知跳过的条数，继续订阅后续事件。
                    Err(RecvError::Lagged(skipped)) => {
                        let hint = format!(r#"{{"type":"ws.lagged","data":{{"skipped":{skipped}}}}}"#);
                        if socket.send(Message::Text(hint)).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    // 客户端关闭或读到 Close：退出。
                    Some(Ok(Message::Close(_))) | None => break,
                    // 忽略 ping/pong/文本（v1 单向推送）。
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}
