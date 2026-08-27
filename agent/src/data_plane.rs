//! 数据面（T-15）：接受 Server 打开的双向流，读取 OPEN_TCP，连接内网目标，回 OPEN_OK /
//! OPEN_FAIL 首帧，随后双向转发原始字节（设计文档 §8.2/§82/§84）。
//!
//! T-34f：连接前先按本地 `[security]` 目标策略（`allow_targets`/`deny_targets`）校验，
//! 拒绝 loopback/link-local 等未授权目标（防止内网扫描/SSRF）。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::io::AsyncWriteExt;

use tunnel_config::SecurityConfig;
use tunnel_core::frame_io::{read_frame, write_frame};
use tunnel_core::target_allowed;
use tunnel_protocol::{Message, OpenFailPayload, OpenOkPayload};

/// 接受循环：为每个 Server 打开的双向流派生一个处理任务，直到连接关闭。
pub async fn accept_data_streams(conn: quinn::Connection, security: Arc<SecurityConfig>) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tracing::debug!("data stream opened");
                let security = Arc::clone(&security);
                tokio::spawn(handle_data_stream(send, recv, security));
            }
            Err(e) => {
                tracing::debug!(error = %e, "accept_bi closed; data plane exiting");
                return;
            }
        }
    }
}

/// 单个数据流：OPEN_TCP → 校验目标策略 → 连接目标 → OPEN_OK/OPEN_FAIL → 双向转发。
pub async fn handle_data_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    security: Arc<SecurityConfig>,
) {
    // 1. 读 OPEN_TCP（首帧）。
    let (request_id, open) = match read_frame(&mut recv).await {
        Ok(Some(frame)) => {
            let rid = frame.request_id;
            match Message::from_frame(&frame) {
                Ok(Message::OpenTcp(p)) => (rid, p),
                Ok(other) => {
                    tracing::warn!(frame = ?other, "expected OPEN_TCP as first data frame");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "decode OPEN_TCP");
                    return;
                }
            }
        }
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "read OPEN_TCP");
            return;
        }
    };

    let target = format!("{}:{}", open.target_host, open.target_port);
    tracing::debug!(route = %open.route_id, %target, client = ?open.client_addr, "opening target");

    // 2. 校验本地目标策略，解析到允许的连接地址（T-34f）。
    let Some(addr) = resolve_target(&security, &open.target_host, open.target_port).await else {
        tracing::warn!(route = %open.route_id, %target, "target denied by local security policy");
        let msg = Message::OpenFail(OpenFailPayload {
            code: "TARGET_DENIED".to_string(),
            message: "target denied by agent security policy".to_string(),
        });
        let _ = send_message(&mut send, msg, request_id).await;
        let _ = send.finish();
        return;
    };

    // 3. 连接内网目标（直连解析出的 IP，避免 DNS 重绑绕过校验）。
    let tcp = match tokio::net::TcpStream::connect(addr).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(%target, error = %e, "target connect failed");
            let msg = Message::OpenFail(OpenFailPayload {
                code: "TARGET_UNREACHABLE".to_string(),
                message: e.to_string(),
            });
            let _ = send_message(&mut send, msg, request_id).await;
            // finish 确保 OPEN_FAIL 帧送达对端再关闭发送方向（否则 drop 会 reset 掉未送达数据）。
            let _ = send.finish();
            return;
        }
    };

    // 4. 回 OPEN_OK（携带目标侧实际地址）。
    let remote = tcp.peer_addr().ok().map(|a| a.to_string());
    let msg = Message::OpenOk(OpenOkPayload {
        remote_addr: remote,
    });
    if send_message(&mut send, msg, request_id).await.is_err() {
        tracing::warn!(%target, "send OPEN_OK failed");
        return;
    }

    // 5. 双向转发（含半关闭：读毕即 finish/关闭写端）。
    copy_duplex(tcp, send, recv).await;
}

/// 按本地目标策略解析并放行目标，返回可直接连接的 `SocketAddr`。
///
/// - `host` 已是 IP 字面量则直接校验（不查 DNS）；
/// - 否则经 DNS 解析，取**首个放行**的地址；直接返回该 IP（而非 host）连接，避免
///   `TcpStream::connect(host)` 二次解析发生 DNS 重绑绕过校验；
/// - 解析失败或所有地址均被拒 → `None`。
async fn resolve_target(security: &SecurityConfig, host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return target_allowed(&security.allow_targets, &security.deny_targets, ip)
            .then(|| SocketAddr::new(ip, port));
    }
    let addrs = tokio::net::lookup_host((host, port)).await.ok()?;
    addrs
        .into_iter()
        .find(|a| target_allowed(&security.allow_targets, &security.deny_targets, a.ip()))
}

/// 双向转发：内网目标 TCP ↔ QUIC 流，读毕即向对端传达半关闭。
async fn copy_duplex(
    tcp: tokio::net::TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    let quic_to_tcp = async move {
        let n = tokio::io::copy(&mut recv, &mut tcp_w).await;
        // Server finish（客户端已发毕）：关闭目标 TCP 写端。
        let _ = tcp_w.shutdown().await;
        n
    };
    let tcp_to_quic = async move {
        let n = tokio::io::copy(&mut tcp_r, &mut send).await;
        // 目标关闭（FIN）：finish 通知 Server 本次发送结束。
        let _ = send.finish();
        n
    };

    let (a, b) = tokio::join!(quic_to_tcp, tcp_to_quic);
    if let Err(e) = a {
        tracing::debug!(error = %e, "quic->tcp copy error");
    }
    if let Err(e) = b {
        tracing::debug!(error = %e, "tcp->quic copy error");
    }
}

/// 组帧并写入数据流。
async fn send_message(send: &mut quinn::SendStream, msg: Message, request_id: u64) -> Result<()> {
    let frame = msg.into_frame(request_id)?;
    write_frame(send, &frame).await
}
