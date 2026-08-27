//! Agent 客户端：QUIC 连接 + 控制流 HELLO→AUTH 认证。

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tunnel_core::frame_io::{read_frame, write_frame};
use tunnel_protocol::{AuthFailPayload, AuthOkPayload, AuthPayload, HelloPayload, Message};

/// 认证结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Ok(AuthOkPayload),
    Fail(AuthFailPayload),
}

/// 一个 QUIC 客户端端点 + 固定的 server_name（SNI）。
pub struct Agent {
    endpoint: quinn::Endpoint,
    server_name: String,
}

impl Agent {
    /// `server_name` 用于 TLS SNI 与证书校验，可与连接地址的主机部分解耦（测试连 IP、SNI 用域名）。
    pub fn new(client_config: quinn::ClientConfig, server_name: String) -> Result<Self> {
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
            .context("create quic client endpoint")?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            server_name,
        })
    }

    /// 建立到 `addr` 的 QUIC 连接（使用固定的 `server_name` SNI）。
    pub async fn connect(&self, addr: SocketAddr) -> Result<quinn::Connection> {
        self.connect_to(addr, &self.server_name).await
    }

    /// 建立到 `addr` 的 QUIC 连接，`server_name` 为该端点的 TLS SNI（T-43：不同服务器可不同 SNI）。
    pub async fn connect_to(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection> {
        self.endpoint
            .connect(addr, server_name)
            .context("connect to server")?
            .await
            .context("quic handshake")
    }

    /// 打开控制流，发送 HELLO→AUTH，读回 AUTH_OK / AUTH_FAIL。控制流保持打开供后续心跳/配置使用。
    pub async fn authenticate(
        &self,
        conn: &quinn::Connection,
        hello: HelloPayload,
        auth: AuthPayload,
    ) -> Result<AuthOutcome> {
        let (mut send, mut recv) = conn.open_bi().await.context("open control stream")?;

        let hello_frame = Message::Hello(hello).into_frame(1)?;
        write_frame(&mut send, &hello_frame).await?;
        let auth_frame = Message::Auth(auth).into_frame(2)?;
        write_frame(&mut send, &auth_frame).await?;

        let frame = read_frame(&mut recv)
            .await?
            .context("server closed before AUTH response")?;
        match Message::from_frame(&frame)? {
            Message::AuthOk(p) => Ok(AuthOutcome::Ok(p)),
            Message::AuthFail(p) => Ok(AuthOutcome::Fail(p)),
            other => anyhow::bail!("unexpected response frame: {other:?}"),
        }
    }
}
