//! 控制协议与数据面 wire 格式（docs/protocol.md）。
//!
//! 纯编解码，无 IO；可被 cargo-fuzz 直接调用。

pub mod datagram;
pub mod frame;
pub mod message;
pub mod payload;

pub use datagram::{
    decode_udp_datagram, encode_udp_datagram, UdpDatagram, UDP_DATAGRAM_HEADER_LEN,
};
pub use frame::{DecodeError, Frame, HEADER_LEN, MAX_FRAME_LEN, MIN_FRAME_LEN};
pub use message::MessageType;
pub use payload::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unexpected message type {0:?}")]
    UnexpectedType(MessageType),
}

/// 类型化消息：`MessageType` + 对应 payload。
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Hello(HelloPayload),
    Auth(AuthPayload),
    AuthOk(AuthOkPayload),
    AuthFail(AuthFailPayload),
    Ping(PingPayload),
    Pong(PingPayload),
    ConfigSnapshot(ConfigSnapshotPayload),
    ConfigUpdate(ConfigUpdatePayload),
    ConfigAck(ConfigAckPayload),
    ConfigResync(ConfigResyncPayload),
    OpenTcp(OpenTcpPayload),
    OpenOk(OpenOkPayload),
    OpenFail(OpenFailPayload),
    Close(ClosePayload),
    UdpOpen(UdpOpenPayload),
    UdpClose(UdpClosePayload),
    Stats(StatsPayload),
    Health(HealthPayload),
    Error(ProtocolErrorPayload),
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Hello(_) => MessageType::Hello,
            Message::Auth(_) => MessageType::Auth,
            Message::AuthOk(_) => MessageType::AuthOk,
            Message::AuthFail(_) => MessageType::AuthFail,
            Message::Ping(_) => MessageType::Ping,
            Message::Pong(_) => MessageType::Pong,
            Message::ConfigSnapshot(_) => MessageType::ConfigSnapshot,
            Message::ConfigUpdate(_) => MessageType::ConfigUpdate,
            Message::ConfigAck(_) => MessageType::ConfigAck,
            Message::ConfigResync(_) => MessageType::ConfigResync,
            Message::OpenTcp(_) => MessageType::OpenTcp,
            Message::OpenOk(_) => MessageType::OpenOk,
            Message::OpenFail(_) => MessageType::OpenFail,
            Message::Close(_) => MessageType::Close,
            Message::UdpOpen(_) => MessageType::UdpOpen,
            Message::UdpClose(_) => MessageType::UdpClose,
            Message::Stats(_) => MessageType::Stats,
            Message::Health(_) => MessageType::Health,
            Message::Error(_) => MessageType::Error,
        }
    }

    /// 序列化为帧。`request_id` 用于请求/响应关联。
    pub fn into_frame(self, request_id: u64) -> Result<Frame, ProtocolError> {
        let message_type = self.message_type();
        let payload = match self {
            Message::Hello(p) => serde_json::to_vec(&p)?,
            Message::Auth(p) => serde_json::to_vec(&p)?,
            Message::AuthOk(p) => serde_json::to_vec(&p)?,
            Message::AuthFail(p) => serde_json::to_vec(&p)?,
            Message::Ping(p) => serde_json::to_vec(&p)?,
            Message::Pong(p) => serde_json::to_vec(&p)?,
            Message::ConfigSnapshot(p) => serde_json::to_vec(&p)?,
            Message::ConfigUpdate(p) => serde_json::to_vec(&p)?,
            Message::ConfigAck(p) => serde_json::to_vec(&p)?,
            Message::ConfigResync(p) => serde_json::to_vec(&p)?,
            Message::OpenTcp(p) => serde_json::to_vec(&p)?,
            Message::OpenOk(p) => serde_json::to_vec(&p)?,
            Message::OpenFail(p) => serde_json::to_vec(&p)?,
            Message::Close(p) => serde_json::to_vec(&p)?,
            Message::UdpOpen(p) => serde_json::to_vec(&p)?,
            Message::UdpClose(p) => serde_json::to_vec(&p)?,
            Message::Stats(p) => serde_json::to_vec(&p)?,
            Message::Health(p) => serde_json::to_vec(&p)?,
            Message::Error(p) => serde_json::to_vec(&p)?,
        };
        Ok(Frame {
            message_type,
            flags: 0,
            request_id,
            payload,
        })
    }

    pub fn from_frame(frame: &Frame) -> Result<Message, ProtocolError> {
        let msg = match frame.message_type {
            MessageType::Hello => Message::Hello(serde_json::from_slice(&frame.payload)?),
            MessageType::Auth => Message::Auth(serde_json::from_slice(&frame.payload)?),
            MessageType::AuthOk => Message::AuthOk(serde_json::from_slice(&frame.payload)?),
            MessageType::AuthFail => Message::AuthFail(serde_json::from_slice(&frame.payload)?),
            MessageType::Ping => Message::Ping(serde_json::from_slice(&frame.payload)?),
            MessageType::Pong => Message::Pong(serde_json::from_slice(&frame.payload)?),
            MessageType::ConfigSnapshot => {
                Message::ConfigSnapshot(serde_json::from_slice(&frame.payload)?)
            }
            MessageType::ConfigUpdate => {
                Message::ConfigUpdate(serde_json::from_slice(&frame.payload)?)
            }
            MessageType::ConfigAck => Message::ConfigAck(serde_json::from_slice(&frame.payload)?),
            MessageType::ConfigResync => {
                Message::ConfigResync(serde_json::from_slice(&frame.payload)?)
            }
            MessageType::OpenTcp => Message::OpenTcp(serde_json::from_slice(&frame.payload)?),
            MessageType::OpenOk => Message::OpenOk(serde_json::from_slice(&frame.payload)?),
            MessageType::OpenFail => Message::OpenFail(serde_json::from_slice(&frame.payload)?),
            MessageType::Close => Message::Close(serde_json::from_slice(&frame.payload)?),
            MessageType::UdpOpen => Message::UdpOpen(serde_json::from_slice(&frame.payload)?),
            MessageType::UdpClose => Message::UdpClose(serde_json::from_slice(&frame.payload)?),
            MessageType::Stats => Message::Stats(serde_json::from_slice(&frame.payload)?),
            MessageType::Health => Message::Health(serde_json::from_slice(&frame.payload)?),
            MessageType::Error => Message::Error(serde_json::from_slice(&frame.payload)?),
        };
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn hello_roundtrip() {
        let msg = Message::Hello(HelloPayload {
            protocol_version: ProtocolVersion { major: 1, minor: 0 },
            agent_version: "0.1.0".into(),
            capabilities: Capabilities::default(),
        });
        let frame = msg.clone().into_frame(42).unwrap();
        assert_eq!(frame.message_type, MessageType::Hello);
        assert_eq!(frame.request_id, 42);
        assert_eq!(Message::from_frame(&frame).unwrap(), msg);
    }

    #[test]
    fn config_snapshot_roundtrip() {
        let msg = Message::ConfigSnapshot(ConfigSnapshotPayload {
            config_version: 184,
            routes: vec![RouteConfig {
                id: uuid::Uuid::new_v4(),
                name: "ssh".into(),
                route_type: RouteType::Tcp,
                enabled: true,
                target_host: "192.168.1.100".into(),
                target_port: 22,
                hostname: None,
                limits: None,
            }],
            acl: vec![AclRule {
                action: AclAction::Allow,
                source_cidr: Some("10.0.0.0/8".into()),
                source_port: None,
                target_host: None,
                target_port: None,
            }],
            limits: Limits::default(),
        });
        let frame = msg.clone().into_frame(0).unwrap();
        assert_eq!(Message::from_frame(&frame).unwrap(), msg);
    }
}
