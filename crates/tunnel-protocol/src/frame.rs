//! 帧编解码。控制流与数据流首帧共用本格式（docs/protocol.md §2）。
//!
//! 帧布局（全部 big-endian）：
//! ```text
//! u32 length | u16 message_type | u16 flags | u64 request_id | payload
//! ```
//! `length` = type(2) + flags(2) + request_id(8) + payload.len()，不含自身 4 字节。

use thiserror::Error;

use crate::message::MessageType;

/// 帧头长度 = length(4) + type(2) + flags(2) + request_id(8)。
pub const HEADER_LEN: usize = 16;
/// `length` 字段的最小合法值（type+flags+request_id = 12）。
pub const MIN_FRAME_LEN: usize = HEADER_LEN - 4;
/// `length` 字段的上限（payload 上限 ≈ 4 MiB - 12）。
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub message_type: MessageType,
    pub flags: u16,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("frame length {length} is too small (min {min})")]
    LengthTooSmall { length: usize, min: usize },
    #[error("frame length {length} exceeds max {max}")]
    FrameTooLarge { length: usize, max: usize },
    #[error("unknown message type 0x{ty:04x}")]
    UnknownMessage { ty: u16 },
}

impl Frame {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            flags: 0,
            request_id: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let length = MIN_FRAME_LEN + self.payload.len();
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&(length as u32).to_be_bytes());
        out.extend_from_slice(&self.message_type.as_u16().to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// 从字节流解码一帧。
    ///
    /// - `Ok(None)`：字节不足，需要更多数据。
    /// - `Ok(Some((frame, consumed)))`：成功解码一帧。
    /// - `Err`：非法输入（长度越界 / 未知消息类型）。
    pub fn try_decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, DecodeError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let length = read_u32(&buf[0..4]) as usize;
        if length < MIN_FRAME_LEN {
            return Err(DecodeError::LengthTooSmall {
                length,
                min: MIN_FRAME_LEN,
            });
        }
        if length > MAX_FRAME_LEN {
            return Err(DecodeError::FrameTooLarge {
                length,
                max: MAX_FRAME_LEN,
            });
        }
        let total = 4 + length;
        if buf.len() < total {
            return Ok(None);
        }
        let ty = read_u16(&buf[4..6]);
        let message_type = MessageType::from_u16(ty).ok_or(DecodeError::UnknownMessage { ty })?;
        let flags = read_u16(&buf[6..8]);
        let request_id = read_u64(&buf[8..16]);
        let payload = buf[16..total].to_vec();
        Ok(Some((
            Frame {
                message_type,
                flags,
                request_id,
                payload,
            },
            total,
        )))
    }
}

fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[0..8]);
    u64::from_be_bytes(a)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn roundtrip() {
        let f = Frame {
            message_type: MessageType::Hello,
            flags: 0,
            request_id: 7,
            payload: br#"{"a":1}"#.to_vec(),
        };
        let encoded = f.encode();
        let (decoded, consumed) = Frame::try_decode(&encoded).unwrap().expect("full frame");
        assert_eq!(decoded, f);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn partial_is_none() {
        let encoded = Frame::new(MessageType::Ping, b"{}".to_vec()).encode();
        assert!(Frame::try_decode(&encoded[..3]).unwrap().is_none());
    }

    #[test]
    fn oversized_length_is_error() {
        let mut buf = vec![0u8; 4];
        buf.copy_from_slice(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes());
        assert!(matches!(
            Frame::try_decode(&buf),
            Err(DecodeError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn too_small_length_is_error() {
        let mut buf = vec![0u8; 4];
        buf.copy_from_slice(&(MIN_FRAME_LEN as u32 - 1).to_be_bytes());
        assert!(matches!(
            Frame::try_decode(&buf),
            Err(DecodeError::LengthTooSmall { .. })
        ));
    }

    #[test]
    fn unknown_type_is_error() {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&(MIN_FRAME_LEN as u32).to_be_bytes());
        buf[4..6].copy_from_slice(&0xffffu16.to_be_bytes());
        assert!(matches!(
            Frame::try_decode(&buf),
            Err(DecodeError::UnknownMessage { .. })
        ));
    }
}
