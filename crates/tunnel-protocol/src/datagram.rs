//! UDP 载荷的 QUIC Datagram 线格式（docs/protocol.md §5）。
//!
//! 每个 UDP 包封装进一个 QUIC Datagram，前面缀一个 10 字节头：
//!
//! ```text
//!  0                   1
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          flags (u16 BE)        |      udp_session_id (u64 BE)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      UDP payload (n bytes)                     |
//! ```
//!
//! - `flags`：bit0 = `fragment`（v1 恒为 0，分片留待后续）；其余保留为 0。
//! - `udp_session_id`：由 Server 在 `UDP_OPEN` 中分配，关联 `(client_addr, route_id)`。
//!
//! 纯编解码，无 IO；可被 cargo-fuzz 直接调用。

/// Datagram 头长度（`flags` u16 + `udp_session_id` u64）。
pub const UDP_DATAGRAM_HEADER_LEN: usize = 10;

/// 一个已解码的 UDP datagram（`payload` 借用输入缓冲区，不复制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub flags: u16,
    pub session_id: u64,
    pub payload: &'a [u8],
}

/// 把一段 UDP 载荷封装成 datagram（`flags` 在 v1 恒为 0，无分片）。
pub fn encode_udp_datagram(session_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(UDP_DATAGRAM_HEADER_LEN + payload.len());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// 解码 datagram；字节不足 10（头不完整）返回 `None`。
pub fn decode_udp_datagram(data: &[u8]) -> Option<UdpDatagram<'_>> {
    if data.len() < UDP_DATAGRAM_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([data[0], data[1]]);
    let session_id = u64::from_be_bytes([
        data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
    ]);
    Some(UdpDatagram {
        flags,
        session_id,
        payload: &data[UDP_DATAGRAM_HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn encode_then_decode_roundtrips() {
        let payload = b"hello-udp";
        let encoded = encode_udp_datagram(42, payload);
        assert_eq!(encoded.len(), UDP_DATAGRAM_HEADER_LEN + payload.len());
        // 头：flags=0 + session_id=42（big-endian）。
        assert_eq!(&encoded[0..2], &[0, 0]);
        assert_eq!(&encoded[2..10], &42u64.to_be_bytes());
        assert_eq!(&encoded[10..], payload);

        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn short_buffer_returns_none() {
        assert!(decode_udp_datagram(&[0u8; 9]).is_none());
        assert!(decode_udp_datagram(&[]).is_none());
    }

    #[test]
    fn empty_payload_is_valid() {
        let encoded = encode_udp_datagram(7, &[]);
        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(decoded.session_id, 7);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn flags_preserved_on_decode() {
        // 手工构造 flags=1（fragment bit）的 datagram，验证 decode 原样读出。
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&99u64.to_be_bytes());
        buf.extend_from_slice(b"x");
        let decoded = decode_udp_datagram(&buf).unwrap();
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.session_id, 99);
    }
}
