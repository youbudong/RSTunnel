//! 消息类型（wire 值，big-endian u16）。见 docs/protocol.md §3。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Hello = 0x0001,
    Auth = 0x0002,
    AuthOk = 0x0003,
    AuthFail = 0x0004,

    Ping = 0x0010,
    Pong = 0x0011,

    ConfigSnapshot = 0x0020,
    ConfigUpdate = 0x0021,
    ConfigAck = 0x0022,
    ConfigResync = 0x0023,

    OpenTcp = 0x0030,
    OpenOk = 0x0031,
    OpenFail = 0x0032,
    Close = 0x0033,

    UdpOpen = 0x0040,
    UdpClose = 0x0041,

    Stats = 0x0050,
    Health = 0x0051,

    Error = 0x0060,
}

impl MessageType {
    pub fn from_u16(v: u16) -> Option<Self> {
        use MessageType::*;
        Some(match v {
            0x0001 => Hello,
            0x0002 => Auth,
            0x0003 => AuthOk,
            0x0004 => AuthFail,
            0x0010 => Ping,
            0x0011 => Pong,
            0x0020 => ConfigSnapshot,
            0x0021 => ConfigUpdate,
            0x0022 => ConfigAck,
            0x0023 => ConfigResync,
            0x0030 => OpenTcp,
            0x0031 => OpenOk,
            0x0032 => OpenFail,
            0x0033 => Close,
            0x0040 => UdpOpen,
            0x0041 => UdpClose,
            0x0050 => Stats,
            0x0051 => Health,
            0x0060 => Error,
            _ => return None,
        })
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_variants() {
        for v in [
            MessageType::Hello,
            MessageType::Auth,
            MessageType::AuthOk,
            MessageType::AuthFail,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::ConfigSnapshot,
            MessageType::ConfigUpdate,
            MessageType::ConfigAck,
            MessageType::ConfigResync,
            MessageType::OpenTcp,
            MessageType::OpenOk,
            MessageType::OpenFail,
            MessageType::Close,
            MessageType::UdpOpen,
            MessageType::UdpClose,
            MessageType::Stats,
            MessageType::Health,
            MessageType::Error,
        ] {
            assert_eq!(MessageType::from_u16(v.as_u16()), Some(v));
        }
    }

    #[test]
    fn unknown_is_none() {
        assert_eq!(MessageType::from_u16(0xffff), None);
    }
}
