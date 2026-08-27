#![no_main]
//! 对任意字节 fuzz 帧 → 类型化消息解码（JSON payload）：不得 panic。
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 先解帧，再解消息；JSON 反序列化失败返回 Err（不 panic）。
    if let Ok(Some((frame, _consumed))) = tunnel_protocol::Frame::try_decode(data) {
        let _ = tunnel_protocol::Message::from_frame(&frame);
    }
});
