#![no_main]
//! 对任意字节输入 fuzz `Frame::try_decode`：不得 panic。
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 连续消费多帧：截断 → 数据不足；非法长度/未知类型 → Err；均不 panic。
    let mut rest = data;
    loop {
        match tunnel_protocol::Frame::try_decode(rest) {
            Ok(Some((_frame, consumed))) => rest = &rest[consumed..],
            Ok(None) | Err(_) => break,
        }
    }
});
