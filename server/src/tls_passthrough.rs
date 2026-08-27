//! TLS 透传（T-28）：Server 仅按 SNI 路由、不解密——窥探 ClientHello 提取 SNI，匹配
//! HTTPS 路由（`tls_mode = 'passthrough'`）后，把原始 TLS 字节（含已窥探的前缀）经
//! QUIC 双向流转发到 Agent（复用 OPEN_TCP），客户端与内网 TLS 目标直连完成握手。
//!
//! 与 TLS 终止（T-27）不同：终止路径在 Server 解密后按 Host 路由，透传路径只做 SNI 路由。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::frame_io::read_frame;
use crate::route::ServerRoute;
use crate::tcp_proxy::{copy_duplex, send_message};
use tunnel_protocol::{Message, OpenTcpPayload};

/// 窥探 ClientHello 的最大字节数（正常 ClientHello + SNI 远小于此）。
const MAX_PEEK_BYTES: usize = 16 * 1024;

/// SNI 提取结果：`Found` 命中；`Absent` 完整 ClientHello 无 SNI；`NeedMore` 字节不足；
/// `NotTls` 非 TLS 握手/非 ClientHello/结构异常。
#[derive(Debug)]
enum Sni {
    Found(String),
    Absent,
    NeedMore,
    NotTls,
}

/// 从字节缓冲中解析 TLS ClientHello 的 SNI（单记录，不支持跨记录分片）。
fn extract_sni(buf: &[u8]) -> Sni {
    // TLS 记录头：5 字节（content_type + version + length）。
    if buf.len() < 5 {
        return Sni::NeedMore;
    }
    if buf[0] != 0x16 {
        return Sni::NotTls;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + rec_len;
    if buf.len() < record_end {
        return Sni::NeedMore;
    }
    // Handshake 消息头：4 字节（type + 3 字节 length）。
    if record_end < 9 || buf[5] != 0x01 {
        return Sni::NotTls;
    }
    let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | (buf[8] as usize);
    let hello = 9;
    let end = hello + hs_len;
    if end > record_end {
        return Sni::NotTls;
    }

    let mut pos = hello;
    // client_version(2) + random(32)
    if pos + 34 > end {
        return Sni::NotTls;
    }
    pos += 34;
    // session_id
    if pos + 1 > end {
        return Sni::NotTls;
    }
    let sid_len = buf[pos] as usize;
    pos += 1;
    if pos + sid_len > end {
        return Sni::NotTls;
    }
    pos += sid_len;
    // cipher_suites
    if pos + 2 > end {
        return Sni::NotTls;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > end {
        return Sni::NotTls;
    }
    pos += cs_len;
    // compression_methods
    if pos + 1 > end {
        return Sni::NotTls;
    }
    let cm_len = buf[pos] as usize;
    pos += 1;
    if pos + cm_len > end {
        return Sni::NotTls;
    }
    pos += cm_len;
    // extensions
    if pos + 2 > end {
        return Sni::Absent;
    }
    let ext_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > end {
        return Sni::NotTls;
    }
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + len > ext_end {
            return Sni::NotTls;
        }
        if ext_type == 0 {
            // server_name 扩展：2 字节 list 长度 + 若干 (name_type + name_len + name)。
            if len < 2 {
                return Sni::Absent;
            }
            let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            if 2 + list_len > len {
                return Sni::NotTls;
            }
            let mut p = pos + 2;
            let list_end = p + list_len;
            while p + 3 <= list_end {
                let name_type = buf[p];
                let name_len = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
                p += 3;
                if p + name_len > list_end {
                    return Sni::NotTls;
                }
                if name_type == 0 {
                    return Sni::Found(String::from_utf8_lossy(&buf[p..p + name_len]).into_owned());
                }
                p += name_len;
            }
            return Sni::Absent;
        }
        pos += len;
    }
    Sni::Absent
}

/// 从流中读取足够字节提取 SNI；返回 `(sni, 已读前缀)`。前缀字节随后必须原样重放
/// （透传路径直接转发，终止路径交还 rustls）。
pub(crate) async fn peek_sni<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(Option<String>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 8192];
    loop {
        match extract_sni(&buf) {
            Sni::Found(sni) => return Ok((Some(sni), buf)),
            Sni::Absent | Sni::NotTls => return Ok((None, buf)),
            Sni::NeedMore => {
                if buf.len() >= MAX_PEEK_BYTES {
                    return Ok((None, buf));
                }
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Ok((None, buf));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
}

/// 流前缀适配器：读时先吐完 `prefix` 再落到 `inner`，写直接委托 `inner`。
/// 供「已窥探前缀 + 原流」在透传/终止两条路径复用同一 `AsyncRead + AsyncWrite` 语义。
pub(crate) struct Prefixed<S> {
    prefix: io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = this.prefix.get_ref().len() as u64 - this.prefix.position();
        if remaining > 0 {
            Pin::new(&mut this.prefix).poll_read(cx, buf)
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 透传一条 TLS 连接：打开双向流 → OPEN_TCP → 读 OPEN_OK/FAIL → 双向拷贝（含前缀）。
pub(crate) async fn forward_passthrough<S>(
    stream: S,
    conn: quinn::Connection,
    route: Arc<ServerRoute>,
    peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut qsend, mut qrecv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(route = %route.name, error = %e, "open bidi stream failed");
            return;
        }
    };
    let msg = Message::OpenTcp(OpenTcpPayload {
        route_id: route.id,
        target_host: route.target_host.clone(),
        target_port: route.target_port,
        client_addr: Some(peer.to_string()),
    });
    if send_message(&mut qsend, msg, 0).await.is_err() {
        return;
    }
    match read_frame(&mut qrecv).await {
        Ok(Some(frame)) => match Message::from_frame(&frame) {
            Ok(Message::OpenOk(_)) => {}
            Ok(Message::OpenFail(p)) => {
                tracing::warn!(route = %route.name, code = %p.code, "agent failed to open target");
                return;
            }
            _ => return,
        },
        _ => return,
    }
    copy_duplex(stream, qsend, qrecv).await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// 手工构造一个含给定 SNI 的最小 ClientHello（单记录、单扩展）。
    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        // server_name 扩展数据：list_len(2) + name_type(1) + name_len(2) + name。
        let mut ext = Vec::new();
        ext.extend_from_slice(&(3 + sni_bytes.len() as u16).to_be_bytes()); // list 长度
        ext.push(0); // name_type = host_name
        ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni_bytes);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id 长度 0
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites 长度
        hello.extend_from_slice(&0x1301u16.to_be_bytes()); // 一个 cipher suite
        hello.push(1); // compression_methods 长度
        hello.push(0); // null
        hello.extend_from_slice(&(4 + ext.len() as u16).to_be_bytes()); // extensions 长度
        hello.extend_from_slice(&0u16.to_be_bytes()); // ext type = server_name
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        record.extend_from_slice(&(4 + hello.len() as u16).to_be_bytes()); // record 长度
        record.push(0x01); // handshake type = ClientHello
        record.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]); // 3 字节长度
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello_with_sni("app.example.com");
        match extract_sni(&hello) {
            Sni::Found(s) => assert_eq!(s, "app.example.com"),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn partial_buffer_returns_need_more() {
        let hello = client_hello_with_sni("app.example.com");
        // 前 8 字节不足一个完整记录头 → NeedMore。
        assert!(matches!(extract_sni(&hello[..8]), Sni::NeedMore));
    }

    #[test]
    fn non_tls_returns_not_tls() {
        // 首字节不是 0x16（handshake）→ NotTls。
        let mut buf = vec![0u8; 16];
        buf[0] = 0x17;
        assert!(matches!(extract_sni(&buf), Sni::NotTls));
    }

    #[test]
    fn prefixed_stream_reads_prefix_then_inner() {
        let inner = io::Cursor::new(vec![9u8, 10u8]);
        let mut prefixed = Prefixed::new(vec![1u8, 2u8, 3u8], inner);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

        // 第一次读：先吐前缀。
        let mut first = [0u8; 16];
        let n = {
            let mut rb = ReadBuf::new(&mut first);
            assert!(Pin::new(&mut prefixed)
                .poll_read(&mut cx, &mut rb)
                .is_ready());
            rb.filled().len()
        };
        assert_eq!(&first[..n], &[1, 2, 3]);

        // 第二次读：前缀耗尽，落到 inner。
        let mut second = [0u8; 16];
        let n2 = {
            let mut rb2 = ReadBuf::new(&mut second);
            assert!(Pin::new(&mut prefixed)
                .poll_read(&mut cx, &mut rb2)
                .is_ready());
            rb2.filled().len()
        };
        assert_eq!(&second[..n2], &[9, 10]);
    }
}
