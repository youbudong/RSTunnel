//! 帧的流式读写：把 [`tunnel_protocol::Frame`] 读写到任意 AsyncRead/AsyncWrite。
//!
//! server 与 agent 共用（T-10 起从 server 抽取）。

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunnel_protocol::{Frame, MAX_FRAME_LEN, MIN_FRAME_LEN};

/// 读取一帧（含 4 字节长度头）。返回 `Ok(None)` 表示流在帧边界处干净关闭。
pub async fn read_frame<R>(r: &mut R) -> Result<Option<Frame>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("read frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&len) {
        anyhow::bail!("invalid frame length {len}");
    }
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.resize(4 + len, 0);
    r.read_exact(&mut full[4..])
        .await
        .context("read frame body")?;
    match Frame::try_decode(&full)? {
        Some((frame, _)) => Ok(Some(frame)),
        None => anyhow::bail!("frame truncated"),
    }
}

/// 写入一帧（含 4 字节长度头）。
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let buf = frame.encode();
    w.write_all(&buf).await.context("write frame")?;
    Ok(())
}
