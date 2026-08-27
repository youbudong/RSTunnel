//! Agent 自动重连：指数退避 + jitter（设计文档 §34）。
//!
//! 退避序列 `1/2/4/8/16/30/60s` 封顶（`Backoff::base_delay`），再叠加等距 jitter
//! 落在 `[base/2, base]`，避免多 Agent 同时重连造成惊群。

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use tokio::sync::watch;

use crate::session::{AgentSession, HeartbeatConfig};

/// 基础退避序列（秒），超出后取末位（60s 封顶）。
const BACKOFF_SECONDS: [u64; 7] = [1, 2, 4, 8, 16, 30, 60];

/// 指数退避器。`attempt` 为当前已重试次数，`cap` 限制单次退避上限。
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    attempt: u32,
    cap: Duration,
}

impl Backoff {
    pub fn new(cap: Duration) -> Self {
        Self { attempt: 0, cap }
    }

    /// 重置退避（一次成功连接后调用，下次断开从 1s 重新开始）。
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// 无 jitter 的基础退避时长（封顶）。
    pub fn base_delay(&self) -> Duration {
        let idx = (self.attempt as usize).min(BACKOFF_SECONDS.len() - 1);
        Duration::from_secs(BACKOFF_SECONDS[idx]).min(self.cap)
    }

    /// 消费一次重试机会，返回带 jitter 的实际退避时长（落在 `[base/2, base]`）。
    pub fn next_delay<R: Rng>(&mut self, rng: &mut R) -> Duration {
        let base = self.base_delay();
        self.attempt += 1;
        let half = (base.as_millis() / 2) as u64;
        let jitter = rng.gen_range(0..=half);
        Duration::from_millis(half + jitter)
    }
}

/// 重连循环参数。
#[derive(Debug, Clone, Copy)]
pub struct ReconnectConfig {
    /// 退避上限（生产 60s；测试可调小加速）。
    pub cap: Duration,
    /// 最大重连次数（None = 无限，直到进程退出）。
    pub max_reconnects: Option<u32>,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            cap: Duration::from_secs(60),
            max_reconnects: None,
        }
    }
}

/// 连接 + 认证 + 心跳，断开/失败后按指数退避自动重连。
///
/// `connect` 每次调用返回一个新会话；`cancel` 置真后在下一次循环边界优雅退出。
/// 每次开始重连（首次之后的连接尝试）前递增 `tunnel_agent_reconnect_total`。
pub async fn run_with_reconnect<F, Fut>(
    mut connect: F,
    heartbeat: HeartbeatConfig,
    reconnect: ReconnectConfig,
    mut cancel: watch::Receiver<bool>,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<AgentSession>>,
{
    let mut backoff = Backoff::new(reconnect.cap);
    let mut reconnects: u32 = 0;

    loop {
        if *cancel.borrow() {
            tracing::info!("reconnect loop cancelled");
            break;
        }

        // 已达最大重连次数即退出（首次连接不计入重连）。
        if let Some(max) = reconnect.max_reconnects {
            if reconnects > max {
                tracing::info!(reconnects, "max reconnects reached");
                break;
            }
        }

        // 非首次连接即是一次重连。
        if reconnects > 0 {
            if let Some(c) = tunnel_metrics::agent_reconnect_total() {
                c.inc();
            }
        }

        match connect().await {
            Ok(session) => {
                let node_id = session.node_id();
                tracing::info!(%node_id, "authenticated");
                backoff.reset();
                match session.run(heartbeat).await {
                    Ok(outcome) => tracing::info!(%node_id, ?outcome, "session ended"),
                    Err(e) => tracing::warn!(%node_id, error = %e, "session error"),
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "connect failed");
            }
        }

        reconnects += 1;
        let delay = backoff.next_delay(&mut rand::thread_rng());
        tracing::debug!(?delay, reconnects, "reconnecting after backoff");
        if sleep_or_cancel(delay, &mut cancel).await {
            break;
        }
    }
}

/// 退避等待，`cancel` 触发时返回 `true`（调用方应退出循环）。
async fn sleep_or_cancel(delay: Duration, cancel: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = cancel.changed() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn backoff_base_sequence_caps_at_60s() {
        let mut b = Backoff::new(Duration::from_secs(60));
        let expected = [1u64, 2, 4, 8, 16, 30, 60, 60, 60];
        for e in expected {
            assert_eq!(b.base_delay(), Duration::from_secs(e));
            b.attempt += 1;
        }
    }

    #[test]
    fn backoff_respects_cap() {
        let mut b = Backoff::new(Duration::from_millis(100));
        for _ in 0..5 {
            assert!(b.base_delay() <= Duration::from_millis(100));
            b.attempt += 1;
        }
    }

    #[test]
    fn backoff_jitter_stays_within_half_range() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut b = Backoff::new(Duration::from_secs(60));
        // 首次 base = 1s，jitter 后应落在 [500ms, 1s]。
        for _ in 0..10 {
            b.reset();
            let d = b.next_delay(&mut rng);
            assert!(d >= Duration::from_millis(500), "got {d:?}");
            assert!(d <= Duration::from_secs(1), "got {d:?}");
        }
    }

    #[test]
    fn backoff_advances_attempt() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut b = Backoff::new(Duration::from_secs(60));
        assert_eq!(b.attempt, 0);
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.attempt, 1);
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.attempt, 2);
    }
}
