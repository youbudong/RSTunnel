//! 按 Route 的并发连接限速（T-35/§32/§72 `max_connections`）。
//!
//! 单 Route 超过 `limits.max_connections` 后，新的入向连接被拒（TCP 丢弃、HTTP/HTTPS 回 429）。
//! 计数以 [`RouteId`] 为键，跨 Tcp/Http/Https 数据面共享；连接结束（[`ConnGuard`] drop）即释放额度。
//!
//! `limits.max_connections` 为 `None` 表示不限（跳过本 limiter）；`Some(0)` 视为「拒绝全部」。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tunnel_core::RouteId;

/// 占用一个连接额度后返回的守卫；`drop` 时释放额度（连接结束）。
pub struct ConnGuard {
    counter: Arc<AtomicU64>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 按 Route 维护活跃连接数的限速器（无锁读、原子增减）。
#[derive(Default)]
pub struct ConnLimiter {
    counters: DashMap<RouteId, Arc<AtomicU64>>,
}

impl ConnLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 尝试占用一个连接额度：未超限返回守卫（连接存续期间持有）；超限返回 `None`。
    ///
    /// `max_connections = 0` 恒拒绝；计数 `fetch_add` 先加后判，超限回滚并拒绝。
    pub fn try_acquire(&self, route_id: RouteId, max_connections: u64) -> Option<ConnGuard> {
        let counter = self
            .counters
            .entry(route_id)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .value()
            .clone();
        let prev = counter.fetch_add(1, Ordering::Relaxed);
        if prev >= max_connections {
            counter.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(ConnGuard { counter })
    }

    /// 当前活跃连接数（测试/观测用）。
    pub fn active(&self, route_id: RouteId) -> u64 {
        self.counters
            .get(&route_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn id(n: u128) -> RouteId {
        RouteId::from_u128(n)
    }

    #[test]
    fn acquire_respects_max_and_releases_on_drop() {
        let limiter = ConnLimiter::new();
        let g1 = limiter.try_acquire(id(1), 2).unwrap();
        assert_eq!(limiter.active(id(1)), 1);
        let g2 = limiter.try_acquire(id(1), 2).unwrap();
        assert_eq!(limiter.active(id(1)), 2);
        // 第 3 个超限被拒。
        assert!(limiter.try_acquire(id(1), 2).is_none());
        assert_eq!(limiter.active(id(1)), 2);

        // 释放一个后又有额度。
        drop(g1);
        assert_eq!(limiter.active(id(1)), 1);
        let _g3 = limiter.try_acquire(id(1), 2).unwrap();
        assert_eq!(limiter.active(id(1)), 2);

        drop((g2, _g3));
        assert_eq!(limiter.active(id(1)), 0);
    }

    #[test]
    fn routes_are_counted_independently() {
        let limiter = ConnLimiter::new();
        let _a = limiter.try_acquire(id(1), 1).unwrap();
        // 不同 Route 各自独立计数。
        let _b = limiter.try_acquire(id(2), 1).unwrap();
        assert_eq!(limiter.active(id(1)), 1);
        assert_eq!(limiter.active(id(2)), 1);
    }

    #[test]
    fn zero_max_rejects_all() {
        let limiter = ConnLimiter::new();
        assert!(limiter.try_acquire(id(1), 0).is_none());
        assert_eq!(limiter.active(id(1)), 0);
    }
}
