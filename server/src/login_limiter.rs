//! 登录防暴力破解限速（T-35/§72）：按用户名在滑动窗口内统计失败次数，超限锁定。
//!
//! 达到 `max_login_attempts` 次失败后，窗口期（`login_window_seconds`）内该用户名被锁定，
//! 登录接口返回 429（`TOO_MANY_REQUESTS`）。成功后清除失败记录。阈值/窗口由
//! `ServerConfig.security` 注入（生产 main），测试可用 [`LoginLimiter::default`]（5 次 / 300 秒）。

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// 默认锁定阈值（窗口内连续失败次数），与 `ServerConfig.security` 缺省一致。
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
/// 默认失败统计窗口（秒）。
const DEFAULT_WINDOW_SECS: u64 = 300;

/// 登录限速器：`max_attempts` 次失败后，窗口期内该用户名被锁定（429）。
pub struct LoginLimiter {
    max_attempts: usize,
    window_secs: u64,
    /// 用户名 → 窗口内的失败时间戳（Unix 秒）。
    failures: DashMap<String, Vec<u64>>,
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_WINDOW_SECS)
    }
}

impl LoginLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            max_attempts: max_attempts as usize,
            window_secs,
            failures: DashMap::new(),
        }
    }

    /// 是否允许本次尝试（未锁定）。窗口外的时间戳在读取时惰性清理。
    pub fn allows(&self, username: &str) -> bool {
        let now = now_secs();
        let mut entry = self.failures.entry(username.to_string()).or_default();
        entry.retain(|t| now.saturating_sub(*t) < self.window_secs);
        entry.len() < self.max_attempts
    }

    /// 记录一次失败。
    pub fn record_failure(&self, username: &str) {
        let now = now_secs();
        let mut entry = self.failures.entry(username.to_string()).or_default();
        entry.retain(|t| now.saturating_sub(*t) < self.window_secs);
        entry.push(now);
    }

    /// 成功后清除该用户名的失败记录。
    pub fn reset(&self, username: &str) {
        self.failures.remove(username);
    }
}

/// 当前 Unix 秒（时钟异常回退 0）。
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn locks_after_max_attempts() {
        let limiter = LoginLimiter::new(3, 300);
        assert!(limiter.allows("admin"));
        limiter.record_failure("admin");
        limiter.record_failure("admin");
        assert!(limiter.allows("admin")); // 2 次未锁定
        limiter.record_failure("admin");
        assert!(!limiter.allows("admin")); // 第 3 次后锁定
    }

    #[test]
    fn success_resets_counter() {
        let limiter = LoginLimiter::new(2, 300);
        limiter.record_failure("admin");
        limiter.reset("admin");
        assert!(limiter.allows("admin"));
        limiter.record_failure("admin");
        assert!(limiter.allows("admin")); // 重置后仅 1 次
    }

    #[test]
    fn usernames_are_counted_independently() {
        let limiter = LoginLimiter::new(1, 300);
        limiter.record_failure("admin");
        assert!(!limiter.allows("admin"));
        assert!(limiter.allows("alice"));
    }

    #[test]
    fn default_is_five_attempts() {
        let limiter = LoginLimiter::default();
        for _ in 0..5 {
            limiter.record_failure("admin");
        }
        assert!(!limiter.allows("admin"));
    }
}
