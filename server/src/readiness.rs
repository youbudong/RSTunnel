//! 服务端就绪状态（T-39/§98）：跟踪 DB/配置/QUIC/HTTP 四类组件的启动就绪情况，
//! 供 `/ready` 判定。
//!
//! §98 就绪条件：database connected / configuration loaded / QUIC listener ready /
//! HTTP listener ready。main 启动时按组件逐个 `mark_*` 置位；`/ready` 还额外对 DB
//! 做一次实时 `SELECT 1` 探测（连接池可能在启动后失联）。

use std::sync::atomic::{AtomicBool, Ordering};

/// 就绪标志集。字段为 [`AtomicBool`]，`Arc<Readiness>` 跨 main 与 `/ready` handler 共享。
#[derive(Debug)]
pub struct Readiness {
    db: AtomicBool,
    config: AtomicBool,
    quic: AtomicBool,
    http: AtomicBool,
}

impl Readiness {
    /// 生产构造：全部未就绪，随启动流程逐步置位。
    pub fn new() -> Self {
        Self {
            db: AtomicBool::new(false),
            config: AtomicBool::new(false),
            quic: AtomicBool::new(false),
            http: AtomicBool::new(false),
        }
    }

    /// 独立/测试构造：全部就绪（等价于已完成的启动流程）。
    pub fn ready() -> Self {
        Self {
            db: AtomicBool::new(true),
            config: AtomicBool::new(true),
            quic: AtomicBool::new(true),
            http: AtomicBool::new(true),
        }
    }

    pub fn mark_db(&self) {
        self.db.store(true, Ordering::Relaxed);
    }
    pub fn mark_config(&self) {
        self.config.store(true, Ordering::Relaxed);
    }
    pub fn mark_quic(&self) {
        self.quic.store(true, Ordering::Relaxed);
    }
    pub fn mark_http(&self) {
        self.http.store(true, Ordering::Relaxed);
    }

    pub fn db_ready(&self) -> bool {
        self.db.load(Ordering::Relaxed)
    }
    pub fn config_ready(&self) -> bool {
        self.config.load(Ordering::Relaxed)
    }
    pub fn quic_ready(&self) -> bool {
        self.quic.load(Ordering::Relaxed)
    }
    pub fn http_ready(&self) -> bool {
        self.http.load(Ordering::Relaxed)
    }

    /// §98 四类组件是否全部就绪（不含 DB 实时探测，后者由 `/ready` handler 补充）。
    pub fn all_ready(&self) -> bool {
        self.db_ready() && self.config_ready() && self.quic_ready() && self.http_ready()
    }
}

impl Default for Readiness {
    fn default() -> Self {
        Self::new()
    }
}
