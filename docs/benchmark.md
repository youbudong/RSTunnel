# 性能基准（T-46）

对 §61「性能目标」与 §149「性能 Benchmark」的实测结果与差距分析。所有数字来自
`bench/` 独立 crate（同 `fuzz/`，非 workspace 成员）在回环网络上的真实运行。

## 1. 环境

| 项 | 值 |
|----|----|
| CPU | AMD Ryzen AI 9 HX 370（24 线程） |
| 内存 | 60 GB（可用 ~51 GB） |
| 系统 | Linux（回环 127.0.0.1） |
| Rust | 1.95.0-nightly（2026-04-15） |
| 构建 | `cargo build --release` |
| 拓扑 | 服务端 + 客户端同进程、同 tokio runtime（multi_thread，24 worker） |
| fd 上限 | `ulimit -n` = 1,048,576 |

> 服务端与客户端同进程运行，因此「内存」为二者合并值（含双方 QUIC 连接状态）。

## 2. 方法

三个子命令（`./bench/target/release/bench <mode> [N]`）：

- **`agents <N>`**：N 个 Agent（各自独立 node + credential）并发完成
  QUIC 握手 + token 认证 + 配置快照拉取并保持在线。统计墙钟时间、建立速率、
  RSS 增量、单连接建立延迟分布。
- **`throughput <MB>`**：单条 TCP 隧道 echo 吞吐。客户端并发「写 + 读」
  （边写边收，避免半双工 echo 目标导致的写后读死锁），写 MB MiB、读回 MB MiB。
- **`tcp <N>`**：N 条并发 TCP 连接穿过**同一条**隧道（单 Route），各自 echo 64 KiB。

内存测量读取 `/proc/self/status` 的 `VmRSS`。

### 离线构建说明

`tunnel-server` 依赖 `utoipa-swagger-ui`，其 build script 默认联网下载 swagger-ui。
离线环境构建时，可指向本地已缓存的 zip：

```bash
SWAGGER_UI_DOWNLOAD_URL=file:///path/to/swagger-ui-v5.17.12.zip \
  cargo build --release --manifest-path bench/Cargo.toml
```

（CI 环境有网络，无需此变量。）

## 3. 结果

### 3.1 Agent 连接规模（§149 Agent 数量 / §61「10,000 Agent connections」）

| 数量 | 成功 | 墙钟 | 建立速率 | 内存/连接 | p50 建立延迟 |
|-----:|-----:|------:|--------:|--------:|----------:|
| 1 | 1 | 1 ms | 658/s | 920 KB* | 1 ms |
| 10 | 10 | 7 ms | 1,362/s | 206 KB* | 3 ms |
| 100 | 100 | 68 ms | 1,455/s | 103 KB | 34 ms |
| 1,000 | 1,000 | 643 ms | 1,555/s | 86 KB | 321 ms |
| 10,000 | 10,000 | 6,246 ms | 1,601/s | 86 KB | 3,078 ms |

\* 小规模时服务端基线内存摊薄不足，单连接 RSS 偏高；≥100 后稳定在 ~86 KB/连接。

### 3.2 并发 TCP 连接（§149 并发连接 / §61「10,000 concurrent TCP connections」）

| 数量 | 成功 | 墙钟 | 聚合吞吐 |
|-----:|-----:|------:|-------:|
| 1 | 1 | 29 ms | 2.1 MiB/s* |
| 10 | 10 | 4 ms | 143.9 MiB/s |
| 100 | 100 | 97 ms | 64.4 MiB/s |
| 1,000 | 1,000 | 566 ms | 110.4 MiB/s |
| 10,000 | 10,000 | 5,878 ms | 106.3 MiB/s |

\* 首条连接含隧道建连（QUIC 握手 + 认证）的一次性开销。

### 3.3 单连接吞吐（§61 关注「throughput」）

| 数据量 | 单方向等效吞吐 |
|------:|----------:|
| 8 MiB | 148.6 MiB/s |
| 64 MiB | 304.7 MiB/s |
| 256 MiB | 359.7 MiB/s |
| 1,024 MiB | 428.9 MiB/s |

## 4. §61 目标核对

| 目标 | 结果 |
|------|------|
| 10,000 Agent connections | ✅ 达成（10,000/10,000，6.2 s，~1,600/s） |
| 10,000 concurrent TCP connections（单 Route） | ✅ 达成（10,000/10,000，5.9 s） |
| 100,000 concurrent Streams | ⚠️ 未直接验证：10k TCP = 10k 条 QUIC bi-stream，未加压到 100k 流。按内存线性外推（~86 KB/连接 → ~8.6 GB）可行，但需更大规模压力测试确认 |

## 5. 瓶颈分析

- **连接建立速率稳定**：100 → 10,000 规模下 ~1,600/s 无明显下降，说明握手/认证
  路径无 O(N) 退化。
- **单连接建立延迟随规模上升**（p50：100→34 ms，1,000→321 ms，10,000→3,078 ms）：
  主要来自并发排队。认证路径走 SQLite 内存库（`max_connections=1`，单连接串行），
  是当前最大的建立延迟瓶颈。生产换 PostgreSQL / WAL 可显著缓解。
- **内存线性**：~86 KB/连接（合并 server+client），10k ≈ 0.86 GB；100k ≈ 8.6 GB（可行）。
- **吞吐**：单连接回环 360–430 MiB/s（约 3.5 Gbps）；10k 并发小包聚合 ~106 MiB/s，
  受每连接开销主导，非带宽瓶颈。

## 6. 注意事项

- 回环测量：真实公网（RTT、丢包、带宽）下建立速率与吞吐会显著下降。
- 服务端 + 客户端同进程，RSS 为合并值，不代表单侧真实占用。
- `tcp` 模式每条连接仅 64 KiB payload，聚合吞吐反映小包/连接开销而非带宽上限。
