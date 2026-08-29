# 定位、优缺点与竞品对比

## 定位

RSTunnel 是一个**可完全自托管、可生产部署的内网穿透平台**：公网侧 Server + 内网侧 Agent，通过 QUIC 承载 HTTP/HTTPS/TCP/UDP 隧道，配 Web 管理后台、REST API、RBAC/ACL/审计。目标是「Cloudflare Tunnel / FRP 这一类的**自托管**替代」，重点解决**流量自主可控**与**多协议**两个诉求。

一句话：**如果你想内网穿透，但不想把流量交给第三方 SaaS，也不想放弃 HTTP Host 路由 / HTTPS / TCP / UDP 的完整能力，RSTunnel 就是为此设计的。**

---

## 优点

- **完全自托管、数据不出门**：Server 跑在自己机器上，流量不经任何第三方中转（对比 Cloudflare Tunnel / ngrok 的 SaaS 模式）。
- **现代传输 QUIC**：Agent 与 Server 之间走 QUIC（基于 Rust `quinn`），多路复用、0-RTT、弱网/移动网络下表现优于纯 TCP 隧道；一个 UDP 连接同时承载多路数据流。
- **多协议齐全**：HTTP（按 Host 路由 + `X-Forwarded-*` 注入）、HTTPS（SNI 终止 / 透传）、任意 TCP、UDP 都支持，覆盖 Web / 数据库 / DNS / 游戏等场景。
- **产品化控制面**：自带 Web 管理后台 + REST API + WebSocket 事件推送；路由存在数据库、可视化增删改。
- **企业级安全默认值**：RBAC、ACL、审计日志、登录防暴力破解、按 Route 的连接限速、Agent 侧 SSRF 目标防护（默认拒 loopback/link-local）、TOFU 证书 pin 防中间人。
- **运维友好**：两个单二进制（`tunnel-server` / `tunnel-agent`），启动即自动建库迁移；Agent 免配证书（TOFU 自动信任并固定）；路由变更实时下发到在线 Agent、Server 路由表热更新（v0.2.6+）；多 Server 故障转移；Prometheus 指标。
- **Agent 无需公网 IP、无需开入站端口**：主动出站建连，天然穿透 NAT/防火墙。

## 缺点 / 现阶段限制（务必知悉）

- **项目年轻（当前 v0.2.x）**：生产部署的成熟度、大并发下长期稳定性尚未经过大规模线上验证（对比 FRP 等已运行多年的项目）。
- **License 未定**：仓库 License 尚标「待定」，商用前需确认。
- **单 Server 无 HA**：目前 Server 是单节点；多 Server 前置 LB 的会话亲和有设计文档（`lb-session-affinity.md`），但集群/高可用尚未落地。
- **数据库默认 SQLite**：够中小规模；PostgreSQL 在 HA 里程碑才启用。
- **TLS 证书走手配**：生产 HTTPS 的 ACME 自动签发（T-27）尚未完成，目前自签或手动配置证书。
- **文档仍在完善**：设计文档详尽，但面向用户的文档（本套）刚起步。

---

## 与同类工具对比

> 「定位」列按该工具最主流的用法写；不少工具（如 FRP、Tailscale）能力随版本演进，请以各自最新文档为准。

| 维度 | **RSTunnel** | Cloudflare Tunnel | FRP | ngrok | Tailscale (Funnel/Serve) | rathole |
|------|-------------|-------------------|-----|-------|--------------------------|---------|
| 部署模式 | 自托管 | SaaS（Cloudflare 边缘） | 自托管 | SaaS 为主 | 自托管（依赖 Tailscale 协调节点） | 自托管 |
| 传输 | QUIC | HTTP/2 + QUIC（cloudflared） | TCP/KCP/QUIC 可选 | TCP | WireGuard（UDP） | 自定义（TCP，Rust） |
| HTTP Host 路由 | ✅ | ✅ | ✅ | ✅ | ✅（Funnel） | ❌（纯端口） |
| HTTPS | ✅ 终止+透传 | ✅（自动证书） | ✅ | ✅（自动证书） | ✅ | ❌ |
| 任意 TCP | ✅ | 需 `cloudflared access`/WARP | ✅ | ✅ | ❌ | ✅ |
| UDP | ✅ | 有限 | ✅ | ❌ | ❌ | ❌ |
| Web 管理后台 | ✅ | ✅（SaaS 控制台） | 基础 dashboard | ✅（SaaS） | ✅（SaaS 控制台） | ❌（仅配置文件） |
| RBAC / ACL / 审计 | ✅ | ✅（Access） | ❌/基础 | ✅（SaaS） | ✅（ACL） | ❌ |
| 流量经过第三方 | 否 | **是（Cloudflare）** | 否 | **是（ngrok）** | 否（DERP 中继可能中转） | 否 |
| 开源 License | 待定 | 客户端开源/边缘闭源 | Apache-2.0 | 客户端开源/服务闭源 | 客户端开源/服务闭源 | Apache-2.0 |
| 成熟度 | 年轻 | 生产级 | 生产级 | 生产级 | 生产级 | 年轻 |
| 典型上手成本 | 中（两进程+路由） | 低（一条命令） | 中（配置文件） | 极低 | 低（两端装客户端） | 低（配置文件） |

### 何时选 RSTunnel

- 要**流量自主可控**（不经过 Cloudflare/ngrok 等第三方），且愿意自托管。
- 既要 **HTTP/HTTPS**，也要 **TCP/UDP** 多协议。
- 想要**可视化 Web 管理 + 权限/审计**，而不只是改配置文件。
- 看重 QUIC 在弱网/移动场景的传输质量。

### 何时不选 RSTunnel（现阶段）

- 想要**零运维 SaaS**、开箱即用的极简体验 → ngrok / Cloudflare Tunnel。
- 已经重度使用 **Cloudflare 全家桶**、看重其免费 DoS 防护与全球边缘 → Cloudflare Tunnel。
- 需要**久经验证、社区庞大**的自托管方案，且不介意改配置文件 → FRP。
- 诉求是**内网组网/点对点互联**而非「把服务暴露到公网」 → Tailscale。
- 只要一个**极简、轻量**的端口转发、无控制面需求 → rathole / bore。
