# LB 会话亲和（T-44，设计文档 §50）

多 Server 实例前放置 L4 负载均衡器（LB）时，必须为 **QUIC/UDP** 与 **TCP 443** 配置会话亲和，
否则同一连接的数据包会在后端间漂移，导致连接中断。本文给出可落地的策略、配置示例与验证方法。

## 1. 为什么需要亲和

QUIC 运行在 UDP 之上，连接状态（握手、流、帧序号、拥塞控制）只存在于**某一台** Server 的
进程内。RSTunnel 的 Server 之间**不共享数据面连接状态**（§51：控制面靠 DB，数据面纯 QUIC）。

若 LB 把同一 QUIC 连接的 datagram 轮询/随机分到不同后端：

- 握手的后续包落到没参与握手的 Server → 握手失败；
- 已建立连接的流数据包漂到别的 Server → 该 Server 没有对应的 `Connection` → 数据被丢、连接超时断流。

因此 LB 必须保证「同一连接的（或至少同一来源的）所有 datagram 始终落到同一后端」。

## 2. 亲和键

| 流量 | 推荐亲和键 | 说明 |
|------|-----------|------|
| QUIC/UDP（443/udp） | **源四元组** `(src_ip, src_port, dst_ip, dst_port)` 哈希 | 最稳。QUIC 支持连接迁移/多路径，CID 会变，四元组相对稳定 |
| QUIC/UDP（可选） | **QUIC Connection ID（DCID）** 一致性哈希 | 需 LB 能解析 QUIC long-header 的 `Destination Connection ID`；对迁移敏感 |
| TCP 443（HTTPS/TLS passthrough） | **源 IP**（或源 IP+端口）哈希 | 见 §2.1 的 NAT 注意项 |

**首选源四元组**：它对所有 UDP 流量通用（不依赖 QUIC 解析），也天然覆盖连接迁移场景。若 LB
明确支持 QUIC CID 哈希（如 Envoy/Cilium 的 QUIC 代理、部分云 LB），也可采用，但需确认其对
CID 变更的处理。

### 2.1 TCP 亲和与 NAT 的取舍

按源 IP 哈希在**同一 NAT 网关后的大量客户端**会共享一个公网 IP → 全落到同一后端，造成不均衡。
生产环境优先 **源 IP + 源端口** 哈希（绝大多数 L4 LB 支持 `source`/`source-port` 一致性哈希），
或对"必须按会话粘性"的 TCP 用粘性表（sticky table）。

## 3. 配置示例

### 3.1 HAProxy（`source` 一致性哈希）

```haproxy
# QUIC/UDP：按源四元组哈希
listen rstunnel-quic
    bind :443/udp
    mode udp
    balance source
    server s1 10.0.0.11:443
    server s2 10.0.0.12:443
    server s3 10.0.0.13:443

# TCP 443（TLS passthrough）：按源 IP+端口哈希
listen rstunnel-tcp
    bind :443
    mode tcp
    balance source
    server s1 10.0.0.11:443
    server s2 10.0.0.12:443
    server s3 10.0.0.13:443
```

### 3.2 nginx `stream`（`hash $binary_remote_addr` 一致性哈希）

```nginx
# 注：nginx stream 的 UDP 负载均衡从 1.19 起支持；一致性哈希用 `hash`。
upstream rstunnel_quic {
    hash $binary_remote_addr consistent;   # 源 IP 一致性哈希
    server 10.0.0.11:443;
    server 10.0.0.12:443;
    server 10.0.0.13:443;
}
server {
    listen 443 udp;
    proxy_pass rstunnel_quic;
    proxy_responses 1;
    proxy_timeout 30s;
}

upstream rstunnel_tcp {
    hash $binary_remote_addr consistent;
    server 10.0.0.11:443;
    server 10.0.0.12:443;
    server 10.0.0.13:443;
}
server {
    listen 443;
    proxy_pass rstunnel_tcp;
    proxy_timeout 30s;
}
```

> nginx 的 `$binary_remote_addr` 只含源 IP（不含源端口）。若担心 NAT 不均衡，改用
> `hash $binary_remote_addr$remote_port consistent`（需 nginx ≥ 1.11.2 的 stream 变量组合）。

### 3.3 云 LB

- **AWS NLB**：UDP/TCP 监听器默认按**四元组**哈希（UDP 用源 IP+端口+协议；TCP 可选源 IP 或源 IP+端口）。
- **GCP 外部 LB（proxy/NLB）**：UDP 会话亲和按源四元组；TCP 按源 IP 或源 IP+端口（`sessionAffinity=CLIENT_IP`）。
- **Azure LB**：UDP/TCP 均按五元组哈希（源 IP+端口+协议+目的 IP+端口）。

统一原则：**让 LB 按源四元组/源 IP+端口哈希，而不是 round-robin 或 least-connections**。

## 4. 与 Agent 多 Server（T-43）的关系

两个机制正交，各管一段：

- **LB 亲和**：保证「已建立的单条连接」不漂移——同一 Agent↔Server 连接的每个包都到同一后端。
- **Agent 故障转移（T-43）**：当某后端整体不可用时，Agent 的 QUIC 连接会断开，然后按
  `[[servers]]` 顺序重连到下一台可用 Server。重连建立的是**新连接**，LB 会重新按哈希选后端，
  因此两者不冲突。

即：亲和管"连接内不漂移"，故障转移管"连接断了换后端"。

## 5. 验证（验收：LB 后连接不漂移）

无真实 LB 的本地环境可用「双后端 + 抓包/日志」验证；有 LB 时直接对公网入口验证。

### 5.1 手动验证（有 LB）

1. 起 N 台 Server（同 CA、同 DB，见 `deploy/`），前置 LB（按 §3 配亲和）。
2. 起 Agent 连 LB 入口，确认上线。
3. 连续发送 UDP/TCP 隧道流量，观察每台 Server 的
   `tunnel_server_connections_total`（或连接建立日志），断言**同一 Client 的所有连接都落在同一台
   Server**（其它后端计数为 0 或不变）。
4. 重启 Agent（触发重连），确认仍可连通（新连接重新哈希到某后端）。

### 5.2 自动化思路（可选，供 CI 参考）

由于需要真实 LB，未纳入仓库集成测试。可在具备环境的 CI 里：

- 用 `haproxy`/`nginx` 容器做 LB，后接两个 `tunnel-server` 容器；
- 客户端从固定 `src_ip:port` 连续建立 QUIC 连接；
- 断言两个后端中**只有一个**出现该客户端的连接（哈希确定性），且连接期间无 `Connection lost`。

### 5.3 无 LB 的单元级验证

仓库内已覆盖"连接不断开、认证/心跳/数据面稳定"（`server/tests/*`、`agent/tests/*`）。LB 亲和
本身是 L4 转发层属性，无法在单进程内模拟，故以本文档 + §5.1/§5.2 作为验收说明。
