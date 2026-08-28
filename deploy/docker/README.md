# Docker 部署（T-40）

演示拓扑：`init`（一次性 seed）→ `server` + `agent` + `target`，`curl` 经 HTTP 隧道打到 `target`。

## 启动

在**仓库根目录**执行：

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

## 验证

HTTP 隧道按 `Host: app.example.com` 路由到 `target` 服务：

```bash
curl -H "Host: app.example.com" http://localhost:8080/
# -> hello from target
```

管理面（仅回环，不对外发布）：

- Web 管理后台：浏览器打开 `http://127.0.0.1:8080/`（server 从 `web_dir` 同源托管 SPA）
- 探针 / 指标：

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
curl http://127.0.0.1:8080/metrics
```

## 关键点

- **非 root**：运行时用户 `65532:65532`（§126）；绑定 80/443 用 `NET_BIND_SERVICE`（§48）。
- **凭据**：`init` 用 `tunnel-cli seed` 种入 `demo-node`，凭据以 SHA-256 哈希入库（明文仅存在于
  `config/agent.toml` 与 seed 命令，二者须一致）。
- **TLS**：server 生成自签名证书（SAN `server`/`localhost`），DER 落盘到共享卷 `certs`；
  agent 以 `[server].ca` 信任该证书后建立 QUIC。生产应由 T-27 从 ACME/配置加载正式证书。
- **幂等**：重复 `up` 时 `demo-node` 已存在则 seed 跳过；重置需清空 `data` 卷。
- **Web 管理后台**：`Dockerfile.server` 用 node 阶段构建 `web/dist` 并 COPY 进镜像，
  server 按 `config/server.toml` 的 `[internal].web_dir = "/app/web/dist"` 同源托管。

## 生产注意

- 把 `443/tcp`（HTTPS/Web/API）与 `443/udp`（QUIC）对外发布，而非演示的高位端口。
- 用 `tunnel-cli token` 生成随机 token，替换 `rstunnel-demo-token`。
