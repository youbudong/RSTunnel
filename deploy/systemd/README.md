# systemd 部署（T-41）

Server / Agent 的 systemd 单元：`Restart=always` + 沙箱（§49），非 root 运行。

## 文件

| 文件 | 安装位置 | 说明 |
|---|---|---|
| `tunnel-server.service` | `/etc/systemd/system/` | Server 单元（`CAP_NET_BIND_SERVICE` 绑定 443） |
| `tunnel-agent.service` | `/etc/systemd/system/` | Agent 单元 |
| `tunnel-server.toml` | `/etc/tunnel/server.toml` | Server 配置 |
| `tunnel-agent.toml` | `/etc/tunnel/agent.toml` | Agent 配置 |

## 一键安装（root）

```bash
cargo build --release -p tunnel-server -p tunnel-agent
sudo deploy/systemd/install.sh --release target/release
```

或由脚本就地构建：

```bash
sudo deploy/systemd/install.sh --build
```

## 手动安装

1. 建用户：`useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin tunnel`
2. 装二进制到 `/usr/local/bin/`
3. 配置到 `/etc/tunnel/`（`chown root:tunnel`，`chmod 640`），并把
   `tunnel-agent.toml` 里的 `token` 换成 Web 后台 / API 签发的明文、`endpoints`
   换成真实服务器地址。
4. 单元到 `/etc/systemd/system/`，`systemctl daemon-reload`
5. `systemctl enable --now tunnel-server tunnel-agent`

## 验证（T-41 验收）

```bash
systemctl is-enabled tunnel-server tunnel-agent   # enabled（开机自启）
systemctl is-active  tunnel-server tunnel-agent   # active（已启动）

# 崩溃重启：kill -9 后观察 Restart=always 生效
systemctl kill -s KILL tunnel-agent
sleep 6 && systemctl is-active tunnel-agent       # active（已重启）
```

## 沙箱说明

两者均启用 `NoNewPrivileges / ProtectSystem=strict / ProtectHome / PrivateTmp / ProtectKernel*
/ RestrictSUIDSGID / PrivateDevices` 等硬化项。Server 额外加 `AmbientCapabilities=CAP_NET_BIND_SERVICE`
以非 root 绑定 443；Agent 无需低端口故不加。`StateDirectory=` 提供可写数据目录
（`/var/lib/tunnel-server`、`/var/lib/tunnel-agent`）。
