#!/usr/bin/env bash
# RSTunnel systemd 安装脚本（需 root）。安装二进制 + 配置 + 单元，并 enable --now。
#
# 用法：
#   sudo ./install.sh                 # 从 ./release/ 安装预编译二进制
#   sudo ./install.sh --build         # 就地 cargo build --release 后安装
#   sudo ./install.sh --release /path # 从指定目录安装二进制
#
# 幂等：已存在的配置不覆盖；重复运行只刷新二进制与单元。

set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/tunnel
UNIT_DIR=/etc/systemd/system
STATE_ROOT=/var/lib

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$SCRIPT_DIR/release"

# ---- 参数 ----
BUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD=1 ;;
        --release) shift; RELEASE_DIR="$1" ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift || true
done

[[ $EUID -eq 0 ]] || { echo "must run as root (sudo)" >&2; exit 1; }

# ---- 构建 ----
if [[ $BUILD -eq 1 ]]; then
    echo "==> cargo build --release"
    cargo build --release -p tunnel-server -p tunnel-agent -p tunnel-cli
    RELEASE_DIR="$SCRIPT_DIR/../../target/release"
fi

for bin in tunnel-server tunnel-agent tunnel-cli; do
    [[ -x "$RELEASE_DIR/$bin" ]] || { echo "missing binary: $RELEASE_DIR/$bin" >&2; exit 1; }
done

# ---- 用户 ----
if ! id -u tunnel >/dev/null 2>&1; then
    echo "==> create system user 'tunnel'"
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin tunnel
fi

# ---- 二进制 ----
echo "==> install binaries"
install -m 0755 "$RELEASE_DIR/tunnel-server" "$RELEASE_DIR/tunnel-agent" "$RELEASE_DIR/tunnel-cli" "$BIN_DIR/"

# ---- 配置（不覆盖已有）----
echo "==> install configs"
mkdir -p "$CONF_DIR"
for cfg in tunnel-server.toml tunnel-agent.toml; do
    if [[ -e "$CONF_DIR/$cfg" ]]; then
        echo "    skip existing $CONF_DIR/$cfg"
    else
        install -m 0640 -o root -g tunnel "$SCRIPT_DIR/$cfg" "$CONF_DIR/$cfg"
        echo "    installed $CONF_DIR/$cfg"
    fi
done

# ---- 状态目录（StateDirectory 由 systemd 管理，此处预建以便直接以 service 用户运行）----
install -d -m 0750 -o tunnel -g tunnel "$STATE_ROOT/tunnel-server"
install -d -m 0750 -o tunnel -g tunnel "$STATE_ROOT/tunnel-agent"

# ---- 单元 ----
echo "==> install units"
install -m 0644 "$SCRIPT_DIR/tunnel-server.service" "$SCRIPT_DIR/tunnel-agent.service" "$UNIT_DIR/"
systemctl daemon-reload

echo "==> enable + start"
systemctl enable --now tunnel-server.service tunnel-agent.service

echo "done. 状态："
systemctl --no-pager --lines=0 status tunnel-server.service tunnel-agent.service
