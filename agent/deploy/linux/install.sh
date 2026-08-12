#!/usr/bin/env bash
# EDR Agent Linux Installer
# =============================================================================
# DEPRECATED / 非推奨 — このスクリプトは現在どこからも参照されない孤立ファイルです。
# 本番のインストールはダッシュボードのエンロール経路（サーバーが動的生成:
# server/internal/api/handlers/installer_handler.go, GET /api/v1/installer/...）を、
# 手動インストールは deploy/install/install.sh を使用してください。
# 詳細: docs/インストーラ・配信経路アーキテクチャ.md
# =============================================================================
# Usage: sudo bash install.sh [--server https://edr.corp.example.com:9090] [--token ENROLLMENT_TOKEN]
set -euo pipefail

# ─── Defaults ──────────────────────────────────────────────────
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
LOG_DIR="/var/log/edr"
QUARANTINE_DIR="/var/quarantine/edr"
PID_DIR="/var/run"
SERVICE_USER="edr"
SERVICE_GROUP="edr"
AGENT_BIN="${INSTALL_DIR}/edr-agent"
WATCHDOG_BIN="${INSTALL_DIR}/edr-watchdog"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Args ──────────────────────────────────────────────────────
SERVER_URL="${EDR_SERVER_URL:-}"
TOKEN="${EDR_ENROLLMENT_TOKEN:-}"
CA_CERT="${EDR_CA_CERT:-}"        # path to CA PEM file

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)  SERVER_URL="$2";  shift 2 ;;
        --token)   TOKEN="$2";       shift 2 ;;
        --ca-cert) CA_CERT="$2";     shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Root check ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: このスクリプトはrootで実行する必要があります (sudo bash install.sh)"
    exit 1
fi

echo "==> EDRエージェントをインストールします"

# ─── System user ───────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "==> サービスユーザー '$SERVICE_USER' を作成します"
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "EDR Agent Service" "$SERVICE_USER"
fi

# ─── Directories ───────────────────────────────────────────────
echo "==> ディレクトリを作成します"
install -d -m 755 -o root  -g root       "$CONFIG_DIR"
install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"
install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$QUARANTINE_DIR"

# ─── Binaries ──────────────────────────────────────────────────
# Expect binaries next to this script (built by CI)
DIST_DIR="${SCRIPT_DIR}/../../"

echo "==> バイナリをコピーします"
if [[ -f "${DIST_DIR}/agent" ]]; then
    install -m 755 -o root -g root "${DIST_DIR}/agent"    "$AGENT_BIN"
fi
if [[ -f "${DIST_DIR}/watchdog" ]]; then
    install -m 755 -o root -g root "${DIST_DIR}/watchdog" "$WATCHDOG_BIN"
fi

# Verify binaries exist
for bin in "$AGENT_BIN" "$WATCHDOG_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: バイナリが見つかりません: $bin"
        echo "       先にビルドを実行してください: make build-linux"
        exit 1
    fi
done

# バイナリを置き換えた場合、前回起動時に保存された整合性ハッシュを削除する。
# 削除しないと次回起動時に「binary integrity check failed: hash mismatch」が記録される。
# 削除後の初回起動で新バイナリのハッシュが自動的に計算・保存される。
if [[ -f "${CONFIG_DIR}/agent.sha256" ]]; then
    rm -f "${CONFIG_DIR}/agent.sha256"
    echo "==> 整合性ハッシュを削除しました (次回起動で新バイナリのハッシュを記録します)"
fi

# ─── Capabilities (eBPF / network) ─────────────────────────────
if command -v setcap &>/dev/null; then
    echo "==> ケーパビリティを設定します"
    # edr-agent needs net_admin for network isolation, sys_ptrace for process introspection
    setcap cap_net_admin,cap_sys_ptrace+eip "$AGENT_BIN"    || true
    # watchdog only needs to start/stop the agent
    setcap ""                                "$WATCHDOG_BIN" || true
fi

# ─── TLS certificates ──────────────────────────────────────────
CERT_DIR="${CONFIG_DIR}/certs"
install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$CERT_DIR"

if [[ -n "$CA_CERT" && -f "$CA_CERT" ]]; then
    echo "==> CA証明書をコピーします"
    install -m 640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$CA_CERT" "${CERT_DIR}/ca.pem"
fi

# ─── Config file ───────────────────────────────────────────────
CONFIG_FILE="${CONFIG_DIR}/agent.toml"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "==> 設定ファイルを生成します"
    HOSTNAME=$(hostname -f)
    AGENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

    cat > "$CONFIG_FILE" <<EOF
[agent]
id       = "${AGENT_ID}"
hostname = "${HOSTNAME}"

[server]
url         = "${SERVER_URL:-https://edr-server:9090}"
ca_cert     = "${CERT_DIR}/ca.pem"
client_cert = "${CERT_DIR}/agent.crt"
client_key  = "${CERT_DIR}/agent.key"
grpc_port   = 9090

[collection]
process_monitoring     = true
file_monitoring        = true
network_monitoring     = true
dns_monitoring         = true
auth_monitoring        = true
yara_scan_on_exec      = true
event_batch_interval_ms  = 500
config_poll_interval_sec = 300
local_buffer_size_mb   = 100
max_events_per_second  = 1000
monitored_paths        = ["/", "/home", "/var"]
excluded_paths         = ["/proc", "/sys", "/dev"]
excluded_processes     = []

[response]
auto_response_enabled = true

[logging]
level       = "info"
file        = "${LOG_DIR}/agent.log"
max_size_mb = 50
max_backups = 3

[quarantine]
dir = "${QUARANTINE_DIR}"
EOF

    chmod 640 "$CONFIG_FILE"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_FILE"
fi

# ─── Enrollment ────────────────────────────────────────────────
# If a token was provided, write it as a one-shot enrollment file.
# The agent reads this on first start and exchanges it for mTLS certs.
if [[ -n "$TOKEN" ]]; then
    echo "==> 登録トークンを保存します"
    echo "$TOKEN" > "${CONFIG_DIR}/enrollment.token"
    chmod 600 "${CONFIG_DIR}/enrollment.token"
    chown "$SERVICE_USER:$SERVICE_GROUP" "${CONFIG_DIR}/enrollment.token"
fi

# ─── systemd service ───────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/edr-watchdog.service"
echo "==> systemdサービスをインストールします"
cp "${SCRIPT_DIR}/edr-watchdog.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable edr-watchdog.service
systemctl restart edr-watchdog.service

echo ""
echo "==> インストール完了"
echo "    ステータス確認: systemctl status edr-watchdog"
echo "    ログ確認:       journalctl -fu edr-watchdog"
echo "    設定ファイル:   ${CONFIG_FILE}"
