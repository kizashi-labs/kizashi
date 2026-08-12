#!/bin/bash
# EDR Agent インストールスクリプト (Linux / macOS)
# 使用方法:
#   curl -fsSL https://your-edr-server.com/install.sh | bash -s -- \
#     --server https://your-edr-server.com \
#     --token YOUR_ENROLLMENT_TOKEN

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Defaults ─────────────────────────────────────────────────
EDR_SERVER=""
ENROLL_TOKEN=""
INSTALL_DIR="/opt/edr-agent"
CONFIG_DIR="/etc/edr-agent"
LOG_DIR="/var/log/edr-agent"
QUARANTINE_DIR="/var/lib/edr-agent/quarantine"
AGENT_USER="edr-agent"

# ─── Parse Arguments ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)  EDR_SERVER="$2"; shift 2 ;;
        --token)   ENROLL_TOKEN="$2"; shift 2 ;;
        --dir)     INSTALL_DIR="$2"; shift 2 ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

[[ -z "$EDR_SERVER" ]]   && error "--server が必要です (例: https://edr.company.com)"
[[ -z "$ENROLL_TOKEN" ]] && error "--token が必要です"
[[ $EUID -ne 0 ]]        && error "root権限が必要です (sudo で実行してください)"

# ─── Detect OS ────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux)
            OS="linux"
            if   [[ -f /etc/debian_version ]]; then DISTRO="debian"
            elif [[ -f /etc/redhat-release ]]; then DISTRO="rhel"
            elif [[ -f /etc/alpine-release ]]; then DISTRO="alpine"
            else DISTRO="linux"
            fi
            ;;
        Darwin) OS="darwin"; DISTRO="macos" ;;
        *) error "サポートされていないOS: $(uname -s)" ;;
    esac

    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "サポートされていないアーキテクチャ: $ARCH" ;;
    esac

    info "OS: $OS ($DISTRO) / $ARCH"
}

# ─── Download Agent Binary ────────────────────────────────────
download_agent() {
    local url="${EDR_SERVER}/downloads/edr-agent-${OS}-${ARCH}"
    local checksum_url="${url}.sha256"
    local tmp="/tmp/edr-agent-download"

    info "エージェントバイナリをダウンロード中: $url"

    if command -v curl &>/dev/null; then
        curl -fsSL -o "$tmp" "$url"
        curl -fsSL -o "${tmp}.sha256" "$checksum_url"
    elif command -v wget &>/dev/null; then
        wget -qO "$tmp" "$url"
        wget -qO "${tmp}.sha256" "$checksum_url"
    else
        error "curl または wget が必要です"
    fi

    # Verify checksum
    local expected
    expected=$(cat "${tmp}.sha256" | awk '{print $1}')
    local actual
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$tmp" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        actual=$(shasum -a 256 "$tmp" | awk '{print $1}')
    fi

    if [[ "$expected" != "$actual" ]]; then
        rm -f "$tmp" "${tmp}.sha256"
        error "チェックサム検証失敗 (expected: $expected, got: $actual)"
    fi

    info "チェックサム検証OK"
    echo "$tmp"
}

# ─── Create User ──────────────────────────────────────────────
create_user() {
    if id "$AGENT_USER" &>/dev/null; then
        info "ユーザー $AGENT_USER は既に存在します"
        return
    fi

    if [[ "$OS" == "linux" ]]; then
        useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$AGENT_USER"
    elif [[ "$OS" == "darwin" ]]; then
        dscl . -create "/Users/$AGENT_USER"
        dscl . -create "/Users/$AGENT_USER" UserShell /usr/bin/false
        dscl . -create "/Users/$AGENT_USER" IsHidden 1
    fi
    info "ユーザー $AGENT_USER を作成しました"
}

# ─── Install Files ────────────────────────────────────────────
install_files() {
    local binary_tmp="$1"

    # Create directories
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$QUARANTINE_DIR"

    # Install binary
    install -o root -g root -m 755 "$binary_tmp" "$INSTALL_DIR/edr-agent"
    rm -f "$binary_tmp" "${binary_tmp}.sha256"

    # Set quarantine directory ownership
    chown -R "$AGENT_USER:$AGENT_USER" "$QUARANTINE_DIR" "$LOG_DIR"
    chmod 700 "$QUARANTINE_DIR"

    info "バイナリをインストールしました: $INSTALL_DIR/edr-agent"
}

# ─── Generate TLS Client Certificate ──────────────────────────
enroll_agent() {
    local agent_id
    agent_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]')

    info "エージェントを登録中 (ID: $agent_id)"

    # Generate private key + CSR
    if ! command -v openssl &>/dev/null; then
        error "openssl が必要です"
    fi

    local key_file="$CONFIG_DIR/agent.key"
    local csr_file="/tmp/agent.csr"

    openssl genrsa -out "$key_file" 2048 2>/dev/null
    chmod 600 "$key_file"

    openssl req -new -key "$key_file" -out "$csr_file" \
        -subj "/CN=$agent_id/O=EDR-Agent" 2>/dev/null

    local csr
    csr=$(cat "$csr_file")
    rm -f "$csr_file"

    # Enroll with server
    local enroll_response
    enroll_response=$(curl -sfS \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"enrollment_token\": \"$ENROLL_TOKEN\",
            \"hostname\": \"$(hostname)\",
            \"os_type\": \"$OS\",
            \"os_version\": \"$(uname -r)\",
            \"agent_version\": \"$(\"$INSTALL_DIR/edr-agent\" --version 2>/dev/null || echo 'unknown')\",
            \"csr\": $(echo "$csr" | jq -Rs .)
        }" \
        "${EDR_SERVER}/grpc/v1/enroll" 2>&1) || {
        error "サーバーへの登録に失敗しました: $enroll_response"
    }

    # Save certificates
    echo "$enroll_response" | jq -r '.signed_cert' > "$CONFIG_DIR/agent.crt"
    echo "$enroll_response" | jq -r '.ca_cert'     > "$CONFIG_DIR/ca.crt"
    chmod 644 "$CONFIG_DIR/agent.crt" "$CONFIG_DIR/ca.crt"

    echo "$agent_id"
}

# ─── Write Config ─────────────────────────────────────────────
write_config() {
    local agent_id="$1"

    cat > "$CONFIG_DIR/config.toml" <<EOF
# EDR Agent Configuration
# 自動生成 - $(date)

[agent]
id       = "$agent_id"
hostname = "$(hostname)"

[server]
url            = "${EDR_SERVER}"
ca_cert        = "${CONFIG_DIR}/ca.crt"
client_cert    = "${CONFIG_DIR}/agent.crt"
client_key     = "${CONFIG_DIR}/agent.key"
grpc_port      = 9090
connect_timeout_sec = 30

[collection]
process_monitoring   = true
file_monitoring      = true
network_monitoring   = true
dns_monitoring       = true
auth_monitoring      = true
yara_scan_on_exec    = true
event_batch_interval_ms = 500
config_poll_interval_sec = 300
local_buffer_size_mb = 100

monitored_paths = ["/", "C:\\\\"]
excluded_paths  = [
    "/proc", "/sys", "/dev",
    "C:\\\\Windows\\\\WinSxS",
]
excluded_processes = []

[response]
auto_response_enabled = true

[logging]
level    = "info"
file     = "${LOG_DIR}/agent.log"
max_size_mb  = 50
max_backups  = 3

[quarantine]
dir = "${QUARANTINE_DIR}"
EOF

    chmod 600 "$CONFIG_DIR/config.toml"
    info "設定ファイルを作成しました: $CONFIG_DIR/config.toml"
}

# ─── Install System Service ───────────────────────────────────
install_service() {
    if [[ "$OS" == "linux" ]]; then
        install_systemd
    elif [[ "$OS" == "darwin" ]]; then
        install_launchd
    fi
}

install_systemd() {
    cat > /etc/systemd/system/edr-agent.service <<EOF
[Unit]
Description=EDR Platform Agent
Documentation=https://github.com/edr-platform
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/edr-agent --config ${CONFIG_DIR}/config.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.log
# Security hardening
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${LOG_DIR} ${QUARANTINE_DIR}
NoNewPrivileges=false
# Agent needs root for eBPF and isolation
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable edr-agent
    systemctl start edr-agent
    info "systemdサービスを起動しました"
}

install_launchd() {
    cat > /Library/LaunchDaemons/com.edrplatform.agent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.edrplatform.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/edr-agent</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.log</string>
</dict>
</plist>
EOF

    launchctl load /Library/LaunchDaemons/com.edrplatform.agent.plist
    info "launchdサービスを起動しました"
}

# ─── Verify Installation ──────────────────────────────────────
verify() {
    sleep 3

    if [[ "$OS" == "linux" ]]; then
        if systemctl is-active --quiet edr-agent; then
            info "✓ エージェントが正常に起動しました"
        else
            warn "エージェントのステータスを確認してください: systemctl status edr-agent"
        fi
    fi

    info "インストール完了"
    info ""
    info "管理コマンド:"
    if [[ "$OS" == "linux" ]]; then
    info "  状態確認: systemctl status edr-agent"
    info "  ログ確認: journalctl -u edr-agent -f"
    info "  再起動:   systemctl restart edr-agent"
    info "  停止:     systemctl stop edr-agent"
    fi
    info ""
    info "ダッシュボード: ${EDR_SERVER}"
}

# ─── Uninstall Function ───────────────────────────────────────
uninstall() {
    info "EDR エージェントをアンインストール中..."

    if [[ "$OS" == "linux" ]]; then
        systemctl stop edr-agent 2>/dev/null || true
        systemctl disable edr-agent 2>/dev/null || true
        rm -f /etc/systemd/system/edr-agent.service
        systemctl daemon-reload
    elif [[ "$OS" == "darwin" ]]; then
        launchctl unload /Library/LaunchDaemons/com.edrplatform.agent.plist 2>/dev/null || true
        rm -f /Library/LaunchDaemons/com.edrplatform.agent.plist
    fi

    rm -rf "$INSTALL_DIR" "$CONFIG_DIR"
    # Note: log and quarantine dirs are preserved for forensic purposes
    info "アンインストール完了 (ログ・隔離ファイルは保存されています: $LOG_DIR, $QUARANTINE_DIR)"
}

# ─── Main ─────────────────────────────────────────────────────
main() {
    info "EDR Platform エージェントをインストールしています..."
    info "サーバー: ${EDR_SERVER}"

    detect_os
    local binary_tmp
    binary_tmp=$(download_agent)
    create_user
    install_files "$binary_tmp"
    local agent_id
    agent_id=$(enroll_agent)
    write_config "$agent_id"
    install_service
    verify
}

# アンインストールモード
if [[ "${1:-}" == "--uninstall" ]]; then
    detect_os
    uninstall
    exit 0
fi

main
