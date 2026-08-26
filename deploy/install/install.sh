#!/usr/bin/env bash
# =============================================================================
# Kizashi — Agent Installer (Linux / macOS)
# =============================================================================
#
# One-liner usage:
#   curl -fsSL https://your-server/install.sh \
#     | ENROLLMENT_TOKEN=xxx SERVER_URL=https://your-server bash
#
# Or download and run manually:
#   chmod +x install.sh
#   sudo SERVER_URL=https://edr.example.com ENROLLMENT_TOKEN=xxx ./install.sh
#
# Optional environment variables:
#   LOG_LEVEL          - Agent log level (default: info)
#   INSTALL_TIMEOUT    - Download timeout in seconds (default: 120)
#   SKIP_VERIFY        - Set to "1" to skip TLS verification (not recommended)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()    { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}  %s\n" "$*" >&2; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
section() { printf "\n${BOLD}${BLUE}==> %s${NC}\n" "$*"; }
step()    { printf "    ${GREEN}→${NC} %s\n" "$*"; }

# ─── Constants ───────────────────────────────────────────────────────────────
AGENT_VERSION="${AGENT_VERSION:-latest}"
INSTALL_BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
LOG_DIR="/var/log/edr"
DATA_DIR="/var/lib/edr"
RUN_DIR="/var/run"
QUARANTINE_DIR="${DATA_DIR}/quarantine"

AGENT_BIN="${INSTALL_BIN_DIR}/edr-agent"
WATCHDOG_BIN="${INSTALL_BIN_DIR}/edr-watchdog"
CONFIG_FILE="${CONFIG_DIR}/agent.toml"

AGENT_USER="edr"
AGENT_GROUP="edr"

SYSTEMD_UNIT_DIR="/etc/systemd/system"
WATCHDOG_SERVICE="edr-watchdog"

LAUNCHD_PLIST_DIR="/Library/LaunchDaemons"
LAUNCHD_LABEL="com.kizashi.edr"
LAUNCHD_PLIST="${LAUNCHD_PLIST_DIR}/${LAUNCHD_LABEL}.plist"

DOWNLOAD_TIMEOUT="${INSTALL_TIMEOUT:-120}"
CURL_OPTS=(-fsSL --connect-timeout 30 --max-time "$DOWNLOAD_TIMEOUT")
WGET_OPTS=(--quiet --timeout=30 --tries=3)

# ─── Cleanup on failure ───────────────────────────────────────────────────────
TMP_DIR=""
cleanup() {
    local exit_code=$?
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    if [ $exit_code -ne 0 ]; then
        warn "Installation failed. Cleaning up temporary files."
        # Remove partially installed service unit if install did not complete
        if [ -f "${SYSTEMD_UNIT_DIR}/${WATCHDOG_SERVICE}.service" ]; then
            systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true
            systemctl disable "$WATCHDOG_SERVICE" 2>/dev/null || true
            rm -f "${SYSTEMD_UNIT_DIR}/${WATCHDOG_SERVICE}.service"
            systemctl daemon-reload 2>/dev/null || true
        fi
        if [ -f "$LAUNCHD_PLIST" ]; then
            launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
            rm -f "$LAUNCHD_PLIST"
        fi
    fi
}
trap cleanup EXIT

# ─── Prerequisite checks ─────────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This installer must be run as root. Try: sudo $0"
    fi
}

check_env() {
    if [ -z "${SERVER_URL:-}" ]; then
        error "SERVER_URL is required. Example: SERVER_URL=https://edr.example.com"
    fi
    if [ -z "${ENROLLMENT_TOKEN:-}" ]; then
        error "ENROLLMENT_TOKEN is required. Obtain it from the EDR dashboard."
    fi
    # Strip trailing slash from URL
    SERVER_URL="${SERVER_URL%/}"
}

check_dependencies() {
    local missing=()

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        missing+=("curl or wget")
    fi

    if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
        missing+=("sha256sum or shasum")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required tools: ${missing[*]}"
    fi
}

# ─── OS / Architecture detection ─────────────────────────────────────────────
detect_platform() {
    local uname_s uname_m

    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "$uname_s" in
        Linux)
            OS="linux"
            if   [ -f /etc/debian_version ];  then DISTRO="debian"
            elif [ -f /etc/redhat-release ];   then DISTRO="rhel"
            elif [ -f /etc/alpine-release ];   then DISTRO="alpine"
            elif [ -f /etc/arch-release ];     then DISTRO="arch"
            else                                    DISTRO="linux"
            fi
            ;;
        Darwin)
            OS="darwin"
            DISTRO="macos"
            ;;
        *)
            error "Unsupported operating system: $uname_s. Supported: Linux, macOS."
            ;;
    esac

    case "$uname_m" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)
            error "Unsupported architecture: $uname_m. Supported: x86_64, arm64."
            ;;
    esac

    info "Platform detected: ${OS}/${ARCH} (${DISTRO})"

    detect_variant
}

# ─── Build variant selection ─────────────────────────────────────────────────
# Beyond the default (telemetry-only) build, two enforcing variants exist:
#
#   edr-agent-linux-amd64-ebpf    eBPF/LSM exec prevention, tamper protection,
#                                 credential-access auditing
#   edr-agent-darwin-<arch>-esf   Apple Endpoint Security Framework collector
#                                 (+ AUTH_EXEC prevention with the entitlement)
#
# Linux is auto-detected: the enforcing build needs a kernel with BPF LSM active
# (CONFIG_BPF_LSM and `bpf` in the boot-time lsm= list), and on such hosts it is
# a strict superset. Until now the enforcing binary was published but nothing
# ever chose it, which is why prevention shipped in name only.
#
# macOS is NOT auto-detected. The ESF build is only functional when signed with
# Apple's approved com.apple.developer.endpoint-security.client entitlement, and
# an unsigned one fails at es_new_client with ERR_NOT_ENTITLED — the installer
# cannot tell from the outside whether the published binary was signed. Picking
# it automatically would trade a working polling agent for a silently dead ESF
# one, so it requires EDR_AGENT_VARIANT=esf.
#
# Override with EDR_AGENT_VARIANT=ebpf|esf (force) or EDR_AGENT_VARIANT=none.
detect_variant() {
    VARIANT=""

    case "${EDR_AGENT_VARIANT:-auto}" in
        none|default) info "Build variant: default (forced via EDR_AGENT_VARIANT)"; return ;;
        ebpf)         VARIANT="ebpf"; warn "Build variant: ebpf (forced via EDR_AGENT_VARIANT; kernel support not checked)"; return ;;
        esf)          VARIANT="esf";  warn "Build variant: esf (forced via EDR_AGENT_VARIANT; requires an entitlement-signed binary)"; return ;;
        auto)         ;;
        *)            warn "Unknown EDR_AGENT_VARIANT='${EDR_AGENT_VARIANT}'; falling back to auto-detection" ;;
    esac

    if [ "$OS" = "darwin" ]; then
        info "Build variant: default (macOS ESF build must be requested with EDR_AGENT_VARIANT=esf)"
        return
    fi

    if [ "$OS" != "linux" ] || [ "$ARCH" != "amd64" ]; then
        info "Build variant: default (the enforcing Linux build is published for linux/amd64 only)"
        return
    fi

    # securityfs exposes the active LSM list. Absent => securityfs not mounted or
    # a kernel too old to report it; either way we cannot confirm BPF LSM.
    local lsm_list="/sys/kernel/security/lsm"
    if [ ! -r "$lsm_list" ]; then
        info "Build variant: default (cannot read ${lsm_list}; BPF LSM unconfirmed)"
        return
    fi

    if grep -qw bpf "$lsm_list" 2>/dev/null; then
        VARIANT="ebpf"
        info "Build variant: ebpf — BPF LSM active, installing the enforcing build"
    else
        info "Build variant: default (BPF LSM not in $(cat "$lsm_list" 2>/dev/null))"
        info "  To enable pre-execution prevention, add 'bpf' to the kernel lsm= boot"
        info "  parameter (e.g. lsm=lockdown,capability,landlock,yama,apparmor,bpf) and re-run."
    fi
}

# ─── Download helper ─────────────────────────────────────────────────────────
http_get() {
    local url="$1"
    local dest="$2"

    if command -v curl &>/dev/null; then
        local opts=("${CURL_OPTS[@]}")
        if [ "${SKIP_VERIFY:-0}" = "1" ]; then
            opts+=(-k)
            warn "TLS verification disabled (SKIP_VERIFY=1)"
        fi
        curl "${opts[@]}" -o "$dest" "$url"
    else
        local opts=("${WGET_OPTS[@]}")
        if [ "${SKIP_VERIFY:-0}" = "1" ]; then
            opts+=(--no-check-certificate)
        fi
        wget "${opts[@]}" -O "$dest" "$url"
    fi
}

# confirm_variant_available downgrades VARIANT to the default build when the
# server has no binary for it, so auto-detection can never turn a working
# install into a failed one. A server that has not yet published the enforcing
# build (agent-ebpf.yml has to have run at least once) is a perfectly normal
# state, and on a BPF-LSM host auto-detection would otherwise pick a variant the
# server 404s on and abort the install.
#
# The warning is deliberately loud: silently installing the non-enforcing build
# on a host that *can* enforce is the failure mode worth being noisy about.
confirm_variant_available() {
    [ -n "${VARIANT:-}" ] || return 0

    local probe="${SERVER_URL}/api/v1/agents/download/checksum?platform=${OS}&arch=${ARCH}&binary=agent&variant=${VARIANT}"
    if http_get "$probe" /dev/null 2>/dev/null; then
        return 0
    fi

    warn "The server has no '${VARIANT}' agent build published for ${OS}/${ARCH}."
    warn "Installing the default (telemetry-only) build — pre-execution prevention will NOT be active."
    case "$VARIANT" in
        ebpf) warn "Publish it by running the 'Agent eBPF Build' workflow, then re-run this installer." ;;
        esf)  warn "Publish it by running the 'Agent macOS ESF Build' workflow with Apple signing secrets configured." ;;
    esac
    VARIANT=""
}

# ─── Download binaries ───────────────────────────────────────────────────────
download_binary() {
    local name="$1"       # e.g. edr-agent or edr-watchdog
    local dest="$2"       # destination path for verified binary

    # binary key for the download API: edr-agent -> agent, edr-watchdog -> watchdog
    local binary="${name#edr-}"

    # Only the agent has variant builds; the watchdog carries no prevention code
    # and one binary serves both. Requesting it with a variant is harmless (the
    # server maps it back to the plain watchdog) but asking plainly is clearer.
    local variant_q="" variant_sfx=""
    if [ -n "${VARIANT:-}" ] && [ "$binary" = "agent" ]; then
        variant_q="&variant=${VARIANT}"
        variant_sfx="-${VARIANT}"
    fi

    local filename="${name}-${OS}-${ARCH}${variant_sfx}"
    # The server exposes binaries via the agent download API, not a static
    # /downloads/ path (that route does not exist on the Go server).
    local url="${SERVER_URL}/api/v1/agents/download?platform=${OS}&arch=${ARCH}&binary=${binary}${variant_q}"
    local checksum_url="${SERVER_URL}/api/v1/agents/download/checksum?platform=${OS}&arch=${ARCH}&binary=${binary}${variant_q}"

    local tmp_bin="${TMP_DIR}/${filename}"
    local tmp_sha="${tmp_bin}.sha256"

    step "Downloading ${filename} from ${url}"
    if ! http_get "$url" "$tmp_bin"; then
        error "Failed to download ${filename}. Check that SERVER_URL is reachable."
    fi

    step "Downloading checksum"
    if ! http_get "$checksum_url" "$tmp_sha"; then
        error "Failed to download checksum for ${filename}."
    fi

    step "Verifying SHA-256 checksum"
    local expected actual

    # The checksum endpoint returns JSON: {"...","checksum":"<hex>"}. Extract the
    # 64-char hex without jq; fall back to the first token for plain-text formats.
    expected="$(sed -n 's/.*"checksum"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$tmp_sha" | head -n1)"
    [ -n "$expected" ] || expected="$(awk '{print $1}' "$tmp_sha")"

    if command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "$tmp_bin" | awk '{print $1}')"
    else
        actual="$(shasum -a 256 "$tmp_bin" | awk '{print $1}')"
    fi

    if [ -z "$expected" ]; then
        error "Checksum file is empty for ${filename}."
    fi

    if [ "$expected" != "$actual" ]; then
        error "Checksum mismatch for ${filename}!
  Expected: ${expected}
  Got:      ${actual}
The download may be corrupted or tampered with."
    fi

    step "Checksum verified: ${actual:0:16}..."
    cp "$tmp_bin" "$dest"
    chmod 755 "$dest"
}

# ─── User / group management ─────────────────────────────────────────────────
create_edr_user_linux() {
    if getent group "$AGENT_GROUP" &>/dev/null; then
        step "Group '${AGENT_GROUP}' already exists"
    else
        groupadd --system "$AGENT_GROUP"
        step "Created system group: ${AGENT_GROUP}"
    fi

    if id "$AGENT_USER" &>/dev/null; then
        step "User '${AGENT_USER}' already exists"
    else
        useradd \
            --system \
            --gid "$AGENT_GROUP" \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "EDR Agent service account" \
            "$AGENT_USER"
        step "Created system user: ${AGENT_USER}"
    fi
}

# macOS: the watchdog runs as root / daemon; no separate user needed.
# The binaries are installed as root:wheel with 755.

# ─── Directory structure ──────────────────────────────────────────────────────
create_directories() {
    local dirs=("$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$QUARANTINE_DIR")

    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        step "Created directory: ${dir}"
    done

    if [ "$OS" = "linux" ]; then
        chown root:"$AGENT_GROUP" "$CONFIG_DIR"
        chmod 750 "$CONFIG_DIR"
        chown "$AGENT_USER":"$AGENT_GROUP" "$LOG_DIR" "$DATA_DIR" "$QUARANTINE_DIR"
        chmod 750 "$LOG_DIR" "$DATA_DIR"
        chmod 700 "$QUARANTINE_DIR"
    else
        # macOS: root:wheel ownership, restrictive permissions
        chown root:wheel "$CONFIG_DIR"
        chmod 755 "$CONFIG_DIR"
        chmod 755 "$LOG_DIR" "$DATA_DIR"
        chmod 700 "$QUARANTINE_DIR"
    fi
}

# ─── Configuration file ───────────────────────────────────────────────────────
write_config() {
    local agent_id
    # Generate a stable UUID for this agent
    if command -v uuidgen &>/dev/null; then
        agent_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    elif [ -r /proc/sys/kernel/random/uuid ]; then
        agent_id="$(cat /proc/sys/kernel/random/uuid)"
    else
        # Fallback: derive from hostname + timestamp
        agent_id="$(printf '%s-%s' "$(hostname)" "$(date +%s)" | sha256sum | cut -c1-36 | sed 's/.\{8\}/&-/;s/.\{13\}/&-/;s/.\{18\}/&-/;s/.\{23\}/&-/')"
    fi

    local hostname
    hostname="$(hostname -f 2>/dev/null || hostname)"

    local log_level="${LOG_LEVEL:-info}"

    step "Writing agent configuration to ${CONFIG_FILE}"

    # Write config — note: cert paths are placeholders (mTLS provisioned post-enroll)
    cat > "$CONFIG_FILE" <<EOF
# Kizashi Agent Configuration
# Generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# Do not edit manually — changes may be overwritten by policy sync.

[agent]
id       = "${agent_id}"
hostname = "${hostname}"

[server]
url                  = "${SERVER_URL}"
grpc_port            = 9090
ingestion_grpc_port  = 9091
connect_timeout_sec  = 30
# cert_pins = []  # Optional: SHA-256 SPKI pins for certificate pinning

[collection]
process_monitoring        = true
file_monitoring           = true
network_monitoring        = true
dns_monitoring            = true
auth_monitoring           = true
yara_scan_on_exec         = true
event_batch_interval_ms   = 500
config_poll_interval_sec  = 300
local_buffer_size_mb      = 100
max_events_per_second     = 1000

monitored_paths    = ["/"]
excluded_paths     = ["/proc", "/sys", "/dev", "/run"]
excluded_processes = []

[response]
auto_response_enabled = true

[logging]
level       = "${log_level}"
file        = "${LOG_DIR}/agent.log"
max_size_mb = 50
max_backups = 5

[quarantine]
dir = "${QUARANTINE_DIR}"

[fim]
enabled      = true
interval_sec = 60
EOF

    chmod 640 "$CONFIG_FILE"

    if [ "$OS" = "linux" ]; then
        chown root:"$AGENT_GROUP" "$CONFIG_FILE"
    else
        chown root:wheel "$CONFIG_FILE"
    fi

    # Store the enrollment token for the watchdog's first-run enrollment call
    local token_file="${CONFIG_DIR}/enrollment.token"
    printf '%s' "$ENROLLMENT_TOKEN" > "$token_file"
    chmod 600 "$token_file"
    [ "$OS" = "linux" ] && chown root:"$AGENT_GROUP" "$token_file" || chown root:wheel "$token_file"

    step "Agent ID: ${agent_id}"
}

# ─── systemd service (Linux) ─────────────────────────────────────────────────
install_systemd() {
    local service_file="${SYSTEMD_UNIT_DIR}/${WATCHDOG_SERVICE}.service"

    step "Writing systemd unit: ${service_file}"

    cat > "$service_file" <<EOF
[Unit]
Description=Kizashi Watchdog
Documentation=https://docs.kizashi-edr.io
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${WATCHDOG_BIN} \\
    --agent ${AGENT_BIN} \\
    --config ${CONFIG_FILE} \\
    --pidfile ${RUN_DIR}/edr-watchdog.pid
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
TimeoutStopSec=30s

# Output / logging
StandardOutput=append:${LOG_DIR}/watchdog.log
StandardError=append:${LOG_DIR}/watchdog.log

# Run as root — the agent needs CAP_BPF / CAP_NET_ADMIN / CAP_SYS_PTRACE for eBPF
User=root
Group=root

# Security hardening
PrivateTmp=true
ProtectHostname=true
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectSystem=false
NoNewPrivileges=false

# Allow writing only to well-known EDR directories
ReadWritePaths=${LOG_DIR} ${DATA_DIR} ${RUN_DIR}

[Install]
WantedBy=multi-user.target
EOF

    step "Reloading systemd daemon"
    systemctl daemon-reload

    step "Enabling ${WATCHDOG_SERVICE}"
    systemctl enable "$WATCHDOG_SERVICE"

    step "Starting ${WATCHDOG_SERVICE}"
    systemctl start "$WATCHDOG_SERVICE"
}

# ─── launchd plist (macOS) ───────────────────────────────────────────────────
install_launchd() {
    step "Writing launchd plist: ${LAUNCHD_PLIST}"

    cat > "$LAUNCHD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${WATCHDOG_BIN}</string>
        <string>--agent</string>
        <string>${AGENT_BIN}</string>
        <string>--config</string>
        <string>${CONFIG_FILE}</string>
        <string>--pidfile</string>
        <string>/var/run/edr-watchdog.pid</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/watchdog.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/watchdog.log</string>

    <key>ProcessType</key>
    <string>Background</string>

    <key>Nice</key>
    <integer>-5</integer>

    <key>EnvironmentVariables</key>
    <dict>
        <key>EDR_CONFIG</key>
        <string>${CONFIG_FILE}</string>
    </dict>
</dict>
</plist>
EOF

    chown root:wheel "$LAUNCHD_PLIST"
    chmod 644 "$LAUNCHD_PLIST"

    # Unload any existing instance first
    launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true

    step "Loading launchd daemon"
    launchctl load -w "$LAUNCHD_PLIST"
}

# ─── Service health verification ─────────────────────────────────────────────
verify_service() {
    local tries=0
    local max_tries=10
    local ok=false

    step "Waiting for service to start..."
    while [ $tries -lt $max_tries ]; do
        sleep 2
        tries=$((tries + 1))

        if [ "$OS" = "linux" ]; then
            if systemctl is-active --quiet "$WATCHDOG_SERVICE" 2>/dev/null; then
                ok=true
                break
            fi
        else
            if launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep -q '"PID"'; then
                ok=true
                break
            fi
        fi
    done

    if $ok; then
        info "Service is running."
    else
        warn "Service did not appear to start within the expected time."
        warn "Run the diagnostic commands below to investigate."
    fi
}

# ─── Post-install summary ────────────────────────────────────────────────────
print_summary() {
    local dashboard_url="${SERVER_URL}"

    printf "\n"
    printf "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${GREEN}║     Kizashi Agent — Installation Complete          ║${NC}\n"
    printf "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n\n"

    printf "  ${BOLD}Server:${NC}    %s\n" "$SERVER_URL"
    printf "  ${BOLD}Config:${NC}    %s\n" "$CONFIG_FILE"
    printf "  ${BOLD}Logs:${NC}      %s\n" "$LOG_DIR"
    printf "  ${BOLD}Platform:${NC}  %s/%s\n\n" "$OS" "$ARCH"

    if [ "$OS" = "linux" ]; then
        printf "  ${BOLD}Management commands:${NC}\n"
        printf "    Status:  systemctl status %s\n"  "$WATCHDOG_SERVICE"
        printf "    Logs:    journalctl -u %s -f\n"  "$WATCHDOG_SERVICE"
        printf "    Restart: systemctl restart %s\n" "$WATCHDOG_SERVICE"
        printf "    Stop:    systemctl stop %s\n"    "$WATCHDOG_SERVICE"
    else
        printf "  ${BOLD}Management commands:${NC}\n"
        printf "    Status:  launchctl list %s\n"                    "$LAUNCHD_LABEL"
        printf "    Logs:    tail -f %s/watchdog.log\n"              "$LOG_DIR"
        printf "    Restart: launchctl kickstart -k system/%s\n"     "$LAUNCHD_LABEL"
        printf "    Stop:    launchctl unload %s\n"                  "$LAUNCHD_PLIST"
    fi

    printf "\n  ${BOLD}Dashboard:${NC} %s\n\n" "$dashboard_url"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    printf "\n${BOLD}Kizashi — Agent Installer${NC}\n"
    printf "Version: %s | $(date -u '+%Y-%m-%d %H:%M UTC')\n\n" "$AGENT_VERSION"

    section "Checking prerequisites"
    check_root
    check_env
    check_dependencies

    section "Detecting platform"
    detect_platform

    # Create working temp directory (cleaned up by trap)
    TMP_DIR="$(mktemp -d /tmp/edr-install.XXXXXX)"

    section "Downloading binaries"
    confirm_variant_available
    local tmp_agent="${TMP_DIR}/edr-agent"
    local tmp_watchdog="${TMP_DIR}/edr-watchdog"

    download_binary "edr-agent"    "$tmp_agent"
    download_binary "edr-watchdog" "$tmp_watchdog"

    section "Installing binaries to ${INSTALL_BIN_DIR}"
    install -o root -m 755 "$tmp_agent"    "$AGENT_BIN"
    install -o root -m 755 "$tmp_watchdog" "$WATCHDOG_BIN"
    step "Installed: ${AGENT_BIN}"
    step "Installed: ${WATCHDOG_BIN}"

    # Record which build was installed so update.sh keeps this host on it. The
    # kernel check cannot be re-run at update time to decide this: an operator
    # may have pinned the default build with EDR_AGENT_VARIANT=none on a
    # BPF-LSM-capable host, and re-detecting would silently override that.
    mkdir -p "$CONFIG_DIR"
    printf '%s\n' "${VARIANT:-}" > "${CONFIG_DIR}/agent-variant"
    chmod 644 "${CONFIG_DIR}/agent-variant"

    section "Creating system user and directories"
    if [ "$OS" = "linux" ]; then
        create_edr_user_linux
    fi
    create_directories

    section "Writing configuration"
    write_config

    section "Installing system service"
    if [ "$OS" = "linux" ]; then
        install_systemd
    else
        install_launchd
    fi

    section "Verifying service health"
    verify_service

    print_summary
}

main "$@"
