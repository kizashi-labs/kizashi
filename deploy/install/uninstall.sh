#!/usr/bin/env bash
# =============================================================================
# Kizashi — Agent Uninstaller (Linux / macOS)
# =============================================================================
#
# Usage:
#   sudo ./uninstall.sh           # Remove agent, keep logs and data
#   sudo ./uninstall.sh --purge   # Remove everything including logs and data
#   sudo ./uninstall.sh --yes     # Skip confirmation prompt
#
# Options:
#   --purge    Also remove log files (/var/log/edr) and data (/var/lib/edr)
#   --yes      Non-interactive — skip confirmation prompt
#   --help     Show this help message
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' NC=''
fi

info()    { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}  %s\n" "$*" >&2; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
section() { printf "\n${BOLD}==> %s${NC}\n" "$*"; }
step()    { printf "    → %s\n" "$*"; }

# ─── Defaults ────────────────────────────────────────────────────────────────
PURGE=false
YES=false

INSTALL_BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
LOG_DIR="/var/log/edr"
DATA_DIR="/var/lib/edr"

AGENT_BIN="${INSTALL_BIN_DIR}/edr-agent"
WATCHDOG_BIN="${INSTALL_BIN_DIR}/edr-watchdog"

AGENT_USER="edr"
AGENT_GROUP="edr"

WATCHDOG_SERVICE="edr-watchdog"
LAUNCHD_LABEL="com.kizashi.edr"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"

# ─── Argument parsing ────────────────────────────────────────────────────────
usage() {
    printf "Usage: %s [options]\n\n" "$(basename "$0")"
    printf "Options:\n"
    printf "  --purge    Remove all data and logs (irreversible)\n"
    printf "  --yes      Skip confirmation prompt\n"
    printf "  --help     Show this help message\n"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)  PURGE=true; shift ;;
        --yes|-y) YES=true;   shift ;;
        --help|-h) usage ;;
        *) warn "Unknown option: $1"; shift ;;
    esac
done

# ─── Prerequisite checks ─────────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root. Try: sudo $0"
    fi
}

detect_os() {
    case "$(uname -s)" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)      error "Unsupported OS: $(uname -s)" ;;
    esac
}

# ─── Confirmation prompt ──────────────────────────────────────────────────────
# ─── Uninstall protection ────────────────────────────────────────────────────
# Removing the agent requires the tenant's uninstall password when the SOC has
# set one. The check runs FIRST — before the confirmation prompt and before
# anything is stopped or deleted — so a refusal leaves the endpoint exactly as
# it was, still monitored.
#
# The decision is made by the agent binary (`edr-agent -verify-uninstall`), not
# here: verifying means 600k PBKDF2 iterations against material on disk, which
# is not something to reimplement in shell. This script only reads its exit code.
#
#   0  authorised (correct password, or no password configured for this tenant)
#   2  denied — the password did not match
#   3  could not decide (guard file unreadable/corrupt)
#
# Anything other than 0 aborts. In particular exit 3 aborts: a damaged guard
# file must not be a cheaper way out than knowing the password.
require_uninstall_authorisation() {
    if [ ! -x "$AGENT_BIN" ]; then
        # No agent binary to ask. Either this is a repair of a half-removed
        # install or someone already deleted it by hand; there is nothing left
        # for this check to protect.
        warn "エージェントバイナリが見つかりません (${AGENT_BIN})。アンインストール保護を確認できません。"
        return 0
    fi

    section "Checking uninstall protection"

    set +e
    "$AGENT_BIN" -config "${CONFIG_DIR}/agent.toml" -verify-uninstall
    local rc=$?
    set -e

    case "$rc" in
        0) step "Authorised." ;;
        2)
            error "アンインストールパスワードが違うため中止しました。
この端末は EDR 管理コンソールで設定されたアンインストールパスワードで保護されています。
管理者からパスワードを受け取り、次のように指定してください:

  sudo EDR_UNINSTALL_PASSWORD='<password>' $0 $*

この試行はサーバに通報されました。"
            ;;
        *)
            error "アンインストール保護の状態を確認できなかったため中止しました (exit ${rc})。
保護設定が壊れている可能性があります。管理コンソールからパスワードを再設定して
エージェントのハートビートを1回待つと復旧します。"
            ;;
    esac
}

confirm_uninstall() {
    printf "\n${BOLD}Kizashi Agent — Uninstaller${NC}\n\n"
    printf "  This will remove the following:\n"
    printf "    - Binaries:     %s, %s\n" "$AGENT_BIN" "$WATCHDOG_BIN"
    printf "    - Config:       %s\n" "$CONFIG_DIR"
    if $PURGE; then
        printf "    - Logs:         %s  ${RED}(--purge)${NC}\n" "$LOG_DIR"
        printf "    - Data/quarantine: %s  ${RED}(--purge)${NC}\n" "$DATA_DIR"
    else
        printf "    - Logs:         %s  (preserved)\n" "$LOG_DIR"
        printf "    - Data:         %s  (preserved)\n" "$DATA_DIR"
    fi
    printf "\n"

    if $YES; then
        return
    fi

    if $PURGE; then
        printf "${RED}WARNING: --purge will permanently delete logs and quarantined files.${NC}\n"
        printf "Type 'yes' to confirm: "
    else
        printf "Type 'yes' to confirm: "
    fi

    read -r answer
    if [ "$answer" != "yes" ]; then
        info "Uninstall cancelled."
        exit 0
    fi
}

# ─── Stop and remove systemd service ─────────────────────────────────────────
remove_systemd() {
    local service_file="/etc/systemd/system/${WATCHDOG_SERVICE}.service"

    if systemctl is-active --quiet "$WATCHDOG_SERVICE" 2>/dev/null; then
        step "Stopping service: ${WATCHDOG_SERVICE}"
        systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true
    fi

    if systemctl is-enabled --quiet "$WATCHDOG_SERVICE" 2>/dev/null; then
        step "Disabling service: ${WATCHDOG_SERVICE}"
        systemctl disable "$WATCHDOG_SERVICE" 2>/dev/null || true
    fi

    if [ -f "$service_file" ]; then
        step "Removing unit file: ${service_file}"
        rm -f "$service_file"
        systemctl daemon-reload
    else
        step "systemd unit not found (already removed?)"
    fi

    # Also handle the legacy edr-agent service name if present
    if systemctl cat edr-agent &>/dev/null 2>&1; then
        systemctl stop edr-agent 2>/dev/null || true
        systemctl disable edr-agent 2>/dev/null || true
        rm -f /etc/systemd/system/edr-agent.service
        systemctl daemon-reload
        step "Removed legacy service: edr-agent"
    fi
}

# ─── Stop and remove launchd daemon ──────────────────────────────────────────
remove_launchd() {
    if launchctl list "$LAUNCHD_LABEL" &>/dev/null 2>&1; then
        step "Unloading launchd daemon: ${LAUNCHD_LABEL}"
        launchctl unload -w "$LAUNCHD_PLIST" 2>/dev/null || true
    fi

    if [ -f "$LAUNCHD_PLIST" ]; then
        step "Removing plist: ${LAUNCHD_PLIST}"
        rm -f "$LAUNCHD_PLIST"
    else
        step "launchd plist not found (already removed?)"
    fi
}

# ─── Remove binaries ─────────────────────────────────────────────────────────
remove_binaries() {
    local removed=false

    for bin in "$AGENT_BIN" "${AGENT_BIN}.bak" "$WATCHDOG_BIN" "${WATCHDOG_BIN}.bak"; do
        if [ -f "$bin" ]; then
            step "Removing binary: ${bin}"
            rm -f "$bin"
            removed=true
        fi
    done

    if ! $removed; then
        step "No binaries found in ${INSTALL_BIN_DIR} (already removed?)"
    fi
}

# ─── Remove config ────────────────────────────────────────────────────────────
remove_config() {
    if [ -d "$CONFIG_DIR" ]; then
        step "Removing config directory: ${CONFIG_DIR}"
        rm -rf "$CONFIG_DIR"
    else
        step "Config directory not found: ${CONFIG_DIR}"
    fi
}

# ─── Remove logs and data (--purge only) ─────────────────────────────────────
remove_data() {
    if [ -d "$LOG_DIR" ]; then
        step "Removing log directory: ${LOG_DIR}"
        rm -rf "$LOG_DIR"
    fi

    if [ -d "$DATA_DIR" ]; then
        step "Removing data directory: ${DATA_DIR}"
        rm -rf "$DATA_DIR"
    fi
}

# ─── Remove system user ───────────────────────────────────────────────────────
remove_user() {
    if [ "$OS" = "linux" ]; then
        if id "$AGENT_USER" &>/dev/null; then
            step "Removing system user: ${AGENT_USER}"
            userdel "$AGENT_USER" 2>/dev/null || warn "Failed to remove user '${AGENT_USER}' (may still have processes)"
        fi

        if getent group "$AGENT_GROUP" &>/dev/null; then
            step "Removing system group: ${AGENT_GROUP}"
            groupdel "$AGENT_GROUP" 2>/dev/null || warn "Failed to remove group '${AGENT_GROUP}'"
        fi
    fi
}

# ─── Remove PID files ────────────────────────────────────────────────────────
remove_pid_files() {
    for pid_file in \
        /var/run/edr-watchdog.pid \
        /var/run/edr-agent.pid; do
        if [ -f "$pid_file" ]; then
            step "Removing PID file: ${pid_file}"
            rm -f "$pid_file"
        fi
    done
}

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary() {
    printf "\n${GREEN}${BOLD}Uninstall complete.${NC}\n\n"

    if ! $PURGE; then
        printf "  The following directories were preserved for forensic purposes:\n"
        [ -d "$LOG_DIR" ] && printf "    Logs:      %s\n" "$LOG_DIR"
        [ -d "$DATA_DIR" ] && printf "    Data:      %s\n" "$DATA_DIR"
        printf "\n"
        printf "  To remove them run: sudo rm -rf %s %s\n" "$LOG_DIR" "$DATA_DIR"
        printf "  Or re-run this script with the --purge flag.\n\n"
    fi
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    check_root
    detect_os
    require_uninstall_authorisation
    confirm_uninstall

    section "Stopping and removing service"
    if [ "$OS" = "linux" ]; then
        remove_systemd
    else
        remove_launchd
    fi

    section "Removing binaries"
    remove_binaries

    section "Removing configuration"
    remove_config

    section "Removing PID files"
    remove_pid_files

    if $PURGE; then
        section "Removing logs and data (--purge)"
        remove_data
    fi

    section "Removing system user and group"
    remove_user

    print_summary
}

main "$@"
