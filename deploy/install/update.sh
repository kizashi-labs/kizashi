#!/usr/bin/env bash
# =============================================================================
# Kizashi — Agent Updater (Linux / macOS)
# =============================================================================
#
# In-place binary update for an already-installed EDR agent. Downloads the
# latest agent + watchdog binaries, verifies their SHA-256 checksums, swaps
# them under the existing install, and restarts the service.
#
# Unlike install.sh this does NOT rewrite agent.toml or regenerate the agent
# ID — the endpoint keeps its dashboard identity. Use this to roll out a new
# agent build; use install.sh only for first-time installs.
#
# Usage:
#   sudo ./update.sh                              # server URL read from config
#   sudo SERVER_URL=https://edr.example.com ./update.sh
#
# Optional environment variables:
#   SERVER_URL       - Override the server base URL (else read from agent.toml)
#   INSTALL_TIMEOUT  - Download timeout in seconds (default: 120)
#   SKIP_VERIFY      - Set to "1" to skip TLS verification (not recommended)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi
info()    { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}  %s\n" "$*" >&2; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
section() { printf "\n${BOLD}${BLUE}==> %s${NC}\n" "$*"; }
step()    { printf "    ${GREEN}→${NC} %s\n" "$*"; }

# ─── Layout (must match install.sh) ──────────────────────────────────────────
INSTALL_BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
CONFIG_FILE="${CONFIG_DIR}/agent.toml"
AGENT_BIN="${INSTALL_BIN_DIR}/edr-agent"
WATCHDOG_BIN="${INSTALL_BIN_DIR}/edr-watchdog"
# Self-integrity hash sidecar. The agent stores/reads the SHA-256 of its own
# binary at <dir-of-config>/agent.sha256 (integrity.Check uses dataDir =
# filepath.Dir(configPath)). Refreshed after a binary swap so the new binary
# does not flag itself as tampered.
SIDECAR_FILE="${CONFIG_DIR}/agent.sha256"

WATCHDOG_SERVICE="edr-watchdog"
LAUNCHD_LABEL="com.kizashi.edr"

DOWNLOAD_TIMEOUT="${INSTALL_TIMEOUT:-120}"
CURL_OPTS=(-fsSL --connect-timeout 30 --max-time "$DOWNLOAD_TIMEOUT")
WGET_OPTS=(--quiet --timeout=30 --tries=3)

TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" || true; }
trap cleanup EXIT

# ─── Prerequisite checks ─────────────────────────────────────────────────────
check_root() {
    [ "$(id -u)" -eq 0 ] || error "This updater must be run as root. Try: sudo $0"
}

# An update only makes sense on top of an existing install.
check_installed() {
    [ -f "$CONFIG_FILE" ] || error "No existing install found at ${CONFIG_FILE}. Run install.sh for a first-time install."
    [ -x "$AGENT_BIN" ]   || error "No agent binary at ${AGENT_BIN}. Run install.sh for a first-time install."
}

check_dependencies() {
    local missing=()
    command -v curl &>/dev/null || command -v wget &>/dev/null || missing+=("curl or wget")
    command -v sha256sum &>/dev/null || command -v shasum &>/dev/null || missing+=("sha256sum or shasum")
    [ ${#missing[@]} -eq 0 ] || error "Missing required tools: ${missing[*]}"
}

# Resolve the server URL: env override > the url already in agent.toml.
resolve_server_url() {
    if [ -n "${SERVER_URL:-}" ]; then
        SERVER_URL="${SERVER_URL%/}"
        return
    fi
    SERVER_URL="$(sed -n 's/^[[:space:]]*url[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n1)"
    [ -n "$SERVER_URL" ] || error "SERVER_URL could not be read from ${CONFIG_FILE}. Pass SERVER_URL=... explicitly."
    SERVER_URL="${SERVER_URL%/}"
    step "Server URL from config: ${SERVER_URL}"
}

# ─── OS / Architecture detection ─────────────────────────────────────────────
detect_platform() {
    case "$(uname -s)" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *) error "Unsupported operating system: $(uname -s). Supported: Linux, macOS." ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $(uname -m)." ;;
    esac
    info "Platform detected: ${OS}/${ARCH}"
}

# ─── Download helper ─────────────────────────────────────────────────────────
http_get() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        local opts=("${CURL_OPTS[@]}")
        [ "${SKIP_VERIFY:-0}" = "1" ] && { opts+=(-k); warn "TLS verification disabled (SKIP_VERIFY=1)"; }
        curl "${opts[@]}" -o "$dest" "$url"
    else
        local opts=("${WGET_OPTS[@]}")
        [ "${SKIP_VERIFY:-0}" = "1" ] && opts+=(--no-check-certificate)
        wget "${opts[@]}" -O "$dest" "$url"
    fi
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Download one binary via the server API and verify its SHA-256.
# The checksum endpoint returns JSON: {"...","checksum":"<hex>"}; extract without jq.
download_binary() {
    local binary="$1"   # agent | watchdog
    local dest="$2"

    local url="${SERVER_URL}/api/v1/agents/download?platform=${OS}&arch=${ARCH}&binary=${binary}"
    local sum_url="${SERVER_URL}/api/v1/agents/download/checksum?platform=${OS}&arch=${ARCH}&binary=${binary}"

    step "Downloading edr-${binary} (${OS}/${ARCH})"
    http_get "$url" "$dest" || error "Failed to download edr-${binary}. Check that SERVER_URL is reachable."

    local sum_json expected actual
    sum_json="$(mktemp "${TMP_DIR}/sum.XXXXXX")"
    http_get "$sum_url" "$sum_json" || error "Failed to download checksum for edr-${binary}."
    expected="$(sed -n 's/.*"checksum"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$sum_json" | head -n1 | tr '[:upper:]' '[:lower:]')"
    [ -n "$expected" ] || error "Checksum response malformed for edr-${binary}."

    actual="$(sha256_of "$dest" | tr '[:upper:]' '[:lower:]')"
    if [ "$expected" != "$actual" ]; then
        error "Checksum mismatch for edr-${binary}!
  Expected: ${expected}
  Got:      ${actual}
The download may be corrupted or tampered with."
    fi
    step "Checksum verified: ${actual:0:16}..."
}

# ─── Service control ─────────────────────────────────────────────────────────
stop_service() {
    if [ "$OS" = "linux" ]; then systemctl stop "$WATCHDOG_SERVICE"
    else launchctl unload "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" 2>/dev/null || true; fi
}
start_service() {
    if [ "$OS" = "linux" ]; then systemctl start "$WATCHDOG_SERVICE"
    else launchctl load -w "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"; fi
}
service_running() {
    if [ "$OS" = "linux" ]; then systemctl is-active --quiet "$WATCHDOG_SERVICE"
    else launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep -q '"PID"'; fi
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    printf "\n${BOLD}Kizashi — Agent Updater${NC}\n"
    printf "$(date -u '+%Y-%m-%d %H:%M UTC')\n"

    section "Checking prerequisites"
    check_root
    check_installed
    check_dependencies
    resolve_server_url

    section "Detecting platform"
    detect_platform

    TMP_DIR="$(mktemp -d /tmp/edr-update.XXXXXX)"

    section "Downloading new binaries"
    local tmp_agent="${TMP_DIR}/edr-agent" tmp_watchdog="${TMP_DIR}/edr-watchdog"
    download_binary "agent"    "$tmp_agent"
    download_binary "watchdog" "$tmp_watchdog"

    # Idempotent: skip the swap (and restart) if the agent is already current.
    if [ -f "$AGENT_BIN" ] && [ "$(sha256_of "$AGENT_BIN")" = "$(sha256_of "$tmp_agent")" ]; then
        info "Agent binary is already up to date — nothing to do."
        exit 0
    fi

    section "Stopping service"
    step "Stopping ${WATCHDOG_SERVICE}"
    stop_service
    sleep 2

    # Back up current binaries (and the integrity sidecar) for rollback so a
    # restored binary stays paired with its matching stored hash.
    local bak_agent="${AGENT_BIN}.bak" bak_watchdog="${WATCHDOG_BIN}.bak"
    local bak_sidecar="${SIDECAR_FILE}.bak"
    cp -f "$AGENT_BIN"    "$bak_agent"    2>/dev/null || true
    cp -f "$WATCHDOG_BIN" "$bak_watchdog" 2>/dev/null || true
    [ -f "$SIDECAR_FILE" ] && cp -f "$SIDECAR_FILE" "$bak_sidecar" 2>/dev/null || true

    section "Installing new binaries"
    if install -o root -m 755 "$tmp_agent" "$AGENT_BIN" && \
       install -o root -m 755 "$tmp_watchdog" "$WATCHDOG_BIN"; then
        step "Updated: ${AGENT_BIN}"
        step "Updated: ${WATCHDOG_BIN}"
    else
        warn "Failed to install new binaries — restoring previous."
        [ -f "$bak_agent" ]    && mv -f "$bak_agent"    "$AGENT_BIN"
        [ -f "$bak_watchdog" ] && mv -f "$bak_watchdog" "$WATCHDOG_BIN"
        start_service || true
        error "Update aborted; previous binaries restored."
    fi

    # Refresh the integrity sidecar to the new agent's hash, but only if one
    # already exists — agents predating the integrity feature have none, and the
    # agent recreates it on first run. Bare lowercase hex, no newline, 0600 to
    # match the agent's own writeHash format.
    if [ -f "$SIDECAR_FILE" ]; then
        printf '%s' "$(sha256_of "$AGENT_BIN")" > "$SIDECAR_FILE"
        chmod 600 "$SIDECAR_FILE"
        step "Refreshed integrity sidecar: ${SIDECAR_FILE}"
    fi

    section "Starting service"
    start_service

    local ok=false i=0
    while [ $i -lt 15 ]; do
        sleep 2; i=$((i + 1))
        if service_running; then ok=true; break; fi
    done

    if $ok; then
        rm -f "$bak_agent" "$bak_watchdog" "$bak_sidecar"
        info "Service is running on the new binaries."
    else
        warn "Service did not start — rolling back to previous binaries."
        stop_service || true
        sleep 1
        # Restore binary AND sidecar together so the old binary matches its hash.
        [ -f "$bak_agent" ]    && mv -f "$bak_agent"    "$AGENT_BIN"
        [ -f "$bak_watchdog" ] && mv -f "$bak_watchdog" "$WATCHDOG_BIN"
        [ -f "$bak_sidecar" ]  && mv -f "$bak_sidecar"  "$SIDECAR_FILE"
        start_service || true
        error "Rolled back to previous binaries. Investigate before retrying."
    fi

    printf "\n${BOLD}${GREEN}Update complete.${NC}\n"
    printf "  Server:  %s\n" "$SERVER_URL"
    printf "  Agent:   %s\n" "$AGENT_BIN"
    if [ "$OS" = "linux" ]; then
        printf "  Verify:  journalctl -u %s -n 30 --no-pager\n\n" "$WATCHDOG_SERVICE"
    else
        printf "  Verify:  tail -n 30 /var/log/edr/watchdog.log\n\n"
    fi
}

main "$@"
