#!/bin/sh
# Runs before the package's files are removed — and, on both dpkg and rpm, also
# before the old version's files are removed during an UPGRADE. Everything here
# has to distinguish the two.
set -e

CONFIG_DIR=/etc/edr
CONFIG_FILE="${CONFIG_DIR}/agent.toml"
AGENT_BIN=/usr/local/bin/edr-agent
SERVICE=edr-watchdog

log() { printf '[edr-agent] %s\n' "$*"; }

# dpkg passes "upgrade"/"remove"; rpm passes a count ("1" = upgrade, "0" = final
# removal). Treat anything that is not a definite removal as an upgrade, because
# stopping the service or prompting for a password mid-upgrade is worse than
# skipping a check that the surviving install still enforces.
is_removal=0
case "$1" in
    remove|purge) is_removal=1 ;;   # dpkg
    0)            is_removal=1 ;;   # rpm: no versions will remain
esac

if [ "$is_removal" = "0" ]; then
    exit 0
fi

# ─── Uninstall protection ────────────────────────────────────────────────────
# The agent refuses removal without the tenant's uninstall password. Enforcing
# it only in uninstall.sh would leave `apt remove edr-agent` as a way around it,
# which on a fleet managed by apt is not an edge case — it is the normal path.
#
# The capability probe matters: this script also runs when removing a package
# built before -verify-uninstall existed, and an unknown flag must not brick the
# removal of an agent that never had protection to begin with.
if [ -x "$AGENT_BIN" ] && "$AGENT_BIN" -help 2>&1 | grep -q -- '-verify-uninstall'; then
    if "$AGENT_BIN" -config "$CONFIG_FILE" -verify-uninstall; then
        :
    else
        rc=$?
        log ""
        log "アンインストールを拒否しました (exit ${rc})。"
        log "この端末は EDR 管理コンソールで設定されたパスワードで保護されています。"
        log "管理者からパスワードを受け取り、次のように実行してください:"
        log ""
        log "  sudo EDR_UNINSTALL_PASSWORD='<password>' apt-get remove edr-agent"
        log "  sudo EDR_UNINSTALL_PASSWORD='<password>' yum remove edr-agent"
        log ""
        # Non-zero aborts the removal on both dpkg and rpm.
        exit "$rc"
    fi
fi

# ─── Stop the service ────────────────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE"    >/dev/null 2>&1 || true
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
fi

exit 0
