#!/bin/sh
# Runs after the .deb/.rpm is unpacked, on both first install and upgrade.
#
# POSIX sh, not bash: RPM-based minimal images do not always ship bash, and a
# postinstall that fails leaves the package half-configured.
set -e

CONFIG_DIR=/etc/edr
CONFIG_FILE="${CONFIG_DIR}/agent.toml"
ENROLL_ENV="${CONFIG_DIR}/enroll.env"
AGENT_USER=edr
AGENT_GROUP=edr
SERVICE=edr-watchdog

log() { printf '[edr-agent] %s\n' "$*"; }

# ─── Service account ─────────────────────────────────────────────────────────
# The systemd unit runs as User=edr, so the account must exist before the
# service starts. Created as a system account with no login shell and no home.
if ! getent group "$AGENT_GROUP" >/dev/null 2>&1; then
    groupadd --system "$AGENT_GROUP"
fi
if ! getent passwd "$AGENT_USER" >/dev/null 2>&1; then
    useradd --system --gid "$AGENT_GROUP" --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Kizashi agent" "$AGENT_USER"
fi

# Created here rather than shipped as package content on purpose: a directory
# the package manager owns is one it deletes on removal once empty, which would
# contradict postremove's promise to preserve logs and quarantined files.
mkdir -p /var/log/edr /var/lib/edr
chmod 0750 /var/log/edr /var/lib/edr 2>/dev/null || true
chown -R "${AGENT_USER}:${AGENT_GROUP}" /var/log/edr /var/lib/edr 2>/dev/null || true

# ─── First-run configuration ─────────────────────────────────────────────────
# Only fills in blanks. On upgrade the file already carries a real agent ID, and
# regenerating it would re-enroll the endpoint under a new identity and orphan
# every alert, incident and timeline entry attached to the old one.
needs_config=0
grep -q '^id[[:space:]]*=[[:space:]]*""' "$CONFIG_FILE" 2>/dev/null && needs_config=1

if [ "$needs_config" = "1" ]; then
    # Agent ID: a stable UUID for this host.
    if command -v uuidgen >/dev/null 2>&1; then
        agent_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    elif [ -r /proc/sys/kernel/random/uuid ]; then
        agent_id="$(cat /proc/sys/kernel/random/uuid)"
    else
        log "cannot generate an agent ID (no uuidgen, no /proc/sys/kernel/random/uuid)"
        exit 1
    fi
    host="$(hostname -f 2>/dev/null || hostname)"

    server_url=""
    if [ -r "$ENROLL_ENV" ]; then
        # shellcheck disable=SC1090
        . "$ENROLL_ENV"
        server_url="${SERVER_URL:-}"
    fi

    # sed in place on the shipped placeholder. Anchored to the exact empty-value
    # lines so a hand-edited file (which would not reach here anyway) is safe.
    sed -i \
        -e "s|^id[[:space:]]*=[[:space:]]*\"\"|id       = \"${agent_id}\"|" \
        -e "s|^hostname[[:space:]]*=[[:space:]]*\"\"|hostname = \"${host}\"|" \
        "$CONFIG_FILE"

    if [ -n "$server_url" ]; then
        sed -i "s|^url[[:space:]]*=[[:space:]]*\"\"|url                  = \"${server_url}\"|" \
            "$CONFIG_FILE"
        log "configured for ${server_url} (agent id ${agent_id})"
    else
        log "no SERVER_URL found in ${ENROLL_ENV}"
        log "the agent is installed but will NOT be started."
        log "set SERVER_URL in ${ENROLL_ENV} and run: systemctl enable --now ${SERVICE}"
    fi

    chown root:"$AGENT_GROUP" "$CONFIG_FILE" 2>/dev/null || true
    chmod 0640 "$CONFIG_FILE" 2>/dev/null || true
fi

# ─── Service ─────────────────────────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true

    # Start only when there is a server to talk to. Starting an agent with an
    # empty URL produces a service that is "active" while connecting to nothing
    # — the failure mode most likely to be mistaken for a working install.
    if grep -q '^url[[:space:]]*=[[:space:]]*""' "$CONFIG_FILE" 2>/dev/null; then
        log "leaving ${SERVICE} stopped until a server URL is configured"
    else
        systemctl enable "$SERVICE" >/dev/null 2>&1 || true
        # restart, not start: on upgrade the old binary is still running.
        systemctl restart "$SERVICE" || {
            log "failed to start ${SERVICE}; check: journalctl -u ${SERVICE} -n 50"
        }
    fi
else
    log "systemd not detected; start the watchdog manually:"
    log "  /usr/local/bin/edr-watchdog --agent /usr/local/bin/edr-agent --config ${CONFIG_FILE}"
fi

exit 0
