#!/bin/sh
# Runs after the package's files are removed.
set -e

log() { printf '[edr-agent] %s\n' "$*"; }

is_removal=0
case "$1" in
    remove|purge) is_removal=1 ;;   # dpkg
    0)            is_removal=1 ;;   # rpm
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

if [ "$is_removal" = "0" ]; then
    exit 0
fi

# Logs, quarantined files and the local event spool are deliberately left in
# place. They are forensic material, and the most common reason an EDR agent is
# being removed from a host in a hurry is that something happened on it —
# deleting the evidence as a side effect of `apt remove` would be the wrong
# default. The `edr` service account is left too: it owns those files.
if [ "$1" = "purge" ]; then
    # purge is the explicit "I want it all gone" request, so honour it.
    rm -rf /var/log/edr /var/lib/edr /etc/edr
    log "purged configuration, logs and data"
else
    log "logs and quarantined files kept in /var/log/edr and /var/lib/edr"
    log "remove them with: apt-get purge edr-agent   (or rm -rf those paths)"
fi

exit 0
