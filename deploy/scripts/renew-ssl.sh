#!/bin/bash
# SSL certificate renewal for EDR Platform
# Certbot renews certificates that are within 30 days of expiry; it exits 0
# with no action taken if renewal is not yet due — safe to run frequently.
#
# Recommended cron schedule (twice daily):
#   0 3,15 * * * /opt/edr-platform/deploy/scripts/renew-ssl.sh >> /var/log/edr-ssl-renew.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${RED}[ERROR]${NC} $*"; exit 1; }

info "Starting certificate renewal check..."

# Attempt renewal (no-op if not due)
docker compose \
    -f "${DEPLOY_DIR}/docker-compose.prod.yml" \
    run --rm certbot renew \
        --webroot \
        --webroot-path /var/www/certbot \
        --quiet \
        --non-interactive

RENEW_EXIT=$?

if [[ $RENEW_EXIT -ne 0 ]]; then
    error "Certbot renewal exited with code ${RENEW_EXIT}. Check output above."
fi

# Reload nginx to pick up any newly issued certificate without downtime.
# docker compose exec returns non-zero if the container is not running.
if docker compose \
        -f "${DEPLOY_DIR}/docker-compose.prod.yml" \
        ps --quiet nginx | grep -q .; then
    info "Reloading nginx to apply renewed certificate..."
    docker compose \
        -f "${DEPLOY_DIR}/docker-compose.prod.yml" \
        exec nginx nginx -s reload
    info "nginx reloaded successfully."
else
    warn "nginx container is not running — skipping reload."
fi

info "Certificate renewal check complete."
