#!/bin/bash
# Initial SSL certificate setup for EDR Platform
# Run this ONCE before starting the full production stack.
#
# Prerequisites:
#   1. DNS A record for ${DOMAIN} must already point to this server's public IP.
#   2. Port 80 must be reachable from the internet (temporary nginx must be up).
#   3. docker compose must be installed.
#
# Usage:
#   DOMAIN=edr.company.com EMAIL=admin@company.com bash init-ssl.sh

set -euo pipefail

DOMAIN="${DOMAIN:-edr.example.com}"
EMAIL="${EMAIL:-admin@example.com}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

info "Requesting Let's Encrypt certificate for domain: ${DOMAIN}"
info "Contact email: ${EMAIL}"

# Ensure the webroot directory exists so nginx can serve ACME challenges
mkdir -p "${DEPLOY_DIR}/certbot/www/.well-known/acme-challenge"
mkdir -p "${DEPLOY_DIR}/certbot/conf"

# Start only nginx in HTTP mode (port 80) so Certbot's webroot challenge can
# be served before the full stack is running.
info "Starting nginx for ACME challenge serving..."
docker compose \
    -f "${DEPLOY_DIR}/docker-compose.prod.yml" \
    up -d nginx

# Give nginx a moment to bind port 80
sleep 3

# Run Certbot to obtain the certificate
info "Running Certbot..."
docker compose \
    -f "${DEPLOY_DIR}/docker-compose.prod.yml" \
    run --rm certbot certonly \
        --webroot \
        --webroot-path /var/www/certbot \
        --domain "${DOMAIN}" \
        --email "${EMAIL}" \
        --agree-tos \
        --no-eff-email \
        --non-interactive

info "Certificate obtained successfully."
info "Files are in: ${DEPLOY_DIR}/certbot/conf/live/${DOMAIN}/"
echo ""
info "Next steps:"
echo "  1. Update deploy/nginx/nginx.conf — replace 'edr.example.com' with '${DOMAIN}'"
echo "  2. Start the full stack: docker compose -f deploy/docker-compose.prod.yml up -d"
echo "  3. Schedule certificate renewal: add deploy/scripts/renew-ssl.sh to cron"
echo "     Example cron entry (runs twice daily):"
echo "     0 3,15 * * * /opt/edr-platform/deploy/scripts/renew-ssl.sh >> /var/log/edr-ssl-renew.log 2>&1"
