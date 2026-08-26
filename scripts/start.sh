#!/bin/bash
# EDR Platform startup script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Starting EDR Platform..."

# Check for .env file
if [ ! -f "$ROOT_DIR/.env" ]; then
    echo "Creating .env from .env.example..."
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    echo "WARNING: Please update .env with your configuration before running in production!"
fi

cd "$ROOT_DIR"

# Pull latest images
echo "Pulling infrastructure images..."
docker compose pull postgres nats 2>/dev/null || true

# Build application images
echo "Building application images..."
docker compose build --parallel

# Start all services
echo "Starting services..."
docker compose up -d

# Wait for health checks
echo "Waiting for services to be healthy..."
timeout=120
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if docker compose ps | grep -q "unhealthy\|starting"; then
        sleep 5
        elapsed=$((elapsed + 5))
        echo "   Waiting... ($elapsed/${timeout}s)"
    else
        break
    fi
done

echo ""
echo "EDR Platform is running!"
echo ""
echo "  Frontend:    http://localhost:${FRONTEND_PORT:-3000}"
echo "  API:         http://localhost:${API_PORT:-8080}"
echo "  API Health:  http://localhost:${API_PORT:-8080}/healthz"
echo "  NATS:        nats://localhost:${NATS_PORT:-4222}"
echo ""
echo "To stop: docker compose down"
echo "To view logs: docker compose logs -f"
