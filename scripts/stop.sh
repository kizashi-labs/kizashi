#!/bin/bash
echo "Stopping EDR Platform..."
cd "$(dirname "${BASH_SOURCE[0]}")/.."
docker compose down
echo "All services stopped."
