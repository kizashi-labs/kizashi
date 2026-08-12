#!/bin/sh
set -e

CONFIG_FILE="${EDR_CONFIG_FILE:-/etc/edr/agent.toml}"

# If no config exists yet, run enrollment
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -z "$EDR_SERVER_URL" ] || [ -z "$EDR_ENROLLMENT_TOKEN" ]; then
        echo "ERROR: EDR_SERVER_URL and EDR_ENROLLMENT_TOKEN must be set for initial enrollment"
        exit 1
    fi
    echo "==> Enrolling agent with server: $EDR_SERVER_URL"
    /usr/local/bin/edr-agent \
        --enroll \
        --server "$EDR_SERVER_URL" \
        --token  "$EDR_ENROLLMENT_TOKEN" \
        --config "$CONFIG_FILE"
    echo "==> Enrollment complete"
fi

# Run agent directly (watchdog is only used for bare-metal/VM deployments)
exec /usr/local/bin/edr-agent --config "$CONFIG_FILE"
