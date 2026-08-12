#!/usr/bin/env bash
# EDR Agent Linux Uninstaller
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: このスクリプトはrootで実行する必要があります"
    exit 1
fi

echo "==> EDRエージェントをアンインストールします"

# Stop and disable service
if systemctl is-active --quiet edr-watchdog 2>/dev/null; then
    systemctl stop edr-watchdog
fi
systemctl disable edr-watchdog 2>/dev/null || true
rm -f /etc/systemd/system/edr-watchdog.service
systemctl daemon-reload

# Remove binaries
rm -f /usr/local/bin/edr-agent
rm -f /usr/local/bin/edr-watchdog

# Remove config (keep logs by default)
echo "==> 設定ファイルを削除します"
rm -rf /etc/edr

# Remove service user
if id edr &>/dev/null; then
    userdel edr 2>/dev/null || true
fi

echo "==> アンインストール完了"
echo "    ログは /var/log/edr に残っています (手動削除: rm -rf /var/log/edr)"
