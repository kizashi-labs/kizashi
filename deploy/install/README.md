# Kizashi Agent — Installation Guide

This directory contains production-ready installer scripts for the Kizashi
agent and watchdog on Linux, macOS, and Windows.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Quick Install — One-Liners](#quick-install--one-liners)
4. [Manual Installation](#manual-installation)
5. [Configuration Reference](#configuration-reference)
6. [Updating an Existing Agent](#updating-an-existing-agent)
7. [Uninstalling](#uninstalling)
8. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

The installer deploys two binaries:

| Binary | Role |
|---|---|
| `edr-agent` | Core sensor: process, file, network, DNS, and registry monitoring |
| `edr-watchdog` | Supervisor: the OS service manager starts *watchdog*, which in turn starts and monitors *edr-agent* |

The watchdog provides automatic binary rollback if an update causes a crash
within 60 seconds of start.

**Install layout (Linux / macOS)**

```
/usr/local/bin/edr-agent          # agent binary
/usr/local/bin/edr-watchdog       # watchdog binary
/etc/edr/agent.toml               # configuration
/etc/edr/enrollment.token         # enrollment token (first-run only)
/var/log/edr/                     # watchdog.log + agent.log
/var/lib/edr/quarantine/          # quarantined threat files
```

**Install layout (Windows)**

```
C:\ProgramData\EDRAgent\
  bin\edr-agent.exe
  bin\edr-watchdog.exe
  agent.toml
  enrollment.token
  logs\
  data\
  quarantine\
```

---

## Prerequisites

### Linux

| Requirement | Notes |
|---|---|
| Root / sudo | Required for service installation |
| `curl` or `wget` | For binary download |
| `sha256sum` | For checksum verification (included in most distros) |
| `systemd` | Service management (RHEL 7+, Debian 8+, Ubuntu 15.04+) |
| Kernel 4.15+ | For eBPF-based process and network monitoring |
| `useradd` / `groupadd` | For creating the `edr` service account |

Supported distributions: Debian/Ubuntu, RHEL/CentOS/Rocky, Alpine, Arch Linux.

### macOS

| Requirement | Notes |
|---|---|
| Root / sudo | Required |
| macOS 12 (Monterey)+ | Recommended; 11 (Big Sur) minimum |
| `curl` | Pre-installed on all macOS versions |
| `shasum` | Pre-installed (used in place of sha256sum) |
| `launchd` | Pre-installed; manages the daemon |
| System Extensions approval | May be required for kernel-level monitoring |

### Windows

| Requirement | Notes |
|---|---|
| Windows 10 / Server 2016+ | 64-bit required |
| Administrator privileges | For service installation |
| PowerShell 5.1+ | Pre-installed on Windows 10 / Server 2016+ |
| TLS 1.2 connectivity | Outbound HTTPS to the EDR server |
| Windows Defender / AV exclusion | Configured automatically by the installer |

---

## Quick Install — One-Liners

Replace `https://your-server` with your actual EDR server URL and supply your
enrollment token from the dashboard (**Settings → Deployments → Tokens**).

### Linux / macOS

```bash
curl -fsSL https://your-server/install.sh \
  | ENROLLMENT_TOKEN=your-token-here SERVER_URL=https://your-server bash
```

#### Optional environment variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_URL` | (required) | Base URL of your EDR server |
| `ENROLLMENT_TOKEN` | (required) | Token from the EDR dashboard |
| `LOG_LEVEL` | `info` | Agent log verbosity: `debug`, `info`, `warn`, `error` |
| `INSTALL_TIMEOUT` | `120` | Binary download timeout in seconds |
| `SKIP_VERIFY` | `0` | Set to `1` to disable TLS verification (not for production) |

### Windows (PowerShell — run as Administrator)

```powershell
# Force TLS 1.2/1.3 and run the installer
[Net.ServicePointManager]::SecurityProtocol = 'Tls12,Tls13'
$env:SERVER_URL = 'https://your-server'
$env:ENROLLMENT_TOKEN = 'your-token-here'
iwr https://your-server/install.ps1 -UseBasicParsing | iex
```

Or if you prefer named parameters over environment variables:

```powershell
.\install.ps1 -ServerUrl https://your-server -EnrollmentToken your-token-here
```

#### Optional parameters (PowerShell)

| Parameter | Default | Description |
|---|---|---|
| `-ServerUrl` | (required) | EDR server base URL |
| `-EnrollmentToken` | (required) | Dashboard enrollment token |
| `-InstallDir` | `C:\ProgramData\EDRAgent` | Installation directory |
| `-LogLevel` | `info` | Agent log verbosity |
| `-SkipVerify` | (off) | Disable TLS certificate verification |

---

## Manual Installation

Use this if you cannot run the one-liner (e.g., air-gapped environments).

### Linux — Manual Steps

**1. Download binaries**

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
SERVER=https://your-server
DL="${SERVER}/api/v1/agents/download"

curl -fsSL -o /tmp/edr-agent    "${DL}?platform=linux&arch=${ARCH}&binary=agent"
curl -fsSL -o /tmp/edr-watchdog "${DL}?platform=linux&arch=${ARCH}&binary=watchdog"
# Checksums are returned as JSON: {"...","checksum":"<hex>"}
curl -fsSL "${DL}/checksum?platform=linux&arch=${ARCH}&binary=agent"
curl -fsSL "${DL}/checksum?platform=linux&arch=${ARCH}&binary=watchdog"
```

**2. Verify checksums**

```bash
# Compare the local SHA-256 against the "checksum" value returned above
sha256sum /tmp/edr-agent /tmp/edr-watchdog
```

**3. Install binaries**

```bash
sudo install -o root -m 755 /tmp/edr-agent    /usr/local/bin/edr-agent
sudo install -o root -m 755 /tmp/edr-watchdog /usr/local/bin/edr-watchdog
```

**4. Create system user and directories**

```bash
sudo groupadd --system edr
sudo useradd --system --gid edr --no-create-home --shell /sbin/nologin edr

sudo mkdir -p /etc/edr /var/log/edr /var/lib/edr/quarantine
sudo chown root:edr /etc/edr && sudo chmod 750 /etc/edr
sudo chown edr:edr /var/log/edr /var/lib/edr/quarantine
```

**5. Write `/etc/edr/agent.toml`**

```toml
[agent]
id       = "generate-a-uuid-here"
hostname = "your-hostname"

[server]
url                 = "https://your-server"
grpc_port           = 9090
ingestion_grpc_port = 9091
connect_timeout_sec = 30

[collection]
process_monitoring       = true
file_monitoring          = true
network_monitoring       = true
dns_monitoring           = true
auth_monitoring          = true
yara_scan_on_exec        = true
event_batch_interval_ms  = 500
config_poll_interval_sec = 300
local_buffer_size_mb     = 100
max_events_per_second    = 1000
monitored_paths          = ["/"]
excluded_paths           = ["/proc", "/sys", "/dev", "/run"]

[response]
auto_response_enabled = true

[logging]
level       = "info"
file        = "/var/log/edr/agent.log"
max_size_mb = 50
max_backups = 5

[quarantine]
dir = "/var/lib/edr/quarantine"

[fim]
enabled      = true
interval_sec = 60
```

```bash
sudo chmod 640 /etc/edr/agent.toml
sudo chown root:edr /etc/edr/agent.toml
```

**6. Store enrollment token**

```bash
echo -n 'your-token-here' | sudo tee /etc/edr/enrollment.token > /dev/null
sudo chmod 600 /etc/edr/enrollment.token
sudo chown root:edr /etc/edr/enrollment.token
```

**7. Install systemd unit**

```bash
sudo tee /etc/systemd/system/edr-watchdog.service > /dev/null <<'EOF'
[Unit]
Description=Kizashi Watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr-watchdog \
    --agent /usr/local/bin/edr-agent \
    --config /etc/edr/agent.toml \
    --pidfile /var/run/edr-watchdog.pid
Restart=on-failure
RestartSec=10s
StandardOutput=append:/var/log/edr/watchdog.log
StandardError=append:/var/log/edr/watchdog.log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now edr-watchdog
```

---

### macOS — Manual Steps

Steps 1–4 are the same as Linux (substituting `shasum -a 256` for `sha256sum`
and omitting `useradd`). Skip user creation; the daemon runs as root.

**Install the launchd daemon**

```bash
sudo tee /Library/LaunchDaemons/com.kizashi.edr.plist > /dev/null <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.kizashi.edr</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/edr-watchdog</string>
        <string>--agent</string>    <string>/usr/local/bin/edr-agent</string>
        <string>--config</string>   <string>/etc/edr/agent.toml</string>
        <string>--pidfile</string>  <string>/var/run/edr-watchdog.pid</string>
    </array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/var/log/edr/watchdog.log</string>
    <key>StandardErrorPath</key> <string>/var/log/edr/watchdog.log</string>
</dict>
</plist>
EOF

sudo chown root:wheel /Library/LaunchDaemons/com.kizashi.edr.plist
sudo chmod 644 /Library/LaunchDaemons/com.kizashi.edr.plist
sudo launchctl load -w /Library/LaunchDaemons/com.kizashi.edr.plist
```

---

### Windows — Manual Steps

**1. Open an Administrator PowerShell**

**2. Create directories**

```powershell
$dirs = 'C:\ProgramData\EDRAgent',
        'C:\ProgramData\EDRAgent\bin',
        'C:\ProgramData\EDRAgent\logs',
        'C:\ProgramData\EDRAgent\data',
        'C:\ProgramData\EDRAgent\quarantine'
$dirs | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force }
```

**3. Download and verify binaries**

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12,Tls13'
$dl = 'https://your-server/api/v1/agents/download'

Invoke-WebRequest "$dl?platform=windows&arch=amd64&binary=agent"    -OutFile 'C:\ProgramData\EDRAgent\bin\edr-agent.exe'    -UseBasicParsing
Invoke-WebRequest "$dl?platform=windows&arch=amd64&binary=watchdog" -OutFile 'C:\ProgramData\EDRAgent\bin\edr-watchdog.exe' -UseBasicParsing

# Verify: compare against the server checksum (returned as JSON {"checksum":"<hex>"})
$exp = ((Invoke-WebRequest "$dl/checksum?platform=windows&arch=amd64&binary=agent" -UseBasicParsing).Content | ConvertFrom-Json).checksum
$act = (Get-FileHash 'C:\ProgramData\EDRAgent\bin\edr-agent.exe' -Algorithm SHA256).Hash
if ($act -ne $exp) { throw "checksum mismatch" }
```

**4. Write `C:\ProgramData\EDRAgent\agent.toml`** (see Linux step 5 for content, adjusting paths).

**5. Install the service**

```powershell
New-Service `
  -Name 'EDRWatchdog' `
  -DisplayName 'Kizashi Watchdog' `
  -BinaryPathName '"C:\ProgramData\EDRAgent\bin\edr-watchdog.exe" --agent "C:\ProgramData\EDRAgent\bin\edr-agent.exe" --config "C:\ProgramData\EDRAgent\agent.toml" --pidfile "C:\ProgramData\EDRAgent\edr-watchdog.pid"' `
  -StartupType Automatic

sc.exe failure EDRWatchdog reset= 86400 actions= restart/10000/restart/30000/restart/60000
Start-Service EDRWatchdog
```

---

## Configuration Reference

The full configuration schema is defined in `agent/internal/config/config.go`.
Key sections:

```toml
[agent]
id       = "<uuid>"          # Unique agent identifier (auto-generated by installer)
hostname = "<hostname>"      # Reported hostname

[server]
url                  = "https://edr.example.com"
grpc_port            = 9090   # Command & control gRPC port
ingestion_grpc_port  = 9091   # Event ingestion gRPC port
connect_timeout_sec  = 30
# cert_pins = ["base64-sha256-spki-fingerprint"]  # Optional pinning

[collection]
process_monitoring        = true
file_monitoring           = true
network_monitoring        = true
dns_monitoring            = true
registry_monitoring       = true   # Windows only
auth_monitoring           = true
yara_scan_on_exec         = true
max_events_per_second     = 1000   # Rate limit to protect endpoint performance

[response]
auto_response_enabled = true       # Allow server-initiated response actions

[fim]
enabled      = true   # File Integrity Monitoring
interval_sec = 60
```

Policy settings pushed from the server take precedence over local config for
collection settings (monitored paths, exclusions, response enablement).

---

## Updating an Existing Agent

Use `update.ps1` / `update.sh` to roll out a **new agent build** to a machine
that is *already enrolled*. The updater downloads the latest `edr-agent` and
`edr-watchdog` binaries (SHA-256 verified), swaps them under the existing
installation, and restarts the service.

> **Do not re-run `install.ps1` / `install.sh` to update.** The installers
> generate a fresh agent ID and rewrite `agent.toml`, which re-enrolls the
> machine as a **duplicate endpoint** in the dashboard. The updater preserves
> `agent.toml` and `enrollment.token`, so the endpoint keeps its identity.

Behaviour:

- Refuses to run if no existing install is found (run the installer first).
- Reads the server URL from the installed `agent.toml` (override with
  `SERVER_URL` / `-ServerUrl`).
- Skips the swap and restart if the running binary is already current
  (idempotent — safe to run from a scheduler or fleet tool).
- Backs up the previous binaries and **rolls back automatically** if the
  service fails to come back up.
- Refreshes the binary self-integrity hash sidecar (`<config-dir>/agent.sha256`)
  to the new binary, so the agent does not flag itself as tampered after the
  swap. Only touched if it already exists; agents that predate the integrity
  feature recreate it on first run. Rolled back together with the binary.
- Pulls binaries from the agent download API
  (`/api/v1/agents/download`), which always serves the build baked into the
  currently deployed server image.

### Linux / macOS

```bash
# Server URL is read from /etc/edr/agent.toml
sudo ./update.sh

# Or override the server URL
sudo SERVER_URL=https://your-server ./update.sh
```

### Windows (PowerShell — run as Administrator)

```powershell
# Server URL is read from the installed agent.toml
.\update.ps1

# Or override the server URL
.\update.ps1 -ServerUrl https://your-server
```

| Variable / Parameter | Default | Description |
|---|---|---|
| `SERVER_URL` / `-ServerUrl` | (from `agent.toml`) | EDR server base URL |
| `INSTALL_TIMEOUT` (sh) | `120` | Download timeout in seconds |
| `-InstallDir` (ps1) | `C:\ProgramData\EDRAgent` | Installation directory |
| `SKIP_VERIFY` / `-SkipVerify` | off | Disable TLS verification (not for production) |

> **Note:** existing agents do not auto-update. Run the updater on each endpoint
> (e.g. via your configuration-management / RMM tool) after a new server image
> is deployed.

---

## Uninstalling

### Linux / macOS

```bash
# Remove service and binaries; preserve logs and data
sudo ./uninstall.sh

# Full removal including logs and quarantine data
sudo ./uninstall.sh --purge

# Non-interactive (for automation)
sudo ./uninstall.sh --yes
sudo ./uninstall.sh --purge --yes
```

### Windows (PowerShell — run as Administrator)

```powershell
# Remove service and binaries; preserve logs and quarantine data
.\uninstall.ps1

# Full removal including logs and quarantine data
.\uninstall.ps1 -Purge

# Non-interactive
.\uninstall.ps1 -Yes
.\uninstall.ps1 -Purge -Yes
```

---

## Troubleshooting

### Linux

**Check service status**

```bash
systemctl status edr-watchdog
journalctl -u edr-watchdog -n 100 --no-pager
```

**Check agent logs**

```bash
tail -f /var/log/edr/watchdog.log
tail -f /var/log/edr/agent.log
```

**Service starts then immediately stops**

```bash
# Run the watchdog manually to see the error:
sudo /usr/local/bin/edr-watchdog \
  --agent /usr/local/bin/edr-agent \
  --config /etc/edr/agent.toml
```

Common causes:
- Invalid TOML syntax in `agent.toml` — validate with `toml --check /etc/edr/agent.toml`
- `agent.id` is empty — must be a non-empty UUID string
- `server.url` is empty or unreachable

**Agent cannot connect to the server**

```bash
# Test connectivity:
curl -v https://your-server/healthz
```

**eBPF errors on older kernels (Linux)**

The agent requires kernel 4.15+ for eBPF monitoring. On older kernels, eBPF
collectors will fall back to `/proc` polling. Check logs for `ebpf` entries.

**Permission errors**

```bash
# Verify binary is executable:
ls -la /usr/local/bin/edr-agent /usr/local/bin/edr-watchdog

# Verify config is readable by root:
sudo cat /etc/edr/agent.toml
```

---

### macOS

**Check daemon status**

```bash
sudo launchctl list com.kizashi.edr
tail -f /var/log/edr/watchdog.log
```

**Daemon exits immediately**

```bash
# Run manually with verbose output:
sudo /usr/local/bin/edr-watchdog \
  --agent /usr/local/bin/edr-agent \
  --config /etc/edr/agent.toml
```

**System Extension / Privacy approval**

On macOS 12+, the agent may require approval in:
**System Preferences → Privacy & Security → Full Disk Access / Developer Tools**

Check Console.app for messages from `edr-agent` if monitoring appears limited.

**Restart the daemon**

```bash
sudo launchctl kickstart -k system/com.kizashi.edr
```

---

### Windows

**Check service status**

```powershell
Get-Service EDRWatchdog
Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 20 |
  Where-Object { $_.Message -match 'EDR' }
```

**Check agent logs**

```powershell
Get-Content 'C:\ProgramData\EDRAgent\logs\watchdog.log' -Tail 50 -Wait
Get-Content 'C:\ProgramData\EDRAgent\logs\agent.log'    -Tail 50 -Wait
```

**Service fails to start**

```powershell
# Run the watchdog manually in a console window to see output:
& 'C:\ProgramData\EDRAgent\bin\edr-watchdog.exe' `
    --agent    'C:\ProgramData\EDRAgent\bin\edr-agent.exe' `
    --config   'C:\ProgramData\EDRAgent\agent.toml' `
    --pidfile  'C:\ProgramData\EDRAgent\edr-watchdog.pid'
```

**Windows Defender / AV interference**

The installer adds `C:\ProgramData\EDRAgent` to the Defender exclusion list
automatically. If a third-party AV removes the binaries, add the directory to
its exclusion list manually, then reinstall.

**PowerShell execution policy**

If `iex` is blocked by the execution policy, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

**TLS errors on Windows Server 2016**

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

---

### Common issues across all platforms

| Symptom | Likely cause | Fix |
|---|---|---|
| Checksum mismatch | Corrupted download or proxy interference | Check network path; retry |
| `agent.id` must be set | Empty or missing `[agent] id` in config | Installer generates this automatically; do not delete it |
| Server connection refused | Firewall blocking port 9090/9091 | Allow outbound TCP 9090 and 9091 to the EDR server |
| Binary not found | Incomplete installation | Re-run the installer |
| Enrollment token expired | Token TTL exceeded | Generate a new token in the dashboard |

---

## Support

- Dashboard: your EDR server URL
- Documentation: `https://your-server/docs`
- Logs: `/var/log/edr/` (Linux/macOS) or `C:\ProgramData\EDRAgent\logs\` (Windows)
