#Requires -Version 5.1
<#
.SYNOPSIS
    Kizashi — Agent Updater for Windows

.DESCRIPTION
    In-place binary update for an already-installed EDR agent. Downloads the
    latest agent + watchdog binaries from the server, verifies their SHA-256
    checksums, swaps them under the existing installation, and restarts the
    service.

    Unlike install.ps1 this script DOES NOT regenerate the agent configuration
    or agent ID — it preserves agent.toml and enrollment.token so the endpoint
    keeps its identity in the dashboard. Use this to roll out a new agent build;
    use install.ps1 only for first-time installs.

    Must be run as Administrator. On failure the previous binaries are restored.

.PARAMETER ServerUrl
    Base URL of the EDR server (e.g. https://edr.example.com).
    Defaults to the [server].url already recorded in the installed agent.toml,
    or the SERVER_URL environment variable.

.PARAMETER InstallDir
    Installation directory. Default: C:\ProgramData\EDRAgent

.PARAMETER SkipVerify
    Skip TLS certificate verification. NOT recommended for production.

.EXAMPLE
    # Update using the server URL from the existing config (run elevated):
    .\update.ps1

.EXAMPLE
    .\update.ps1 -ServerUrl https://edr.example.com
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServerUrl  = $env:SERVER_URL,
    [string]$InstallDir = 'C:\ProgramData\EDRAgent',
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Enforce TLS 1.2+ ────────────────────────────────────────────────────────
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

if ($SkipVerify) {
    Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsUpdate : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint svcPoint, X509Certificate cert,
        WebRequest req, int problemCode) { return true; }
}
'@
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsUpdate
    Write-Warning 'TLS verification disabled (SkipVerify). Do not use in production.'
}

# ─── Layout (must match install.ps1) ─────────────────────────────────────────
$ServiceName = 'EDRWatchdog'
$BinDir      = Join-Path $InstallDir 'bin'
$ConfigFile  = Join-Path $InstallDir 'agent.toml'
$TokenFile   = Join-Path $InstallDir 'enrollment.token'
$AgentExe    = Join-Path $BinDir 'edr-agent.exe'
$WatchdogExe = Join-Path $BinDir 'edr-watchdog.exe'
# Self-integrity hash sidecar. The agent stores/reads the SHA-256 of its own
# binary at <dir-of-config>/agent.sha256 (see integrity.Check, dataDir =
# filepath.Dir(configPath)). After a binary swap this must be refreshed or the
# new binary flags itself as tampered.
$SidecarFile = Join-Path (Split-Path $ConfigFile -Parent) 'agent.sha256'
$TmpDir      = Join-Path $env:TEMP "edr-update-$(Get-Random)"

# ─── Console helpers ─────────────────────────────────────────────────────────
function Write-Section([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan -BackgroundColor Black }
function Write-Step([string]$msg)    { Write-Host "    -> $msg" -ForegroundColor DarkCyan }
function Write-Info([string]$msg)    { Write-Host "[INFO]  $msg" -ForegroundColor Green }
function Write-Warn([string]$msg)    { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg)    { Write-Host "[ERROR] $msg" -ForegroundColor Red; throw $msg }

# ─── Prerequisite checks ─────────────────────────────────────────────────────
function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail 'This updater must be run as Administrator. Right-click PowerShell and select "Run as Administrator".'
    }
}

# An update only makes sense on top of an existing install. Refuse otherwise so
# the operator runs install.ps1 (which enrolls and generates an agent ID) first.
function Assert-Installed {
    if (-not (Test-Path $ConfigFile)) {
        Write-Fail "No existing installation found at $ConfigFile. Run install.ps1 for a first-time install."
    }
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Fail "Service '$ServiceName' is not installed. Run install.ps1 for a first-time install."
    }
}

# Resolve the server URL: explicit param > env > the url already in agent.toml.
function Resolve-ServerUrl {
    if (-not [string]::IsNullOrWhiteSpace($ServerUrl)) {
        $script:ServerUrl = $ServerUrl.TrimEnd('/')
        return
    }
    $line = Select-String -Path $ConfigFile -Pattern '^\s*url\s*=\s*"([^"]+)"' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if ($line) {
        $script:ServerUrl = $line.Matches[0].Groups[1].Value.TrimEnd('/')
        Write-Step "Server URL from config: $ServerUrl"
        return
    }
    Write-Fail 'ServerUrl could not be determined. Pass -ServerUrl or set $env:SERVER_URL.'
}

# ─── Architecture detection (mirrors install.ps1) ────────────────────────────
function Get-Architecture {
    $proc = (Get-CimInstance -ClassName Win32_Processor -Property Architecture |
             Select-Object -First 1).Architecture
    switch ($proc) {
        12      { return 'arm64' }
        9       { return 'amd64' }
        0       { return 'amd64' }
        default { return 'amd64' }
    }
}

# ─── Download and SHA-256 verification (mirrors install.ps1) ──────────────────
function Invoke-VerifiedDownload {
    param([string]$Url, [string]$Destination, [string]$ChecksumUrl)

    Write-Step "Downloading: $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
    catch { Write-Fail "Download failed for ${Url}: $_" }

    Write-Step "Downloading checksum: $ChecksumUrl"
    $checksumContent = try {
        (Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing).Content
    }
    catch { Write-Fail "Checksum download failed for ${ChecksumUrl}: $_" }

    # Checksum endpoint returns JSON: {"platform":...,"checksum":"<hex>"}.
    $expectedHash = try {
        ($checksumContent | ConvertFrom-Json).checksum.ToLowerInvariant()
    }
    catch {
        ($checksumContent -split '\s+')[0].Trim().ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        Write-Fail "Checksum response is empty or malformed: $ChecksumUrl"
    }

    Write-Step "Verifying SHA-256"
    $actualHash = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Remove-Item $Destination -Force -ErrorAction SilentlyContinue
        Write-Fail "Checksum mismatch for $(Split-Path $Destination -Leaf)!`n  Expected: $expectedHash`n  Got:      $actualHash`nThe download may be corrupted or tampered with."
    }
    Write-Step "Checksum verified: $($actualHash.Substring(0,16))..."
}

# ─── Main ────────────────────────────────────────────────────────────────────
function Invoke-Update {
    Write-Host ''
    Write-Host 'Kizashi -- Agent Updater (Windows)' -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm UTC')"
    Write-Host ''

    Write-Section 'Checking prerequisites'
    Assert-Administrator
    Assert-Installed
    Resolve-ServerUrl

    $arch = Get-Architecture
    Write-Info "Platform: windows/$arch"

    Write-Section 'Downloading new binaries'
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

    $agentUrl    = "$ServerUrl/api/v1/agents/download?platform=windows&arch=$arch"
    $watchdogUrl = "$ServerUrl/api/v1/agents/download?platform=windows&arch=$arch&binary=watchdog"
    $agentSumUrl    = "$ServerUrl/api/v1/agents/download/checksum?platform=windows&arch=$arch"
    $watchdogSumUrl = "$ServerUrl/api/v1/agents/download/checksum?platform=windows&arch=$arch&binary=watchdog"

    $tmpAgent    = Join-Path $TmpDir 'edr-agent.exe'
    $tmpWatchdog = Join-Path $TmpDir 'edr-watchdog.exe'

    Invoke-VerifiedDownload -Url $agentUrl    -Destination $tmpAgent    -ChecksumUrl $agentSumUrl
    Invoke-VerifiedDownload -Url $watchdogUrl -Destination $tmpWatchdog -ChecksumUrl $watchdogSumUrl

    # Skip the swap if the running binary is already identical — keeps re-runs
    # idempotent and avoids a needless service restart.
    if ((Test-Path $AgentExe) -and
        ((Get-FileHash $AgentExe -Algorithm SHA256).Hash -eq (Get-FileHash $tmpAgent -Algorithm SHA256).Hash)) {
        Write-Info 'Agent binary is already up to date — nothing to do.'
        Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    Write-Section 'Stopping service'
    Write-Step "Stopping $ServiceName"
    Stop-Service -Name $ServiceName -Force
    # Wait for the watchdog/agent process to release the .exe before overwriting.
    Start-Sleep -Seconds 3

    # Back up current binaries (and the integrity sidecar) so a failed start can
    # roll back to a consistent binary+hash pair.
    $backupAgent    = "$AgentExe.bak"
    $backupWatchdog = "$WatchdogExe.bak"
    $backupSidecar  = "$SidecarFile.bak"
    if (Test-Path $AgentExe)     { Copy-Item $AgentExe     $backupAgent    -Force }
    if (Test-Path $WatchdogExe)  { Copy-Item $WatchdogExe  $backupWatchdog -Force }
    if (Test-Path $SidecarFile)  { Copy-Item $SidecarFile  $backupSidecar  -Force }

    try {
        Write-Section 'Installing new binaries'
        Copy-Item $tmpAgent    $AgentExe    -Force
        Copy-Item $tmpWatchdog $WatchdogExe -Force
        Write-Step "Updated: $AgentExe"
        Write-Step "Updated: $WatchdogExe"

        # Refresh the integrity sidecar to the new agent's hash *only if it
        # already exists* — agents that pre-date the integrity feature have none,
        # and the agent recreates it on first run. Written as bare lowercase hex
        # with no trailing newline to match the agent's own format.
        if (Test-Path $SidecarFile) {
            $newHash = (Get-FileHash $AgentExe -Algorithm SHA256).Hash.ToLower()
            [System.IO.File]::WriteAllText($SidecarFile, $newHash)
            Write-Step "Refreshed integrity sidecar: $SidecarFile"
        }

        Write-Section 'Starting service'
        Start-Service -Name $ServiceName

        # Health check
        $ok = $false
        for ($i = 0; $i -lt 15; $i++) {
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') { $ok = $true; break }
        }
        if (-not $ok) { Write-Fail "Service did not reach Running state after update." }
        Write-Info 'Service is running on the new binaries.'
    }
    catch {
        Write-Warn "Update failed: $_"
        Write-Warn 'Rolling back to the previous binaries...'
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        # Restore binary AND sidecar together so the rolled-back binary matches
        # its stored hash (otherwise the old binary would flag itself tampered).
        if (Test-Path $backupAgent)    { Copy-Item $backupAgent    $AgentExe    -Force }
        if (Test-Path $backupWatchdog) { Copy-Item $backupWatchdog $WatchdogExe -Force }
        if (Test-Path $backupSidecar)  { Copy-Item $backupSidecar  $SidecarFile -Force }
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-Fail 'Rolled back to previous binaries. Investigate before retrying.'
    }
    finally {
        Remove-Item $backupAgent, $backupWatchdog, $backupSidecar -Force -ErrorAction SilentlyContinue
        Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║     Kizashi Agent -- Update Complete               ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Server:   $ServerUrl"
    Write-Host "  Agent:    $AgentExe"
    Write-Host "  Service:  $ServiceName"
    Write-Host ''
    Write-Host ("  Verify:   Get-Content '{0}\logs\agent.log' -Tail 30" -f $InstallDir)
    Write-Host ''
}

# ─── Entry point ─────────────────────────────────────────────────────────────
try {
    Invoke-Update
}
catch {
    Write-Host "`n[ERROR] Update failed: $_" -ForegroundColor Red
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}
