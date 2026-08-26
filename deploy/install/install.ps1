#Requires -Version 5.1
<#
.SYNOPSIS
    Kizashi — Agent Installer for Windows

.DESCRIPTION
    Downloads, verifies, configures, and installs the EDR agent and watchdog
    as a Windows service. Must be run as Administrator.

.PARAMETER ServerUrl
    Base URL of the EDR server (e.g. https://edr.example.com).
    Can also be set via the SERVER_URL environment variable.

.PARAMETER EnrollmentToken
    Enrollment token from the EDR dashboard.
    Can also be set via the ENROLLMENT_TOKEN environment variable.

.PARAMETER InstallDir
    Installation directory. Default: C:\ProgramData\EDRAgent

.PARAMETER LogLevel
    Agent log verbosity. Default: info

.PARAMETER SkipVerify
    Skip TLS certificate verification. NOT recommended for production.

.EXAMPLE
    # One-liner (run in an elevated PowerShell):
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12,Tls13'
    $env:SERVER_URL = 'https://edr.example.com'
    $env:ENROLLMENT_TOKEN = 'your-token-here'
    iwr https://edr.example.com/install.ps1 -UseBasicParsing | iex

.EXAMPLE
    # Manual run:
    .\install.ps1 -ServerUrl https://edr.example.com -EnrollmentToken abc123
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServerUrl       = $env:SERVER_URL,
    [string]$EnrollmentToken = $env:ENROLLMENT_TOKEN,
    [string]$InstallDir      = 'C:\ProgramData\EDRAgent',
    [string]$LogLevel        = ($env:LOG_LEVEL ?? 'info'),
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
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint svcPoint, X509Certificate cert,
        WebRequest req, int problemCode) { return true; }
}
'@
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
    Write-Warning 'TLS verification disabled (SkipVerify). Do not use in production.'
}

# ─── Service configuration ────────────────────────────────────────────────────
$ServiceName        = 'EDRWatchdog'
$ServiceDisplayName = 'Kizashi Watchdog'
$ServiceDescription = 'Kizashi Endpoint Detection and Response — watchdog supervisor for edr-agent'

# ─── Directory layout ─────────────────────────────────────────────────────────
$BinDir        = Join-Path $InstallDir 'bin'
$ConfigDir     = Join-Path $InstallDir 'config'
$LogDir        = Join-Path $InstallDir 'logs'
$DataDir       = Join-Path $InstallDir 'data'
$QuarantineDir = Join-Path $InstallDir 'quarantine'
$TmpDir        = Join-Path $env:TEMP "edr-install-$(Get-Random)"

$AgentExe    = Join-Path $BinDir 'edr-agent.exe'
$WatchdogExe = Join-Path $BinDir 'edr-watchdog.exe'
$ConfigFile  = Join-Path $InstallDir 'agent.toml'
$PidFile     = Join-Path $InstallDir 'edr-watchdog.pid'

# ─── Console helpers ─────────────────────────────────────────────────────────
function Write-Section([string]$msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan -BackgroundColor Black
}
function Write-Step([string]$msg) {
    Write-Host "    -> $msg" -ForegroundColor DarkCyan
}
function Write-Info([string]$msg) {
    Write-Host "[INFO]  $msg" -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "[WARN]  $msg" -ForegroundColor Yellow
}
function Write-Fail([string]$msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
    throw $msg
}

# ─── Cleanup on failure ───────────────────────────────────────────────────────
$CleanupActions = [System.Collections.Generic.List[scriptblock]]::new()

function Register-Cleanup([scriptblock]$action) {
    $CleanupActions.Insert(0, $action)
}

function Invoke-Cleanup {
    foreach ($action in $CleanupActions) {
        try { & $action } catch { Write-Warn "Cleanup step failed: $_" }
    }
}

# ─── Prerequisite checks ─────────────────────────────────────────────────────
function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail 'This installer must be run as Administrator. Right-click PowerShell and select "Run as Administrator".'
    }
}

function Assert-Parameters {
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        Write-Fail 'ServerUrl is required. Set -ServerUrl or $env:SERVER_URL.'
    }
    if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        Write-Fail 'EnrollmentToken is required. Set -EnrollmentToken or $env:ENROLLMENT_TOKEN.'
    }
    # Normalize: strip trailing slash
    $script:ServerUrl = $ServerUrl.TrimEnd('/')
}

# ─── Architecture detection ───────────────────────────────────────────────────
function Get-Architecture {
    $proc = (Get-CimInstance -ClassName Win32_Processor -Property Architecture |
             Select-Object -First 1).Architecture
    switch ($proc) {
        12   { return 'arm64' }   # ARM64
        9    { return 'amd64' }   # x64
        0    { return 'amd64' }   # x86 (treat as amd64; agent is 64-bit only)
        default { return 'amd64' }
    }
}

# ─── Download and SHA-256 verification ───────────────────────────────────────
function Invoke-VerifiedDownload {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$ChecksumUrl
    )

    Write-Step "Downloading: $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
    catch {
        Write-Fail "Download failed for ${Url}: $_"
    }

    Write-Step "Downloading checksum: $ChecksumUrl"
    $checksumContent = try {
        (Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing).Content
    }
    catch {
        Write-Fail "Checksum download failed for ${ChecksumUrl}: $_"
    }

    # Checksum endpoint returns JSON: {"platform":...,"arch":...,"binary":...,"checksum":"<hex>"}
    $expectedHash = try {
        ($checksumContent | ConvertFrom-Json).checksum.ToLowerInvariant()
    }
    catch {
        # Fall back to plain text format (first whitespace-delimited token)
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

# ─── Directory creation with ACLs ─────────────────────────────────────────────
function New-SecureDirectory([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    # Restrict access: SYSTEM + Administrators full control only
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($account in @('SYSTEM', 'Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

function New-AllDirectories {
    $dirs = @($InstallDir, $BinDir, $ConfigDir, $LogDir, $DataDir, $QuarantineDir)
    foreach ($dir in $dirs) {
        New-SecureDirectory $dir
        Write-Step "Created: $dir"
    }
}

# ─── Configuration file ───────────────────────────────────────────────────────
function Write-AgentConfig {
    $agentId  = [System.Guid]::NewGuid().ToString()
    $hostname = $env:COMPUTERNAME
    $now      = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'

    $config = @"
# Kizashi Agent Configuration
# Generated by install.ps1 on $now
# Do not edit manually -- changes may be overwritten by policy sync.

[agent]
id       = "$agentId"
hostname = "$hostname"

[server]
url                  = "$ServerUrl"
grpc_port            = 9090
ingestion_grpc_port  = 9091
connect_timeout_sec  = 30
# cert_pins = []  # Optional: SHA-256 SPKI pins for certificate pinning

[collection]
process_monitoring        = true
file_monitoring           = true
network_monitoring        = true
dns_monitoring            = true
registry_monitoring       = true
auth_monitoring           = true
yara_scan_on_exec         = true
event_batch_interval_ms   = 500
config_poll_interval_sec  = 300
local_buffer_size_mb      = 100
max_events_per_second     = 1000

monitored_paths    = ["C:\\Users", "C:\\Windows\\Temp", "C:\\ProgramData"]
excluded_paths     = ["C:\\Windows\\WinSxS", "C:\\Windows\\SoftwareDistribution"]
excluded_processes = []

[response]
auto_response_enabled = true

[logging]
level       = "$LogLevel"
file        = "$($LogDir.Replace('\','\\'))\\agent.log"
max_size_mb = 50
max_backups = 5

[quarantine]
dir = "$($QuarantineDir.Replace('\','\\'))"

[fim]
enabled      = true
interval_sec = 60
"@

    Write-Step "Writing config: $ConfigFile"
    $config | Set-Content -Path $ConfigFile -Encoding UTF8

    # Restrict config permissions
    $acl = Get-Acl $ConfigFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($account in @('SYSTEM', 'Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $ConfigFile -AclObject $acl

    # Store enrollment token separately for first-run enrollment
    $tokenFile = Join-Path $InstallDir 'enrollment.token'
    $EnrollmentToken | Set-Content -Path $tokenFile -Encoding ASCII -NoNewline
    $acl = Get-Acl $tokenFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($account in @('SYSTEM', 'Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $tokenFile -AclObject $acl

    Write-Step "Agent ID: $agentId"
    return $agentId
}

# ─── Windows Service ──────────────────────────────────────────────────────────
function Install-WatchdogService {
    # Remove existing service if present
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "Stopping and removing existing service: $ServiceName"
        if ($existing.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Build the service binary path — watchdog supervises the agent
    $binPath = "`"$WatchdogExe`" --agent `"$AgentExe`" --config `"$ConfigFile`" --pidfile `"$PidFile`""

    Write-Step "Creating Windows service: $ServiceName"
    New-Service `
        -Name $ServiceName `
        -DisplayName $ServiceDisplayName `
        -Description $ServiceDescription `
        -BinaryPathName $binPath `
        -StartupType Automatic `
        -ErrorAction Stop | Out-Null

    # Configure failure recovery: restart on crash (10s, 30s, 60s delays)
    & sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

    # Set service to run as LocalSystem with a delayed start
    & sc.exe config $ServiceName start= delayed-auto | Out-Null

    Register-Cleanup {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $ServiceName | Out-Null
        }
    }

    Write-Step "Starting service: $ServiceName"
    Start-Service -Name $ServiceName

    # Add Windows Defender exclusion for agent directory
    try {
        Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
        Write-Step "Added Windows Defender exclusion for: $InstallDir"
    }
    catch {
        Write-Warn "Could not add Windows Defender exclusion (non-fatal): $_"
    }
}

# ─── Service health check ─────────────────────────────────────────────────────
function Wait-ServiceRunning {
    $tries   = 0
    $maxTries = 15

    Write-Step "Waiting for service to start..."
    while ($tries -lt $maxTries) {
        Start-Sleep -Seconds 2
        $tries++
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            return $true
        }
    }
    return $false
}

# ─── Post-install summary ─────────────────────────────────────────────────────
function Write-Summary {
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║     Kizashi Agent -- Installation Complete         ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Server:    $ServerUrl"
    Write-Host "  Config:    $ConfigFile"
    Write-Host "  Logs:      $LogDir"
    Write-Host "  Service:   $ServiceName"
    Write-Host ''
    Write-Host '  Management commands:' -ForegroundColor Cyan
    Write-Host "    Status:  Get-Service $ServiceName"
    Write-Host "    Logs:    Get-Content '$LogDir\watchdog.log' -Wait -Tail 50"
    Write-Host "    Restart: Restart-Service $ServiceName"
    Write-Host "    Stop:    Stop-Service $ServiceName"
    Write-Host ''
    Write-Host "  Dashboard: $ServerUrl" -ForegroundColor Cyan
    Write-Host ''
}

# ─── Main ────────────────────────────────────────────────────────────────────
function Invoke-Install {
    Write-Host ''
    Write-Host 'Kizashi -- Agent Installer (Windows)' -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm UTC')"
    Write-Host ''

    Write-Section 'Checking prerequisites'
    Assert-Administrator
    Assert-Parameters

    $arch = Get-Architecture
    Write-Info "Platform: windows/$arch"

    Write-Section 'Creating temporary workspace'
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
    Register-Cleanup { Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Section 'Downloading binaries'
    $agentFilename    = "edr-agent-windows-${arch}.exe"
    $watchdogFilename = "edr-watchdog-windows-${arch}.exe"

    $agentUrl    = "$ServerUrl/api/v1/agents/download?platform=windows&arch=$arch"
    $watchdogUrl = "$ServerUrl/api/v1/agents/download?platform=windows&arch=$arch&binary=watchdog"

    $agentChecksumUrl    = "$ServerUrl/api/v1/agents/download/checksum?platform=windows&arch=$arch"
    $watchdogChecksumUrl = "$ServerUrl/api/v1/agents/download/checksum?platform=windows&arch=$arch&binary=watchdog"

    $tmpAgent    = Join-Path $TmpDir $agentFilename
    $tmpWatchdog = Join-Path $TmpDir $watchdogFilename

    Invoke-VerifiedDownload `
        -Url $agentUrl `
        -Destination $tmpAgent `
        -ChecksumUrl $agentChecksumUrl

    Invoke-VerifiedDownload `
        -Url $watchdogUrl `
        -Destination $tmpWatchdog `
        -ChecksumUrl $watchdogChecksumUrl

    Write-Section 'Creating directory structure'
    New-AllDirectories

    Write-Section 'Installing binaries'
    Copy-Item -Path $tmpAgent    -Destination $AgentExe    -Force
    Copy-Item -Path $tmpWatchdog -Destination $WatchdogExe -Force
    Write-Step "Installed: $AgentExe"
    Write-Step "Installed: $WatchdogExe"

    Write-Section 'Writing configuration'
    $agentId = Write-AgentConfig

    Write-Section 'Installing Windows service'
    Install-WatchdogService

    Write-Section 'Verifying service health'
    if (Wait-ServiceRunning) {
        Write-Info 'Service is running.'
    }
    else {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-Warn "Service did not reach Running state. Current status: $($svc.Status)"
        Write-Warn "Check logs at: $LogDir\watchdog.log"
    }

    # Cleanup temp files (success path — remove from undo list)
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Summary
}

# ─── Entry point ─────────────────────────────────────────────────────────────
try {
    Invoke-Install
}
catch {
    Write-Host "`n[ERROR] Installation failed: $_" -ForegroundColor Red
    Write-Host '        Rolling back partial installation...' -ForegroundColor Yellow
    Invoke-Cleanup
    exit 1
}
