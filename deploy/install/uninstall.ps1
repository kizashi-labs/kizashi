#Requires -Version 5.1
<#
.SYNOPSIS
    Kizashi — Agent Uninstaller for Windows

.DESCRIPTION
    Stops and removes the EDR watchdog service, binaries, and configuration.
    By default, logs and quarantine data are preserved for forensic purposes.
    Use -Purge to remove all files.

.PARAMETER InstallDir
    Installation directory. Default: C:\ProgramData\EDRAgent

.PARAMETER Purge
    Remove ALL files including logs and quarantined threats (irreversible).

.PARAMETER Yes
    Skip the confirmation prompt (non-interactive / scripted uninstall).

.EXAMPLE
    # Interactive:
    .\uninstall.ps1

.EXAMPLE
    # Silent full removal:
    .\uninstall.ps1 -Purge -Yes

.EXAMPLE
    # Non-interactive, preserve logs:
    .\uninstall.ps1 -Yes
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallDir  = 'C:\ProgramData\EDRAgent',
    [switch]$Purge,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Console helpers ─────────────────────────────────────────────────────────
function Write-Section([string]$msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
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

# ─── Service names / paths ────────────────────────────────────────────────────
$ServiceName    = 'EDRWatchdog'
$LegacyService  = 'EDRAgent'           # previous service name, if any

$BinDir         = Join-Path $InstallDir 'bin'
$AgentExe       = Join-Path $BinDir 'edr-agent.exe'
$WatchdogExe    = Join-Path $BinDir 'edr-watchdog.exe'
$ConfigFile     = Join-Path $InstallDir 'agent.toml'
$LogDir         = Join-Path $InstallDir 'logs'
$QuarantineDir  = Join-Path $InstallDir 'quarantine'
$DataDir        = Join-Path $InstallDir 'data'

# ─── Prerequisite check ───────────────────────────────────────────────────────
function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[ERROR] This script must be run as Administrator.' -ForegroundColor Red
        exit 1
    }
}

# ─── Confirmation prompt ──────────────────────────────────────────────────────
function Confirm-Uninstall {
    Write-Host ''
    Write-Host 'Kizashi Agent -- Uninstaller' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  This will remove:'
    Write-Host "    - Service:   $ServiceName"
    Write-Host "    - Binaries:  $BinDir"
    Write-Host "    - Config:    $ConfigFile"

    if ($Purge) {
        Write-Host "    - Logs:      $LogDir  (--Purge)" -ForegroundColor Red
        Write-Host "    - Data:      $DataDir  (--Purge)" -ForegroundColor Red
        Write-Host "    - Quarantine: $QuarantineDir  (--Purge)" -ForegroundColor Red
    }
    else {
        Write-Host "    - Logs:      $LogDir  (preserved)"
        Write-Host "    - Data:      $DataDir  (preserved)"
        Write-Host "    - Quarantine: $QuarantineDir  (preserved)"
    }

    Write-Host ''

    if ($Yes) { return }

    if ($Purge) {
        Write-Host 'WARNING: --Purge will permanently delete logs and quarantined files!' `
            -ForegroundColor Red
    }

    $answer = Read-Host "Type 'yes' to confirm uninstall"
    if ($answer -ne 'yes') {
        Write-Info 'Uninstall cancelled.'
        exit 0
    }
}

# ─── Stop and remove Windows service ─────────────────────────────────────────
function Remove-WatchdogService([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Step "Service '$Name' not found (already removed?)"
        return
    }

    if ($svc.Status -ne 'Stopped') {
        Write-Step "Stopping service: $Name"
        try {
            Stop-Service -Name $Name -Force -ErrorAction Stop
            # Wait up to 15 seconds for the service to stop
            $timeout = [datetime]::UtcNow.AddSeconds(15)
            while ($svc.Status -ne 'Stopped' -and [datetime]::UtcNow -lt $timeout) {
                Start-Sleep -Milliseconds 500
                $svc.Refresh()
            }
        }
        catch {
            Write-Warn "Could not gracefully stop service '$Name': $_"
        }
    }

    Write-Step "Deleting service: $Name"
    & sc.exe delete $Name 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    Write-Step "Service removed: $Name"
}

function Remove-AllServices {
    Remove-WatchdogService $ServiceName

    # Handle the legacy service name if it exists
    $legacy = Get-Service -Name $LegacyService -ErrorAction SilentlyContinue
    if ($legacy) {
        Write-Step "Found legacy service '$LegacyService', removing..."
        Remove-WatchdogService $LegacyService
    }
}

# ─── Remove Windows Defender exclusion ───────────────────────────────────────
function Remove-DefenderExclusion {
    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs -and $prefs.ExclusionPath -contains $InstallDir) {
            Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
            Write-Step "Removed Windows Defender exclusion for: $InstallDir"
        }
    }
    catch {
        Write-Warn "Could not remove Defender exclusion (non-fatal): $_"
    }
}

# ─── Safe file/directory removal ─────────────────────────────────────────────
function Remove-IfExists([string]$Path, [switch]$Recurse) {
    if (Test-Path $Path) {
        try {
            if ($Recurse) {
                Remove-Item $Path -Recurse -Force -ErrorAction Stop
            }
            else {
                Remove-Item $Path -Force -ErrorAction Stop
            }
            Write-Step "Removed: $Path"
        }
        catch {
            Write-Warn "Could not remove '${Path}': $_"
        }
    }
    else {
        Write-Step "Not found (skipped): $Path"
    }
}

# ─── Remove binaries ──────────────────────────────────────────────────────────
function Remove-Binaries {
    $files = @(
        $AgentExe,
        "$AgentExe.bak",
        $WatchdogExe,
        "$WatchdogExe.bak",
        (Join-Path $InstallDir 'edr-agent.new'),
        (Join-Path $BinDir 'edr-agent.new')
    )

    foreach ($f in $files) {
        Remove-IfExists $f
    }

    # Remove the bin directory if now empty
    if ((Test-Path $BinDir) -and -not (Get-ChildItem $BinDir -ErrorAction SilentlyContinue)) {
        Remove-IfExists $BinDir -Recurse
    }
}

# ─── Remove configuration ────────────────────────────────────────────────────
function Remove-Config {
    $configFiles = @(
        $ConfigFile,
        (Join-Path $InstallDir 'enrollment.token'),
        (Join-Path $InstallDir 'edr-watchdog.pid'),
        (Join-Path $InstallDir 'edr-agent.pid')
    )

    foreach ($f in $configFiles) {
        Remove-IfExists $f
    }
}

# ─── Remove data / logs (--Purge only) ───────────────────────────────────────
function Remove-AllData {
    foreach ($dir in @($LogDir, $DataDir, $QuarantineDir)) {
        Remove-IfExists $dir -Recurse
    }
}

# ─── Remove install directory if empty ───────────────────────────────────────
function Remove-InstallDirIfEmpty {
    if (Test-Path $InstallDir) {
        $remaining = Get-ChildItem $InstallDir -ErrorAction SilentlyContinue
        if (-not $remaining) {
            Remove-IfExists $InstallDir -Recurse
        }
        else {
            Write-Step "Install directory not empty, leaving in place: $InstallDir"
            Write-Step "Remaining items:"
            $remaining | ForEach-Object { Write-Step "  - $($_.Name)" }
        }
    }
}

# ─── Summary ─────────────────────────────────────────────────────────────────
function Write-Summary {
    Write-Host ''
    Write-Host 'Uninstall complete.' -ForegroundColor Green
    Write-Host ''

    if (-not $Purge) {
        $preserved = @()
        if (Test-Path $LogDir)        { $preserved += $LogDir }
        if (Test-Path $DataDir)       { $preserved += $DataDir }
        if (Test-Path $QuarantineDir) { $preserved += $QuarantineDir }

        if ($preserved.Count -gt 0) {
            Write-Host '  The following were preserved for forensic purposes:' -ForegroundColor Cyan
            foreach ($p in $preserved) {
                Write-Host "    $p"
            }
            Write-Host ''
            Write-Host '  To remove them permanently, run:'
            Write-Host "    Remove-Item '$InstallDir' -Recurse -Force" -ForegroundColor Yellow
            Write-Host '  Or re-run this script with the -Purge flag.'
        }
    }

    Write-Host ''
}

# ─── Main ────────────────────────────────────────────────────────────────────
function Invoke-Uninstall {
    Assert-Administrator
    Confirm-Uninstall

    Write-Section 'Stopping and removing services'
    Remove-AllServices

    Write-Section 'Removing Windows Defender exclusion'
    Remove-DefenderExclusion

    Write-Section 'Removing binaries'
    Remove-Binaries

    Write-Section 'Removing configuration'
    Remove-Config

    if ($Purge) {
        Write-Section 'Removing logs and data (-Purge)'
        Remove-AllData
    }

    Write-Section 'Final cleanup'
    Remove-InstallDirIfEmpty

    Write-Summary
}

Invoke-Uninstall
