#Requires -RunAsAdministrator
#Requires -Version 5.1
# =============================================================================
# DEPRECATED / 非推奨 — このスクリプトは現在どこからも参照されない孤立ファイルです。
# 本番のインストールはダッシュボードのエンロール経路（サーバーが動的生成:
# server/internal/api/handlers/installer_handler.go, GET /api/v1/installer/...）を、
# 手動インストールは deploy/install/install.ps1 を使用してください。
# 詳細: docs/インストーラ・配信経路アーキテクチャ.md
# =============================================================================
<#
.SYNOPSIS
    EDR Agent Windows Installer (DEPRECATED — use dashboard enrollment or deploy/install/)

.DESCRIPTION
    Installs the EDR Agent and Watchdog as a Windows Service.
    The watchdog is registered with SCM; it manages the agent process internally.

.PARAMETER ServerUrl
    gRPC server URL, e.g. https://edr.corp.example.com:9090

.PARAMETER EnrollmentToken
    One-time enrollment token from the EDR console.

.PARAMETER CACertPath
    Path to the CA certificate PEM file.

.PARAMETER InstallDir
    Installation directory. Default: C:\Program Files\EDRAgent

.PARAMETER DataDir
    Data directory for config, certs, logs. Default: C:\ProgramData\EDRAgent

.EXAMPLE
    .\Install-EDRAgent.ps1 -ServerUrl "https://edr.corp.example.com:9090" -EnrollmentToken "tok_abc123"
#>

[CmdletBinding()]
param(
    [string]$ServerUrl        = $env:EDR_SERVER_URL,
    [string]$EnrollmentToken  = $env:EDR_ENROLLMENT_TOKEN,
    [string]$CACertPath       = $env:EDR_CA_CERT,
    [string]$InstallDir       = "C:\Program Files\EDRAgent",
    [string]$DataDir          = "C:\ProgramData\EDRAgent",
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName    = 'EDRWatchdog'
$ServiceDisplay = 'EDR Agent Watchdog'
$ServiceDesc    = 'Manages the EDR security agent lifecycle with automatic restart and self-healing.'
$WatchdogExe    = Join-Path $InstallDir 'edr-watchdog.exe'
$AgentExe       = Join-Path $InstallDir 'edr-agent.exe'
$ConfigFile     = Join-Path $DataDir    'agent.toml'
$CertDir        = Join-Path $DataDir    'certs'
$LogDir         = Join-Path $DataDir    'logs'
$QuarantineDir  = Join-Path $DataDir    'quarantine'
$ScriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Path

# ─── Uninstall ─────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host "==> EDRエージェントをアンインストールします" -ForegroundColor Cyan

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Host "    サービスを削除しました: $ServiceName"
    }

    if (Test-Path $InstallDir) {
        Remove-Item $InstallDir -Recurse -Force
        Write-Host "    インストールディレクトリを削除しました: $InstallDir"
    }

    Write-Host "==> アンインストール完了 (データは $DataDir に残っています)" -ForegroundColor Green
    exit 0
}

# ─── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "==> EDR Agent Windows Installer" -ForegroundColor Cyan
Write-Host "    インストール先: $InstallDir"
Write-Host "    データ:         $DataDir"
Write-Host ""

# ─── Directories ───────────────────────────────────────────────
foreach ($dir in @($InstallDir, $DataDir, $CertDir, $LogDir, $QuarantineDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "==> ディレクトリを作成しました: $dir"
    }
}

# ─── Binaries ──────────────────────────────────────────────────
# Look for built binaries relative to this script (produced by: make build-windows)
$DistDir = Resolve-Path (Join-Path $ScriptDir '..\..')

$agentSrc    = Join-Path $DistDir 'agent.exe'
$watchdogSrc = Join-Path $DistDir 'watchdog.exe'

foreach ($pair in @(
    @{ Src = $agentSrc;    Dst = $AgentExe },
    @{ Src = $watchdogSrc; Dst = $WatchdogExe }
)) {
    if (Test-Path $pair.Src) {
        Copy-Item $pair.Src $pair.Dst -Force
        Write-Host "==> バイナリをコピーしました: $($pair.Dst)"
    } elseif (-not (Test-Path $pair.Dst)) {
        Write-Error "バイナリが見つかりません: $($pair.Src)`n先にビルドを実行してください: make build-windows"
    }
}

# バイナリを置き換えた場合、前回起動時に保存された整合性ハッシュを削除する。
# 削除しないと次回起動時に「binary integrity check failed: hash mismatch」が記録される。
# 削除後の初回起動で新バイナリのハッシュが自動的に計算・保存される。
$hashFile = Join-Path $DataDir 'agent.sha256'
if (Test-Path $hashFile) {
    Remove-Item $hashFile -Force
    Write-Host "==> 整合性ハッシュを削除しました (次回起動で新バイナリのハッシュを記録します)"
}

# ─── CA Certificate ────────────────────────────────────────────
if ($CACertPath -and (Test-Path $CACertPath)) {
    $destCA = Join-Path $CertDir 'ca.pem'
    Copy-Item $CACertPath $destCA -Force
    Write-Host "==> CA証明書をコピーしました"
}

# ─── Config file ───────────────────────────────────────────────
if (-not (Test-Path $ConfigFile)) {
    Write-Host "==> 設定ファイルを生成します"

    $hostname = $env:COMPUTERNAME
    $agentId  = [System.Guid]::NewGuid().ToString()

    $config = @"
[agent]
id       = "$agentId"
hostname = "$hostname"

[server]
url         = "$($ServerUrl ?? 'https://edr-server:9090')"
ca_cert     = "$($CertDir.Replace('\','\\'))\\ca.pem"
client_cert = "$($CertDir.Replace('\','\\'))\\agent.crt"
client_key  = "$($CertDir.Replace('\','\\'))\\agent.key"
grpc_port   = 9090

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
monitored_paths          = ["C:\\Users", "C:\\Windows\\System32", "C:\\Program Files"]
excluded_paths           = ["C:\\Windows\\WinSxS"]
excluded_processes       = []

[response]
auto_response_enabled = true

[logging]
level       = "info"
file        = "$($LogDir.Replace('\','\\'))\\agent.log"
max_size_mb = 50
max_backups = 3

[quarantine]
dir = "$($QuarantineDir.Replace('\','\\'))"
"@

    Set-Content -Path $ConfigFile -Value $config -Encoding UTF8
    Write-Host "    設定ファイル: $ConfigFile"
}

# ─── Enrollment token ──────────────────────────────────────────
if ($EnrollmentToken) {
    $tokenFile = Join-Path $DataDir 'enrollment.token'
    Set-Content -Path $tokenFile -Value $EnrollmentToken -Encoding ASCII
    Write-Host "==> 登録トークンを保存しました"
}

# ─── ACL: restrict DataDir to SYSTEM + Administrators ──────────
Write-Host "==> ディレクトリのアクセス権を設定します"
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)  # disable inheritance
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

foreach ($identity in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        'FullControl',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow'
    )
    $acl.AddAccessRule($rule)
}
Set-Acl -Path $DataDir -AclObject $acl

# ─── Windows Service ───────────────────────────────────────────
$svcArgs = "--agent `"$AgentExe`" --config `"$ConfigFile`""

$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "==> 既存のサービスを停止・更新します"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe config $ServiceName `
        binpath= "`"$WatchdogExe`" $svcArgs" `
        start= auto `
        DisplayName= $ServiceDisplay | Out-Null
} else {
    Write-Host "==> Windowsサービスを登録します: $ServiceName"
    sc.exe create $ServiceName `
        binpath= "`"$WatchdogExe`" $svcArgs" `
        start= auto `
        DisplayName= $ServiceDisplay `
        obj= "LocalSystem" | Out-Null
}

# Set description
sc.exe description $ServiceName $ServiceDesc | Out-Null

# Configure failure actions: restart after 5s on first 2 failures, 30s thereafter
sc.exe failure $ServiceName `
    reset= 86400 `
    actions= restart/5000/restart/5000/restart/30000 | Out-Null

# Set service to restart on failure
$svc = Get-Service -Name $ServiceName
$svc.Start()
Write-Host "==> サービスを起動しました: $ServiceName"

# Wait a moment and verify
Start-Sleep -Seconds 2
$svc.Refresh()
if ($svc.Status -eq 'Running') {
    Write-Host ""
    Write-Host "==> インストール完了" -ForegroundColor Green
    Write-Host "    ステータス確認: Get-Service $ServiceName"
    Write-Host "    ログ確認:       Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
    Write-Host "    設定ファイル:   $ConfigFile"
} else {
    Write-Warning "サービスの起動に失敗した可能性があります。ステータス: $($svc.Status)"
    Write-Host "ログを確認してください: Get-EventLog -LogName System -Newest 20"
}
