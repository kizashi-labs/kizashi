# EDR Agent インストールスクリプト (Windows)
# 管理者権限のPowerShellで実行してください
# 使用方法:
#   iwr https://your-edr-server.com/install.ps1 | iex -Token YOUR_TOKEN -Server https://your-edr-server.com
#
# または:
#   & .\install-agent.ps1 -Server https://your-edr-server.com -Token YOUR_ENROLLMENT_TOKEN

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [string]$Token,

    [string]$InstallDir = "C:\ProgramData\EDRAgent",
    [string]$ServiceName = "EDRAgent",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# ─── Helper Functions ─────────────────────────────────────────

function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Error2 { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─── Uninstall ────────────────────────────────────────────────

function Uninstall-Agent {
    Write-Info "EDR エージェントをアンインストール中..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Info "サービスを削除しました: $ServiceName"
    }

    if (Test-Path $InstallDir) {
        # Preserve quarantine and logs
        $preserve = @("quarantine", "logs")
        Get-ChildItem $InstallDir | Where-Object {
            $_.Name -notin $preserve
        } | Remove-Item -Recurse -Force

        Write-Info "アンインストール完了"
        Write-Info "隔離ファイルとログは保存されています: $InstallDir"
    }
}

if ($Uninstall) {
    Uninstall-Agent
    exit 0
}

# ─── Main Install ─────────────────────────────────────────────

function Install-Agent {
    Write-Info "EDR Platform エージェントをインストールしています..."

    # Admin check
    if (-not (Test-Admin)) {
        Write-Error2 "管理者権限が必要です。PowerShellを管理者として実行してください。"
    }

    # Detect architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    Write-Info "プラットフォーム: windows-$arch"

    # Create directories
    $dirs = @(
        $InstallDir,
        "$InstallDir\bin",
        "$InstallDir\config",
        "$InstallDir\logs",
        "$InstallDir\quarantine",
        "$InstallDir\certs"
    )
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Write-Info "ディレクトリを作成しました"

    # Download binary
    $binaryUrl   = "$Server/api/v1/agents/download?platform=windows&arch=$arch"
    $checksumUrl = "$Server/api/v1/agents/download/checksum?platform=windows&arch=$arch"
    $binaryPath  = "$InstallDir\bin\edr-agent.exe"
    $tmpPath     = "$env:TEMP\edr-agent-download.exe"

    Write-Info "バイナリをダウンロード中: $binaryUrl"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest -Uri $binaryUrl -OutFile $tmpPath -UseBasicParsing

        # Checksum endpoint returns JSON: {"platform":...,"arch":...,"checksum":"<hex>"}
        $checksumJson = (Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing).Content | ConvertFrom-Json
        $expectedHash = $checksumJson.checksum.ToLowerInvariant()

        # Verify SHA256
        $actualHash = (Get-FileHash -Path $tmpPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            Remove-Item $tmpPath -Force
            Write-Error2 "チェックサム検証失敗 (expected: $expectedHash, got: $actualHash)"
        }
        Write-Info "チェックサム検証OK"

        Move-Item -Force $tmpPath $binaryPath
    }
    catch {
        Write-Error2 "ダウンロードに失敗しました: $_"
    }

    # Generate agent ID
    $agentId = [System.Guid]::NewGuid().ToString()

    # Generate TLS client key and CSR
    Write-Info "クライアント証明書を生成中..."
    $keyPath  = "$InstallDir\certs\agent.key"
    $csrPath  = "$env:TEMP\agent.csr"
    $certPath = "$InstallDir\certs\agent.crt"
    $caPath   = "$InstallDir\certs\ca.crt"

    # Use certreq or openssl if available
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl genrsa -out $keyPath 2048 2>$null
        openssl req -new -key $keyPath -out $csrPath -subj "/CN=$agentId/O=EDR-Agent" 2>$null
    } else {
        # Use Windows built-in certificate generation
        $cert = New-SelfSignedCertificate `
            -Subject "CN=$agentId, O=EDR-Agent" `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(5) `
            -CertStoreLocation Cert:\LocalMachine\My

        $csrContent = [Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $csrContent | Set-Content $csrPath
    }

    # Enroll with server
    Write-Info "サーバーにエージェントを登録中..."
    $hostname = $env:COMPUTERNAME
    $osVersion = (Get-WmiObject Win32_OperatingSystem).Caption

    $ipAddresses = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" }).IPAddress

    $csrContent = if (Test-Path $csrPath) { Get-Content $csrPath -Raw } else { "" }

    $enrollBody = @{
        enrollment_token = $Token
        hostname         = $hostname
        os_type          = "windows"
        os_version       = $osVersion
        ip_addresses     = @($ipAddresses)
        csr              = $csrContent
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod `
            -Uri "$Server/grpc/v1/enroll" `
            -Method POST `
            -ContentType "application/json" `
            -Body $enrollBody

        $response.signed_cert | Set-Content $certPath
        $response.ca_cert     | Set-Content $caPath
        Write-Info "登録完了 (Agent ID: $agentId)"
    }
    catch {
        Write-Warn "サーバー登録に失敗しました: $_ (オフラインモードで続行)"
        $agentId | Set-Content "$InstallDir\config\agent_id.txt"
    }

    # Write config
    Write-Config -AgentId $agentId
    Write-Info "設定ファイルを作成しました"

    # Install Windows Service
    Install-WindowsService
    Write-Info "Windowsサービスをインストールしました"

    # Verify
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Info "✓ エージェントが正常に起動しました"
    } else {
        Write-Warn "サービスの状態を確認してください: Get-Service $ServiceName"
    }

    Write-Info ""
    Write-Info "インストール完了"
    Write-Info "管理コマンド:"
    Write-Info "  状態確認: Get-Service $ServiceName"
    Write-Info "  ログ確認: Get-Content $InstallDir\logs\agent.log -Wait"
    Write-Info "  再起動:   Restart-Service $ServiceName"
    Write-Info "  停止:     Stop-Service $ServiceName"
    Write-Info ""
    Write-Info "ダッシュボード: $Server"
}

function Write-Config {
    param([string]$AgentId)

    $configContent = @"
# EDR Agent Configuration
# 自動生成 - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

[agent]
id       = "$AgentId"
hostname = "$env:COMPUTERNAME"

[server]
url            = "$Server"
ca_cert        = "$InstallDir\\certs\\ca.crt"
client_cert    = "$InstallDir\\certs\\agent.crt"
client_key     = "$InstallDir\\certs\\agent.key"
grpc_port      = 9090
connect_timeout_sec = 30

[collection]
process_monitoring   = true
file_monitoring      = true
network_monitoring   = true
dns_monitoring       = true
registry_monitoring  = true
auth_monitoring      = true
yara_scan_on_exec    = true
event_batch_interval_ms = 500
config_poll_interval_sec = 300
local_buffer_size_mb = 100

monitored_paths = ["C:\\\\Users", "C:\\\\Windows\\\\Temp", "C:\\\\ProgramData"]
excluded_paths  = ["C:\\\\Windows\\\\WinSxS", "C:\\\\Windows\\\\SoftwareDistribution"]

[response]
auto_response_enabled = true

[logging]
level    = "info"
file     = "$InstallDir\\logs\\agent.log"
max_size_mb  = 50
max_backups  = 3

[quarantine]
dir = "$InstallDir\\quarantine"
"@

    $configContent | Set-Content "$InstallDir\config\config.toml" -Encoding UTF8
    # Restrict config file permissions
    $acl = Get-Acl "$InstallDir\config\config.toml"
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators", "FullControl", "Allow"
    )
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "Allow"
    )
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl "$InstallDir\config\config.toml" $acl
}

function Install-WindowsService {
    # Remove existing service if present
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Create service
    New-Service `
        -Name $ServiceName `
        -DisplayName "EDR Platform Agent" `
        -Description "Endpoint Detection and Response Agent - セキュリティ監視エージェント" `
        -BinaryPathName "`"$InstallDir\bin\edr-agent.exe`" --config `"$InstallDir\config\config.toml`"" `
        -StartupType Automatic `
        -ErrorAction Stop | Out-Null

    # Configure service recovery (restart on failure)
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

    # Start service
    Start-Service -Name $ServiceName
}

# Run main install
Install-Agent
