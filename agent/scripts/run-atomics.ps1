#requires -Version 5.1
<#
.SYNOPSIS
  Atomic Red Team のテクニックを順次実行し、attack-scorer 用の runlog CSV を出力する。

.DESCRIPTION
  指定した ATT&CK テクニック群を Invoke-AtomicTest で1つずつ実行し、各実行の
  開始/終了時刻を RFC3339(UTC) で記録した runlog CSV を生成する。各テスト後に
  -Cleanup を必ず実行して原状回復する。出力した runlog.csv を attack-scorer に
  渡すと検知率スコアカードが算出できる。

  PowerShell Core(pwsh)であれば Windows / Linux 両方で動作する。

  前提:
    Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
    Import-Module Invoke-AtomicRedTeam

.PARAMETER Techniques
  実行するテクニックID配列。例: T1059.001,T1003.001,T1490

.PARAMETER TechniqueFile
  1行1テクニックのファイル(# でコメント可)。Techniques と併用可。

.PARAMETER OutLog
  出力する runlog CSV のパス(既定 runlog.csv)。

.PARAMETER SettleSeconds
  各テスト実行後、テレメトリ送出を待つ秒数(既定 8)。

.PARAMETER NoCleanup
  指定時は -Cleanup を実行しない(破壊的変更が残るので原則使わない)。

.PARAMETER Scenario
  任意。この実行の全テクニックを1つの多段攻撃チェーンとしてタグ付けする。
  attack-scorer がチェーン採点(段ごと + 連鎖断ち切り率, MITRE Evals 形式)を行う。

.EXAMPLE
  pwsh ./run-atomics.ps1 -Techniques T1059.001,T1003.001,T1490 -OutLog runlog.csv

.EXAMPLE
  # 侵入チェーンを順に実行し1シナリオとして採点
  pwsh ./run-atomics.ps1 -Techniques T1566.001,T1059.001,T1003.001,T1021.002,T1041 `
    -Scenario intrusion-chain -OutLog chain.csv

.NOTES
  ⚠ 隔離された検証用 VM でのみ実行すること。詳細は docs/ATT&CK検知率測定計画.md。
#>
param(
    [string[]]$Techniques = @(),
    [string]$TechniqueFile,
    [string]$OutLog = "runlog.csv",
    [int]$SettleSeconds = 8,
    [switch]$NoCleanup,
    # 任意: この実行の全テクニックを1つの多段攻撃チェーンとしてタグ付けする。
    # attack-scorer がこの scenario 列でグルーピングし、チェーン採点(段ごとの
    # 可視化/検知/technique特定/防御 + 連鎖断ち切り率)を行う。MITRE Evals 形式。
    [string]$Scenario = ""
)

$ErrorActionPreference = "Stop"

if ($TechniqueFile) {
    if (-not (Test-Path $TechniqueFile)) { throw "TechniqueFile が見つかりません: $TechniqueFile" }
    $fromFile = Get-Content $TechniqueFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") }
    $Techniques += $fromFile
}
$Techniques = $Techniques | Select-Object -Unique
if (-not $Techniques) { throw "実行するテクニックがありません (-Techniques または -TechniqueFile を指定)" }

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    throw "Invoke-AtomicTest が見つかりません。Import-Module Invoke-AtomicRedTeam を先に実行してください。"
}

function Now-Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

$rows = New-Object System.Collections.Generic.List[object]
Write-Host "実行対象: $($Techniques -join ', ')" -ForegroundColor Cyan

foreach ($tech in $Techniques) {
    Write-Host "`n=== $tech ===" -ForegroundColor Yellow
    $testName = $tech
    try {
        # 前提条件の取得(必要なファイル等)。失敗しても続行。
        Invoke-AtomicTest $tech -GetPrereqs -ErrorAction SilentlyContinue | Out-Null
    } catch { Write-Warning "GetPrereqs 失敗: $($_.Exception.Message)" }

    $start = Now-Utc
    $exit = 0
    try {
        Invoke-AtomicTest $tech -ErrorAction Stop
    } catch {
        $exit = 1
        Write-Warning "実行エラー: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $SettleSeconds   # テレメトリがサーバに届くのを待つ
    $end = Now-Utc

    if (-not $NoCleanup) {
        try { Invoke-AtomicTest $tech -Cleanup -ErrorAction SilentlyContinue | Out-Null }
        catch { Write-Warning "Cleanup 失敗: $($_.Exception.Message)" }
    }

    $rows.Add([pscustomobject]@{
        technique = $tech
        test_name = $testName
        start_utc = $start
        end_utc   = $end
        exit_code = $exit
        scenario  = $Scenario
    })
}

$rows | Export-Csv -Path $OutLog -NoTypeInformation -Encoding UTF8
Write-Host "`nrunlog 出力: $OutLog ($($rows.Count) 件)" -ForegroundColor Green
Write-Host "採点: attack-scorer -server <URL> -token <TOKEN> -runlog $OutLog" -ForegroundColor Green
