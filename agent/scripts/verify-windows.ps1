#requires -Version 5.1
<#
.SYNOPSIS
  EDR-Agent endpoint visibility verification (Windows).

.DESCRIPTION
  Reports the installed agent's service state and, from its log, which collection
  path is active (ETW vs polling). Then runs the bundled etw-verify.exe harness to
  prove the opt-in ETW collectors (process / network / DNS / auth) actually emit
  events on this machine, reporting PASS/FAIL per telemetry type.

  Run from an ELEVATED (Administrator) PowerShell. ETW real-time sessions and the
  Security log subscription require elevation.

  ASCII-only on purpose: Windows PowerShell 5.1 misparses non-ASCII .ps1 files that
  lack a UTF-8 BOM, depending on the system code page. Keep this file ASCII.

.NOTES
  Place etw-verify.exe in the SAME folder as this script, then run. Paste the whole
  output back.
#>

$ErrorActionPreference = 'Continue'
$sep = ('=' * 70)
function Section($t) { Write-Host "`n$sep`n== $t`n$sep" }

Section "0. Execution context"
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Administrator : $isAdmin"
"Hostname      : $env:COMPUTERNAME"
"OS            : $((Get-CimInstance Win32_OperatingSystem).Caption)"
if (-not $isAdmin) {
  Write-Warning "Not elevated. ETW checks WILL fail. Re-run from an Administrator PowerShell."
}

Section "1. Agent / watchdog service state"
foreach ($svc in 'EDRAgent','EDRWatchdog') {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s) { "{0,-14}: {1}" -f $svc, $s.Status }
  else    { "{0,-14}: (not found)" -f $svc }
}
"Processes:"
Get-Process -Name 'edr-agent','edr-watchdog' -ErrorAction SilentlyContinue |
  Select-Object Name, Id, @{n='RSS(MB)';e={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize

Section "2. Agent log - collection path (ETW vs polling)"
$log = 'C:\ProgramData\EDRAgent\logs\agent.log'
if (Test-Path $log) {
  "Log: $log"
  "--- ETW / EvtSubscribe lines (last 20) ---"
  Select-String -Path $log -Pattern 'ETW|EvtSubscribe' |
    Select-Object -Last 20 | ForEach-Object { $_.Line }
  "--- WARN/ERROR lines (last 10) ---"
  Select-String -Path $log -Pattern '"level":"(ERROR|WARN)"' |
    Select-Object -Last 10 | ForEach-Object { $_.Line }
  ""
  "Interpretation:"
  "  Lines containing 'monitoring started' / 'EvtSubscribe' -> running on the ETW path"
  "  Lines containing 'fallback' / 'polling'               -> default polling path"
  "  (the agent logs these in Japanese; matching on 'ETW'/'EvtSubscribe' still works)"
} else {
  "Log not found: $log"
}

Section "3. etw-verify harness - runtime check of the opt-in ETW collectors"
$harness = Join-Path $PSScriptRoot 'etw-verify.exe'
if (Test-Path $harness) {
  "harness: $harness"
  "Forces EDR_AGENT_ETW=1, starts each collector, self-generates known activity,"
  "and reports PASS/FAIL on event delivery. (auth needs a manual logon -> shown as INFO;"
  "trigger a logon during its watch window to turn it into PASS.)"
  "----------------------------------------------------------------------"
  & $harness
  "----------------------------------------------------------------------"
  "exit code: $LASTEXITCODE  (0 = process/network/dns all PASS)"
} else {
  Write-Warning "etw-verify.exe is not in this folder: $harness"
  "Build it and place it next to this script:"
  "  cd agent; `$env:GOOS='windows'; `$env:GOARCH='amd64'; go build -o scripts/etw-verify.exe ./cmd/etw-verify"
}

Section "Done"
"Paste this entire output (sections 0-3) back."
