#!/usr/bin/env python3
"""ETW センサーの起動失敗が、また黙って捨てられたら気づけること。

対象:
  agent/internal/platform/windows/{registry,wmi,pipe,script,thread,imageload,psmodule}_etw.go
  agent/internal/platform/windows/etw_status.go
  agent/internal/telemetry/mode.go

守っている検査:
  agent/internal/platform/windows/etw_reporting_contract_test.go
  agent/internal/telemetry/failed_mode_test.go

7本の ETW センサーは、登録に失敗しても `return nil` で続きます。以前は
`slog.Warn` を1行書くだけで、**サーバから見た端末は何も起きていない端末と
まったく同じ姿**でした。いまは telemetry に ModeFailed として記録し、
ハートビートの telemetry_mode に載せます。

戻せる形が3通りあります。どれもコードは通り、検査も（守りが無ければ）通り、
**報告だけが静かに消えます:**

  - 呼び出しを消す（元の slog.Warn に戻す）
  - ModeFailed ではなく ModeOff で記録する（aggregate が無視します）
  - aggregate から failed の判定を外す

置いていない変異:

  検査そのものの assert 行を潰す変異（`if !calls(...)` を `if false && …` に
  するなど）は置いていません。**どのテストも殺せないからです** ——
  それは「そのテストを消す」のと同じで、同じファイルの負の対照は
  ヘルパー（`calls` / `startFailureBranches`）を直接呼ぶので、
  トップレベルの判定行は通りません。置くと毎回 SURVIVED が並び、
  本物の生き残りがその中に埋もれます。

  代わりにヘルパー側を壊す変異を置いてあります。判定の中身が緩めば、
  負の対照が落とします。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

W = 'agent/internal/platform/windows/'
STATUS = W + 'etw_status.go'
MODE = 'agent/internal/telemetry/mode.go'

CASES = [
    # ── 呼び出しそのもの（7本すべて）────────────────────────────────────────
    (W + 'registry_etw.go', '\t\tetwSensorFailed(sensorETWRegistry, err)', '',
     'レジストリ監視が、失敗を報告しなくなる'),
    (W + 'wmi_etw.go', '\t\tetwSensorFailed(sensorETWWMI, err)', '',
     'WMI 監視が、失敗を報告しなくなる'),
    (W + 'pipe_etw.go', '\t\tetwSensorFailed(sensorETWPipe, err)', '',
     '名前付きパイプ監視が、失敗を報告しなくなる'),
    (W + 'script_etw.go', '\t\tetwSensorFailed(sensorETWScript, err)', '',
     'スクリプトブロック監視が、失敗を報告しなくなる'),
    (W + 'thread_etw.go', '\t\tetwSensorFailed(sensorETWThread, err)', '',
     'リモートスレッド監視が、失敗を報告しなくなる'),
    (W + 'imageload_etw.go', '\t\tetwSensorFailed(sensorETWImageLoad, err)', '',
     'イメージロード監視が、失敗を報告しなくなる'),
    (W + 'psmodule_etw.go', '\t\tetwSensorFailed(sensorETWPSModule, err)', '',
     'PowerShell モジュール監視が、失敗を報告しなくなる'),

    # ── 記録の中身 ─────────────────────────────────────────────────────────
    (STATUS, '\ttelemetry.Set(sensor, telemetry.ModeFailed, err.Error())',
             '\ttelemetry.Set(sensor, telemetry.ModeOff, err.Error())',
     '失敗を「無効にしてある」として記録する（aggregate が無視します）'),
    (STATUS, '\ttelemetry.Set(sensor, telemetry.ModeFailed, err.Error())', '',
     '記録そのものをやめ、ログだけに戻す'),

    # ── SeDebugPrivilege（同じ家族）────────────────────────────────────────
    (W + 'process_collector.go',
     '\t\t\tseDebugUnavailable("プロセストークンを開けません", err)',
     '\t\t\tslog.Warn("SeDebugPrivilege: プロセストークンを開けません", "error", err)',
     'トークンを開けなかったことを、ログだけに戻す'),
    (W + 'process_collector.go',
     '\t\t\tseDebugUnavailable("特権を有効化できません（管理者で動いていない可能性）", err)',
     '\t\t\tslog.Warn("SeDebugPrivilege を有効化できませんでした", "error", err)',
     '特権を取れなかったことを、ログだけに戻す'),
    (W + 'process_collector.go',
     '\ttelemetry.Set(sensorProcessCommandLine, telemetry.ModePoll,',
     '\ttelemetry.Set(sensorProcessCommandLine, telemetry.ModeOff,',
     '劣化を「無効にしてある」として記録する（Aggregate が無視します）'),

    # ── macOS のセンサー（同じ家族）─────────────────────────────────────────
    ('agent/internal/platform/darwin/auth_collector.go',
     '\t\tsensorUnavailable(sensorAuth, "log コマンドが見つかりません", err)',
     '\t\tslog.Info("macOS の log コマンドが見つかりません。認証コレクタは無効です")',
     'macOS 認証コレクタが、起動失敗をログだけに戻す'),
    ('agent/internal/platform/darwin/sensor_status.go',
     '\ttelemetry.Set(sensor, telemetry.ModeFailed, why)',
     '\ttelemetry.Set(sensor, telemetry.ModeOff, why)',
     'macOS の失敗を「無効にしてある」として記録する'),

    # ── 集約 ───────────────────────────────────────────────────────────────
    (MODE, '\tfor _, s := range in {\n\t\tif s.Mode == ModeFailed {\n\t\t\treturn ModeFailed\n\t\t}\n\t}',
           '',
     'aggregate が failed を見なくなる（off と同じ扱いに戻る）'),
    (MODE, '\t\tif s.Mode == ModeFailed {\n\t\t\treturn ModeFailed\n\t\t}',
           '\t\tif s.Mode == ModeFailed {\n\t\t\treturn ModePoll\n\t\t}',
     '失敗を poll として集約する（「劣った手段で見えている」に化ける）'),
    (MODE, '\t\tif s.Mode == ModeOff {\n\t\t\tcontinue\n\t\t}',
           '\t\tif s.Mode == ModeOff {\n\t\t\treturn ModePoll\n\t\t}',
     '無効にしてあるセンサーまで劣化として数える（本物がその中に埋もれます）'),

    # ── 走査の範囲 ─────────────────────────────────────────────────────────
    (W + 'etw_reporting_contract_test.go',
     '\t"registry_etw.go":  "レジストリ改変（永続化）",', '',
     '検査の対象一覧から1本落とす'),
    (W + 'etw_reporting_contract_test.go',
     '\t\tif id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {\n\t\t\tfound = true\n\t\t}',
     '\t\tif id, ok := call.Fun.(*ast.Ident); ok && id.Name != "" && name != "" {\n\t\t\tfound = true\n\t\t}',
     '「呼んでいるか」が何にでも当たる'),
]

RUN = ('TestEveryETWSensorReportsItsStartFailure|TestTheFailureIsRecordedAsFailedNotOff|'
       'TestTheRuleFires|TestTheDisabledBranchIsNotAFailure|'
       'TestEveryPrivilegeFailurePathReports|TestTheDegradationIsPollNotFailedOrOff|'
       'TestMacSensorFailuresAreReported|TestTheMacDegradationIsFailedNotOff|'
       'TestAFailedSensorIsNotSwallowed|TestFailedOutranksPoll|'
       'TestDisabledSensorsAreStillIgnored|TestOnlyFailedSensorsReportFailed|'
       'TestNothingRegisteredIsStillUnreported|TestTheReasonSurvives|'
       'TestAggregate|TestEveryETWSensorReportsItsStartFailure')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/platform/windows/', './internal/platform/darwin/',
         './internal/telemetry/', './internal/collector/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
