#!/usr/bin/env python3
"""メモリスキャナが「見られなかった」ことを、また黙らないこと。

対象:
  agent/internal/collector/memory_scan.go
  agent/internal/collector/memory_scan_linux.go
  agent/internal/collector/memory_scan_windows.go

このスキャナは RWX / 非バック実行領域 —— **コード注入とシェルコード**
を探します。開けなかったプロセスの中は見ていません。サーバから見ると、
注入されていない端末と、中を見られなかった端末が同じ姿でした。

そして数そのものが使えませんでした。`SkippedUnreadable` は「断られた」と
「もう居なかった」を1つに入れていました —— **プロセスは走査中に普通に
終了する**ので、健全な端末でも毎周期ゼロになりません。ゼロにならない数
では判定できず、実際どこも判定していませんでした。

効くのは Windows です。`MemoryScanStats` のコメント自身が書いていると
おり、**SeDebugPrivilege が無いとシステムプロセスはほぼ開けません。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じで、置くと毎回
  SURVIVED が並び、本物の生き残りがその中に埋もれます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

S = 'agent/internal/collector/memory_scan.go'
L = 'agent/internal/collector/memory_scan_linux.go'

CASES = [
    # ── 分類 ───────────────────────────────────────────────────────────────
    (S, '\t\treturn skipGone\n\t}\n\treturn skipDenied',
        '\t\treturn skipGone\n\t}\n\treturn skipGone',
     '断られたことを「もう居なかった」と同じにする（元の実装）'),
    (S, '\tif errors.Is(err, fs.ErrNotExist) {',
        '\tif errors.Is(err, fs.ErrPermission) {',
     '終了と拒否の判定を入れ替える（健全な端末が毎周期赤くなります）'),
    (S, '\tif err == nil {\n\t\treturn skipNone\n\t}', '',
     '走査できた場合まで「断られた」に数える'),

    # ── 報告そのもの ───────────────────────────────────────────────────────
    (S, '\tcase s.SkippedUnreadable > 0:', '\tcase false:',
     '開けなかったプロセスがあっても黙る（元の姿）'),
    (S, '\tcase s.ProcessesEnumerated == 0:', '\tcase false:',
     '1件も列挙できなくても黙る（所見0件と走査0件が同じになります）'),
    (S, '\t\ttelemetry.Set(memScanSensor, telemetry.ModeFailed,\n'
        '\t\t\tfmt.Sprintf("開けなかったプロセス %d 件 / 列挙 %d 件",',
        '\t\ttelemetry.Set(memScanSensor, telemetry.ModeOff,\n'
        '\t\t\tfmt.Sprintf("開けなかったプロセス %d 件 / 列挙 %d 件",',
     '見えていないことを「無効にしてある」として登録する'
     '（Aggregate は off を無視します）'),
    (S, '\t\ttelemetry.Forget(memScanSensor)', '',
     '直っても赤いまま（直らない赤は、赤でないのと同じです）'),
    (S, '\tcase s.SkippedUnreadable > 0:', '\tcase s.SkippedGone > 0:',
     '終了しただけのプロセスで赤くする'),

    # ── 数え分け ───────────────────────────────────────────────────────────
    (L, '\t\t\tst.SkippedUnreadable++', '\t\t\tst.SkippedGone++',
     '断られたプロセスを「終了していた」として数える'),
    (L, '\t\t\tst.SkippedGone++', '\t\t\tst.SkippedUnreadable++',
     '終了したプロセスを「断られた」として数える'),
    (L, 'var scanPidMapsStatsFn = scanPidMapsStats',
        'var scanPidMapsStatsFn = func(int, string) ([]MemoryFinding, int, skipReason) '
        '{ return nil, 0, skipNone }',
     '既定の走査が、常に「走査できた」を返す'),
    (S, '\t\t"skipped_gone", s.SkippedGone,', '',
     '内訳をログから落とす（分けた意味が読む人に届きません）'),

    # ── 呼ばれていること ───────────────────────────────────────────────────
    (L, '\tst.report()\n\treturn out, st', '\treturn out, st',
     '本物のスキャンが報告しなくなる'),
]

RUN = ('TestClassifySkipSeparatesGoneFromDenied|'
       'TestDeniedProcessesAreReportedOffTheEndpoint|'
       'TestScanningNothingIsReported|'
       'TestProcessesThatMerelyExitedAreNotABlindSpot|'
       'TestAHealthyMemoryScanRegistersNothing|'
       'TestARecoveredMemoryScanStopsReportingFailed|'
       'TestTheSkipBreakdownIsLogged|TestARealScanReportsItsCoverage|'
       'TestDeniedProcessesLandInSkippedUnreadable|TestGoneProcessesLandInSkippedGone|'
       'TestOnlyDeniedProcessesTurnTheEndpointRed|'
       'TestScanPidMapsClassifiesAMissingPID|TestTheDefaultMapsScannerIsTheRealOne')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/collector/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
