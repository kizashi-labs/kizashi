#!/usr/bin/env python3
"""測れなかった値が、また 0 として送られたら気づけること。

対象:
  agent/internal/collector/resource_collector.go
  agent/internal/collector/resource_collector_{linux,darwin,windows}.go
  agent/internal/hostmetrics/cpu.go
  agent/internal/heartbeat/heartbeat.go
  server/internal/ingestion/handler.go

守っている検査:
  agent/internal/collector/unmeasured_test.go
  agent/internal/hostmetrics/cpu_test.go
  server/internal/store/uncovered_methods_test.go（DB 必須）

0 は測定値として最も強い主張になります。CPU の 0% は「アイドル」で、
高負荷を探す側からは**問題なし**。ディスクの 0 GB は「空きが全く無い」で、
**いちばん深刻な観測値**。向きが逆なので「安全側に倒す」では片付きません。

戻し方はどれも1文字から2行です。**コードは通り、画面には数字が出ます。**
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

C = 'agent/internal/collector/'
RES = C + 'resource_collector.go'
CPU = 'agent/internal/hostmetrics/cpu.go'

CASES = [
    # ── 欄を落とす仕組み ────────────────────────────────────────────────────
    (RES, '\tCPUPercent *float64 `json:"cpu_pct,omitempty"`',
          '\tCPUPercent *float64 `json:"cpu_pct"`',
     '未測定の CPU を null として載せる（0 と同じ欄が出ます）'),
    (RES, '\tDiskFreeGB *float64 `json:"disk_free_gb,omitempty"`',
          '\tDiskFreeGB *float64 `json:"disk_free_gb"`',
     '未測定のディスクを null として載せる'),

    # ── 測れなかったときに値を入れてしまう ────────────────────────────────
    (RES, '\tif gb, ok := readDiskFreeGBFn(); ok {\n\t\tsnap.DiskFreeGB = &gb\n\t}',
          '\tgb, _ := readDiskFreeGBFn()\n\tsnap.DiskFreeGB = &gb',
     '測れたかを見ずに、ディスクの値をそのまま載せる'),
    (RES, '\t\tif deltaTotal > 0 && deltaIdle <= deltaTotal {',
          '\t\tif deltaTotal > 0 {',
     'idle が total を超えても CPU% を出す（巻き戻りで巨大な値）'),

    # ── 測れた 0 を落としてしまう（逆向きの嘘）──────────────────────────
    # ── 各プラットフォームの「未実装」────────────────────────────────────
    (C + 'resource_collector_windows.go',
     'func readDiskFreeGB() (float64, bool) {',
     'func readDiskFreeGB() float64 {',
     'Windows が「測れたか」を返さない形に戻る'),
    (C + 'resource_collector_windows.go',
     '\t\treturn 0, false\n\t}\n\treturn float64(freeToCaller)',
     '\t\treturn 0, true\n\t}\n\treturn float64(freeToCaller)',
     '測れなかったディスクを「測れた 0 GB」として返す'),
    (C + 'resource_collector_windows.go',
     '\tif err := windows.GetDiskFreeSpaceEx(root, &freeToCaller, &totalBytes, &totalFree); err != nil {',
     '\tif err := error(nil); err != nil {',
     'Windows のディスク測定が、実装ごと消える'),
    (C + 'resource_collector_windows.go',
     '\tidle, total, ok := hostmetrics.SystemCPUCounters()',
     '\tidle, total, ok := uint64(0), uint64(0), false; _ = ok',
     'Windows の CPU が、共通の読み取りを通らなくなる'),
    (C + 'resource_collector_windows.go',
     'os.Getenv("SystemDrive")',
     'os.Getenv("SystemDriveX")',
     'システムドライブを取り違える'),

    # ── CPU サンプラ ───────────────────────────────────────────────────────
    (CPU, '\t\t\tv, err := strconv.ParseUint(fields[i], 10, 64)',
          '\t\t\tv, err := strconv.ParseUint(fields[i], 10, 64)\n\t\t\terr = nil',
     '壊れた欄を 0 として足し、部分的な合計を返す'),
    (CPU, '\t\tif len(fields) < 6 {', '\t\tif len(fields) < 2 {',
     '欄が足りない行でも読めたことにする'),
    (CPU, '\tif !primed || total <= prevTotal {', '\tif !primed {',
     'カウンタが進んでいなくても 0% を測定値として返す'),

    # ── メモリ（測っていないのではなく、別のものを測っていた）──────────────
    (RES, '\tif used, _, ok := hostMemoryFn(); ok {\n\t\tsnap.MemMB = &used\n\t}',
          '\tused, _, _ := hostMemoryFn()\n\tsnap.MemMB = &used',
     '測れたかを見ずに、メモリの値をそのまま載せる'),
    (RES, '\tMemMB      *float64 `json:"mem_mb,omitempty"`',
          '\tMemMB      *float64 `json:"mem_mb"`',
     '未測定のメモリを null として載せる'),
    (CPU, '\tif !haveTotal || !haveAvail || totalKB == 0 || availKB > totalKB {',
          '\tif false {',
     'MemAvailable が無くても、あり得ない値でも測れたことにする'),
    (CPU, '\treturn float64(totalKB-availKB) / 1024, float64(totalKB) / 1024, true',
          '\t_ = availKB\n\treturn float64(totalKB) / 1024, float64(totalKB) / 1024, true',
     'used を MemTotal そのものにする（全端末がメモリ逼迫に見えます）'),
    (CPU, '\t\tcase strings.HasPrefix(line, "MemAvailable:"):',
          '\t\tcase strings.HasPrefix(line, "MemFree:"):',
     'MemFree で引く（ページキャッシュを「使用中」に数えます）'),

    # ── 差し替え可能にした点そのもの ────────────────────────────────────────
    (RES, '\treadDiskFreeGBFn = readDiskFreeGB', '\treadDiskFreeGBFn = func() (float64, bool) { return 0, true }',
     '既定の測定関数が、常に「測れた 0 GB」を返す'),
    (RES, '\thostMemoryFn     = hostmetrics.Memory',
          '\thostMemoryFn     = func() (float64, float64, bool) { _, _, _ = hostmetrics.Memory(); return 0, 0, true }',
     '既定のメモリ測定が、常に「測れた 0 MB」を返す'),
]

RUN = ('TestAnUnmeasuredSnapshotOmitsItsFields|TestAMeasuredZeroIsStillReported|'
       'TestCollectWithoutADeltaOmitsCPU|TestParsesTheAggregateLine|'
       'TestABrokenFieldIsNotAPartialTotal|TestATruncatedLineIsNotUsable|'
       'TestNoAggregateLineIsNotMeasured|TestAMissingFileIsNotMeasured|'
       'TestTheFirstSampleHasNoDelta|TestNoProgressIsNotZeroPercent|'
       'TestAProperDeltaIsMeasured|TestAnUnmeasurableDiskIsNotReportedAsZero|'
       'TestAMeasurableDiskIsReportedEvenWhenZero|TestImpossibleIdleGrowthOmitsCPU|'
       'TestAProperDeltaIsReported|TestEveryPlatformReportsWhetherItMeasured|'
       'TestImpossibleIdleGrowthIsNotMeasured|TestTheDefaultReaderIsTheRealOne|'
       'TestTheDefaultReadersArePlatformImplementations|'
       'TestAnUnmeasurableMemoryIsNotReported|TestAMeasurableMemoryIsReported|'
       'TestUsedMemoryIsTotalMinusAvailable|TestMissingMemAvailableIsNotMeasured|'
       'TestMissingMemTotalIsNotMeasured|TestImpossibleMemoryValuesAreNotMeasured|'
       'TestABrokenMemInfoValueIsNotMeasured|TestAMissingMemInfoFileIsNotMeasured|'
       'TestMemoryIsReportedInMegabytes|TestWindowsResourceReadersAreImplemented')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/collector/', './internal/hostmetrics/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
