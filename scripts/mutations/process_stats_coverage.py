#!/usr/bin/env python3
"""プロセス一覧が、また静かに欠けないこと。

対象:
  agent/internal/collector/process_stats_linux.go
  agent/internal/collector/process_stats_mem.go
  agent/internal/collector/process_stats_collector.go
  server/internal/detection/cryptominer.go

`process_stats` は `CryptoMinerScorer` (T1496) の入力です。**snapshot に
出ない PID は、CPU を焼き続けても永久に検知されません。** そして届いた
側には、全部入りの snapshot と欠けた snapshot を見分ける手立てが
ありません。

実測（2026-08-11、このコンテナ、uid=0）:

  /proc の PID          75
  processListImpl       75 件
  readProcessStatsRaw    8 件   ← 89% が消えていました
  落ちた理由            VmRSS 行が無い 67 件（stat は全件読めています）

**この欠陥は、直前の修正が作りました。** 「読めなかったメモリを 0 と
して載せない」を「行ごと落とす」で実装したので、メモリが読めないことを
理由に、同じ行で読めていた CPU まで捨てていました。ここに置く変異は、
その両方の向き —— 落としすぎと、0 に化けさせる —— を戻します。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

L = 'agent/internal/collector/process_stats_linux.go'
M = 'agent/internal/collector/process_stats_mem.go'
E = 'agent/internal/collector/process_stats_collector.go'

CASES = [
    # ── 行を落とす向き（今回の欠陥そのもの）─────────────────────────────
    (L,
     '\t\tmemKB, mem := readVmRSSFn(pid)\n\t\tstats = append(stats, processStatRaw{',
     '\t\tmemKB, mem := readVmRSSFn(pid)\n\t\tif mem != memMeasured {\n\t\t\tcontinue\n\t\t}\n'
     '\t\tstats = append(stats, processStatRaw{',
     'メモリを読めなかった行を落とす（直前の実装。この端末では 89% が消えます）'),
    (L, '\treturn 0, memNoUserSpace\n}', '\treturn 0, memUnknown\n}',
     'VmRSS 行が無いことを「読めなかった」と同じにする'),

    # ── 0 に化けさせる向き（その前の欠陥）───────────────────────────────
    (M, '\tif st != memMeasured {\n\t\treturn nil\n\t}', '\tif false {\n\t\treturn nil\n\t}',
     '測れなかったメモリを 0 MB として載せる'),
    (M, '\tmemUnknown memState = iota\n\t// memMeasured — 数値が取れました。\n\tmemMeasured',
        '\tmemMeasured memState = iota\n\t// memUnknown\n\tmemUnknown',
     '零値が「測った」になる（触り忘れたフィールドが 0 MB の測定値になります）'),
    (E, '\tMemMB  *float64 `json:"mem_mb,omitempty"`',
        '\tMemMB  *float64 `json:"mem_mb"`',
     '測れなかったメモリを null として出す'),

    # ── 読み取りそのもの ───────────────────────────────────────────────────
    (L, '\t\t\treturn 0, memUnknown\n\t\t}\n\t\tkb, perr := strconv.ParseUint',
        '\t\t\treturn 0, memMeasured\n\t\t}\n\t\tkb, perr := strconv.ParseUint',
     'VmRSS 行が壊れていても「測れた 0」を返す'),
    (L, '\t\tif perr != nil {\n\t\t\treturn 0, memUnknown\n\t\t}',
        '\t\tif perr != nil {\n\t\t\treturn 0, memNoUserSpace\n\t\t}',
     '数値として読めない VmRSS を「ユーザ空間が無い」に化けさせる'),
    (L, '\tif scanner.Err() != nil {\n\t\treturn 0, memUnknown\n\t}', '',
     '途中で消えたプロセスを、カーネルスレッドとして扱う'),
    (L, '\tf, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G304 -- /proc path\n'
        '\tif err != nil {\n\t\treturn 0, memUnknown\n\t}',
        '\tf, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G304 -- /proc path\n'
        '\tif err != nil {\n\t\treturn 0, memNoUserSpace\n\t}',
     '開けなかったことを「ユーザ空間が無い」に化けさせる'),
    (L, '\tdefer f.Close()\n\treturn parseVmRSS(f)',
        '\tdefer f.Close()\n\treturn 0, memMeasured',
     '本物が、切り出した読み取りを通らなくなる'),
    (L, 'var readVmRSSFn = readVmRSS',
        'var readVmRSSFn = func(int) (uint64, memState) { return 0, memMeasured }',
     '既定の読み取りが、常に「測れた 0 kB」を返す'),
]

RUN = ('TestVmRSSForAMissingProcessIsNotZero|TestVmRSSForOurselvesIsMeasured|'
       'TestAStatusWithoutVmRSSIsNotMeasured|TestKernelThreadsExistOnThisHost|'
       'TestATaskWithoutUserMemoryIsStillListed|'
       'TestAnUnreadableProcessKeepsItsCPUButNotItsMemory|'
       'TestAReadableProcessIsStillListed|TestTheStatsListCoversMostOfProcfs|'
       'TestUnmeasuredMemoryIsAbsentFromTheWire|TestTheZeroMemStateIsUnknown|'
       'TestTheDefaultVmRSSReaderIsTheRealOne|TestParseVmRSSOutcomes|'
       'TestATruncatedStatusIsNotAKernelThread|TestReadVmRSSGoesThroughTheParser')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/collector/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
