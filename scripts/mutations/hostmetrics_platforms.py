#!/usr/bin/env python3
"""Windows と macOS の測定が、また「測れない」に戻らないこと。

対象:
  agent/internal/hostmetrics/platform_math.go
  agent/internal/hostmetrics/cpu_windows.go
  agent/internal/hostmetrics/cpu_darwin.go
  agent/internal/hostmetrics/cpu_other.go

Windows は CPU もメモリもディスクも報告していませんでした
（`(0, 0, false)` / `(0, false)`）。false なので 0 の嘘にはなりません ——
**ただしフリート健全性アラータの CPU 判定とメモリ判定は、Windows 端末に
対して一度も発火できませんでした。** コメントには "not implemented
without cgo" とありましたが、cgo は要りません。

**この端末では Windows も macOS も走らせられません。** syscall と外部
コマンドの呼び出しは確かめようがありませんが、**間違えるのは算術と解析の
側です。** そこを build tag の無いファイルに出してあるので、変異もそこに
置きます。加えて、本物がその算術を**通っていること**を AST で見ます ——
切り出した側だけ検査して本物が別実装なら、検査は緑で値は嘘です。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  `parsePageSize` の「0 を弾く」変異も置いていません。置いたら生き残り
  ました —— `parseVMStat` 側の `pageSize == 0` が同じことを見ていたので、
  **外しても振る舞いが変わらなかった**からです。番人を二重に置くと、
  片方が壊れても検査に映りません。番人の方を1箇所に減らしました。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

M = 'agent/internal/hostmetrics/platform_math.go'
W = 'agent/internal/hostmetrics/cpu_windows.go'
D = 'agent/internal/hostmetrics/cpu_darwin.go'
O = 'agent/internal/hostmetrics/cpu_other.go'

CASES = [
    # ── Windows: FILETIME と CPU ───────────────────────────────────────────
    (M, '\treturn uint64(high)<<32 | uint64(low)', '\treturn uint64(high) | uint64(low)',
     'FILETIME の上位32ビットを捨てる'),
    (M, '\treturn uint64(high)<<32 | uint64(low)', '\treturn uint64(low)<<32 | uint64(high)',
     'FILETIME の上下を入れ替える'),
    (M, '\ttotal := kernel + user', '\ttotal := kernel + user + idle',
     'kernel に含まれる idle を二重に足す（使用率が実際より低く出ます）'),
    (M, '\ttotal := kernel + user', '\ttotal := user',
     'kernel 時間を分母から落とす（使用率が実際より高く出ます）'),
    (M, '\tif total == 0 || idle > total {\n\t\treturn 0, 0, false\n\t}\n\treturn idle, total, true',
        '\treturn idle, total, true',
     '起動直後の 0 を「測れた」として返す'),

    # ── Windows: メモリ ────────────────────────────────────────────────────
    (M, '\treturn float64(totalPhys-availPhys) / mb, float64(totalPhys) / mb, true',
        '\treturn float64(availPhys) / mb, float64(totalPhys) / mb, true',
     '利用可能な量を「使用量」として返す'),
    (M, '\tif totalPhys == 0 || availPhys > totalPhys {\n\t\treturn 0, 0, false\n\t}',
        '\tif false {\n\t\treturn 0, 0, false\n\t}',
     '合計 0 のまま「測れた」として返す'),

    # ── macOS: vm_stat ─────────────────────────────────────────────────────
    (M, '\treturn (active + wired + compressor) * pageSize, true',
        '\treturn (active + wired + compressor) * 4096, true',
     'ページサイズを 4096 と決め打ちする（Apple Silicon で 1/4 になります）'),
    (M, '\treturn (active + wired + compressor) * pageSize, true',
        '\treturn (active + wired + compressor*0) * pageSize, true',
     '圧縮されたメモリを数えない（物理 RAM を占めています）'),
    (M, '\t\tcase "Pages occupied by compressor":',
        '\t\tcase "Pages stored in compressor":',
     '圧縮前の論理ページ数を、占有量として使う'),
    (M, '\t\tcase "Pages active":\n\t\t\tactive, haveActive = value, true',
        '\t\tcase "Pages inactive":\n\t\t\tactive, haveActive = value, true',
     '回収できる inactive を使用中に数える'),
    (M, '\tif pageSize == 0 || !haveActive || !haveWired {',
        '\tif pageSize == 0 && !haveActive && !haveWired {',
     '欠けた出力でも、部分的な合計を測定値として返す'),
    (M, '\tif pageSize == 0 || !haveActive || !haveWired {',
        '\tif !haveActive || !haveWired {',
     'ページサイズが読めなくても答える'),

    # ── macOS: 組み立て ────────────────────────────────────────────────────
    (M, '\tif totalBytes == 0 || usedBytes > totalBytes {\n\t\treturn 0, 0, false\n\t}',
        '\tif false {\n\t\treturn 0, 0, false\n\t}',
     '合計が測れていなくても使用量だけ出す（使用率が壊れます）'),
    (M, '\tv, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)\n'
        '\tif err != nil || v == 0 {\n\t\treturn 0, false\n\t}',
        '\tv, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)\n'
        '\tif false {\n\t\treturn 0, false\n\t}',
     'sysctl の読めない出力を 0 として返す'),

    # ── 本物が算術を通っていること ─────────────────────────────────────────
    (W, '\treturn windowsCPUTotals(', '\treturn 0, 0, true // ',
     'Windows の CPU が、検査の通っている算術を通らなくなる'),
    (W, '\treturn windowsMemoryMB(st.totalPhys, st.availPhys)',
        '\treturn 0, 0, true',
     'Windows のメモリが、検査の通っている算術を通らなくなる'),
    (D, '\treturn darwinMemoryFrom(out, sz)', '\treturn 0, 0, true',
     'macOS のメモリが、検査の通っている組み立てを通らなくなる'),

    # ── 実装のないプラットフォーム ─────────────────────────────────────────
    (O, '\treturn 0, 0, false\n}\n\n// readMemory', '\treturn 0, 0, true\n}\n\n// readMemory',
     '実装のない CPU が、0% を測定値として返す'),
    (O, '//go:build !linux && !windows && !darwin', '//go:build !linux',
     'stub の build tag が、実装済みのプラットフォームを含んだままになる'),
]

RUN = ('TestFiletimeHalvesCombine|TestWindowsCPUTotals|TestWindowsMemoryMB|'
       'TestVMStat|TestParseSysctlUint|TestDarwinMemory|'
       'TestWindowsReadersUseTheTestedArithmetic|'
       'TestDarwinReadersUseTheTestedArithmetic|'
       'TestTheUnimplementedStubNeverClaimsAMeasurement|'
       'TestTheStubBuildTagMatchesWhatIsImplemented|'
       'TestTheImplementedPlatformFilesExist')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/hostmetrics/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
