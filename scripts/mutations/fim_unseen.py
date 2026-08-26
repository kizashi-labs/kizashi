#!/usr/bin/env python3
"""FIM の「見ていない」が、また「変更なし」に戻らないこと。

対象:
  agent/internal/collector/fim_collector.go
  agent/internal/collector/fim_unseen_test.go

FIM が黙っていることは、画面では「そのファイルは変わっていない」と読まれ
ます。**直す前は3つの別々のことが同じ沈黙になっていました:**

  1. 本当に変わっていない
  2. 読みに行ったが開けなかった（権限・I/O）
  3. 監視対象そのものを見に行けなかった（stat / walk の失敗）

ここに置く変異は、そのどれかを元の「同じ沈黙」に戻します。**どれも
1〜2行で、コードは通り、イベントは減るか増えるかするだけです。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じで、置くと毎回
  SURVIVED が並び、本物の生き残りがその中に埋もれます。
  代わりに、判定が見るデータの側と、製品の分岐を壊します。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

C = 'agent/internal/collector/fim_collector.go'
T = 'agent/internal/telemetry/mode.go'

CASES = [
    # ── 読めなかったファイル ───────────────────────────────────────────────
    (C,
     '\t\t\tif _, known := f.hashes[p]; !known {\n\t\t\t\tf.hashes[p] = ""\n\t\t\t}',
     '\t\t\tf.hashes[p] = ""',
     '読めなかった時点で基準値を潰す（元の実装。読めるように戻った瞬間に'
     '偽の modified が出ます）'),
    (C, '\t\tdelete(f.unreadable, p)\n\n\t\tprev, known := f.hashes[p]',
        '\n\t\tprev, known := f.hashes[p]',
     '読めるように戻っても「読めない」の記録が残る（赤が消えなくなります）'),
    (C, '\t\t\tf.unreadable[p] = struct{}{}\n', '',
     '読めなかったことを記録しない（サーバから見て健全な端末と同じになります）'),

    # ── 見に行けなかった対象 ───────────────────────────────────────────────
    (C, '\t\tif f.isBlocked(p) {\n\t\t\tcontinue\n\t\t}\n', '',
     '見に行けなかった配下を「削除された」として報告する'
     '（/usr/bin の1回の失敗で 1065 件）'),
    (C, '\t\t\t\tif !os.IsNotExist(err) || ancestorIsNotADirectory(base) {\n\t\t\t\t\tf.blocked = append(f.blocked, base)',
        '\t\t\t\tif false {\n\t\t\t\t\tf.blocked = append(f.blocked, base)',
     '「無い」と「見に行けない」をまた同じ扱いにする'),
    (C, '\t\t\t\tif !os.IsNotExist(err) || ancestorIsNotADirectory(base) {\n\t\t\t\t\tf.blocked = append(f.blocked, base)',
        '\t\t\t\tif true {\n\t\t\t\t\tf.blocked = append(f.blocked, base)',
     '存在しないだけのパスまで失敗に数える（ほぼ全端末が赤くなります）'),
    (C, '\tf.blocked = nil\n', '',
     '見に行けなかった記録を持ち越す（そのあと本当に消されたものが'
     '永久に報告されません）'),
    (C, '\t\tif p == base || strings.HasPrefix(p, base+string(filepath.Separator)) {',
        '\t\tif p == base {',
     '抑制が対象そのものにしか効かず、配下のファイルに届かない'),

    # ── 端末の外に出すところ ───────────────────────────────────────────────
    (C, '\ttelemetry.Set(fimSensor, telemetry.ModeFailed,',
        '\ttelemetry.Set(fimSensor, telemetry.ModeOff,',
     '見えていないことを「無効にしてある」として登録する'
     '（Aggregate は off を無視します）'),
    (C, '\t\ttelemetry.Forget(fimSensor)\n\t\treturn', '\t\treturn',
     '直っても赤いまま（直らない赤は、赤でないのと同じです）'),
    (C, '\tf.reportCoverage()\n}\n\n// isBlocked', '}\n\n// isBlocked',
     'スキャンのたびの報告をやめる（最初の1回だけになります）'),

    # ── 差し替え口 ─────────────────────────────────────────────────────────
    (C, 'var hashFileFn = hashFile',
        'var hashFileFn = func(string) (string, error) { return "", nil }',
     '既定の読み取りが、常に「読めた空ハッシュ」を返す'),

    # ── telemetry 側 ───────────────────────────────────────────────────────
    (T, '\tdelete(sensors, sensor)', '\t_ = sensor',
     'Forget が何もしない'),
]

RUN = ('TestAnUnreadableSpellDoesNotInventAChange|'
       'TestAChangeAcrossAnUnreadableSpellKeepsItsBaseline|'
       'TestUnreadableFilesAreReportedOffTheEndpoint|'
       'TestAHealthyFIMDoesNotFlipTheFleetView|'
       'TestARecoveredFIMStopsReportingFailed|'
       'TestAnAbsentPathIsNotAFailure|TestAnAbsentPathStillCatchesCreation|'
       'TestAnUnreachableTargetIsNotAMassDeletion|'
       'TestAConfirmedAbsenceIsStillADeletion|'
       'TestTheSuppressionDoesNotOutliveTheBlock|'
       'TestTheDefaultFIMHashReaderIsTheRealOne|'
       'TestTheCaptureActuallySeesFIMEvents|TestFIM_')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/collector/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
