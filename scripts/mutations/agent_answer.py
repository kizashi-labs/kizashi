#!/usr/bin/env python3
"""agent 側の「失敗に値で答える」判定が、骨抜きにされたら気づけること。

対象:
  agent/internal/agentcontract/answered_with_a_value_test.go

サーバ側の同じ検査には守りがあります（server_answer.py）。**agent 側には
今回まで検査自体がありませんでした。** 数えるものが増えたので、数え方が
緩まないことも一緒に留めます。

緩め方はどれも1〜2行です。**コードは通り、検査も通り、報告される件数
だけが静かに正しくなくなります:**

  - 上限を上げる
  - 走査の範囲を狭める（internal/ だけ、build tag を尊重する、など）
  - 判定を緩める（記録だけの分岐を「対処した」に数える、など）
  - 端末に配られない QA 道具を製品の数に混ぜる

置いていない変異:

  検査そのものの assert 行を潰す変異は置いていません。**どのテストも
  殺せないからです** —— それは「そのテストを消す」のと同じです。
  置くと毎回 SURVIVED が並び、本物の生き残りがその中に埋もれます。

  代わりに、**判定が見るデータの側**を壊します。走査の根を変える、
  platform/ を外す、といった変異は、assert 行に触らずに答えを変えるので
  殺せます。実際 `agentRoot = "."` と `platform を外す` はどちらも
  killed です。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

G = 'agent/internal/agentcontract/answered_with_a_value_test.go'
R = 'agent/internal/response/executor.go'

CASES = [
    # ── 上限 ───────────────────────────────────────────────────────────────
    (G, '\tagentReturnCeiling   = 157', '\tagentReturnCeiling   = 400',
     'return の上限を上げる'),
    (G, '\tagentContinueCeiling = 45', '\tagentContinueCeiling = 100',
     'continue の上限を上げる'),
    (G, '\tagentNilErrCeiling = 0', '\tagentNilErrCeiling = 30',
     'nil を error の位置に置く箇所の上限を上げる'),
    (G, '\tharnessCeiling = 5', '\tharnessCeiling = 50',
     'QA 道具の上限を上げる'),

    # ── ラチェット（下回っても落ちること）─────────────────────────────
    (G, '\tif actual < ceiling {', '\tif false {',
     '実測が上限を下回っても言わなくなる'),
    (G, '\tif actual > ceiling {', '\tif false {',
     '実測が上限を超えても言わなくなる'),

    # ── 走査の範囲 ─────────────────────────────────────────────────────────
    (G, 'const agentRoot = "../.."', 'const agentRoot = "."',
     '走査を agentcontract ディレクトリだけに狭める'),
    (G, '\t\tif !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {',
        '\t\tif !strings.HasSuffix(path, ".go") || strings.Contains(path, "platform") {',
     'platform/ を走査から外す（windows と darwin が丸ごと消えます）'),

    # ── 判定そのもの ───────────────────────────────────────────────────────
    (G, '\t\t\tif !isLoggingCall(s.X) {\n\t\t\t\treturn "", false\n\t\t\t}',
        '\t\t\treturn "", false',
     '記録してから値を返す分岐が、見えなくなる'),
    (G, '\t\t\tif touches(s, errs) || returnsAnError(s) {\n\t\t\t\treturn "", false\n\t\t\t}',
        '\t\t\tif false {\n\t\t\t\treturn "", false\n\t\t\t}',
     'err を返す分岐まで「値で答えている」に数える'),
    (G, '\treturn recv == "slog" || recv == "log" || strings.Contains(recv, "log")',
        '\treturn true',
     '何でも「記録だけの呼び出し」に分類する'),

    # ── 製品と道具の切り分け ───────────────────────────────────────────────
    (G, '\treturn !shippedCmds["cmd/"+dir]',
        '\treturn true || !shippedCmds["cmd/"+dir]',
     'cmd/agent まで QA 道具として数から外す'),
    (G, '\treturn !shippedCmds["cmd/"+dir]',
        '\treturn false && !shippedCmds["cmd/"+dir]',
     'QA 道具を製品の数に混ぜる'),

    # ── 理由リスト ─────────────────────────────────────────────────────────
    (G, '\t"internal/hostmetrics/cpu.go:readMemInfo":       "同上",', '',
     '理由を1つ落とす（その箇所が上限に加算されます）'),
    (G, '\t"internal/collector/named_pipe.go:BuildNamedPipeEvent":                 marshalUnreachable,',
        '',
     'json.Marshal 系の理由を1つ落とす'),
    # 常駐メモリの読み取りは process_stats_coverage.py に移しました。
    # **「読めなかったら飛ばす」自体が欠陥になった**ので（同じ行で読めて
    # いた CPU まで捨てていました）、ここの変異は対象ごと消えています。
    (G, '\t"internal/hostmetrics/cpu.go:readProcStat":      "同上。ファイルを開けなかったことを false で返します",',
        '\t"internal/hostmetrics/cpu.go:readProcStatX":     "同上。ファイルを開けなかったことを false で返します",',
     '理由が、実在しない関数を指している'),

    # ── 隔離レポート ───────────────────────────────────────────────────────
    #
    # 数を減らした分の中身。**隔離したファイルが `/quarantine` の一覧に
    # 出ず、画面から復元できなくなる**、という状態でした。数字が減った
    # ことだけでは、それが直ったことになりません。
    (R,
     '\tif err := e.reportQuarantineToServer(ctx, cmd.AlertID, cmd.Path, fileSize, fileHash, quarantineID); err != nil {',
     '\tif err := e.reportQuarantineToServer(ctx, cmd.AlertID, cmd.Path, fileSize, fileHash, quarantineID); err == nil {',
     '記録が届かなかったことを、ack に載せなくなる'),
    (R,
     '\t\t\t[]byte(quarantineID+" (未記録: サーバの隔離一覧に出ません)"))',
     '\t\t\t[]byte(quarantineID))',
     'ack の中身が、全部通ったときと見分けられなくなる'),
    (R,
     '\t\te.ackSuccess(ctx, cmd.CommandID,\n\t\t\t[]byte(quarantineID+" (未記録: サーバの隔離一覧に出ません)"))',
     '\t\te.ackError(ctx, cmd.CommandID, "quarantine report failed")',
     '記録が落ちただけで、隔離そのものを失敗として返す'),
    (R,
     '\t\treturn fmt.Errorf("隔離レポートが拒否されました: HTTP %d", resp.StatusCode)',
     '\t\treturn nil',
     'サーバが拒否した (4xx/5xx) のを、届いたことにする'),
    (R,
     '\t\treturn fmt.Errorf("隔離レポートを送れません: %w", err)',
     '\t\treturn nil',
     '送れなかったのを、届いたことにする'),
    (R,
     '\t\treturn nil // サーバの宛先が無い構成。記録先が無いのは失敗ではありません',
     '\t\treturn fmt.Errorf("宛先がありません")',
     '宛先を持たない構成でも「未記録」を出す'),
    (R,
     '\t\t"quarantine_id": quarantineID,',
     '',
     '記録から隔離IDを落とす（届いても復元コマンドが指せません）'),
]

RUN = ('TestAgentFailuresAreNotAnsweredWithAValue|TestNoAgentReasonHasGoneStale|'
       'TestTheCeilingComplainsBothWays|TestTheScanReachesTheWholeModule|'
       'TestQuarantineRecordRejectedIsSurfaced|'
       'TestQuarantineRecordUnreachableIsSurfaced|'
       'TestQuarantineWithNoServerIsNotAFailure|'
       'TestQuarantineRecordCarriesWhatTheListNeeds|'
       'TestExecutor_QuarantineFile_Success')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/agentcontract/', './internal/response/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
