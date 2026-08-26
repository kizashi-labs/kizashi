#!/usr/bin/env python3
"""書き込みを捨てたまま「保存しました」と答えないこと。

対象:
  server/internal/api/handlers/discarded_write_test.go
  server/internal/api/handlers/errs.go
  server/internal/api/handlers/software_vulnerability_handler.go
  server/internal/api/handlers/dns_security_handler.go
  server/internal/api/handlers/recovery_code_handler.go

読み取りの `_ = QueryRow(…).Scan(…)` は 338 → 16 まで下げました。
**書き込みの `_, _ = Exec(…)` は一度も測っていませんでした。**

実測 (2026-08-12): `server/internal` に 122 か所。**うち 55 は、そのあと
200/201/202 で答える関数の中**にありました —— 状態を変えたと答えながら、
1行も書いていないことがあります:

    software_vulnerability:UpdateStatus  UPDATE を捨てて `{"status": 変更後}`
    dns_security:DeleteBlocklistEntry    DELETE を捨てて "entry removed"
    recovery_code:Generate               **利用者が控える復旧コード**を、
                                         保存を確かめずに返す（MFA の最後の手段）
    identity_handler:SaveConfig          INSERT が失敗したときの UPDATE を
                                         捨てる —— どちらも書けずに「保存」

`WriteOK(c, err)` に通しました（55 → 0、全体 122 → 54）。さらに
`internal/scheduler` の 10 か所を `fail(ctx, err, …)` に通して 44 ——
**周期の仕事には「回」があるので、書けなかったことが `last_success` に
出ます**:

    backup_scheduler   完了の記録（**書けないと、取れたバックアップが
                       「実行中」のまま残り、しかも SLO の成功時刻は
                       押されます**）／失敗の記録
    darkweb_scheduler  被害の検知行 ×2（**アラートと通知は出るのに、
                       一覧には無い**）／投稿キャッシュ／死活 ×2
    heartbeat_monitor  オフライン化（**落ちている端末が画面では
                       「オンライン」のまま**）
    retro_rule_hunter  watermark
    version_checker    バージョン分布 —— ここだけ 42P01 を通します
**`ReadOK` と違って「まだ無い」を通しません** —— 読み取りなら「テーブルが
まだ無い」は事実ですが、書き込みでそれが起きたら、書けていないのに
「保存しました」と答えることになります。

置いていない変異:

  docstring への変異は置いていません。**どのテストも殺せないからです。**

  残り 54 か所への変異は置いていません。**答えを返さない経路**
  （goroutine の後始末、ベストエフォートの記録）で、直す対象では
  ありません。増える方向には数で留めています。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/api/handlers/discarded_write_test.go'
# 共有ヘルパ (answersWithSuccess) は判定ファイルの外に出した。
# 判定ファイルの中に置くと、その 1 本を外した配置でコンパイルごと落ちる。
AH = 'server/internal/api/handlers/scan_ast_helpers_test.go'
E = 'server/internal/api/handlers/errs.go'
SV = 'server/internal/api/handlers/software_vulnerability_handler.go'
DS = 'server/internal/api/handlers/dns_security_handler.go'
RC = 'server/internal/api/handlers/recovery_code_handler.go'
BS = 'server/internal/scheduler/backup_scheduler.go'
HM = 'server/internal/scheduler/heartbeat_monitor.go'
VC = 'server/internal/scheduler/version_checker.go'
HB = 'server/internal/scheduler/heartbeat.go'

VC_NOW = """\tif _, err := v.pool.Exec(ctx,
\t\t`INSERT INTO system_metadata (key, value, updated_at)
         VALUES ('agent_version_distribution', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
\t\tstring(summary),
\t); err != nil && !tableMissing(err) {
\t\tfail(ctx, err, "エージェントのバージョン分布を保存できませんでした")
\t}
"""

VC_WAS = """\t_, _ = v.pool.Exec(ctx,
\t\t`INSERT INTO system_metadata (key, value, updated_at)
         VALUES ('agent_version_distribution', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
\t\tstring(summary),
\t)
\t_ = tableMissing
"""

CASES = [
    # ── 直した箇所（元の実装に戻します） ─────────────────────────────────
    (SV, '\tif _, err := h.pool.Exec(c.Request.Context(),\n'
         '\t\t`UPDATE vulnerability_findings SET status=$1, updated_at=NOW() WHERE id=$2`,\n'
         '\t\treq.Status, id); !WriteOK(c, err) {\n\t\treturn\n\t}\n',
         '\t_, _ = h.pool.Exec(c.Request.Context(),\n'
         '\t\t`UPDATE vulnerability_findings SET status=$1, updated_at=NOW() WHERE id=$2`,\n'
         '\t\treq.Status, id)\n',
     '脆弱性の状態変更が、**書けていなくても「変更しました」と答える**'
     '（元の実装）'),
    (DS, '\t\tif _, err := h.pool.Exec(c.Request.Context(), `DELETE FROM dns_blocklist WHERE id=$1`, id); !WriteOK(c, err) {\n\t\t\treturn\n\t\t}\n',
         '\t\t_, _ = h.pool.Exec(c.Request.Context(), `DELETE FROM dns_blocklist WHERE id=$1`, id)\n',
     'ブロックリストの削除が、**消えていなくても "entry removed" と答える**'
     '（元の実装）'),

    (HM, '\tif _, err := m.pool.Exec(ctx,\n'
         "\t\t`UPDATE agents SET status='offline', updated_at=NOW() WHERE id=$1`, agentID); err != nil {\n"
         '\t\tfail(ctx, err, "エージェントをオフラインにできませんでした", "agent_id", agentID)\n\t}\n',
         '\t_, _ = m.pool.Exec(ctx,\n'
         "\t\t`UPDATE agents SET status='offline', updated_at=NOW() WHERE id=$1`, agentID)\n",
     'オフライン化が書けなくても黙る（**落ちている端末が画面では'
     '「オンライン」のままです**）'),
    (VC, VC_NOW, VC_WAS,
     'バージョン分布が書けなくても黙る（**元の実装。DB が応答しない'
     'だけでも「任意のテーブル」と同じ扱いです**）'),
    (HB, '\treturn errors.As(err, &pgErr) && pgErr.Code == "42P01"',
         '\treturn errors.As(err, &pgErr)',
     '**どの DB エラーも「テーブルが無い」に数える**（DB が応答しない'
     'だけで黙ります）'),

    # ── 仕組みそのもの ───────────────────────────────────────────────────
    (E, '\tif err == nil {\n\t\treturn true\n\t}\n\tc.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})\n\treturn false\n}\n\n// absent reports',
        '\treturn true\n}\n\n// absent reports',
     '`WriteOK` が、書けていなくても「書けた」と答える（**直した 68 か所が'
     '全部そのまま元に戻ります**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, 'const discardedWritesThatClaimSuccess = 0', 'const discardedWritesThatClaimSuccess = 100',
     '「成功として答えている」件数を留めなくなる'),
    (T, 'const discardedWritesTotal = 0', 'const discardedWritesTotal = 500',
     '全体の件数を留めなくなる'),
    (T, 'const writeScanRoot = "../.."', 'const writeScanRoot = ".."',
     '走査の根を1つ上までにする（**`internal/api` しか見ず、5 か所に'
     'なります**）'),
    (T, '\tcase "Exec", "SendBatch", "CopyFrom":\n\t\treturn true\n',
        '\tcase "ExecXXX":\n\t\treturn true\n',
     '捨てている書き込みを1つも見つけなくなる（**0 件を検査して緑**）'),
    (T, '\t\tif id, ok := l.(*ast.Ident); !ok || id.Name != "_" {\n\t\t\treturn false\n\t\t}\n',
        '\t\tif _, ok := l.(*ast.Ident); !ok {\n\t\t\treturn false\n\t\t}\n',
     '`_, _ =` 以外の受け方まで数える'),
    (AH, '\tcase "StatusOK", "StatusCreated", "StatusAccepted":\n\t\t\tfound = true\n',
        '\tcase "StatusOKXXX":\n\t\t\tfound = true\n',
     '200/201 を成功と見なくなる（**「保存しました」と答えている関数が'
     '全部素通りします**）'),
]

RUN = ('TestNoDiscardedWriteIsAnsweredWithSuccess|'
       'TestTheDiscardedWriteScanRecognisesTheRealThing|'
       'TestTheDiscardedWriteWalkReachesTheTree|'
       'TestWriteOKDoesNotForgiveAnything')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN + '|TestTableMissingIsOnly42P01',
         './internal/api/handlers/', './internal/scheduler/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
