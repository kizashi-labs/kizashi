#!/usr/bin/env python3
"""1行読みの error を捨てないこと（api/handlers と internal/scheduler の外）。

対象:
  server/internal/store/discarded_read_test.go
  server/internal/reports/generator.go
  server/internal/audit/logger.go
  server/internal/store/alerts.go
  server/internal/store/yara_rules.go
  server/internal/api/router.go

実測 (2026-08-12): `server/internal` 全体で 338 か所。
`api/handlers` 248・`internal/scheduler` 32・**その外 58**。
前の2つは別の検査が 9 と 11 に留めています。ここは残りの 58 —— **7 まで
下げました。**

    api/router.go            25  `handlers.ReadOK(c, err)`（gin のクロージャ）
    reports/generator.go     11  error を返せるので返します
    compliance/evaluator.go   4  同上
    audit/logger.go           4  同上（1つは一覧の総件数 —— ページャの母数）
    behavioral 2・detectionmetrics 1・support 1・incidents 1
    store/alerts.go           1  変更前の状態（履歴の「何から」）
    store/yara_rules.go       1  既存確認（「作成しました」と返る分岐）

**綴じられた報告書の 0 は、あとから「その期間は 0 件だった」として
読まれます。** 画面のカードと違って、消えません。

残る 7 は error を返せない関数か、行が無いのが普通の経路です。理由を
書いてあり、理由の側も宛先が実在することを見ています。

置いていない変異:

  理由つきの 7 か所への変異は置いていません。**直す対象ではないからです。**
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/store/discarded_read_test.go'
G = 'server/internal/reports/generator.go'
A = 'server/internal/audit/logger.go'
AL = 'server/internal/store/alerts.go'
Y = 'server/internal/store/yara_rules.go'

CASES = [
    (G, '\tif err := g.pool.QueryRow(ctx, `\n'
        '\t\t\tSELECT COUNT(*) FROM alerts\n'
        '\t\t\tWHERE severity >= 9 AND created_at BETWEEN $1 AND $2\n'
        '\t\t`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.CriticalAlerts); err != nil {\n'
        '\t\treturn nil, fmt.Errorf("数えられないため報告を作りません: %w", err)\n\t}\n',
        '\t_ = g.pool.QueryRow(ctx, `\n'
        '\t\t\tSELECT COUNT(*) FROM alerts\n'
        '\t\t\tWHERE severity >= 9 AND created_at BETWEEN $1 AND $2\n'
        '\t\t`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.CriticalAlerts)\n',
     'エグゼクティブ報告書の「重大アラート」が、読めなかった 0 として'
     '綴じられる（元の実装）'),
    (A, '\tif err := l.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {\n'
        '\t\treturn nil, 0, fmt.Errorf("監査ログの件数を数えられません: %w", err)\n\t}\n',
        '\t_ = l.pool.QueryRow(ctx, countQuery, args...).Scan(&total)\n',
     '監査ログの総件数が 0 になる（**ページャの母数なので、1ページ目が'
     '「全部」に見えます**）'),
    (AL, '\t\tif err := s.pool.QueryRow(ctx, "SELECT status FROM alerts WHERE id = $1", id).\n'
         '\t\t\tScan(&prevStatus); err != nil && !errors.Is(err, pgx.ErrNoRows) {\n'
         '\t\t\treturn fmt.Errorf("変更前の状態を読めません: %w", err)\n\t\t}\n',
         '\t\t_ = s.pool.QueryRow(ctx, "SELECT status FROM alerts WHERE id = $1", id).Scan(&prevStatus)\n',
     'アラート履歴の「何から変わったか」が空になる（**嘘が記録に'
     '残ります**）'),
    (Y, '\tif err := s.pool.QueryRow(ctx, `SELECT id FROM yara_rules WHERE name = $1`, in.Name).\n'
        '\t\tScan(&existingID); err != nil && !errors.Is(err, pgx.ErrNoRows) {\n'
        '\t\treturn false, fmt.Errorf("既存のYARAルールを確認できません: %w", err)\n\t}\n',
        '\t_ = s.pool.QueryRow(ctx, `SELECT id FROM yara_rules WHERE name = $1`, in.Name).Scan(&existingID)\n',
     '既存の YARA ルールが「新規」に倒れる（**利用者には「作成しました」と'
     '返ります**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, 'const discardedReadSites = 1', 'const discardedReadSites = 100',
     '留めている数を実測から引き離す'),
    (T, '\treturn reasons[key] == ""\n', '\treturn false\n',
     '理由の無い箇所を1件も挙げなくなる'),
    (T, '\t\tif !seen[key] {\n\t\t\tstale = append(stale, key)\n\t\t}\n', '\t\t_ = key\n',
     '宛先の消えた理由が残っても気づかなくなる'),
    (T, '\tid, ok := as.Lhs[0].(*ast.Ident)\n\tif !ok || id.Name != "_" {\n\t\treturn false\n\t}\n',
        '\tif _, ok := as.Lhs[0].(*ast.Ident); !ok {\n\t\treturn false\n\t}\n',
     '`_ =` 以外の受け方まで数える'),
    (T, 'var scanSkip = []string{"api/handlers/", "scheduler/"}',
        'var scanSkip = []string{"api/handlers/", "scheduler/", "reports/", "audit/"}',
     '直した package を走査から外す（**「探したが無かった」を'
     '「無い」と読み違えます**）'),
    (T, 'const scanFileFloor = 400', 'const scanFileFloor = 0',
     '走査の床を 0 に落とす'),
]

RUN = ('TestNoDiscardedRowReadOutsideTheTwoCoveredPackages|'
       'TestTheDiscardedScanDetectorRecognisesTheRealThing|'
       'TestTheStaleScanReasonListRecognisesTheRealThing|'
       'TestTheDiscardedScanWalkReachesTheTree|'
       'TestTheReadSiteJudgementRecognisesTheRealThing|'
       'TestTheScanFloorAndSkipListAreNotHollowedOut')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
