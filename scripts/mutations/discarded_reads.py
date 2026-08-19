#!/usr/bin/env python3
"""1行読みの error を捨てないこと。

対象:
  server/internal/scheduler/discarded_read_test.go
  server/internal/scheduler/compliance_scorer.go
  server/internal/scheduler/daily_briefing_scheduler.go
  server/internal/scheduler/digest_scheduler.go
  server/internal/scheduler/alert_digest_sender.go
  server/internal/scheduler/billing_grace_worker.go
  server/internal/scheduler/darkweb_scheduler.go

`_ = pool.QueryRow(…).Scan(&n)` は、**読めなかった 0 と本当の 0 を同じ形に
します。** 前回「存在確認」の3か所を直しましたが、あれは同じ形の一部でした。

実測 (2026-08-12): `server/internal` に 338 か所、うち `internal/scheduler`
が 32。**21 か所は、その 0 が何かを決めていました**:

    compliance_scorer          6  0 がそのままスコアになり、履歴テーブルに
                                  残ります（あとから「その日は低かった」と
                                  読まれます）
    daily_briefing_scheduler   5  朝のメールに「緊急アラート 0件」
    digest_scheduler           4  日次ダイジェストに「クリティカル 0件」
    alert_digest_sender        4  同上 —— **読んだ人にとって最も安心できる行**
    billing_grace_worker       1  **購読数が読めないと、購読中のテナントの
                                  ライセンスを Free に落としていました**
    darkweb_scheduler          1  キャッシュが読めないことと「まだ無い」が
                                  同じ形で、照合が行われません

残る 11 か所は重複の抑止です。読めなかった 0 は「まだ無い」に倒れ、同じ
アラートがもう1件出るだけ —— **出過ぎる方向**なので理由を書いて外します。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです。**

  重複抑止の 11 か所への変異も置いていません。**直す対象ではないからです** ——
  理由を一覧に書いてあり、一覧が効いていることは判定を潰す変異が見ています。

  「存在確認を二重に挙げない」除外への変異も置いていません。**いま
  `server/internal` に捨てている存在確認は 0 件で**（`internal/store` の
  検査が留めています）、除外を外しても挙がる件数が変わらないためです。
  除外そのもの（`isExistenceProbe`）は切り出してあり、見本を食わせる
  検査が見ています。

  `internal/scheduler` の外の 306 か所は、この仕様書の対象外です。
  **測ってはいますが、直していません** —— api/handlers の 248 が
  どれも同じ重みとは限らないので、次の回に分けます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/scheduler/discarded_read_test.go'
CS = 'server/internal/scheduler/compliance_scorer.go'
DB = 'server/internal/scheduler/daily_briefing_scheduler.go'
DS = 'server/internal/scheduler/digest_scheduler.go'
AD = 'server/internal/scheduler/alert_digest_sender.go'
BG = 'server/internal/scheduler/billing_grace_worker.go'
DW = 'server/internal/scheduler/darkweb_scheduler.go'

CASES = [
    # ── 直した箇所（どれも元の実装に戻します） ───────────────────────────
    (CS, '\tif err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents); err != nil {\n'
         '\t\tfail(ctx, err, "コンプライアンススコア: エージェント数を数えられないため記録しません")\n\t\treturn\n\t}\n',
         '\t_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents)\n',
     'エージェント数が読めなくても、**0 のままスコアにして履歴に書く**'
     '（元の実装）'),
    (CS, '\tif err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&totalRules); err != nil {\n'
         '\t\tfail(ctx, err, "コンプライアンススコア: ルール総数を数えられないため記録しません")\n\t\treturn\n\t}\n',
         '\t_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&totalRules)\n',
     'ルール総数が読めなくても、そのままスコアにする（元の実装）'),
    (CS, '\tif err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&alertCount); err != nil {\n'
         '\t\tfail(ctx, err, "コンプライアンススコア: アラート総数を数えられないため記録しません")\n\t\treturn\n\t}\n',
         '\t_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&alertCount)\n',
     'アラート総数が読めなくても、そのままスコアにする（元の実装）'),
    (DB, '\t\tif err := s.pool.QueryRow(ctx, c.sql).Scan(c.into); err != nil {\n'
         '\t\t\treturn nil, fmt.Errorf("%sを数えられません: %w", c.what, err)\n\t\t}\n',
         '\t\t_ = s.pool.QueryRow(ctx, c.sql).Scan(c.into)\n',
     '朝のブリーフィングが、**数えられなかった 0 を「緊急アラート 0件」'
     'として送る**（元の実装）'),
    (DS, '\t\tif err := d.pool.QueryRow(ctx, c.sql, c.args...).Scan(c.into); err != nil {\n'
         '\t\t\tfail(ctx, err, "日次ダイジェスト: 数えられないため送りません", "what", c.what)\n\t\t\treturn\n\t\t}\n',
         '\t\t_ = d.pool.QueryRow(ctx, c.sql, c.args...).Scan(c.into)\n',
     '日次ダイジェストが、**数えられなかった 0 を「クリティカル 0件」'
     'として送る**（元の実装）'),
    (AD, '\t\tif err := s.pool.QueryRow(ctx, c.sql, since).Scan(c.into); err != nil {\n'
         '\t\t\treturn nil, fmt.Errorf("%s のアラート数を数えられません: %w", c.what, err)\n\t\t}\n',
         '\t\t_ = s.pool.QueryRow(ctx, c.sql, since).Scan(c.into)\n',
     'アラートダイジェストが、数えられなかった 0 を件数として送る'
     '（元の実装）'),
    (BG, '\tif err := w.pool.QueryRow(ctx,\n\t\t`SELECT COUNT(*) FROM billing_subscriptions`,\n'
         '\t).Scan(&totalCount); err != nil {\n'
         '\t\tfail(ctx, err, "課金猶予: 購読数を数えられないため降格しません")\n\t\treturn\n\t}\n',
         '\t_ = w.pool.QueryRow(ctx,\n\t\t`SELECT COUNT(*) FROM billing_subscriptions`,\n\t).Scan(&totalCount)\n',
     '**購読数が読めないだけで、購読中のテナントのライセンスを Free に'
     '落とす**（元の実装。戻すのは人の手です）'),
    (DW, '\tswitch err := s.pool.QueryRow(ctx,\n'
         '\t\t`SELECT raw_posts FROM darkweb_ransomware_sites WHERE onion_url = \'__cache__\'`,\n'
         '\t).Scan(&rawPosts); {\n'
         '\tcase errors.Is(err, pgx.ErrNoRows):\n\t\treturn // まだ一度も同期していません。失敗ではありません。\n'
         '\tcase err != nil:\n\t\tfail(ctx, err, "darkweb: キャッシュした投稿一覧を読めず、照合を行いませんでした")\n\t\treturn\n\t}\n',
         '\t_ = s.pool.QueryRow(ctx,\n'
         '\t\t`SELECT raw_posts FROM darkweb_ransomware_sites WHERE onion_url = \'__cache__\'`,\n'
         '\t).Scan(&rawPosts)\n\t_, _ = errors.Is, pgx.ErrNoRows\n',
     'キャッシュが読めないことと「まだ無い」が、また同じ形になる'
     '（元の実装。照合は静かに行われません）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, '\tid, ok := as.Lhs[0].(*ast.Ident)\n\tif !ok || id.Name != "_" {\n\t\treturn false\n\t}\n',
        '\tif _, ok := as.Lhs[0].(*ast.Ident); !ok {\n\t\treturn false\n\t}\n',
     '`_ =` 以外の受け方まで「捨てている」に数える（**直した箇所が'
     '全部違反として並びます**）'),
    (T, '\tsel, ok := call.Fun.(*ast.SelectorExpr)\n\treturn ok && sel.Sel.Name == "Scan"',
        '\t_, ok = call.Fun.(*ast.SelectorExpr)\n\treturn ok',
     '`Scan` 以外の捨てている呼び出しまで数える'),
    (T, '\treturn strings.Contains(sql, "information_schema") || strings.Contains(sql, "pg_tables")',
        '\treturn strings.Contains(sql, "select")',
     '普通の集計まで「存在確認」として除く（**走査から丸ごと外れます**）'),
    (T, 'const minDiscardedReads = 5', 'const minDiscardedReads = 0',
     '走査の床を 0 に落とす'),
    (T, 'const discardedReadSiteCount = 11', 'const discardedReadSiteCount = 100',
     '件数を留めなくなる（**同じ関数に増やした分が、鍵の検査では'
     '見えません**）'),
    (T, '\treturn reasons[s.key()] == ""\n', '\treturn false\n',
     '理由の無い箇所を1件も挙げなくなる'),
    (T, 'func (s readSite) key() string { return s.file + ":" + s.fn }',
        'func (s readSite) key() string { return s.file }',
     '理由の宛先をファイル単位にする（**同じファイルの別の関数が、'
     '書いてある理由で通ります**）'),
    (T, '\t\tif !seen[key] {\n\t\t\tstale = append(stale, key)\n\t\t}\n', '\t\t_ = key\n',
     '宛先の消えた理由が残っても気づかなくなる'),
]

RUN = ('TestEveryDiscardedRowReadHasAReason|'
       'TestTheDiscardedReadScanRecognisesTheRealThing|'
       'TestTheDiscardedReadFloorNoticesAnEmptyWalk|'
       'TestNoExistenceProbeThrowsAwayItsError')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/scheduler/', './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
