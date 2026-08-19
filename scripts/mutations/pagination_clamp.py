#!/usr/bin/env python3
"""頁送りの補完 —— 0 件と「数えられなかった」を同じ姿にしないこと。

対象:
  server/internal/api/handlers/pagination.go
  server/internal/api/handlers/pagination_contract_test.go
  server/internal/store/vulnerabilities.go
  server/internal/store/reproduced_logic_test.go
  agent/internal/agentcontract/reproduced_logic_test.go

`per_page` の補完は、同じ4行がハンドラの中に 21 か所ばらまかれていました。
**そのうち2か所には上限の行そのものがありませんでした。**
検査ファイルの側には `clampPage` / `clampPerPage` / `quarantineOffset` と
いう写しが置いてあり、試されていたのは写しの方だけです。

直す前に測りました (2026-08-12)。`/api/v1/vulnerabilities`:

    per_page 指定なし → 200 / 50件 / total=120
    per_page=0        → 200 / **0件** / total=120
    per_page=abc      → 200 / **0件** / total=120（Atoi が 0 を返します）
    per_page=-1       → **500**「脆弱性一覧の取得に失敗しました」
    per_page=100000   → 200 / **120件**（上限なし）

`/training/campaigns/:id/results` はもっと静かで、`per_page=-1` が
**200 の 0 件**で返ります（`LIMIT must not be negative` は警告ログに
落ちるだけ）。total は 80 と出るので、画面には「80件あるのに1件も
表示されない」が並びます。

**0 件と「数えられなかった」が同じ姿になるのがここでの害です。**

`internal/store` の側にはもう1つありました。件数の救済
（`if f.Limit == 0 { f.Limit = 50 }`）が `vulnListWhere` の中に書いて
あり、あの関数は `VulnFilter` を**値で**受け取ります。書き込みは写しの
上に落ちて、呼び出し側には届きません。**救済があるように見えて、
効いていませんでした。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  `pageOffset` の `(page-1)*perPage` を `page*perPage` にする変異も
  置いていません。`clampPageParams` の中で自分と突き合わせている
  ため、**同じ式を両側で使う検査は、両側が同時に変わると生き残ります**。
  代わりに `TestClampPageParamsNeverProducesANegativeOffset` が
  「OFFSET は負にならない」という**式に依らない性質**を留めます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

P = 'server/internal/api/handlers/pagination.go'
C = 'server/internal/api/handlers/pagination_contract_test.go'
V = 'server/internal/store/vulnerabilities.go'
VH = 'server/internal/api/handlers/vulnerabilities_handler.go'
TH = 'server/internal/api/handlers/training_handler.go'
R = 'server/internal/store/reproduced_logic_test.go'
AR = 'agent/internal/agentcontract/reproduced_logic_test.go'

CASES = [
    # ── 補完そのもの ─────────────────────────────────────────────────────
    (P, '\tif perPage < 1 || perPage > max {\n\t\treturn def\n\t}\n\treturn perPage',
        '\treturn perPage',
     '件数の補完を外す（0 がそのまま LIMIT 0 になり、「該当なし」と'
     '見分けが付きません）'),
    (P, '\tif perPage < 1 || perPage > max {\n\t\treturn def\n\t}',
        '\tif perPage > max {\n\t\treturn def\n\t}',
     '下限だけ外す（0 と負が通ります）'),
    (P, '\tif perPage < 1 || perPage > max {\n\t\treturn def\n\t}',
        '\tif perPage < 1 {\n\t\treturn def\n\t}',
     '上限だけ外す（per_page=100000 が全件返します）'),
    (P, '\tif perPage < 1 || perPage > max {\n\t\treturn def\n\t}',
        '\tif perPage < 1 || perPage >= max {\n\t\treturn def\n\t}',
     '上限ちょうどを弾く（境界が1つずれます）'),
    (P, '\tif perPage < 1 || perPage > max {\n\t\treturn def\n\t}\n\treturn perPage',
        '\tif perPage < 1 || perPage > max {\n\t\treturn 0\n\t}\n\treturn perPage',
     '範囲外を 0 に倒す（**まさに直した状態に戻ります**）'),
    (P, '\tif page < 1 {\n\t\treturn 1\n\t}\n\treturn page',
        '\treturn page',
     'ページの補完を外す（負の OFFSET を Postgres が拒否します）'),
    (P, '\tif page < 1 {\n\t\treturn 1\n\t}',
        '\tif page < 0 {\n\t\treturn 1\n\t}',
     'page=0 を通す（OFFSET が負になります）'),
    (P, '\treturn (page - 1) * perPage', '\treturn page * perPage',
     'オフセットが1ページぶんずれる'),
    (P, '\tpage = clampPage(page)\n\tperPage = clampPerPage(perPage, def, max)\n',
        '\n',
     'まとめ役が補完を呼ばなくなる'),
    (P, '\tperPage = clampPerPage(perPage, def, max)\n', '',
     'まとめ役が件数だけ補完しなくなる'),

    # ── ハンドラが本物を呼ぶこと ─────────────────────────────────────────
    (VH, '\tpage, limit, offset := clampPageParams(page, limit, 50, 200)',
         '\toffset := (page - 1) * limit',
     '脆弱性一覧が補完を呼ばなくなる（**元の実装**）'),
    (TH, '\tpage, limit, offset := clampPageParams(page, limit, 50, 200)',
         '\toffset := (page - 1) * limit',
     '訓練結果が補完を呼ばなくなる（**元の実装**）'),
    (VH, '"page": page, "per_page": limit})', '"page": page})',
     '脆弱性一覧が、実際に使った件数を名乗らなくなる'),
    (TH, '"page": page, "per_page": limit})', '"page": page})',
     '訓練結果が、実際に使った件数を名乗らなくなる'),

    # ── 走査が届いていること ─────────────────────────────────────────────
    (C, '\t\t\tif !readsPerPage {\n\t\t\t\tcontinue\n\t\t\t}',
        '\t\t\tif !readsPerPage || true {\n\t\t\t\tcontinue\n\t\t\t}',
     '`per_page` を読む関数を1つも見つけない（**0件を検査して緑**）'),
    (C, '\tcase "clampPageParams", "clampPerPage", "clampNotificationPage":',
        '\tcase "clampPageParams", "clampPerPage", "clampNotificationPage", "Atoi":',
     '補完の呼び出しの数え方を広げる（`strconv.Atoi` を呼べば通ります）'),
    (C, '\t\t\tif name == "pagination.go" {\n\t\t\t\tcontinue\n\t\t\t}',
        '\t\t\tif strings.HasSuffix(name, ".go") {\n\t\t\t\tcontinue\n\t\t\t}',
     '除外を広げて全ファイルを飛ばす'),

    # ── 件数の救済（値渡しの罠） ─────────────────────────────────────────
    (V, '\tf.Limit = clampVulnLimit(f.Limit)\n', '',
     '救済を呼ばなくなる（**元の実装。per_page=0 が 0 件返ります**）'),
    (V, '\tif limit < 1 || limit > maxVulnLimit {\n\t\treturn defaultVulnLimit\n\t}',
        '\tif limit > maxVulnLimit {\n\t\treturn defaultVulnLimit\n\t}',
     '救済の下限が外れる（0 と負が SQL へ届きます）'),
    (V, '\tdefaultVulnLimit = 50', '\tdefaultVulnLimit = 0',
     '救済先が 0 になる（救済しているのに 0 件返ります）'),
    (V, '\tf.Limit = clampVulnLimit(f.Limit)\n', '\tf.Limit = f.Limit\n',
     '救済が名前だけになる'),

    # ── 写しの見張り（サーバ） ───────────────────────────────────────────
    (R, 'const reproductionRoot = ".."', 'const reproductionRoot = "."',
     '走査を `internal/store` に戻す（**広げて見つかった7件が消えます**）'),
    (R, 'const minReproductionScan = 200', 'const minReproductionScan = 0',
     '走査の床を 0 に落とす（走査が壊れた日に、写しゼロと同じ緑を返します）'),
    (R, '\treturn scanned >= floor', '\treturn true',
     '走査が届いているかを見なくなる'),
    (R, 'var reproductionMarkers = []string{"テスト専用", "再現する", "テスト内ヘルパー"}',
        'var reproductionMarkers = []string{"テスト専用"}',
     '印の一覧を狭める（最初これで 13 件に見えていました）'),

    # ── 写しの見張り（agent） ────────────────────────────────────────────
    (AR, 'const agentReproductionRoot = "../.."', 'const agentReproductionRoot = "."',
     'agent 側の走査が `agentcontract` だけになる'),
    (AR, 'const minAgentScan = 90', 'const minAgentScan = 0',
     'agent 側で走査の床を 0 に落とす'),
    (AR, '\treturn scanned >= floor', '\treturn true',
     'agent 側で走査が届いているかを見なくなる'),
    (AR, 'var agentReproductionMarkers = []string{"テスト専用", "再現する", "テスト内ヘルパー"}',
         'var agentReproductionMarkers = []string{"テスト専用"}',
     'agent 側の印の一覧を狭める'),
    (AR, '\tif actual > ceiling {', '\tif actual > ceiling+100 {',
     'agent 側で、増えても言わなくなる'),
    (AR, '\tif actual < ceiling {', '\tif false {',
     'agent 側で、減っても言わなくなる'),
]

RUN = ('TestClampPerPage|TestClampPage|TestClampPageParams|TestEveryHandlerThatReadsPerPageClampsIt|'
       'TestListResponsesReportThePageSizeTheyActuallyUsed|TestQuarantineOffset|'
       'TestValidatePlaybookActionCount|TestClampIOCSeverity|TestOnlyTheRealClampCountsAsClamping|'
       'TestTheScanFloorNoticesAnEmptyWalk|TestThePageSizeCheckLooksAtTheResponseNotTheRequest')

SERVER_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         RUN + '|TestClampVulnLimit|TestVulnListWhereDoesNotPretendToRescueTheLimit|'
               'TestVulnStoreListCallsTheLimitRescue|TestTheLimitRescueIsNotHiddenInTheValueCopy|'
               'TestNoNewLogicIsReproducedInTests|TestTheReproductionCeilingComplainsBothWays|'
               'TestTheReproductionScanFloorNoticesAnEmptyWalk',
         './internal/api/handlers/', './internal/store/'],
    cwd='server',
)

AGENT_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoLogicIsReproducedInAgentTests|TestTheAgentReproductionCeilingComplainsBothWays|'
         'TestTheAgentMarkerListIsNotNarrowed|TestTheAgentScanFloorNoticesAnEmptyWalk',
         './internal/agentcontract/'],
    cwd='agent',
)

SERVER_CASES = [c for c in CASES if not c[0].startswith('agent/')]
AGENT_CASES = [c for c in CASES if c[0].startswith('agent/')]

if __name__ == '__main__':
    rc = SERVER_HARNESS.run(SERVER_CASES)
    rc |= AGENT_HARNESS.run(AGENT_CASES)
    sys.exit(rc)
