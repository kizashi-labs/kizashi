#!/usr/bin/env python3
"""接続プーラとテナントの絞り込み、そして捨てている書き込みの分類。

対象:
  deploy/docker/pgbouncer.ini
  server/internal/store/session_state_vs_pooler_test.go
  server/internal/api/handlers/discarded_write_reasons_test.go
  server/internal/api/handlers/discarded_write_test.go

## 接続プーラ

テナントの絞り込みは RLS が行い、その入力は接続のセッション変数
`app.tenant_id` 1つです。`docker-compose.scale.yml` は8つのサービス
全部を pgbouncer 経由にしていて、`pgbouncer.ini` は
`pool_mode = transaction` でした。

実測 (2026-08-12)。PostgreSQL 16.13 + pgbouncer 1.22、本番と同じプール
（PrepareConn = prepareConnForTenant）でテナント A の要求を 200 回:

    直接                        見えた行 1 が 200 回
    pgbouncer (transaction)     見えた行 2 が 199 回  ← 両テナント
    pgbouncer (session)         見えた行 1 が 200 回

`pool_mode = session` にしました。**その設定ファイル自身が「接続ごとに
SET/PREPARE を使うなら session が要る」と書いています。**

## 捨てている書き込みの分類

残り 44 か所（35 の関数）を読んで4つに分けました。**上限だけでは、
いま在る 44 が捨ててよいものかを誰も見ていません。**

置いていない変異:

  `docker-compose.scale.yml` の `@pgbouncer:` を消す変異は置いていません。
  **それは「プーラを使わない配置にする」で、検査が通るのは正しい
  ことです** —— 変異ではなく別の直し方です。

  分類の文言そのものへの変異は置いていません。文言は人が読むもので、
  機械が殺せるのは「分類名が4つのどれか」「中身が空でない」までです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

INI = 'deploy/docker/pgbouncer.ini'
P = 'server/internal/store/session_state_vs_pooler_test.go'
R = 'server/internal/api/handlers/discarded_write_reasons_test.go'
W = 'server/internal/api/handlers/discarded_write_test.go'

POOLER_CASES = [
    # ── 元の配置に戻す ───────────────────────────────────────────────────
    (INI, 'pool_mode       = session', 'pool_mode       = transaction',
     'transaction プーリングに戻る（**元の配置。テナント A の要求 200 回の'
     'うち 199 回が両テナントの行を見ました**）'),
    (INI, 'pool_mode       = session', 'pool_mode       = statement',
     'statement プーリングにする（もっと短い単位なので、同じことが起きます）'),

    # ── 判定 ─────────────────────────────────────────────────────────────
    (P, '\treturn v.sessionScoped && v.routed &&\n'
        '\t\t(v.poolMode == "transaction" || v.poolMode == "statement")',
        '\treturn false',
     '判定が何も言わなくなる'),
    (P, '(v.poolMode == "transaction" || v.poolMode == "statement")',
        '(v.poolMode == "statement")',
     '`transaction` を見逃す（**いまの配置がそれです**）'),
    (P, '(v.poolMode == "transaction" || v.poolMode == "statement")',
        '(v.poolMode == "transaction")',
     '`statement` を見逃す'),
    (P, '\treturn v.sessionScoped && v.routed &&', '\treturn v.sessionScoped &&',
     'プーラ経由かどうかを見ない（**プーラを使わない配置まで違反になります**）'),

    # ── 読む先 ───────────────────────────────────────────────────────────
    (P, '\tsessionScopedCall = "set_config(\'app.tenant_id\', $1, false)"',
        '\tsessionScopedCall = "set_config(\'app.tenant_id\', $1, true)"',
     'コードの側を読み違える（**「探したが無かった」で Fatal に落ちます**）'),
    (P, 'poolerConfigPath  = "../../../deploy/docker/pgbouncer.ini"',
        'poolerConfigPath  = "pgbouncer.ini"',
     '配られる設定ではなく、在りもしないファイルを読む'),
    (P, 'scaleComposePath  = "../../../docker-compose.scale.yml"',
        'scaleComposePath  = "../../../docker-compose.yml"',
     'プーラを使っていない compose を読む（**8つのサービスが数から'
     '消えます**）'),
    (P, 'var poolModeLine = regexp.MustCompile(`(?m)^\\s*pool_mode\\s*=\\s*(\\w+)`)',
        'var poolModeLine = regexp.MustCompile(`pool_mode\\s*=\\s*(\\w+)`)',
     'コメント行の pool_mode まで読む（**「; pool_mode = session」で'
     '通ります**）'),
    (P, '\trouted := strings.Count(string(compose), "@pgbouncer:")',
        '\trouted := strings.Count(string(compose), "@pgbouncer-nowhere:")',
     '配置がプーラを向いていることを読まなくなる（**床が落とします**）'),
    (P, 'const routedFloor = 5', 'const routedFloor = 0',
     '床を 0 に落とす（**読む先を間違えても黙ります**）'),
]

WRITE_CASES = [
    (R, '\t\tif _, ok := discardedWriteReasons[key]; !ok {',
        '\t\tif _, ok := discardedWriteReasons[key]; ok {',
     '分類されている箇所の方を違反にする'),
    (R, 'func isKnownWriteCategory(s string) bool {\n\tswitch s {',
        'func isKnownWriteCategory(s string) bool {\n\treturn true\n\tswitch s {',
     '自由文の分類を通す（**「あとで見る」が理由になります**）'),
    (R, 'const discardedWriteFuncs = 1', 'const discardedWriteFuncs = 0',
     '分類の件数を留めなくなる'),
    (R, '\tcatRestart:  0,', '\tcatRestart:  1,',
     '**分類を寄せる**（`covered` の1件を `restart` に数えたことにする。'
     '**0 が規則の分類に、黙って1件入ります**）'),
    (R, '\t\tif got[c] != want[c] {', '\t\tif false {',
     '分類ごとの数を見なくなる（**全部を1つに寄せられます**）'),
    (R, '\treturn strings.TrimSpace(reason[len(cat)+1:]) == ""', '\treturn false',
     '分類名だけ書いてあれば通す'),
    (R, '\t\tif !seen[reasonKeyBase(key)] {', '\t\tif !seen[key] {',
     '接尾辞つきの鍵を「宛先が消えた」に数える'),
    (R, 'func staleWriteReasonKeys(reasons map[string]string, seen map[string]bool) []string {\n\tvar out []string',
        'func staleWriteReasonKeys(reasons map[string]string, seen map[string]bool) []string {\n\treturn nil\n\tvar out []string',
     '消えた箇所の分類が残っても気づかなくなる'),
    (R, 'func reasonKeyBase(key string) string {\n\tif i := strings.Index(key, "-"); i > 0 {',
        'func reasonKeyBase(key string) string {\n\tif i := strings.Index(key, "-"); i < 0 {',
     '接尾辞を落とさなくなる'),
    (W, '\t\t\t\tkeys = append(keys, rel+":"+fn.Name.Name)\n', '',
     '分類の側に鍵が1つも渡らなくなる（**0件を検査して緑**）'),
]

# `run_mutations.py --check` はモジュール直下の CASES を読みます。
CASES = POOLER_CASES + WRITE_CASES

HARNESS_POOL = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestSessionScopedTenantStateIsNotBehindATransactionPooler|'
         'TestThePoolerRuleActuallyFires|TestThePoolerScanReadsRealFiles',
         './internal/store/'],
    cwd='server',
)

HARNESS_WRITE = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestEveryDiscardedWriteIsClassified|TestEveryWriteCategoryIsOneOfTheFour|'
         'TestTheWriteClassificationRuleActuallyFires|'
         'TestNoDiscardedWriteIsAnsweredWithSuccess|'
         'TestTheDiscardedWriteWalkReachesTheTree',
         './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    rc = HARNESS_POOL.run(POOLER_CASES)
    rc |= HARNESS_WRITE.run(WRITE_CASES)
    sys.exit(rc)
