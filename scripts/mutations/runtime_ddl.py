#!/usr/bin/env python3
"""出荷するコードが DDL を発行していないか。

対象:
  server/internal/api/handlers/runtime_ddl_test.go
  server/internal/scheduler/retro_rule_hunter.go

「テナントの絞り込みが接続プーラの下で外れる」を直す前段で、**既定の
compose では RLS がそもそも一切効いていない**ことが分かりました。
`POSTGRES_USER: edr` は postgres イメージが SUPERUSER として作るロールで、
`APP_DATABASE_URL` は既定で空 —— 4サービスとも所有者ロールに落ちるので、
`FORCE ROW LEVEL SECURITY` すら素通りします。

最小権限ロール edr_app（migration 325）へ切り替えようとして、実測で
止まりました:

    SET ROLE app_probe;
    CREATE TABLE IF NOT EXISTS endpoint_tags (...);
    ERROR:  permission denied for schema public

**テーブルが既に存在していても落ちます。** PostgreSQL は存在チェックより
先にスキーマの CREATE 権限を見ます。本番コードには 11 テーブル分の DDL が
残っていて、**11 すべてに migration があった**ので全部冗長でした ——
それでも 7 つのハンドラは `ensureTable` の error を返しており、切り替えた
瞬間に 500 になるところでした。

**皮肉なことに、エラーを握り潰さないよう直した結果**、握り潰されずに
表面化する側に回っていました。

理由は権限だけではありません。ランタイム DDL は「どのエンドポイントを、
どの順で開いたか」で実配備のスキーマが変わるということで、migration の
履歴を読む道具（全 SELECT をスキーマに突き合わせる検査を含む）からは
見えません。migration 443 が同じことを書いています。

**0 が規則です。上限ではありません。**

## 判定の形

    非テストの .go の文字列リテラルの中に
    CREATE TABLE / CREATE INDEX / CREATE EXTENSION / CREATE SCHEMA /
    ALTER TABLE / DROP TABLE / DROP INDEX
    があること

コメントは文字列リテラルではないので、migration を説明するために
`CREATE TABLE` を引用しているコメント（何か所かあります）は数えません
—— **実際に DB へ送れる文だけ**を見ます。

## 置いていない変異

**木がきれいなあいだ、結果が変わらない壊し方**は置いていません。1箇所
だけ壊すハーネスでは殺せません —— 初版で3つ置いてしまい、3つとも
SURVIVED しました:

  * 床（`minDDLScanFiles`）を 0 にする。DDL が 0 件なら出力は同じです。
  * 「解析できなかった」の報告を消す。読めない file が1つも無いので
    同じです。
  * 「古くなった例外」の報告を消す。例外がすべて使われているので同じです。

**assertion は、自分が消されたことを自分では検知できません。** 3つとも、
汚した入力を渡す判定側のテストに移しました:

    TestTheDDLScanReportsWhatItCouldNotRead   壊れた .go を食わせる
    TestStaleAllowancesAreFound               使われない例外を食わせる

そのうえで、**判定そのもの**を壊す変異に置き換えてあります（走査が
読めない file を忘れる／棚卸しの条件を反転する）。床が効いていることは、
**走査の根を狭める変異**と **.go を1つも拾わない変異**がそこで殺される
ことで分かります。

`ddlAllowed` に新しい file を足す変異も置いていません。例外が増えたことは
`TestNoRuntimeDDL` から見て正常な状態です。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/api/handlers/runtime_ddl_test.go'
R = 'server/internal/scheduler/retro_rule_hunter.go'
W = 'server/internal/scheduler/retro_watermark_test.go'
L = 'server/internal/ldap/connector.go'

CASES = [
    # ── 判定そのもの ─────────────────────────────────────────────────────
    #
    # 正規表現を骨抜きにすると、木がきれいなあいだは 0 件のまま緑です。
    # **負の対照（TestRuntimeDDLScanCanSee）が無いと、ここは全部生き残り
    # ます。**
    (T, r"`(?is)\b(CREATE\s+(TABLE|INDEX|UNIQUE\s+INDEX|EXTENSION|SCHEMA)|ALTER\s+TABLE|DROP\s+(TABLE|INDEX))\b`",
        r"`(?is)\bCREATE\s+TABLESPACE\b`",
     '**判定を、実際には出てこない語だけにする**（DDL 全部が素通りします）'),
    (T, r"`(?is)\b(CREATE\s+(TABLE|INDEX|UNIQUE\s+INDEX|EXTENSION|SCHEMA)|ALTER\s+TABLE|DROP\s+(TABLE|INDEX))\b`",
        r"`(?s)\b(CREATE\s+(TABLE|INDEX|UNIQUE\s+INDEX|EXTENSION|SCHEMA)|ALTER\s+TABLE|DROP\s+(TABLE|INDEX))\b`",
     '**大文字小文字を区別する**（`create table` が素通りします）'),
    (T, r"`(?is)\b(CREATE\s+(TABLE|INDEX|UNIQUE\s+INDEX|EXTENSION|SCHEMA)|ALTER\s+TABLE|DROP\s+(TABLE|INDEX))\b`",
        r"`(?is)\bCREATE (TABLE|INDEX)\b`",
     '**`\\s+` を空白1つに固定する**（改行やタブを挟んだ DDL —— '
     'この木で実際に多い形 —— が素通りします）'),

    # ── 走査の広さ ───────────────────────────────────────────────────────
    #
    # `cmd/` を走査の外に置いたせいで周期処理8本が長く数えられていなかった
    # ことがあります。同じ形を繰り返さないため、server 配下を全部見ます。
    (T, 'const ddlScanRoot = "../../.."', 'const ddlScanRoot = "."',
     '**handlers だけを歩く**（store/migrate.go も cmd/ も走査の外に'
     '出ます）'),
    (T, 'const ddlScanRoot = "../../.."', 'const ddlScanRoot = "../.."',
     '**internal だけを歩く**（`cmd/` のランタイム DDL が見えなく'
     'なります）'),

    # ── 床 ───────────────────────────────────────────────────────────────
    (T, '\t\tif !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {',
        '\t\tif !strings.HasSuffix(path, ".goX") || strings.HasSuffix(path, "_test.go") {',
     '**.go を1つも拾わない**（床がここで殺します）'),

    # ── 走査が黙って飛ばさないこと ───────────────────────────────────────
    #
    # 判定側（`scanRuntimeDDL` の返り値）を壊します。**報告する行を消す
    # 変異は置いていません** —— 木がきれいなあいだ読めない file は1つも
    # 出ないので、結果が変わりません。下の2つは
    # `TestTheDDLScanReportsWhatItCouldNotRead` が汚した入力で殺します。
    (T, '\t\t\tout.unreadable = append(out.unreadable, rel)',
        '\t\t\t_ = rel',
     '**解析できなかった file を走査が忘れる**（読めない file が'
     '「DDL は無い」と同じ答えになります）'),
    (T, '\t\tif !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {\n'
        '\t\t\treturn nil\n\t\t}',
        '\t\tif !strings.HasSuffix(path, ".go") {\n\t\t\treturn nil\n\t\t}',
     '**_test.go も数える**（出荷しないコードの DDL が違反になります）'),

    # ── 例外の棚卸し ─────────────────────────────────────────────────────
    #
    # 同じ理由で、報告する行ではなく判定そのものを壊します。
    # `TestStaleAllowancesAreFound` が殺します。
    (T, '\tvar stale []string\n\tfor f := range allowed {\n\t\tif !used[f] {\n'
        '\t\t\tstale = append(stale, f)\n\t\t}\n\t}',
        '\tvar stale []string\n\tfor f := range allowed {\n\t\tif used[f] {\n'
        '\t\t\tstale = append(stale, f)\n\t\t}\n\t}',
     '**古くなった例外の判定を反転する**（使われている例外を古いと言い、'
     '本当に古い行を見逃します）'),
    (T, 'func notAllowed(sites []ddlSite, allowed map[string]string) []ddlSite {\n'
        '\tvar kept []ddlSite',
        'func notAllowed(sites []ddlSite, allowed map[string]string) []ddlSite {\n'
        '\treturn nil\n\tvar kept []ddlSite',
     '**例外でない DDL も落とす**（どんな DDL も例外扱いになります）'),

    # ── 実際に DDL を戻す ────────────────────────────────────────────────
    #
    # ここが本番です。**判定が生きていれば、これは殺されます。**
    (R, '\tif _, err := h.pool.Exec(ctx,\n'
        '\t\t`INSERT INTO retro_rule_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {',
        '\tif _, err := h.pool.Exec(ctx,\n'
        '\t\t`CREATE TABLE IF NOT EXISTS retro_rule_state (id INT PRIMARY KEY)`); err != nil {',
     '**ensureState に CREATE TABLE を戻す**（edr_app では必ず'
     'permission denied になり、遡及ハントが毎 tick 黙って止まります）'),
]

# 置いていない変異:
#
# `ldap/connector.go` の `CREATE TABLE IF NOT EXISTS ad_users` を戻す変異は
# 置いていません。**`TestNoRuntimeDDL` と `discarded_write_test.go` の
# 両方が落ちるので、どちらが効いたのか分かりません。** 戻す形の代表は
# 上の retro_rule_hunter で見ています（あちらは error を返すので、
# 捨てている書き込みの数には出ません）。
_ = (W, L)

# 2 package を1つの走行で回します。retro_rule_hunter に DDL を戻す変異は
# `internal/scheduler` の検査が殺し、それ以外は `internal/api/handlers` の
# 検査が殺します。**別々に回すと、片方だけ緑でも気づけません。**
# **`-run` に負の対照を入れ忘れないこと。** 初版は入れ忘れていて、
# それらが殺すはずの変異2件がそのまま生き残りました ——
# **走らせていない検査は、無い検査と同じです。**
HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoRuntimeDDL|'
         'TestRuntimeDDLScanCanSee|'
         'TestTheDDLScanReportsWhatItCouldNotRead|'
         'TestStaleAllowancesAreFound|'
         'TestPreparingTheStateIssuesNoDDL',
         './internal/api/handlers/', './internal/scheduler/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
