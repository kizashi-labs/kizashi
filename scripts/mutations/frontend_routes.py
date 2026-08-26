#!/usr/bin/env python3
"""宛先・モック漏れ・作り物の数値を見ているゲート。

対象:
  frontend/tests/lib/server-routes.test.ts           （サーバに無い宛先を叩いていないか）
  frontend/tests/lib/mock-leak.test.ts               （MOCK_* が本番に出ていないか）
  frontend/tests/lib/fabricated-data.test.ts         （Math.random() / FALLBACK_*）
  frontend/tests/lib/backend-pending-coverage.test.ts（API の無い画面を告知しているか）

`server-routes` の上限 117 / 150 は、このキャンペーンで扱ってきた中で
**いちばん大きい数字なのに、一度も変異させていませんでした。** 大きい
上限ほど、下がったことに気づく機会が多いので安全に見えますが、逆です
— 走査を1つ狭めれば件数は下がり、ラチェットが「減りました、上限を
下げてください」と言うだけで、**狭めたことと直したことの区別は付きません。**
なので走査側（CALL_SITES / isUnrouted / hasRoute）も一緒に壊します。

`--isolated` で走らせてください。1回3〜4分かかります。

通しで 17/17 kill、生存0、SKIP 0（変異19以降を足す前の実測）。

**assertion 自身を潰す変異は置いていません。** `nav.includes(…)` を
`|| true` にする変異は、その assertion では検知できません（自分が
消されたことは自分では分かりません）。その assertion が効いていることは、
**本番側の変異**（`isBackendPending(href)` を `false` にする）が
殺されることで分かります —— そちらは置いてあり、殺せています。

**22 件の通しは、この環境では終わりませんでした (2026-08-12)。**
1変異あたり5つの vitest file を回すので約7分×22 ＝ 2.7 時間かかり、
コンテナの再起動に2回潰されました。今回足した/触った 7 件
（幻の経路2・告知の逆向き3・読み取り上限2）は、**それが関わりうる
2つの file だけ**を回して確かめてあります —— 7/7 kill、生存0。

**file を減らして増えうるのは「生き残り」であって、偽の kill では
ありません。** 減らした版で kill と出たものは、通しでも kill です
（通しは同じ判定に、さらに file を足すだけです）。逆に生き残りが
出たときは、その1件を通しで確かめ直す必要があります —— いまは
生存0なので、確かめ直す対象はありません。

残る 15 件は、この変更で触っていません（上限の値だけが 117→119 に
動いた2件は上の7件に含めてあります）。

最初の実行では「素の fetch を宛先の判定から外す」が生存と出ましたが、
**判定は在って、走らせていなかっただけ**でした（下の FILES を参照）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

SRO = 'frontend/tests/lib/server-routes.test.ts'
ML = 'frontend/tests/lib/mock-leak.test.ts'
FD = 'frontend/tests/lib/fabricated-data.test.ts'
BP = 'frontend/tests/lib/backend-pending-coverage.test.ts'
SB = 'frontend/components/layout/Sidebar.tsx'
MF = 'frontend/tests/lib/mutation-failure-surface.test.ts'

CASES = [
    # ── 呼び出しの見つけ方（型引数） ───────────────────────────────────────
    #
    # **`apiFetch<{ … }>(…)` の形を1件も拾っていませんでした。**
    # 型引数から `{` を除いていたためで、実測 154 件 / 90 file が判定の
    # 外にありました。**見えない呼び出しは、宛先が無くても数に出ません。**
    (SRO, '{ re: /\\bapiFetch(?:List)?\\s*(?:<[^()]*?>)?\\s*\\(/g, pathArg: 0 },',
          '{ re: /\\bapiFetch(?:List)?\\s*(?:<[^;{]*?>)?\\s*\\(/g, pathArg: 0 },',
     '**型引数に object を書いた呼び出しを見なくなる**（元の姿。'
     '154 件が判定の外に出ます）'),

    # ── SDK と mobile ──────────────────────────────────────────────────────
    #
    # **照合していたのは `frontend/` だけ**でした。SDK は配布物なので、
    # 宛先が違えば利用者の呼び出しがそのまま 404 になります。
    (SRO, """    for (const m of src.matchAll(/["'`](GET|POST|PUT|PATCH|DELETE)["'`]\\s*,\\s*f?[`'"]([^`'"]+)[`'"]/g)) {
      add(m[1], m[2], toPosix(f).replace(toPosix(repo) + '/', ''))
    }""",
          '    // 走査しない\n',
     '**SDK の呼び出しを1本も見なくなる**（宛先が違っても数に出ません）'),
    # **通しで出た唯一の生き残りでした (2026-08-13)。** 合計の床が 40 で、
    # python 25 + typescript 24 だけでも 49 残るので、mobile の 5 本が丸ごと
    # 消えても検査は緑のままでした。配布物ごとの床を入れて殺せるように
    # なりました。
    (SRO, "    for (const m of src.matchAll(/\\bapi\\.(get|post|put|patch|delete)(?:<[^>]*>)?\\(\\s*[`'\"]([^`'\"]+)[`'\"]/g)) {",
          '    for (const m of [] as RegExpMatchArray[]) {',
     '**mobile の呼び出しを見なくなる**'),
    (SRO, '  mobile: 5,\n', '  mobile: 0,\n',
     'mobile の床を 0 にする（消えても言わなくなります）'),
    (SRO, "    for (const k of Object.keys(out)) if (c.where.startsWith(k)) out[k]++",
          '    void c',
     '**配布物ごとに数え分けなくなる**（どの配布物も 0 本と答えます）'),
    (SRO, "    raw.split('?')[0].replace(/\\$\\{[^}]*\\}/g, ':p').replace(/\\{[^}]*\\}/g, ':p')",
          "    raw.split('?')[0].replace(/\\$\\{[^}]*\\}/g, ':p')",
     '**`{alert_id}` を経路のパラメータとして扱わなくなる**（Python SDK の'
     '宛先が全部「無い」になります）'),

    # ── 宛先の prefix ─────────────────────────────────────────────────────
    #
    # **`/api/v1` で始まる宛先しか見ていませんでした。** サーバは
    # `/taxii2` も出しているので、**版のついていない宛先は、間違って
    # いても数に出ません**でした。17 件出て、うち 13 件は本当に
    # ルートがありません（ITDR の読み取り3本は書き間違いでした）。
    (SRO, "      if (!literal.startsWith('/')) continue",
          '      if (!literal.startsWith(API_PREFIX)) continue',
     '**版のついていない宛先を見なくなる**（元の姿。`/api/itdr/…` も'
     '`/api/nta/…` も、間違っていることが数に出ません）'),

    # ── group 変数の解決（幻の経路） ───────────────────────────────────────
    #
    # **同じ名前が別の場所で別の path に束ねられているのが 19 個**あります
    # （`ep` は `/endpoints` と `/admin/edr-policies`）。union すると
    # 存在しない経路が生まれ、`:id` は1 segment に何でも当たるので、
    # **無い宛先が「サーバにある」として数から消えます。**
    (SRO, '      const d = local[local.length - 1]', '      const d = local[0]',
     '**いちばん遠い宣言**で解決する（別の幻が生まれます）'),
    (SRO, '    const local = (perSource[i].get(name) ?? []).filter(d => d.at < at)',
          '    const local: Decl[] = []',
     '**file ごとの表を使わなくなる**（元の姿。19 個の変数が'
     '幻の経路を作ります）'),

    # ── 告知の逆向き ───────────────────────────────────────────────────────
    (BP, 'const ANNOUNCED_BUT_ALIVE_CEILING = 0',
         '  const ANNOUNCED_BUT_ALIVE_CEILING = 100',
     '**告知したまま届く画面**の上限を上げる（動いている機能が'
     '「準備中」と言い続けます）'),
    (BP, 'const ANNOUNCED_BUT_ALIVE_CEILING = 0',
         '  const ANNOUNCED_BUT_ALIVE_CEILING = 3',
     '上限が実測を下回っても言わなくなる、の逆確認'),
    (BP, '    const routed = calls.filter(c => !isUnrouted(c, routes))',
         '    const routed = calls.filter(c => isUnrouted(c, routes))',
     '**届く呼び出しと届かない呼び出しを取り違える**'),

    # ── 一部だけ届かない画面 ───────────────────────────────────────────────
    #
    # **これまで見ていたのは「全部死んでいる画面」だけ**でした。一部だけ
    # 死んでいる画面は、動く区画があるぶん見分けにくい形です。
    (BP, '  const PARTLY_DEAD_CEILING = 0', '  const PARTLY_DEAD_CEILING = 300',
     '一部だけ届かない画面の上限を上げる'),
    # **2026-08-17 に 38 → 0 になりました**（38 画面すべてを告知）。
    # 0 は上限ではなく規則なので、「下回っても言わない」の逆確認は
    # 意味を持ちません —— `NAKED_MUTATION_CEILING = 0` と同じ形で、
    # **少しだけ許す**方を2つ目に置きます。
    (BP, '  const PARTLY_DEAD_CEILING = 0', '  const PARTLY_DEAD_CEILING = 10',
     '**告知されていない画面を10枚まで許す**（0 が規則です）'),
    (BP, "  if (bad === total) return 'dead'", "  if (bad === total) return 'partly'",
     '**全部死んでいる画面を「一部だけ」に数える**（告知済みの画面が'
     '二重に出ます）'),
    (BP, "  if (bad === 0) return 'clean'", "  if (bad === 0) return 'partly'",
     '**全部届く画面まで「一部だけ」に数える**'),
    (BP, '      if (announced.full.has(route) || announced.partial.has(route)) continue',
         '      if (announced.full.has(route)) continue',
     '**「一部準備中」の告知を見なくなる**（告知してあるのに'
     '違反として挙がります）'),

    # ── 補間の展開 ─────────────────────────────────────────────────────────
    #
    # クエリを組み立てる入れ子の内側を「最後の補間」と読んでいたので、
    # **動いている 2 件が `…/items:p` という存在しない経路**として
    # 報告されていました。
    (SRO, "    if (quote === '`' && src[i] === '$' && src[i + 1] === '{') { interp++; i++; continue }\n",
          '',
     '**入れ子のテンプレートで literal を切る**（元の姿。補間の途中で'
     '終わる literal が、存在しない経路として報告されます）'),

    # ── 失敗を出せない mutation ────────────────────────────────────────────
    #
    # 既存の判定は**画面ごと**で、「1つでもあれば通る」形でした ——
    # `/incidents/[id]` は 13 のうち 11 が裸のまま通っていました。
    (MF, '  const NAKED_MUTATION_CEILING = 0', '  const NAKED_MUTATION_CEILING = 500',
     '失敗を出せない mutation の上限を上げる（0 が規則です）'),
    (MF, '  const NAKED_MUTATION_CEILING = 0', '  const NAKED_MUTATION_CEILING = 10',
     '**裸の mutation を10本まで許す**（0 が規則です）'),
    (MF, '  return Math.max(0, mutations - perMutation)', '  return 0',
     '**どの画面も裸ゼロと答える**（数が動かなくなります）'),
    (MF, "  if (/<PageSaveFailed/.test(clean) || /<SaveFailed/.test(clean) || /\\busePersist\\s*\\(/.test(clean)) {",
         "  if (false) {",
     '**画面全体の帯を見なくなる**（覆えている画面まで裸に数えます）'),

    # ── サイドバーの「準備中」 ─────────────────────────────────────────────
    #
    # **サイドバーの 292 項目のうち 60 が準備中**です（実測 2026-08-12）。
    # 印が無ければ、動く 232 と見分けがつきません。
    (BP, 'const NAV_PENDING = 0', '  const NAV_PENDING = 300',
     'サイドバーに出ている準備中の上限を上げる'),
    (BP, 'const NAV_PENDING = 0', '  const NAV_PENDING = 10',
     '上限が実測を下回っても言わなくなる、の逆確認（サイドバー）'),
    (SB, '              const pending = isBackendPending(href)',
         '              const pending = false',
     '**サイドバーが印を出さなくなる**（60 の準備中が、動く 232 と'
     '同じ顔で並びます）'),

    # ── 宛先の上限 ─────────────────────────────────────────────────────────
    (SRO, 'const UNROUTED_READ_CEILING = 129', 'const UNROUTED_READ_CEILING = 300',
     'ルートの無い読み取りの上限を上げる'),
    (SRO, 'const UNROUTED_READ_CEILING = 129', 'const UNROUTED_READ_CEILING = 50',
     '上限が実測を下回っても言わなくなる、の逆確認（読み取り）'),
    (SRO, 'const UNROUTED_WRITE_CEILING = 17', 'const UNROUTED_WRITE_CEILING = 400',
     'ルートの無い書き込みの上限を上げる'),

    # ── 走査の広さ（狭めると件数は「下がる」）──────────────────────────
    (SRO, '  { re: /(?<![.\\w])fetch\\s*\\(/g, pathArg: 0 },\n', '',
     '素の fetch を宛先の判定から外す'),
    (SRO, '  { re: /\\bpersist\\s*\\(/g, pathArg: 1 },\n', '',
     'persist を宛先の判定から外す'),
    (SRO, '  return call.paths.every(p => !hasRoute(call.method, p, routes))',
          '  return call.paths.some(p => !hasRoute(call.method, p, routes))',
     '候補パスが1つでも無ければ「宛先が無い」に数える'),
    (SRO, '    if (matchesRoute(entry.slice(sp + 1), bare)) return true',
          '',
     ':id を含むルートに当たらなくなる（全部「宛先が無い」になる）'),
    (SRO, '  if (entry.slice(0, sp) !== method) continue',
          '  if (false) continue',
     'メソッドを見ずに、パスさえ合えば宛先があることにする'),

    # ── モック漏れ ─────────────────────────────────────────────────────────
    (ML, 'const MOCK_LEAK_CEILING = 0', 'const MOCK_LEAK_CEILING = 10',
     'モック漏れの上限を0から上げる'),
    (ML, 'export function guardedByUseMock(clean: string, at: number, levels = 4): boolean {',
         'export function guardedByUseMock(clean: string, at: number, levels = 0): boolean {',
     '囲みを1段も遡らなくなる（USE_MOCK の外側の守りが見えなくなる）'),

    # ── 作り物の数値 ───────────────────────────────────────────────────────
    (FD, 'const RANDOM_VALUE_CEILING = 1', 'const RANDOM_VALUE_CEILING = 100',
     'Math.random() の上限を上げる'),
    (FD, 'const RANDOM_VALUE_CEILING = 1', 'const RANDOM_VALUE_CEILING = 5',
     '上限が実測を下回っても言わなくなる、の逆確認（乱数）'),
    (FD, 'const FALLBACK_FILE_CEILING = 0', 'const FALLBACK_FILE_CEILING = 10',
     'FALLBACK_* を持つファイル数の上限を0から上げる'),
    (FD, 'const UNGUARDED_RANDOM_CEILING = 0', 'const UNGUARDED_RANDOM_CEILING = 10',
     '説明の無い乱数の上限を0から上げる'),
    (FD, "  return src.split('\\n').filter(l => !/^\\s*(\\/\\/|\\*|\\/\\*)/.test(l))",
         "  return src.split('\\n')",
     'コメントの中の Math.random() を、作り物として数える'),

    # ── 準備中の告知 ───────────────────────────────────────────────────────
    (BP, '    if (!announced.full.has(route) && !announced.partial.has(route)) {',
         '    if (false) {',
     '告知の無い死んだ画面を、言わなくなる'),
    (BP, '      return calls.length > 0 && calls.every(c => isUnrouted(c, routes))',
         '      return calls.length > 0 && calls.some(c => isUnrouted(c, routes))',
     '1本でも届かなければ「API がすべて届かない画面」に数える'),
]

FILES = [
    'tests/lib/server-routes.test.ts',
    'tests/lib/mock-leak.test.ts',
    'tests/lib/fabricated-data.test.ts',
    'tests/lib/backend-pending-coverage.test.ts',
    # raw-fetch は「宛先の判定が素の fetch を見ているか」を持っています。
    # 最初はこれを外していたので、CALL_SITES から素の fetch を落とす変異が
    # 生き残り、**それを捕まえる検査が無いのだと読み違えました。** 検査は
    # 在って、走らせていなかっただけです。この取り違えはこのキャンペーンで
    # 3度目で、3度とも私の絞り込みの側でした。
    'tests/lib/raw-fetch.test.ts',
    # **4度目です (2026-08-13)。** MF の4件は
    # mutation-failure-surface.test.ts を書き換えるのに、その file を
    # 走らせていませんでした。`NAKED_MUTATION_CEILING = 0` には
    # `expect(...).toBe(0)` が在って、上限を 10 や 500 に上げれば必ず
    # 赤になります —— **走らせていなかったので、2件が生き残りました。**
    # 通しで回して初めて出ました。絞り込み版では、この2件は一度も
    # 実行されていません。
    'tests/lib/mutation-failure-surface.test.ts',
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['npx', 'vitest', 'run'] + FILES,
    cwd='frontend',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
