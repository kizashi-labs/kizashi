#!/usr/bin/env python3
"""フロントエンドのゲートが骨抜きにされたら気づけること。

対象:
  frontend/tests/lib/blank-noise.ts               （すべての判定の下ごしらえ）
  frontend/tests/lib/raw-fetch.test.ts            （素の fetch の応答確認）
  frontend/tests/lib/mutation-failure-surface.test.ts （保存の失敗を出す手段）
  frontend/tests/lib/catch-scan.ts                （読み取りの失敗を答えにすり替える走査）
  frontend/tests/lib/silent-writes.test.ts        （書き込みの失敗を握りつぶす）

`blank-noise.ts` を最初に置いているのは、**5本すべてがこれを通した後の
文字列しか見ないから**です。ここが1つ見落とすと、その範囲はどの判定からも
消えます。正規表現リテラルを知らなかったあいだ、9ファイル・1,668行が
どのゲートにも映っていませんでした。**空白になったコードは、無いコードと
同じ形をしています。**

1回の実行に3分ほどかかります（判定が app/ + components/ + lib/ を毎回
読み直すため）。15件で50分近くになるので、CI には載せていません。

最初に通したとき、1件だけ生き残りました: `respondsToFailure` の窓を次の
fetch の手前で切る行です。**判定は直っていましたが、それを守るものが
ありませんでした。** ソースのコメントには /settings/cloud で実際に起きた
ことまで書いてあるのに、その形の検査が無かったので、行を消しても誰も
気づきません。`raw-fetch.test.ts` に検査を足しました。

その後 `--isolated` で通し直して 15/15 kill、生存0、SKIP 0。

なお blank-noise.ts は fabricated-verdict.test.ts の中にありました。7本の
ゲートがそこから import していたので、**どれを走らせてもあちらのテストが
丸ごと一緒に走ります** — 65秒かかるものを含めて。道具として import した
テストファイルは、その実行を連れてきます。この仕様書を書くために時間を
測って気づきました。

**同じことが3組で残っていました (2026-08-19)。** swallowed-reads /
mock-leak / server-routes が道具として import されており、走査が
借りた側の収集のたびに動いていました。道具は catch-scan.ts /
mock-scan.ts / route-scan.ts に出してあります。上の 3 件が
`swallowed-reads.test.ts` ではなく `catch-scan.ts` を指しているのは
そのためです。戻らないように no-test-imports.test.ts が見ています。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

BN = 'frontend/tests/lib/blank-noise.ts'
CS = 'frontend/tests/lib/catch-scan.ts'
RF = 'frontend/tests/lib/raw-fetch.test.ts'
MF = 'frontend/tests/lib/mutation-failure-surface.test.ts'
SW = 'frontend/tests/lib/silent-writes.test.ts'

CASES = [
    # ── 下ごしらえ（ここが漏れると、全ゲートが同時に目を潰されます）──────
    (BN, "    if (c === '/' && regexCanStartHere(out.join(''))) {",
         "    if (false) {",
     '正規表現リテラルを、また文字列として読む（引用符の対応がずれる）'),
    (BN, "  if ('(,=:[!&|?{};+-*~%^'.includes(last)) return true",
         "  if ('(,=:[!&|?{};+-*~%^<'.includes(last)) return true",
     'JSX の閉じタグ </div> を正規表現の開始として読む'),
    (BN, "        else if (src[j] === '\\n') break // 1行で閉じない = 正規表現ではなかった",
         "        else if (src[j] === '\\n') { j += 1; continue }",
     '1行で閉じない / を正規表現として食べ続ける'),

    # ── 素の fetch ─────────────────────────────────────────────────────────
    (RF, "const RAW = /(?<![.\\w])fetch\\s*\\(/g",
         "const RAW = /fetch\\s*\\(/g",
     'refetch() を fetch として数え始める'),
    (RF, "    if (new RegExp(`\\\\b${V}\\\\.status\\\\b`).test(text)) return true",
         '',
     'res.status を見ている箇所を「確かめていない」に数える'),
    (RF, "  const nextFetch = clean.slice(end).search(/(?<![.\\w])fetch\\s*\\(/)",
         "  const nextFetch = -1",
     '隣の fetch が書いた !r.ok を、こちらの確認として数える'),
    (RF, "  'lib/auth.tsx':\n    'ログアウトの投げっぱなし。サーバ側のセッション失効が失敗しても、' +",
         "  'lib/auth.tsx.gone':\n    'ログアウトの投げっぱなし。サーバ側のセッション失効が失敗しても、' +",
     '理由が、もう存在しないファイルを指している'),

    # ── 保存の失敗を出す手段 ───────────────────────────────────────────────
    (MF, "    /\\bonError\\s*:/.test(clean) ||        // その mutation で個別に出す",
         '',
     'onError を「失敗を出す手段」と数えなくなる'),
    (MF, "  return /\\buseMutation\\s*[<(]/.test(clean)",
         "  return /\\buseMutationX\\s*[<(]/.test(clean)",
     '走査が useMutation を1つも見つけなくなる'),
    (MF, "      const clean = blankNoise(f.src)\n      return hasMutations(clean) && !showsSaveFailures(clean)",
         "      const clean = f.src\n      return hasMutations(clean) && !showsSaveFailures(clean)",
     'コメントの中の onError を、手段として数える'),

    # ── 読み取りの失敗 ─────────────────────────────────────────────────────
    (CS, 'const SWALLOWED_READ_CEILING = 3', 'const SWALLOWED_READ_CEILING = 30',
     '読み取りを握りつぶす箇所の上限を上げる'),
    (CS, 'const SWALLOWED_READ_CEILING = 3', 'const SWALLOWED_READ_CEILING = 0',
     '上限が実測を下回っても言わなくなる、の逆確認'),
    (CS, "  'app/status/page.tsx':\n    'サービス状態ページ。読めなかったこと自体がこの画面の出力です — ' +",
         "  'app/status/page.tsx.gone':\n    'サービス状態ページ。読めなかったこと自体がこの画面の出力です — ' +",
     '理由が、もう存在しないファイルを指している'),

    # ── 書き込みの失敗 ─────────────────────────────────────────────────────
    (SW, 'const SILENT_WRITE_CEILING = 0', 'const SILENT_WRITE_CEILING = 10',
     '黙って捨てる書き込みの上限を0から上げる'),
    (SW, "  'app/live-response/page.tsx':\n"
         "    'useEffect の後始末で、コンポーネントが消える瞬間にセッションを閉じます。' +",
         "  'app/live-response/page.tsx.gone':\n"
         "    'useEffect の後始末で、コンポーネントが消える瞬間にセッションを閉じます。' +",
     '理由が、もう存在しないファイルを指している'),
]

FILES = [
    'tests/lib/blank-noise.ts',  # 走らせる対象ではありませんが、変異の対象です
    'tests/lib/fabricated-verdict.test.ts',  # blankNoise 自身の検査
    'tests/lib/raw-fetch.test.ts',
    'tests/lib/mutation-failure-surface.test.ts',
    'tests/lib/swallowed-reads.test.ts',
    'tests/lib/silent-writes.test.ts',
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['npx', 'vitest', 'run'] + [f for f in FILES if f.endswith('.test.ts')],
    cwd='frontend',
    # vitest は構文エラーを Transform failed / Failed to load として出します。
    # 判定が落ちたのではないので kill には数えません。
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
