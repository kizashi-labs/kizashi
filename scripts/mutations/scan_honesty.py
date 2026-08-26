#!/usr/bin/env python3
"""走査が file を黙って飛ばさないこと。

対象:
  server/internal/tick/scan_honesty_test.go
  server/internal/store/reachable_test.go
  server/internal/store/probe_error_test.go
  server/internal/scheduler/discarded_read_test.go
  server/internal/api/handlers/discarded_read_test.go

このリポジトリの検査は、ソースを AST で歩いて数を留めます。歩き方が
`parser.ParseFile` の失敗を黙って飛ばしていると、**その file は走査から
消えます** —— 中に何が書いてあっても 0 件です。

**変異検査が実際に通り抜けました。** 実測 (2026-08-12):

    internal/tick           元の実装に戻す変異が 3件 生き残った
    internal/api/handlers   同じ形で 1件

構文を壊した file は、`go test` の対象 package でなければコンパイルも
走りません。**壊したことに誰も気づかず、走査からも消えて、検査は緑**
でした。

`server/internal` の `*_test.go` を数えたら 16 か所（`return nil` 12、
`continue` 4）。全部直して、`TestNoScanSwallowsAParseFailure` が 0 を
留めます。

置いていない変異:

  `os.ReadFile` の失敗を飛ばす形には変異を置いていません。**同じ形です
  が、変異検査が実際に通り抜けたのは parse の方**です。検査もそちらしか
  見ていません —— 広げるなら、広げたことが分かるようにします。

  直した 16 か所すべてへの変異は置いていません。**1つ戻せば
  `silentParseSkips` が 0 から 1 になります** —— 代表して4か所（歩き方
  2つ・ループ2つ）に置いてあります。

  「1つだけの文か」を `len(b.List) != 1` から `< 1` に緩める変異は置いて
  いません。**通る木でも見本でも同じ答えになります** —— 先頭が
  `continue` で、そのあとに文が続くブロックは書けない（到達しない）
  ためです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/tick/scan_honesty_test.go'
RE = 'server/internal/store/reachable_test.go'
PE = 'server/internal/store/probe_error_test.go'
SD = 'server/internal/scheduler/discarded_read_test.go'
HD = 'server/internal/api/handlers/discarded_read_test.go'

SWALLOW_LOOP = '''\t\tf, parseErr := parser.ParseFile(fset, path, src, 0)
\t\tif parseErr != nil {
\t\t\t// **黙って飛ばすと、その file は走査から消えます** ——
\t\t\t// 中に何が書いてあっても 0 件になります。
\t\t\tt.Fatalf("%s を parse できません: %v", path, parseErr)
\t\t}'''
SWALLOW_LOOP_WAS = '''\t\tf, parseErr := parser.ParseFile(fset, path, src, 0)
\t\tif parseErr != nil {
\t\t\tcontinue
\t\t}'''

CASES = [
    # ── 直した箇所を元に戻す（代表4か所） ────────────────────────────────
    (RE, '\t\tf, perr := parser.ParseFile(fset, path, nil, 0)\n\t\tif perr != nil {\n'
         '\t\t\t// **黙って飛ばすと、その file は走査から消えます。**\n\t\t\treturn perr\n\t\t}',
         '\t\tf, perr := parser.ParseFile(fset, path, nil, 0)\n\t\tif perr != nil {\n'
         '\t\t\treturn nil // 生成物や壊れたファイルは飛ばします\n\t\t}',
     '到達判定の走査が、壊れた file を黙って飛ばす（**元の実装。'
     'コメントに意図まで書いてありました**）'),
    (PE, '\t\tf, parseErr := parser.ParseFile(fset, rel, src, 0)\n\t\tif parseErr != nil {\n'
         '\t\t\t// **黙って飛ばすと、その file は走査から消えます。**\n\t\t\treturn parseErr\n\t\t}',
         '\t\tf, parseErr := parser.ParseFile(fset, rel, src, 0)\n\t\tif parseErr != nil {\n'
         '\t\t\treturn nil\n\t\t}',
     '存在確認の走査が、壊れた file を黙って飛ばす'),
    (SD, SWALLOW_LOOP, SWALLOW_LOOP_WAS,
     '`internal/scheduler` の捨てた読み出しの走査が、壊れた file を飛ばす'),
    (HD, SWALLOW_LOOP, SWALLOW_LOOP_WAS,
     'ハンドラの捨てた読み出しの走査が、壊れた file を飛ばす'),

    # ── 判定と件数 ───────────────────────────────────────────────────────
    (T, 'const silentParseSkips = 0', 'const silentParseSkips = 100',
     '件数を留めなくなる'),
    (T, 'const minParseFileCalls = 40', 'const minParseFileCalls = 0',
     '**走査の床を外す**（0 件が「無い」なのか「探していない」なのか'
     '分からなくなります）'),
    (T, '\t\tif s.Tok == token.CONTINUE {\n\t\t\treturn "continue", true\n\t\t}',
        '\t\tif s.Tok == token.BREAK {\n\t\t\treturn "continue", true\n\t\t}',
     '`continue` で飛ばす形を見なくなる（**実測では 4 か所ありました**）'),
    (T, '\t\t\tif id, ok := s.Results[0].(*ast.Ident); ok && id.Name == "nil" {\n'
        '\t\t\t\treturn "return nil", true\n\t\t\t}',
        '\t\t\tif id, ok := s.Results[0].(*ast.Ident); ok && id.Name == "err" {\n'
        '\t\t\t\treturn "return nil", true\n\t\t\t}',
     '`return nil` の代わりに `return err` を違反にする（**向きが逆です**）'),
    (T, '\tid, ok := sel.X.(*ast.Ident)\n\treturn ok && id.Name == "parser"',
        '\tid, ok := sel.X.(*ast.Ident)\n\treturn ok && id.Name != ""',
     '`parser` 以外の `ParseFile` まで数える'),
    (T, '\tif !ok || sel.Sel.Name != "ParseFile" {\n\t\treturn false\n\t}',
        '\tif !ok || sel.Sel.Name != "ParseDir" {\n\t\treturn false\n\t}',
     '`ParseFile` ではなく `ParseDir` を探す（**0 件を検査して緑**）'),
    (T, '\t\tif ev.Name == "_" {', '\t\tif ev.Name == "zzz" {',
     'error を `_` に捨てている形を見なくなる'),
    (T, '\t\tif perr != nil {\n\t\t\treturn perr\n\t\t}\n'
        '\t\trel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))',
        '\t\tif perr != nil {\n\t\t\treturn nil\n\t\t}\n'
        '\t\trel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))',
     '**この検査自身が、壊れた file を黙って飛ばす**'),
]

RUN = ('TestNoScanSwallowsAParseFailure|TestTheParseSkipRuleActuallyFires|'
       'TestTheParseSkipScanDoesNotSkipABrokenFile')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/tick/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
