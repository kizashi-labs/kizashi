#!/usr/bin/env python3
"""store の公開関数に、呼ぶ人がいるか — の判定が骨抜きにされたら。

対象:
  server/internal/store/reachable_test.go

フロントエンドに掛けた「宛先がサーバに無い呼び出し」の裏返しです。
あちらは呼ぶ側が宙に浮いていました。こちらは**呼ばれる側**です。

この判定を書いているあいだに、自分で3回同じ形を踏みました。仕様書は
その3つを固定します。

1. `[.\\b]` を文字クラスで書いたので \\b が後退文字になり、**ドットが
   前に付かない呼び出しを全部見落としていました。** 狭い照合は「私は
   この形しか見ていません」ではなく、数を報告します。
2. 「誰も呼ばない」の分岐が最初から無く、そこに落ちるものを黙って
   捨てていました。**いちばん鋭い種類が、判定から丸ごと消えていました。**
3. 宣言そのものの名前を「使用」に数えていたので、store で宣言された名前は
   すべて「store の中で使われている」に落ち、上の分岐は構造上たどり着け
   なくなっていました。上限0は「0件だった」ではなく「数える経路が無かった」
   です — continue の上限0とまったく同じ形でした。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

RT = 'server/internal/store/reachable_test.go'
AL = 'server/internal/store/alerts.go'

CASES = [
    # ── 上限と理由リスト ───────────────────────────────────────────────────
    (RT, 'const testOnlyCeiling = 28', '\tconst testOnlyCeiling = 50',
     'テストからしか呼ばれない関数の上限を上げる'),
    (RT, 'const testOnlyCeiling = 28', '\tconst testOnlyCeiling = 5',
     '上限が実測を下回っても言わなくなる、の逆確認'),
    # 理由リストは両方向に効きます。実在しない関数を指す項目は、
    # 「誰も呼ばない」を1件ぶん静かに消します。逆に、繋いだあとも残った
    # 項目は、まだ動いていないと読ませます。**後者で実際に落ちました** ——
    # AlertStore.WithEncryptor を cmd/api から呼んだとき、この検査が
    # 「もう誰も呼ばないではありません」と言って項目を消させました。
    (RT, '\t"AgentPolicyStore.GetForGroup": "グループ単位のポリシー取得。呼び出し側がおらず、"',
         '\t"AgentPolicyStore.GetForGroupX": "グループ単位のポリシー取得。呼び出し側がおらず、"',
     '理由が、実在しない関数を指している'),

    # ── 走査の広さ ─────────────────────────────────────────────────────────
    (RT, '\t\t\t\tif fn.Body != nil {\n\t\t\t\t\tadd(fn.Body)\n\t\t\t\t}',
         '',
     '関数の中身を歩かなくなる（本体からの呼び出しが全部消える）'),
    (RT, '\t\t\tif fn, ok := d.(*ast.FuncDecl); ok {',
         '\t\t\tif fn, ok := d.(*ast.FuncDecl); ok && false {',
     '宣言そのものの名前を「使用」に数える（誰も呼ばない、が構造上0になる）'),
    (RT, '\t\t\t\tif id, ok := x.(*ast.Ident); ok {\n\t\t\t\t\tout[id.Name] = true\n\t\t\t\t}',
         '',
     '識別子を1つも数えなくなる'),
    (RT, '\toutside := identsUnder(t, "../..", false, inStore)',
         '\toutside := identsUnder(t, ".", false, inStore)',
     '本番コードの走査を store ディレクトリだけに狭める'),
    (RT, '\tfromTests := identsUnder(t, "../..", true, nil)',
         '\tfromTests := map[string]bool{}',
     'テストからの呼び出しを見なくなる（写しが全部「誰も呼ばない」に化ける）'),

    # ── 分岐そのもの ───────────────────────────────────────────────────────
    (RT, '\t\tdefault:\n', '\t\tcase false:\n',
     '「誰も呼ばない」の分岐に、また落ちなくなる'),
    (RT, '\t\tcase inside[s.name]:', '\t\tcase len(inside) >= 0:',
     'store の中で使われている扱いが、何にでも当たる'),
    (RT, '\tfor q := range reasons {', '\tfor q := range map[string]string{} {',
     '古くなった理由を言わなくなる'),
    (RT, '\t\tif _, ok := reasons[q]; !ok {', '\t\tif false {',
     '理由の無い「誰も呼ばない」関数を言わなくなる'),

    # ここに無いもの:
    #
    # 「走査が届いているかの負の対照をやめる」「公開シンボルが0件でも進む」は、
    # 木がきれいなあいだ結果が変わらないので1箇所の変異では殺せません。
    # 走査が壊れたときにだけ効く保険で、壊れていない状態では効いても効かなくても
    # 同じ出力です。
    #
    # alerts.go の `if s.encryptor == nil` を反転する変異も置いていません。
    # **どのテストも通りません** — s.encryptor は本番で常に nil なので、
    # この分岐の暗号化側は一度も実行されず、覆っているテストもありません。
    # それ自体が neverCalledReasons に書いてある所見です。判定の穴ではなく、
    # 有効化されていない機能の話なので、変異では表現できません。
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    # -run に判定を直接動かす検査を入れ忘れると、判定を壊した変異が
    # 生き残ります。**このキャンペーンで4度目です。** 走っていない検査と、
    # 通った検査は、要約行が同じです。
    cmd=['go', 'test', '-count=1', '-run',
         'TestStoreSymbolsAreReachable|TestTheReachabilityRuleFires',
         './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
