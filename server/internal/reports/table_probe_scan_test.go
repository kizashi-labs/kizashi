package reports

import (
	"os"
	"strings"
	"testing"
)

// この package が、表の有無を自前で確かめに戻っていないこと。
//
// ## 何を守っているのか
//
// 表の有無は `store.TableIsThere` が答えます。**あれは確認そのものの失敗を
// 「無い」と答えません**（store/table_probe.go）。自前で
// `information_schema` を引くと、その判断を迂回して、**DB に届かなかった
// だけの回を「その表は無い」に倒します。**
//
// ここは予定表（`scheduled_reports`）の確認に使っています。倒れると
// **予定されたレポートが、何もしないまま正常終了します。** 誰も見ていない
// ので、止まっていることに気づく手掛かりがありません。
//
// ## なぜ「ゼロ」で留めるのか
//
// これを留めていたのは `internal/api/handlers/table_probe_test.go` でしたが、
// **上流はそのファイルを公開版に同梱しないと決めました**（#74 が
// `NOT_SHIPPED.txt` に足しています）。戻しても次の同期で消えます。
//
// 元の検査は `internal` 全体を見て、1 件ずつ理由を持っていました。
// **その理由は同梱されていません。** いま `internal/` には 16 ファイルが
// `information_schema` を引いていますが、**15 件を「許可」と宣言する根拠を
// 私は持っていません** —— 根拠のない許可は、ゲートが防ごうとしている
// ものそのものです。
//
// なので、**いまゼロである package だけを、ゼロのまま留めます。**
// 一覧も理由も要らず、増えたことだけが分かります。
//
// **広げるときは理由ごと広げてください。** 他の package を足すなら、
// そこにある `information_schema` が「なぜ TableIsThere では足りないのか」を
// 1 件ずつ書いた一覧が要ります。名前だけ並べると、読んだ人は
// 「確かめた上で許した」と読みます。
func TestReportsDoesNotProbeTablesOnItsOwn(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("この package を読めません: %v", err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s を読めません: %v", name, err)
		}
		if strings.Contains(string(src), "information_schema") {
			t.Errorf("%s が自前で `information_schema` を引いています。\n"+
				"    表の有無は store.TableIsThere が答えます —— **あれは確認\n"+
				"    そのものの失敗を「無い」と答えません。** 自前で引くと、\n"+
				"    DB に届かなかっただけの回が「その表は無い」に倒れ、\n"+
				"    **予定されたレポートが何もしないまま正常終了します。**", name)
		}
	}

	// **走査が空でないこと。** ファイルを 1 つも見ていなければ、この検査は
	// 何も確かめずに緑を返します。
	if scanned == 0 {
		t.Fatal("この package の .go を 1 つも読めませんでした。" +
			"**走査が届いていません** —— ゼロなのではなく、見ていません")
	}
}
