package handlers

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ハンドラが自前で `information_schema` を引きに戻っていないこと。
//
// ## なぜここに要るのか
//
// これを留めていたのは `table_probe_test.go` でしたが、**上流はそのファイルを
// 公開版に同梱しないと決めました**（#74 が `NOT_SHIPPED.txt` に足しています）。
// 戻しても次の同期で消えるので、公開版が自分で持ちます。
//
// ## 何を守っているのか
//
// 表の有無は `store.TableIsThere` が答えます。**あれは確認そのものの失敗を
// 「無い」と答えません**（table_probe.go）。ハンドラが自前で
// `information_schema` を引くと、その判断を迂回して、
// **DB に届かなかっただけの回を「その表は無い」に倒します。**
//
// ## 名前で留めています。理由は書いていません
//
// 元の検査は 1 件ずつ理由を持っていました。**それは同梱されなかったので、
// ここには来ていません。** 知らない理由を書くくらいなら書かないほうが
// ましなので、ここは名前だけで留めます。
//
// **理由が要るなら、触った人が書いてください。** 一覧を増やすときは、
// なぜ `store.TableIsThere` では足りないのかを添えてください ——
// 足りるなら、それを使うのが正しい直し方です。
var handlersThatQueryInformationSchema = map[string]bool{
	"errs.go":                    true,
	"iot_ot_handler.go":          true,
	"sandbox_handler.go":         true,
	"stix_handler.go":            true,
	"tip_integration_handler.go": true,
}

func TestNoNewHandlerAsksInformationSchemaOnItsOwn(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("handlers を読めません: %v", err)
	}

	var found []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("%s を読めません: %v", name, err)
		}
		if strings.Contains(string(src), "information_schema") {
			found = append(found, name)
		}
	}
	sort.Strings(found)

	// **走査が空でないこと。** 一覧が合っていても、走査が何も見ていなければ
	// この検査は毎回緑を返します。
	if len(found) == 0 {
		t.Fatal("`information_schema` を引くハンドラが 1 つも見つかりません。" +
			"**走査が届いていません** —— 一覧が正しいのではなく、何も見て" +
			"いない可能性があります")
	}

	seen := map[string]bool{}
	for _, f := range found {
		seen[f] = true
		if !handlersThatQueryInformationSchema[f] {
			t.Errorf("%s が自前で `information_schema` を引いています。\n"+
				"    表の有無は store.TableIsThere が答えます —— **あれは確認\n"+
				"    そのものの失敗を「無い」と答えません。** 自前で引くと、\n"+
				"    DB に届かなかっただけの回が「その表は無い」に倒れます。\n"+
				"    どうしても要るなら、なぜ TableIsThere では足りないのかを\n"+
				"    添えて handlersThatQueryInformationSchema に足してください", f)
		}
	}
	for f := range handlersThatQueryInformationSchema {
		if !seen[f] {
			t.Errorf("%s は一覧にありますが、もう `information_schema` を"+
				"引いていません。**古い項目は、読んだ人に「まだ直っていない」と"+
				"思わせます** —— 一覧から消してください", f)
		}
	}
}
