package handlers

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// **残り 44 か所を、1つずつ読んで分類しました (2026-08-12)。**
//
// **そのうち「回」の中にあった 7 か所は直したので、いまは 37 です。**
//
// **7 のうち 2 は、ここに手で書いた分類が間違っていました** ——
// `reports/scheduler.go:runReport` と `threatintel/feed.go:FetchFeed` を
// `restart` に入れていましたが、どちらも `tick.Run` から届きます。
// `internal/tick/tracked_workers_test.go` の
// `TestTrackedWorkersDoNotDiscardWrites` が走査で挙げました。
// **手で書いた「0 件です」は、走査で裏を取るまで信用できません。**
//
// `discarded_write_test.go` は「成功として答える関数の中では 0 件」を
// 留めています。**それは上限であって、残り 44 が捨ててよいものかは
// 誰も見ていませんでした** —— `cert_expiry_checker` の Warn 2件と同じ形
// です。上限は「これ以上増やすな」しか言いません。
//
// 読んだ結果、4つに分かれました:
//
//	catRestart    記憶を先に変えて、DBへの反映を捨てている。
//	              **プロセスが生きているあいだは正しく見え、再起動で戻ります。**
//	catNoCaller   goroutine の中など、報告する相手がいない。
//	              → `metrics.BackgroundFailed` が正しい綴りです。
//	              **いまは 0 件で、0 であることが規則です。**
//	catHasRun     周期の仕事の中。→ `tick.Fail` が使えます。
//	              **いまは 0 件で、0 であることが規則です。**
//	catCovered    直後の別の呼び出しが、同じ失敗を報告する。
//
// **一番多いのは catRestart で、これが一番見つけにくい形です。** 画面は
// 記憶を映すので、削除も改名も無効化も「効いた」ように見えます。次の
// 再起動で戻ったとき、**それが「戻った」ことだと分かる人はいません**
// —— 消したはずのスケジュールがまた動き出した、としか見えません。

// 分類の名前。**自由文は通しません。**
const (
	catRestart  = "restart"
	catNoCaller = "no-caller"
	catHasRun   = "has-run"
	catCovered  = "covered"
)

func isKnownWriteCategory(s string) bool {
	switch s {
	case catRestart, catNoCaller, catHasRun, catCovered:
		return true
	}
	return false
}

// 鍵は `パス:関数名`。同じ関数の複数箇所はまとめて1つの理由です。
var discardedWriteReasons = map[string]string{
	// ── 記憶とDBが食い違う（再起動で戻る） ───────────────────────────
	//
	// **空になりました (2026-08-12)。** 6つとも読んで答えました:
	//
	//	siem/connector.go:sendOne          goroutine の中 →
	//	                                   `metrics.BackgroundFailed`
	//	ldap/connector.go:SyncUsers        同期は成功しているので error は
	//	                                   返さず、件数に出す
	//	store/incidents.go:Delete          **外部キーがあるので、書けなければ
	//	                                   直後の DELETE が 23503 で落ちます**
	//	                                   —— 生の制約違反より先に答える
	//	detection/curate_service.go:RunRound  **回がありました** →
	//	                                   `tick.FailComponent`
	//	api/handlers/ingest_handler.go:upsertAgent  取り込みは落とさず件数に出す
	//	api/handlers/asset_criticality_handler.go:computeScoreForAgent
	//	                                   **書き込みごと消しました** ——
	//	                                   誰も読まない値で、手動の重要度を
	//	                                   上書きしていたのがこれです
	//
	// **この分類が空であることは、それ自体が規則です。** 記憶を先に
	// 変えて DB を捨てる形は、プロセスが生きているあいだ正しく見えます。

	// ── 報告する相手がいない ─────────────────────────────────────────

	// ── 回がある ─────────────────────────────────────────────────────
	//
	// **空になりました (2026-08-12)。** 5つの関数（`cloud/poller.go`、
	// `dedup/alert_dedup.go` ×2、`reports/scheduler.go`、
	// `threatintel/feed.go`、計 7 か所）はどれも `tick.Run` の中に
	// あり、**うち3つは同じ関数の中で既に `tick.Fail` を使っていました**
	// —— この書き込みだけが黙っていました。`tick.Fail` に通しました。
	//
	// **残り2つは、ここで `restart` に分類していた誤りです。**
	// 走査（`internal/tick` の `TestTrackedWorkersDoNotDiscardWrites`）が
	// 挙げてくれました。**3つ目が `curate_service.go:RunRound` です** ——
	// これは走査も挙げませんでした（package をまたぐので見えません）。
	//
	// **この分類が空であることは、それ自体が規則です**（下の
	// `discardedWriteCounts` が 0 を留めます）。「回」がある場所で
	// 書き込みを捨てるなら、それは直す合図です。

	// ── 直後の別の呼び出しが報告する ─────────────────────────────────
	// **鍵から `-createtable` が取れました。** 同じ関数の中にもう1つ
	// （`last_sync`／`user_count`）あったので分けていましたが、そちらは
	// 件数に出すようにしたので、この関数に残る捨て方は1つだけです。
}

// **数**。実測 (2026-08-12): 44 → 「回」の中の 7 か所を `tick.Fail` に
// 通して 37 → 呼び出し側が error を受け取れる 11 か所を直して 26 →
// **報告する相手がいない 10 か所**を `metrics.BackgroundFailed` に通して
// 16 → **返り値の無かった7つの関数に `error` を持たせて** 9 か所、
// 6 の関数（`パス:関数名` で畳んだ数）。分類は 7 ——
// `ldap/connector.go:SyncUsers` だけ、同じ関数の中の2つを別の分類に
// 分けているためです。
const discardedWriteFuncs = 0

// **分類ごとの数を、そのまま留めます。** 床（「20 以上」）にしていたら、
// 床を 0 に落とす変異が生き残りました —— 床は「これ以上減らすな」しか
// 言わず、**全部を1つの分類に寄せる動きを止められません。**
var discardedWriteCounts = map[string]int{
	catRestart:  0, // **0 が規則です。** 記憶を先に変えて DB を捨てると、再起動まで正しく見えます
	catNoCaller: 0, // **0 が規則です。** 報告する相手がいないなら、部品ごとの件数に出せます
	catHasRun:   0, // **0 が規則です。**「回」があるなら `tick.Fail` に出せます
	catCovered:  0,
}

func writeCategoryOf(reason string) string {
	if i := strings.Index(reason, ":"); i > 0 {
		return reason[:i]
	}
	return ""
}

// reasonSaysNothing — 分類名しか書いていない理由か。
//
// これを判定として切り出してあるのは、**通る木では一度も真にならない**
// からです。`if strings.TrimSpace(…) == ""` を `if false` に潰す変異が
// 生き残りました —— 木がきれいなあいだ、その行は在っても無くても
// 同じに見えます。
func reasonSaysNothing(reason string) bool {
	cat := writeCategoryOf(reason)
	if cat == "" {
		return true
	}
	return strings.TrimSpace(reason[len(cat)+1:]) == ""
}

// reasonKeyBase — `path.go:Fn-suffix` から `path.go:Fn` を取り出す。
// 同じ関数の中の別の箇所を別の分類にしたいときの接尾辞を落とします。
func reasonKeyBase(key string) string {
	if i := strings.Index(key, "-"); i > 0 {
		return key[:i]
	}
	return key
}

// categoryCountProblems — 分類ごとの数が実測と違うものを挙げる。
//
// **判定として切り出してあります。** 木がきれいなあいだ、この比較は
// 一度も真になりません —— `if counts[c] != want[c]` を `if false` に潰す
// 変異が生き残りました。
func categoryCountProblems(got, want map[string]int) []string {
	var out []string
	for _, c := range []string{catRestart, catNoCaller, catHasRun, catCovered} {
		if got[c] != want[c] {
			out = append(out, fmt.Sprintf(
				"`%s` が %d 件です（実測は %d）。**分類を移したなら、"+
					"移した先と元の両方の数を直してください** —— 数が動かない"+
					"まま分類だけ変わると、寄せたことが見えません",
				c, got[c], want[c]))
		}
	}
	sort.Strings(out)
	return out
}

// staleWriteReasonKeys — 宛先が消えた分類。
func staleWriteReasonKeys(reasons map[string]string, seen map[string]bool) []string {
	var out []string
	for key := range reasons {
		if !seen[reasonKeyBase(key)] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryDiscardedWriteIsClassified — 44 か所の宛先がすべて分類されて
// いること。**新しい箇所は、4つのどれかに書くまで落ちます。**
func TestEveryDiscardedWriteIsClassified(t *testing.T) {
	_, total := discardedWriteSites(t)
	if total != discardedWritesTotal {
		t.Fatalf("捨てている書き込みが %d か所です（留めているのは %d）。"+
			"**分類の一覧より先に、そちらを直してください**",
			total, discardedWritesTotal)
	}

	seen := map[string]bool{}
	for _, key := range discardedWriteSiteKeys(t) {
		seen[key] = true
		if _, ok := discardedWriteReasons[key]; !ok {
			t.Errorf("%s の書き込みが分類されていません。**捨ててよいかは"+
				"読まないと分かりません** —— restart / no-caller / has-run / "+
				"covered のどれかを書いてください", key)
		}
	}
	// `-createtable` のような、同じ関数の中の別の箇所を指す鍵は、
	// 接頭辞が実在すれば良いことにします。
	for _, key := range staleWriteReasonKeys(discardedWriteReasons, seen) {
		t.Errorf("%s の分類が残っていますが、その箇所はもうありません。"+
			"**消した分は一覧からも消してください**", key)
	}
}

// TestEveryWriteCategoryIsOneOfTheFour — 自由文を通さないこと。
func TestEveryWriteCategoryIsOneOfTheFour(t *testing.T) {
	counts := map[string]int{}
	for key, reason := range discardedWriteReasons {
		cat := writeCategoryOf(reason)
		if !isKnownWriteCategory(cat) {
			t.Errorf("%s の分類 %q は4つのどれでもありません。**「あとで見る」の"+
				"ような自由文は通しません** —— 書けないなら、それは直す合図です",
				key, cat)
			continue
		}
		counts[cat]++
		if reasonSaysNothing(reason) {
			t.Errorf("%s に分類しか書いてありません。何が起きるかを"+
				"書いてください", key)
		}
	}
	// **分類ごとの数をそのまま留めます。** 床にすると、床を落とす変異が
	// 生き残り、全部を1つの分類に寄せられます（`catNoCaller` は
	// 「報告する相手がいない」なので、そう書けばどれも外せてしまいます）。
	for _, p := range categoryCountProblems(counts, discardedWriteCounts) {
		t.Error(p)
	}
	if len(discardedWriteReasons) != discardedWriteFuncs {
		t.Errorf("分類が %d 件です（留めているのは %d）",
			len(discardedWriteReasons), discardedWriteFuncs)
	}
}

// discardedWriteSiteKeys — `パス:関数名` の一覧（重複は畳みます）。
func discardedWriteSiteKeys(t *testing.T) []string {
	t.Helper()
	keys := map[string]bool{}
	for _, s := range allDiscardedWriteSites(t) {
		keys[s] = true
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// 分類そのものが動くこと。上の2つは通る木では何も push しません。
func TestTheWriteClassificationRuleActuallyFires(t *testing.T) {
	for _, c := range []struct {
		name   string
		reason string
		ok     bool
	}{
		{"restart", catRestart + ": 記憶とDBが食い違います", true},
		{"no-caller", catNoCaller + ": goroutine です", true},
		{"has-run", catHasRun + ": 回があります", true},
		{"covered", catCovered + ": 直後が報告します", true},
		{"自由文", "あとで見ます", false},
		{"似た名前", "restarting: 記憶と食い違います", false},
		{"分類だけ", catRestart + ":", true}, // 分類としては通るが中身が空
	} {
		if got := isKnownWriteCategory(writeCategoryOf(c.reason)); got != c.ok {
			t.Errorf("%s: 通った = %v, want %v", c.name, got, c.ok)
		}
	}
	if writeCategoryOf("分類がありません") != "" {
		t.Error("`:` の無い理由から分類を取り出しています")
	}

	// **中身が空かどうかの判定。** 通る木では一度も真になりません。
	for _, c := range []struct {
		name   string
		reason string
		want   bool
	}{
		{"分類だけ", catRestart + ":", true},
		{"分類と空白", catRestart + ":   ", true},
		{"分類がない", "説明だけ", true},
		{"中身がある", catRestart + ": 記憶とDBが食い違います", false},
	} {
		if got := reasonSaysNothing(c.reason); got != c.want {
			t.Errorf("%s: reasonSaysNothing = %v, want %v", c.name, got, c.want)
		}
	}

	// **宛先が消えた分類を挙げること。**
	seen := map[string]bool{"a.go:F": true}
	stale := staleWriteReasonKeys(map[string]string{
		"a.go:F":        "x",
		"a.go:F-suffix": "y", // 接尾辞つきは接頭辞が在れば良い
		"b.go:Gone":     "z",
	}, seen)
	if len(stale) != 1 || stale[0] != "b.go:Gone" {
		t.Errorf("古くなった分類の抽出 = %v, want [b.go:Gone]", stale)
	}
	if reasonKeyBase("a.go:F-suffix") != "a.go:F" {
		t.Error("接尾辞を落とせていません")
	}

	// **分類ごとの数の比較。** 通る木では一度も真になりません。
	want := map[string]int{catRestart: 2, catNoCaller: 1, catHasRun: 1, catCovered: 1}
	if got := categoryCountProblems(want, want); len(got) != 0 {
		t.Errorf("一致しているのに %d 件挙げています: %v", len(got), got)
	}
	moved := map[string]int{catRestart: 1, catNoCaller: 2, catHasRun: 1, catCovered: 1}
	if got := categoryCountProblems(moved, want); len(got) != 2 {
		t.Errorf("寄せた分の両側を挙げていません: %v", got)
	}
	if got := categoryCountProblems(map[string]int{}, want); len(got) != 4 {
		t.Errorf("空の集計で %d 件です（4つ全部が違うはずです）: %v", len(got), got)
	}
}
