package handlers

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// **画面が読む項目を、サーバが送っていること。**
//
// 実測 (2026-08-12): `GET /api/v1/endpoints/criticality` という経路は
// ありませんでした。登録してあるのは `/:id/criticality`・
// `/criticality/bulk`・`PUT /:id/criticality` の3本だけで、
// **2 segment のこの path はどれにも当たりません**（gin は 404）。
// 画面の `useQuery` は `retry: false` で失敗を空配列にするので、
// **資産が1台も無い一覧**として出ていました。
//
// 経路を足すだけでは足りません。**点数を作る側は `agent_id`／`score`
// を返し、画面は `id`／`criticality_score`／`hostname`／`os` を
// 読んでいます** —— 足しただけなら、全行が「点数0の名無し」で並びます。

// 画面が読む項目（`app/admin/asset-criticality/page.tsx` の
// `interface AssetCriticality`）。
var criticalityListFields = []string{
	"id", "hostname", "os", "criticality_score", "tier", "factors",
	"manual_override", "last_calculated", "is_online",
}

func TestTheListRowCarriesWhatTheConsoleReads(t *testing.T) {
	raw, err := json.Marshal(criticalityListRow{})
	if err != nil {
		t.Fatalf("行を JSON にできません: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("読み戻せません: %v", err)
	}
	for _, f := range criticalityListFields {
		if _, ok := got[f]; !ok {
			t.Errorf("`%s` を送っていません。**画面はこの名前で読むので、"+
				"欄が空のまま出ます** —— 経路が404だったときと同じ姿です", f)
		}
	}
}

// 手動の行だけが `manual_score` / `manual_reason` を持つこと。
// **全行に付けると、画面は「全部が手動で決められている」と読みます。**
//
// 行は `manualRow` / `computedRow` に作らせます。**検査が同じ構造体を
// 組み立て直していたときは、`manual_score` を落とす変異が生き残り
// ました** —— 上書きダイアログは、そこから前の値を出します。
func TestOnlyAManualRowCarriesTheManualFields(t *testing.T) {
	base := identityRow(criticalityAgentRow{
		id: "a-1", hostname: "pay-01", osType: "linux", osVersion: "22.04", status: "online",
	})
	row := manualRow(base, storedManual{
		result:  manualResult("a-1", 90, "決済サーバ"),
		updated: time.Unix(1_700_000_000, 0).UTC(),
	})
	if !row.Manual || row.Score != 90 || row.Tier != scoreTier(90) {
		t.Errorf("手動の行 = %+v。点数と段がそのまま出ません", row)
	}
	if row.ID != "a-1" || row.Hostname != "pay-01" || row.OS != "linux 22.04" || !row.IsOnline {
		t.Errorf("端末の情報が落ちています: %+v。**手動にした端末だけ"+
			"名無しで並びます**", row)
	}
	if row.Calculated.IsZero() {
		t.Error("`last_calculated` が空です。いつ決めたのか画面に出ません")
	}
	manual, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("行を JSON にできません: %v", err)
	}
	if !strings.Contains(string(manual), `"manual_score":90`) ||
		!strings.Contains(string(manual), `"manual_reason":"決済サーバ"`) {
		t.Errorf("手動の行に手動の値が入っていません: %s", manual)
	}

	now := time.Unix(1_700_000_001, 0).UTC()
	plain := computedRow(identityRow(criticalityAgentRow{id: "a-2"}),
		scoreAgent(criticalityInputs{agentID: "a-2"}), now)
	if plain.Manual || plain.Calculated != now {
		t.Errorf("計算した行 = %+v。手動の印が付くか、時刻が今でありません", plain)
	}
	computed, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("行を JSON にできません: %v", err)
	}
	if strings.Contains(string(computed), "manual_score") ||
		strings.Contains(string(computed), "manual_reason") {
		t.Errorf("計算した行に手動の欄が入っています: %s", computed)
	}
}

// **上書きの保存は、必ず 400 で落ちていました。**
//
// 画面は `{manual_score, reason}` を送り、サーバは `score` を
// `binding:"required"` で読んでいました —— 綴りが違うので値は入らず、
// required が落とします。**手で決めた重要度が効かなかったのは上書きの
// 方だけではなく、そもそも保存に届いていませんでした。**
//
// `required` はもう1つ悪さをします: **0 を「未指定」として弾きます。**
// 重要度 0 は正しい値です。
func TestBothSpellingsOfTheManualScoreAreAccepted(t *testing.T) {
	i := func(v int) *int { return &v }

	cases := []struct {
		name        string
		score       *int
		manualScore *int
		want        int
		ok          bool
	}{
		{name: "score", score: i(70), want: 70, ok: true},
		{name: "manual_score（画面が送る綴り）", manualScore: i(70), want: 70, ok: true},
		{name: "0 は正しい値", score: i(0), want: 0, ok: true},
		{name: "100 も正しい値", score: i(100), want: 100, ok: true},
		{name: "どちらも無い", ok: false},
		{name: "範囲の外（下）", score: i(-1), ok: false},
		{name: "範囲の外（上）", score: i(101), ok: false},
		{name: "両方あれば score を採る", score: i(30), manualScore: i(90), want: 30, ok: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := manualScoreOf(tc.score, tc.manualScore)
			if ok != tc.ok {
				t.Fatalf("受け取ったか = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("点数 = %d, want %d", got, tc.want)
			}
		})
	}
}

// **点数の作り方が1つであること。**
//
// 一覧は1台ずつ計算しません（1000 台で問い合わせが 3000 本になります）。
// 入力をまとめ読みして、点数は1台ぶんと同じ `scoreAgent` に通します ——
// **ladder を書き写したら、同じ端末が画面によって別の重要度で出ます。**
func TestEveryCriticalityPathGoesThroughOneScorer(t *testing.T) {
	const path = "asset_criticality_handler.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("%s を解析できません: %v", path, err)
	}

	for _, fn := range []string{"computeScoreForAgent", "scoreAllAgents"} {
		if !calls(f, fn, "scoreAgent") {
			t.Errorf("`%s` が `scoreAgent` を通っていません。"+
				"**ladder が2つになると、片方だけ直した日に同じ端末が"+
				"画面によって別の段で出ます**", fn)
		}
	}

	// 段の閾値が1箇所であること。`scoreTier` の外に段の数字が現れたら、
	// それは写しです。
	if countTierLadders(f) != 1 {
		t.Errorf("段を決めている関数が %d 個です（1 つのはずです）。"+
			"**画面とサーバで段がずれると、同じ点数が別の色で出ます**",
			countTierLadders(f))
	}
}

// countTierLadders — `>= 85` と `>= 65` の両方を含む関数の数。
func countTierLadders(f *ast.File) int {
	n := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		seen85, seen65 := false, false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				return true
			}
			switch lit.Value {
			case "85":
				seen85 = true
			case "65":
				seen65 = true
			}
			return true
		})
		if seen85 && seen65 {
			n++
		}
	}
	return n
}

// **一覧が渡す入力に、落とし物が無いこと。**
//
// `status` を渡し忘れれば一覧だけオフライン減点が効かず、`alerts` と
// `vulns` を取り違えれば 15 点と 10 点が入れ替わります。**どちらも
// 「それらしい点数」で並ぶので、画面からは分かりません。**
func TestTheListCarriesEveryScoringInput(t *testing.T) {
	a := criticalityAgentRow{
		id: "a-1", hostname: "web-01", osType: "windows",
		osVersion: "11", status: "offline",
	}
	in := listInputs(a, map[string]int{"a-1": 3}, map[string]int{"a-1": 7})

	want := criticalityInputs{
		agentID: "a-1", osType: "windows", osVersion: "11",
		status: "offline", activeAlerts: 3, highVulns: 7,
	}
	if in != want {
		t.Errorf("一覧が渡す入力 = %+v, want %+v", in, want)
	}

	// 1台ぶんの経路と同じ点数になること。
	if got, one := scoreAgent(in).Score, scoreAgent(want).Score; got != one {
		t.Errorf("一覧の点数 = %d, 1台ぶんの点数 = %d", got, one)
	}
}

// 段の走査が効くこと。**見本を食わせて確かめます** —— いま違反は 0 件
// なので、判定を潰しても挙がる数は変わりません。
func TestTheTierLadderScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+src, 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f
	}

	one := parse("func t(s int) string { if s >= 85 { return \"c\" }; if s >= 65 { return \"h\" }; return \"l\" }")
	if got := countTierLadders(one); got != 1 {
		t.Errorf("段を1つ持つ見本で %d と答えました", got)
	}
	two := parse(
		"func a(s int) string { if s >= 85 { return \"c\" }; if s >= 65 { return \"h\" }; return \"l\" }\n" +
			"func b(s int) string { if s >= 85 { return \"c\" }; if s >= 65 { return \"h\" }; return \"l\" }")
	if got := countTierLadders(two); got != 2 {
		t.Errorf("**段の写しを見つけられません**（%d）。"+
			"これだと ladder が何個あっても通ります", got)
	}
	if got := countTierLadders(parse("func n(s int) int { return s + 1 }")); got != 0 {
		t.Errorf("段を持たない関数を数えています: %d", got)
	}
}

// **一覧の経路が登録されていること。**
//
// 上の検査は「送る中身」しか見ません。router に無ければ、中身がどれだけ
// 揃っていても 404 です —— **それが元の姿でした。**
func TestTheCriticalityListRouteIsRegistered(t *testing.T) {
	src, err := os.ReadFile("../router.go")
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	want := `ep.GET("/criticality", s.handlers.AssetCriticality.List)`
	if !strings.Contains(string(src), want) {
		t.Errorf("`GET /endpoints/criticality` が登録されていません。"+
			"**画面はここから一覧を取ります** —— 404 は空配列になり、"+
			"資産が1台も無い画面として出ます (%s)", want)
	}
}
