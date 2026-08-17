package handlers

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// **手で決めた重要度が、計算し直しに消されないこと。**
//
// 実測 (2026-08-12): `PUT /endpoints/:id/criticality` は
// `system_metadata` の `agent_criticality_<id>` に書いて 200 を返し、
// **その行を読むものはどこにもありませんでした。** `GetScore` も
// `BulkScore` も `computeScoreForAgent` を通り、そこが OS・状態・
// アラート・脆弱性から計算し直して**同じ行を上書き**していました。
//
// つまり手動の重要度は「保存されて、次の表示で消える」ものでした ——
// 一覧の再計算ボタン1回で戻ります。**再起動すら要りません。**
//
// 画面側は `manual_override` と `manual_score` を持っていて（
// `frontend/app/admin/asset-criticality/page.tsx`）、**API が一度も
// 送ったことのない項目を読んでいました。**

func TestAStoredManualScoreIsUsedAndAComputedOneIsNot(t *testing.T) {
	manual, err := json.Marshal(criticalityResult{
		AgentID: "a-1", Score: 95, Tier: "critical",
		ManualOverride: true, Reason: "決済サーバ",
	})
	if err != nil {
		t.Fatalf("見本を作れません: %v", err)
	}
	// この変更より前に書かれていた行 —— 計算値のキャッシュです。
	computed, err := json.Marshal(criticalityResult{
		AgentID: "a-1", Score: 70, Tier: "high",
		Factors: []criticalityFactor{{Name: "server_os", Impact: 20, Value: "linux"}},
	})
	if err != nil {
		t.Fatalf("見本を作れません: %v", err)
	}

	cases := []struct {
		name    string
		raw     string
		wantUse bool
		wantErr bool
		score   int
	}{
		{name: "手動なら使う", raw: string(manual), wantUse: true, score: 95},
		{name: "古い計算値は使わない", raw: string(computed)},
		{name: "印が無ければ使わない", raw: `{"agent_id":"a-1","score":95}`},
		{name: "壊れていれば error", raw: `{`, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			saved, err := manualCriticality(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if (saved != nil) != tc.wantUse {
				t.Fatalf("使うか = %v, want %v。**手動を「使わない」と答えると、"+
					"上書きこそしませんが、手で決めた値は画面に出ません**",
					saved != nil, tc.wantUse)
			}
			if tc.wantUse && saved.Score != tc.score {
				t.Errorf("点数 = %d, want %d", saved.Score, tc.score)
			}
		})
	}
}

// **手動で保存するものに印が付いていること。**
//
// `manualCriticality` がどれだけ正しくても、書く側が印を付けなければ
// 一件も手動として読まれません。**両側を1つの検査で結びます。**
func TestWhatSetManualScoreWritesIsReadBackAsManual(t *testing.T) {
	// **検査が構造体を組み立て直さないこと。** 元はここで同じ literal を
	// 書いていたので、**書く側が `ManualOverride: true` をやめても通り
	// ました**（その変異が生き残りました）。`SetManualScore` が使うのと
	// 同じ `manualResult` を通します。
	written, err := json.Marshal(manualResult("a-1", 30, "検証機"))
	if err != nil {
		t.Fatalf("見本を作れません: %v", err)
	}
	saved, err := manualCriticality(string(written))
	if err != nil || saved == nil {
		t.Fatalf("書いたものが手動として読み戻せません (saved=%v, err=%v)", saved, err)
	}
	if saved.Score != 30 || saved.Reason != "検証機" {
		t.Errorf("読み戻し = %+v。点数と理由がそのまま返らないと、"+
			"画面は手動で決めた値と違うものを出します", saved)
	}
}

// **計算する側が、保存された値を上書きしないこと。**
//
// 上の検査は「印を見ている」ことしか留めません。書き込みが戻ってくれば
// 印を見ていても消えます —— **消していた行そのものを、走査で留めます。**
//
// 規則: `asset_criticality_handler.go` の中で `system_metadata` に
// 書く関数は `SetManualScore` だけ。
func TestOnlyTheManualEndpointWritesTheCriticalityRow(t *testing.T) {
	const path = "asset_criticality_handler.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("%s を解析できません: %v", path, err)
	}

	writers := writesSystemMetadata(f)
	if len(writers) != 1 || writers[0] != "SetManualScore" {
		t.Errorf("`system_metadata` に書いている関数 = %v, want [SetManualScore]。"+
			"**計算する側が書くと、手で決めた重要度が次の表示で消えます** ——"+
			"一覧の再計算1回で戻る形でした", writers)
	}

	// **計算する側が、保存されている値を先に見ること。**
	//
	// 上の走査は「上書きしないこと」しか留めません。読むのをやめれば
	// 上書きもしませんが、**手で決めた値は画面に出ません** —— それも
	// 元の姿と同じです。DB を立てずに留めるには、呼んでいることを
	// 見るしかありません（この分岐は本物の行が要るので、DB 無しでは
	// 通れません）。
	if !calls(f, "computeScoreForAgent", "storedCriticality") {
		t.Error("`computeScoreForAgent` が `storedCriticality` を呼んでいません。" +
			"**手で決めた重要度が読まれず、毎回計算値が返ります**")
	}
	if !calls(f, "SetManualScore", "manualResult") {
		t.Error("`SetManualScore` が `manualResult` を使っていません。" +
			"**印の付け方が2箇所に分かれると、検査は片方しか見ません**")
	}
}

// calls — file の中の関数 fn が、名前 want の呼び出しを含むか。
func calls(f *ast.File, fn, want string) bool {
	found := false
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Name.Name != fn || d.Body == nil {
			continue
		}
		ast.Inspect(d.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch e := call.Fun.(type) {
			case *ast.Ident:
				if e.Name == want {
					found = true
				}
			case *ast.SelectorExpr:
				if e.Sel.Name == want {
					found = true
				}
			}
			return true
		})
	}
	return found
}

// writesToSystemMetadata — 書き込みの形。
//
// **「SYSTEM_METADATA と UPDATE を含む」では足りませんでした。**
// `SELECT key, value, COALESCE(updated_at, NOW()) FROM system_metadata`
// が引っかかります —— 列名の `updated_at` が UPDATE を含むためです。
// **読み取りを書き込みに数える走査は、直しようのない違反を報告し続け、
// やがて誰も見なくなります。**
var writesToSystemMetadata = regexp.MustCompile(`(INSERT\s+INTO|UPDATE)\s+SYSTEM_METADATA`)

// writesSystemMetadata — その file の中で `system_metadata` への
// INSERT/UPDATE を含む関数名。
//
// **判定を切り出してあるのは、通る木では違反が 0 件だからです。**
// 見本を食わせないと、走査を潰す変異が生き残ります。
func writesSystemMetadata(f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if writesToSystemMetadata.MatchString(strings.ToUpper(lit.Value)) {
				found = true
			}
			return true
		})
		if found {
			out = append(out, fn.Name.Name)
		}
	}
	return out
}

// 走査が効くこと。**違反する見本を食わせて確かめます。**
func TestTheSystemMetadataWriteScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+src, 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f
	}

	got := writesSystemMetadata(parse("func w() {\n" +
		"_, _ = p.Exec(ctx, `INSERT INTO system_metadata (key, value) VALUES ($1,$2)`)\n}"))
	if len(got) != 1 || got[0] != "w" {
		t.Errorf("書いている関数を見つけられません: %v", got)
	}

	if got := writesSystemMetadata(parse("func r() {\n" +
		"_ = p.QueryRow(ctx, `SELECT value FROM system_metadata WHERE key = $1`)\n}")); len(got) != 0 {
		t.Errorf("読み取りを書き込みに数えています: %v", got)
	}
	if got := writesSystemMetadata(parse("func o() {\n" +
		"_, _ = p.Exec(ctx, `UPDATE agents SET status='online'`)\n}")); len(got) != 0 {
		t.Errorf("別のテーブルへの書き込みを数えています: %v", got)
	}
	// 列名に updated_at を含む読み取り。**これを書き込みに数えていました。**
	if got := writesSystemMetadata(parse("func u() {\n" +
		"_, _ = p.Query(ctx, `SELECT key, COALESCE(updated_at, NOW()) FROM system_metadata`)\n}")); len(got) != 0 {
		t.Errorf("`updated_at` という列名を UPDATE に数えています: %v", got)
	}

	callSample := parse("func a() { b() }\nfunc c() { d.e() }\nfunc f() {}")
	if !calls(callSample, "a", "b") {
		t.Error("直接の呼び出しを見つけられません")
	}
	if !calls(callSample, "c", "e") {
		t.Error("メソッド呼び出しを見つけられません")
	}
	if calls(callSample, "f", "b") {
		t.Error("**呼んでいない関数を「呼んでいる」と答えています。** " +
			"これだと、どの関数を消しても通ります")
	}
}
