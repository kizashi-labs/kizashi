package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// **store の error を `_` に捨てているハンドラ。**
//
// `store` 側を直しても、呼び出し側が `x, _ = h.Users.Foo(…)` なら
// **元に戻ります。** 実際そうでした —— `UseBackupCode` が「消費できな
// かったら false と error」を返すようにしたあと、`auth_handler.go` は
// `verified, _ =` で受けていて、**401（コードが違う）と 500（DB に
// 書けない）が同じ応答**になっていました。直したあと、`store` の側だけを
// 元に戻す変異は殺せるのに、**呼び出し側を元に戻す変異は生き残りました。**
//
// 走査の範囲を、この形に絞ってあります。実測 (2026-08-12):
//
//	`x, _ = <なにか>(…)`（2つ以上の左辺、最後が `_`）  536 か所（internal 全体）
//	うち `internal/api/handlers`                        384 か所
//	うち `h.<フィールド>.<メソッド>(…)` の形             19 か所
//
// **536 は別の campaign です**（`json.Marshal` の第2返り値など、捨てて
// よいものが多く混ざります）。19 は「ハンドラが store／サービスに
// 頼んだ結果の error」だけで、ここが答えの正しさに直結します。
//
// **19 を1つずつ読んで、全部直しました (2026-08-12)。** どれも同じ
// 答え方でした —— `ReadOK(c, err)` を通すと、失敗は 500 になり、
// テーブルがまだ無い配置（42P01）は今まで通り空で返ります。
//
// 直す前に何が見えていたか:
//
//	alerts_handler       ダッシュボードの「最近のアラート」「脅威の多い
//	                     端末」「24時間の時系列」が**空**（＝0件と同じ姿）
//	rules_ie_handler     **「検知ルール 0 件」** —— ルールが1本も無い配置と
//	                     DB に届かない配置が同じ表示
//	system_updates       **「最新です」** —— 更新が出ていても、読めなければ
//	                     `up_to_date` を返していました
//	live_response        再接続した端末に**それまでのコマンドが1つも無い**
//	                     ものが流れる
//	container / email /  各 GetStats の区画が空
//	zero_trust / vuln /
//	mobile / soc_ticket
//
// **`if rows != nil` は死んだ分岐でした。** pgx の `pool.Query` は失敗時に
// `errRows{err}` を返すので nil にはならず、`Next()` が即 false、
// `rows.Err()` が `slog.Warn` に出て、区画は空のまま返っていました。
//
// **0 が規則でした。** そのあと走査を広げて、`_ = h.<ストア>.<メソッド>(…)`
// —— 返り値が `error` 1つだけの呼び出しを捨てる形 —— も見るようにしたら、
// **20 か所出ました** (2026-08-12)。`RecordRun` に `error` を持たせた直後、
// `_ = h.Store.RecordRun(…)` に戻す変異が生き残ったので気づきました。
//
// **20 を1つずつ読んで、全部直しました (2026-08-12)。** 直す前に
// 何が起きていたか:
//
//	Isolate            **端末に隔離コマンドが届かなくても
//	                   「隔離しました」と答えていました。**
//	                   ハートビートには `should_unisolate` の巻き戻しが
//	                   ありますが、**`should_isolate` はありません** ——
//	                   届かなければ、その端末は二度と隔離されません。
//	                   いまは 500 で答えます。
//	Unisolate          こちらは次のハートビートが巻き戻します。跡だけ残します。
//	対応操作の記録 ×8   隔離・解除・スキャン・停止・プロセス終了・
//	                   ファイル隔離・復元・スキャン結果。**インシデントの
//	                   時系列から、誰がいつ何をしたかが抜けます。**
//	検疫からの復元      コマンドが届かないのに `MarkRestored` だけが通り、
//	                   **画面は「復元済み」、実物は検疫のまま。**
//	ログインのセッション「best-effort」と書いてありましたが、**一覧に出ず、
//	                   強制ログアウトの対象にもなりません。**
//	パスワード変更      初回変更フラグが消えず、**変えたのに変更を
//	                   求められ続けます。**
//	webhook の登録      行は残るので画面には出るのに、**一度も発火しません。**
//	レポートの3状態     `pending` のまま／失敗が `running` のまま永久に／
//	                   **出来上がったレポートが取り出せない。**
//	ハートビート        復帰した端末のオフラインアラートが開いたまま。
//	フィード同期        「最終同期」が止まったまま IOC だけ増える。
//
// **0 が規則です。**

const storeErrorScanRoot = "."

// **床。** 実測が 0 になったので、「見つからない」と「走っていない」が
// 同じ形です。実測 (2026-08-12): この package の関数は 1,400 個ほど。
const handlerFuncFloor = 500

// 実測 (2026-08-12): 20 → `auth_handler.go` を直して 19 → 全部直して 0
// → 走査を `_ = …` の形にも広げて 20 → 全部直して 0。
const discardedStoreErrors = 0

// discardedStoreErrorSites — `x, _ = h.<フィールド>.<メソッド>(…)`。
func discardedStoreErrorSites(t *testing.T) []string {
	t.Helper()
	out, err := discardedStoreErrorsUnder(storeErrorScanRoot)
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return out
}

// discardedStoreErrorsUnder は走査そのものです。根を引数に取るのは、
// **parse できない file を黙って飛ばしていないこと**を確かめるためです ——
// 本物の木はどの file も parse できるので、`return nil` と
// `return parseErr` が同じに見えます（その変異が生き残りました）。
func discardedStoreErrorsUnder(root string) ([]string, error) {
	fset := token.NewFileSet()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || !discardsAStoreError(as) {
					return true
				}
				out = append(out, rel+":"+fn.Name.Name+":"+
					strconv.Itoa(fset.Position(as.Pos()).Line))
				return true
			})
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// discardsAStoreError — 判定。**通る木でも真になる形なので**（19 か所
// 残っています）、走査と分けてあるのは見本を食わせるためです。
func discardsAStoreError(as *ast.AssignStmt) bool {
	if len(as.Rhs) != 1 || len(as.Lhs) < 1 {
		return false
	}
	last, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
	if !ok || last.Name != "_" {
		return false
	}
	// **`_ = h.Store.Foo(ctx, …)` も同じ形です。** 最初は左辺が2つ以上の
	// ものだけを見ていて、返り値が `error` 1つだけの呼び出しを捨てる形が
	// 素通りしました —— `RecordRun` に `error` を持たせた直後、
	// `_ = h.Store.RecordRun(…)` に戻す変異が生き残りました。
	//
	// 左辺が2つ以上のときは、受け取っているものが1つ以上あること。
	// 全部 `_` は「結果もいらない」で、別の形です。
	if len(as.Lhs) > 1 {
		keeps := false
		for _, l := range as.Lhs[:len(as.Lhs)-1] {
			if id, isID := l.(*ast.Ident); !isID || id.Name != "_" {
				keeps = true
			}
		}
		if !keeps {
			return false
		}
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	// `h.<フィールド>.<メソッド>(…)` の形だけ。
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv, ok := inner.X.(*ast.Ident)
	return ok && recv.Name == "h"
}

// handlerFuncsSeen は、同じ歩き方で見えている関数の数です。
// **上の 0 件が「探した結果」であることの裏付けです。**
func handlerFuncsSeen(t *testing.T) int {
	t.Helper()
	fset := token.NewFileSet()
	n := 0
	err := filepath.WalkDir(storeErrorScanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				n++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return n
}

func TestHandlersDoNotDiscardStoreErrors(t *testing.T) {
	sites := discardedStoreErrorSites(t)
	if len(sites) > discardedStoreErrors {
		t.Errorf("store の error を捨てているハンドラが %d から %d に"+
			"増えました。**store 側を直しても、ここで元に戻ります**: %v",
			discardedStoreErrors, len(sites), sites[discardedStoreErrors:])
	}
	if len(sites) < discardedStoreErrors {
		t.Errorf("store の error を捨てているハンドラが %d まで減りました。"+
			"**留めている数を %d に下げてください** —— 読んで直した分と、"+
			"たまたま消えた分を混ぜないためです", len(sites), len(sites))
	}
	t.Logf("store の error を捨てているハンドラ: %d か所", len(sites))
}

// **MFA の復旧コードだけは、いま直してあること。**
//
// 上限は「これ以上増やすな」しか言いません。19 のうちどれが直っているかは
// 数からは分かりません。ここが一番効くので、名指しで留めます。
func TestTheBackupCodeCallDoesNotDiscardItsError(t *testing.T) {
	src, err := os.ReadFile("auth_handler.go")
	if err != nil {
		t.Fatalf("auth_handler.go を読めません: %v", err)
	}
	body := string(src)
	if strings.Contains(body, "verified, _ = h.Users.UseBackupCode") {
		t.Error("`UseBackupCode` の error を捨てています。**復旧コードを" +
			"消費できなかった回（DB に書けない）と、コードが違う回が、" +
			"同じ 401 になります** —— `store` 側で false を返しても、" +
			"利用者には区別がつきません")
	}
	if !strings.Contains(body, "ok, err := h.Users.UseBackupCode") {
		t.Error("`UseBackupCode` の呼び出しを読めていません。**名前が" +
			"変わったならこの検査も追ってください** —— 探して無かったのと" +
			"探していないのは、ここでは同じ形になります")
	}
}

// 判定が本物を見ていること。
func TestTheStoreErrorRecogniserLooksAtTheShape(t *testing.T) {
	first := func(src string) *ast.AssignStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out *ast.AssignStmt
		ast.Inspect(f.Decls[0].(*ast.FuncDecl).Body, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && out == nil {
				out = as
			}
			return true
		})
		return out
	}
	for _, c := range []struct {
		name string
		src  string
		want bool
	}{
		{"store の error を捨てている", "v, _ := h.Users.UseBackupCode(ctx, id, code)", true},
		{"error だけを捨てている", "_ = h.Store.RecordRun(ctx, id)", true},
		{"error を受けている", "v, err := h.Users.UseBackupCode(ctx, id, code)", false},
		{"全部捨てている", "_, _ = h.Users.UseBackupCode(ctx, id, code)", false},
		{"h ではない", "v, _ := s.Users.Foo(ctx)", false},
		{"h の直下のメソッド", "v, _ := h.foo(ctx)", false},
		{"package の関数", "v, _ := json.Marshal(x)", false},
		{"1つしか返らない", "v := h.Users.Foo(ctx)", false},
	} {
		if got := discardsAStoreError(first(c.src)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	// **走査が届いていること。**
	//
	// 実測が 0 になったので、「見つからない」と「走っていない」が
	// 同じ形になりました。**この package の関数を読めていること**を
	// 別に確かめます —— 走査が空を返しても、ここで落ちます。
	if n := handlerFuncsSeen(t); n < handlerFuncFloor {
		t.Fatalf("走査が %d 個の関数しか見ていません（床 %d）。"+
			"**0 件は「無い」ではなく「探していない」かもしれません**",
			n, handlerFuncFloor)
	}
	if handlerFuncFloor < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}

// **parse できない file は「問題の無い file」ではありません。**
func TestABrokenHandlerFileIsAFailureNotAnAbsence(t *testing.T) {
	root := t.TempDir()
	const src = `package p

func f(c *gin.Context) {
	v, _ := h.Users.UseBackupCode(ctx, id, code)
	_ = v
}
`
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := discardedStoreErrorsUnder(root)
	if err != nil {
		t.Fatalf("読める木で失敗しています: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("読める木で %d 件です（1 のはずです）: %v", len(got), got)
	}

	if err := os.WriteFile(filepath.Join(root, "ok.go"),
		[]byte(src+"\nfunc broken( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err = discardedStoreErrorsUnder(root); err == nil {
		t.Errorf("parse できない file を黙って飛ばしています（%d 件を"+
			"返しました）。**壊れた file が「捨てていない file」と同じ"+
			"扱いになります**", len(got))
	}
}
