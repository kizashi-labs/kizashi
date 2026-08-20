package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 読めなかった行を黙って捨てるループ。
//
// 最初の計測では382箇所あり、「一覧が恒久的に一部を欠いたまま返り続ける」と
// 報告しました。それは間違いでした。
//
// pgx は Scan が失敗すると baseRows.fatal を呼び、結果セットを閉じて err を
// 覚えます。閉じたあと Next() は false を返すので、ループはそこで終わり、
// rows.Err() がその err を返します。つまり `continue` は実際には continue
// しません —— ループを抜けて、そのあとの rows.Err() の検査が答えます。
// その検査は rows_err_policy_test.go が107箇所に入れさせたものです。
//
// 直す前に確かめた結果、382 のうち黙っていたのは13箇所でした。残りは既に
// 報告されています。数える前に直していたら、369箇所を無意味に書き換えて
// いたことになります。
//
// ただし2つ、この形には条件が要ります:
//
//  1. そのループのあとで rows.Err() が参照されていること。参照が無ければ、
//     Scan の失敗はどこにも出ません。
//  2. 失敗の出どころが pgx の rows であること。json.Unmarshal や
//     HTTP クライアントの失敗で continue すると、ループは本当に次へ進み、
//     その項目だけが黙って落ちます。
//
// この検査はその2つを見ます。形（continue と書いてあるか）ではなく、
// 失敗が誰かに届くかどうかで数えます。
//
// 黙っていた13箇所のうち鋭かったもの:
//
//	mobile_threat_handler / mobile_network_handler / mobile_app_inventory /
//	mobile_compliance_scanner — アラートの重複確認 `err != nil || exists`。
//	  確認に失敗しただけで exists と同じ扱いになり、root 化された端末の
//	  アラートが1件も作られません。応答の created は 0 で、脅威が無かった
//	  ときと同じです。
//	store/software_inventory UpsertBatch — 入らなかった行を飛ばして Commit
//	  し、成功を返していました。ソフトウェア一覧は脆弱性の突き合わせ元です。
//	cloud/poller — 設定が読めない統合は「設定済み」のまま一度も収集されません。
//	sync/wazuh — 端末単位で脆弱性の取得に失敗しても、合計だけが返ります。

type skipSite struct {
	file   string
	fn     string
	line   int
	src    string
	silent bool
	// viaRows: 失敗したのが、この for が回している rows そのものであること。
	// そのときだけ、ループを抜けた後の rows.Err() が同じ失敗を報告します。
	//
	// この検査は「行を黙って飛ばしていないか」を見るので、判定としては
	// これで足りていました。区別が要るのは answered_with_a_value_test.go の
	// 側です。あちらは二重に数えないためにこの一覧を使うので、rows.Err()
	// が拾わない箇所まで一緒に外すと、continue の件数が実際より小さく出ます。
	viaRows bool
	snip    string
}

// callParts returns the receiver and name of a call expression.
func callParts(e ast.Expr) (recv, name string) {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return "", ""
	}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return "", fn.Name
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return id.Name, fn.Sel.Name
		}
		return "", fn.Sel.Name
	}
	return "", ""
}

// onlyContinue reports whether a branch does nothing but skip the row.
//
// 記録してから飛ばすのも、飛ばしています。
//
//	if err := rows.Scan(&a, &b); err != nil {
//	    slog.Warn("scan error", "error", err)
//	    continue
//	}
//
// 以前は「文がちょうど1つで、それが continue」だけを見ていました。
// slog を1行足すと、その箇所は判定そのものに映らなくなります — 行スキャン
// かどうかも、rows.Err() を見ているかも、確かめられません。
// answered_with_a_value_test.go で同じ形の見落としを直したばかりで、
// こちらにも同じものが残っていました。判定を1つ直しても、写しは直りません。
func onlyContinue(b *ast.BlockStmt) bool {
	seen := false
	for _, st := range b.List {
		switch v := st.(type) {
		case *ast.BranchStmt:
			if v.Tok != token.CONTINUE {
				return false
			}
			seen = true
		case *ast.ExprStmt:
			if !isLoggingCall(v.X) {
				return false // 後始末や再試行をしているものは対象外
			}
		default:
			return false
		}
	}
	return seen
}

// errIsConsulted reports whether <recv>.Err() is read anywhere after `after`.
//
// Three shapes exist in this codebase and all three count:
//
//	if err := rows.Err(); err != nil { … }
//	if rows.Err() != nil { … }
//	return entries, len(entries), rows.Err()
//
// An earlier version of this scan knew only the first and reported 31 silent
// loops where the real number was 13. A narrow matcher does not report "I only
// looked for one shape" — it reports a number.
func errIsConsulted(fn *ast.FuncDecl, recv string, after token.Pos) bool {
	if recv == "" {
		return false
	}
	isErr := func(e ast.Expr) bool {
		r, name := callParts(e)
		return name == "Err" && r == recv
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found || n == nil || n.Pos() < after {
			return !found
		}
		switch v := n.(type) {
		case *ast.IfStmt:
			if as, ok := v.Init.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && isErr(as.Rhs[0]) {
				found = true
			}
			if bin, ok := v.Cond.(*ast.BinaryExpr); ok && bin.Op == token.NEQ && isErr(bin.X) {
				found = true
			}
		case *ast.ReturnStmt:
			for _, r := range v.Results {
				if isErr(r) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// rowsVarOf returns the variable a `for <x>.Next()` loop is iterating.
//
// 走査が「rows」という名前を決め打ちしないためです。呼び名は rows, r,
// cursor などまちまちで、名前で判定すると、名前が違うだけの行が
// 「行スキャンではない」に分類され、数から静かに落ちます。
func rowsVarOf(st ast.Stmt) string {
	f, ok := st.(*ast.ForStmt)
	if !ok || f.Cond == nil || f.Init != nil || f.Post != nil {
		return ""
	}
	recv, name := callParts(f.Cond)
	if name != "Next" {
		return ""
	}
	return recv
}

// handedTheRows reports whether a call was given the loop's rows variable.
//
// scanSchedule(sc, rows) や scanYARARule(rows) のようなヘルパーです。
// 中で rows.Scan を呼ぶので、失敗すれば結果セットは閉じ、ループの
// rows.Err() が答えます — 走査からは呼び出しの向こう側が見えないだけです。
//
// ここは以前 map[string]bool{"scanSchedule": true} でした。名前を1つずつ
// 書き足す形だったので、書き足していない scanYARARule などは「行スキャン
// ではない」に分類され、rows.Err() を見ずに済んでいました。1件ずつ列挙
// する判定は、列挙し忘れた分を静かに正しいことにします。
func handedTheRows(e ast.Expr, rowsVar string) bool {
	if rowsVar == "" {
		return false
	}
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, a := range c.Args {
		if id, ok := a.(*ast.Ident); ok && id.Name == rowsVar {
			return true
		}
	}
	return false
}

// errAssignedJustBefore finds `err := <call>` immediately preceding an
// `if err != nil { continue }` that has no init of its own.
//
//	err := rows.Scan(&a, &b, …)
//	if err != nil {
//	    continue
//	}
//
// 以前はこの形を見ていませんでした。判定が if の Init だけを見ていたので、
// 代入を1行前に出した書き方は「行スキャンではない」に落ち、rows.Err() を
// 確かめる対象から外れます。store/alerts.go の ListAlerts がそれで、
// アラート一覧の中心にある関数です。
func errAssignedJustBefore(list []ast.Stmt, idx int, is *ast.IfStmt) ast.Expr {
	if is.Init != nil || idx == 0 {
		return nil
	}
	bin, ok := is.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return nil
	}
	lhs, ok := bin.X.(*ast.Ident)
	if !ok {
		return nil
	}
	if rhs, ok := bin.Y.(*ast.Ident); !ok || rhs.Name != "nil" {
		return nil
	}
	as, ok := list[idx-1].(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return nil
	}
	for _, l := range as.Lhs {
		if id, ok := l.(*ast.Ident); ok && id.Name == lhs.Name {
			return as.Rhs[0]
		}
	}
	return nil
}

// stmtLists returns every statement list nested directly inside st.
//
// BlockStmt だけを見ると、switch と select の中身が丸ごと落ちます。
// case 節の本体は []ast.Stmt で、BlockStmt ではありません。
func stmtLists(st ast.Stmt) [][]ast.Stmt {
	var out [][]ast.Stmt
	add := func(b *ast.BlockStmt) {
		if b != nil {
			out = append(out, b.List)
		}
	}
	switch v := st.(type) {
	case *ast.BlockStmt:
		add(v)
	case *ast.IfStmt:
		add(v.Body)
		if eb, ok := v.Else.(*ast.BlockStmt); ok {
			add(eb)
		} else if ei, ok := v.Else.(*ast.IfStmt); ok {
			out = append(out, []ast.Stmt{ei})
		}
	case *ast.ForStmt:
		add(v.Body)
	case *ast.RangeStmt:
		add(v.Body)
	case *ast.SwitchStmt:
		add(v.Body)
	case *ast.TypeSwitchStmt:
		add(v.Body)
	case *ast.SelectStmt:
		add(v.Body)
	case *ast.CaseClause:
		out = append(out, v.Body)
	case *ast.CommClause:
		out = append(out, v.Body)
	case *ast.LabeledStmt:
		out = append(out, []ast.Stmt{v.Stmt})
	}
	return out
}

// classifySkip is the rule. The tree walk and the table below both call this
// one function.
//
// It was two functions for one round — the walk had the logic and the table
// had a copy — and the mutations that gutted the walk's copy all survived,
// because the table was exercising the other one. 規則の写しを持つと、
// 写しのほうだけが正しくなります。
func classifySkip(fn *ast.FuncDecl, list []ast.Stmt, idx int, rowsVar string, is *ast.IfStmt) (src string, silent, viaRows, matched bool) {
	if !onlyContinue(is.Body) {
		return "", false, false, false
	}
	var rhs ast.Expr
	if as, ok := is.Init.(*ast.AssignStmt); ok && len(as.Rhs) == 1 {
		rhs = as.Rhs[0]
	} else if list != nil {
		rhs = errAssignedJustBefore(list, idx, is)
	}
	if rhs == nil {
		return "", false, false, false
	}
	recv, name := callParts(rhs)
	if name == "" {
		return "", false, false, false // not an error branch at all (dedup, cooldown …)
	}
	viaRows = (name == "Scan" && recv == rowsVar && rowsVar != "") || handedTheRows(rhs, rowsVar)
	if viaRows && recv != rowsVar {
		recv = rowsVar
	}
	return name, !(viaRows && errIsConsulted(fn, recv, is.End())), viaRows, true
}

func findSkipSites(t *testing.T, root string) []skipSite {
	t.Helper()
	var out []skipSite
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") ||
			strings.Contains(path, "/gen/") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// 文の並びを直接たどります。case 節の本体は BlockStmt では
			// なく []ast.Stmt なので、ブロックだけを探すと switch の中の
			// ループが1つも見えません。report_scheduler の generateReport が
			// まさにそれで、5つの行ループが「行スキャンではない」に落ちて
			// いました。
			var walk func(list []ast.Stmt, rowsVar string)
			walk = func(list []ast.Stmt, rowsVar string) {
				for i, st := range list {
					if is, ok := st.(*ast.IfStmt); ok {
						if name, silent, viaRows, matched := classifySkip(fn, list, i, rowsVar, is); matched {
							out = append(out, skipSite{
								file: rel, fn: fn.Name.Name,
								line: fset.Position(is.Pos()).Line,
								src:  name, silent: silent,
								viaRows: viaRows,
								snip:    snip(fset, is),
							})
						}
					}
					// for <x>.Next() に入るときだけ rows を差し替えます。
					inner := rowsVar
					if v := rowsVarOf(st); v != "" {
						inner = v
					}
					for _, sub := range stmtLists(st) {
						walk(sub, inner)
					}
				}
			}
			walk(fn.Body.List, "")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out
}

func snip(fset *token.FileSet, n ast.Node) string {
	p, e := fset.Position(n.Pos()), fset.Position(n.End())
	b, err := os.ReadFile(p.Filename)
	if err != nil || e.Offset > len(b) {
		return ""
	}
	s := strings.Join(strings.Fields(string(b[p.Offset:e.Offset])), " ")
	if len(s) > 110 {
		s = s[:110]
	}
	return s
}

// 説明の無い箇所。0 で固定。
// skipExceptions は「黙って飛ばしてよい」5箇所です。キーは file:fn。
//
// 上限を 0 のまま残せるのは、残った分に理由が書けているあいだだけです。
// 書けないものは例外ではなく、直す対象でした — この回に直した7箇所が
// それです。
var skipExceptions = map[string]string{
	// 取得元を順に試し、行が返ったものを採用する探索。1 つの取得元が
	// 読めなかったからといって残りを試さないのは誤りで、飛ばしたことは
	// slog.Warn に残る。pgx の行ループではなく取得元のループなので、
	// rows.Err() で拾える種類の失敗でもない。
	"api/handlers/cloud_posture_handler.go:GetPosture": "取得元ごとの" +
		"フォールバック。1 つ読めなくても次を試すのが目的で、" +
		"飛ばした取得元は slog.Warn に残る",
	// エージェントが 1 回のハートビートに複数の ack を相乗りさせる。
	// 1 件の記録に失敗しても、同じ便に載った他の ack は畳める。
	// 落ちた ack は次の便で再送されない代わりに、期限切れワーカーが
	// timeout として畳むので、記録が消えるのではなく粗くなる。
	"ingestion/handler.go:applyCommandAcks": "1 便に複数の ack が載る。" +
		"1 件の記録失敗で残りを捨てない。落ちた分は期限切れワーカーが" +
		"timeout として畳む",
	"api/handlers/api_security_handler.go:runOWASPScan": "機微パスへの" +
		"プローブ。/.env に到達できないのは、まさに調べている結果です。" +
		"到達できた場合だけが所見になります",
	"api/handlers/backup_handler.go:List": "ディレクトリ一覧を取った後に" +
		"e.Info() が失敗するのは、その間にファイルが消えた場合です。" +
		"消えたバックアップを一覧に出す方が困ります",
	"api/handlers/geolocation_handler.go:isPrivateIP": "定数として書いた" +
		"CIDR を解析しています。失敗するのは定数を書き間違えたときだけで、" +
		"実行時のデータでは起きません",
	// 「壊れた1件で全部を巻き添えにしない」という判断で飛ばしているもの。
	// どれも、その1件が効かなくなることをコードのコメントで認めています。
	// `cloud/poller.go:poll` は直しました (2026-08-12) —— 記録だけでなく
	// `tick.Fail` に届くので、その回は「終えられなかった」になります。
	"detection/custom_rules.go:LoadFromDB": "条件が壊れているルールは" +
		"「常に一致」でも「常に不一致」でもなく読み飛ばします。" +
		"壊れた1件で他のルールを巻き添えにしません",
	"store/alert_assign_store.go:FindMatch": "条件を読めない割り当て" +
		"ルールは適用しません。この関数は (string, bool) しか返せないので、" +
		"記録だけが手がかりです。担当者が付かないだけで、アラートは残ります",
	"store/rules.go:ListChannels": "設定を読めない通知チャネルは返しません。" +
		"空の Config で返すと、送信先の無いセンダーが「有効」として作られ、" +
		"アラートごとに送信が失敗します",
	// #543 で入った 2 か所。`internal/scheduler` の他の 21 か所と同じ形で、
	// pgx が Scan の失敗で結果セットを終えるため continue の先に読める行は
	// 無く、直後の `rows.Err()` が `fail` に出します。ここだけ break に
	// 揃え直すと、揃っていた 21 か所のほうが例外に見えるようになります。
	// 同じ判断が `tick/tracked_workers_test.go` の
	// silentErrorBranchReasons にも書いてあります。
	"scheduler/agent_health_alerter.go:resolveRecoveredSensorAlerts": "行走査の" +
		"失敗。直後の rows.Err() が fail に出すので、閉じ切れていない" +
		"アラートが残ることは外から見えます",
	"scheduler/agent_health_alerter.go:checkDegradedSensors": "同上。" +
		"降格センサーの一覧が短くなったことは rows.Err() が報告します",
	"scheduler/darkweb_scheduler.go:syncRansomwareLive": "外部フィードの" +
		"被害者エントリ。時刻が読めないものは30日より古い扱いにします。" +
		"フィードの書式は先方の都合で変わるので、1件で同期全体を止めません",
}

// TestNoSkipExceptionHasGoneStale — 直した箇所の理由が残り続けないこと。
// 古い理由は、読んだ人にまだ壊れていると思わせます。
func TestNoSkipExceptionHasGoneStale(t *testing.T) {
	found := map[string]bool{}
	for _, s := range findSkipSites(t, "../..") {
		found[s.file+":"+s.fn] = true
	}
	for key := range skipExceptions {
		if !found[key] {
			t.Errorf("%s: 例外として残していますが、実測に見当たりません。"+
				"直したのなら理由も消してください", key)
		}
	}
}

const silentSkipCeiling = 0

// silentSkipProblem は件数の判定そのもの。
//
// 木が綺麗な通常状態では len(silent) == 0 なので、上限の比較はどちらの側にも
// 入りません。上限を 5 に上げても、比較ごと消しても、何も落ちません。
// 判定を関数にして、下の表から直接動かします。
func silentSkipProblem(actual, ceiling int) string {
	if actual > ceiling {
		return fmt.Sprintf(
			"失敗を黙って飛ばしているループが %d から %d に増えています。"+
				"pgx は Scan の失敗で結果セットを閉じるので、そのあとに rows.Err() を"+
				"見ていれば黙りません。見ていないもの、あるいは pgx 以外の失敗で"+
				"飛ばしているものが対象です", ceiling, actual)
	}
	// 上限が実測より高いことも言います。0 の絶対規則に「下げる余地」は
	// 無いので一度は落としましたが、それは間違いでした。この一行が、
	// 上限を黙って 5 に引き上げる変更を見つける唯一の目です。
	if actual < ceiling {
		return fmt.Sprintf(
			"黙って飛ばしているループは %d 箇所です。上限 %d は実測より高く、"+
				"その差の分だけ新しい見落としが素通りします。上限を %d に下げてください",
			actual, ceiling, actual)
	}
	return ""
}

func TestSkippedRowsAreNotSilent(t *testing.T) {
	sites := findSkipSites(t, "../..")
	if len(sites) < 200 {
		t.Fatalf("走査が届いていません: %d 箇所しか見つかりません", len(sites))
	}

	var silent []skipSite
	for _, s := range sites {
		if !s.silent {
			continue
		}
		// 理由を書いた箇所は上限から外します。件数ではなく理由が根拠に
		// なるので、外すには skipExceptions に1行書く必要があります。
		if _, ok := skipExceptions[s.file+":"+s.fn]; ok {
			continue
		}
		silent = append(silent, s)
	}

	if msg := silentSkipProblem(len(silent), silentSkipCeiling); msg != "" {
		detail := ""
		for i, s := range silent {
			if i == 12 {
				detail += fmt.Sprintf("\n  … ほか %d 件", len(silent)-12)
				break
			}
			detail += fmt.Sprintf("\n  %s:%d %s — %s", s.file, s.line, s.fn, s.snip)
		}
		t.Errorf("%s:%s", msg, detail)
	}
}

func TestTheSilentSkipCountIsJudged(t *testing.T) {
	for _, tc := range []struct {
		actual, ceiling int
		want            bool
	}{
		{0, 0, false},
		{1, 0, true},
		{13, 0, true},
		// 上限が実測より高い状態も問題として扱います。上限を黙って
		// 引き上げる変更は、これが無いと何にも映りません。
		{5, 10, true},
		{0, 5, true},
	} {
		if got := silentSkipProblem(tc.actual, tc.ceiling) != ""; got != tc.want {
			t.Errorf("%d/%d: 判定 %v (want %v)", tc.actual, tc.ceiling, got, tc.want)
		}
	}
}

// 通常状態では上の判定は肯定側に入りません。分類そのものを直接動かします。
func TestTheSkipRuleFires(t *testing.T) {
	classify := func(t *testing.T, body string) (src string, silent, viaRows, matched bool) {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("parse: %v (%s)", err, body)
		}
		fn := f.Decls[0].(*ast.FuncDecl)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			is, ok := n.(*ast.IfStmt)
			if !ok || matched {
				return true
			}
			if s, sl, vr, m := classifySkip(fn, nil, 0, "rows", is); m {
				src, silent, viaRows, matched = s, sl, vr, m
			}
			return true
		})
		return
	}

	for _, tc := range []struct {
		name        string
		body        string
		wantSilent  bool
		wantViaRows bool
		wantMatch   bool
	}{
		{
			name: "Scan で飛ばし、あとで rows.Err() を見る",
			body: "for rows.Next() {\nif err := rows.Scan(&a); err != nil { continue }\n}\n" +
				"if err := rows.Err(); err != nil { return err }",
			wantSilent: false, wantViaRows: true, wantMatch: true,
		},
		{
			name: "Scan で飛ばし、rows.Err() != nil の形で見る",
			body: "for rows.Next() {\nif err := rows.Scan(&a); err != nil { continue }\n}\n" +
				"if rows.Err() != nil { return rows.Err() }",
			wantSilent: false, wantViaRows: true, wantMatch: true,
		},
		{
			name: "Scan で飛ばし、返り値に rows.Err() を混ぜる",
			body: "for rows.Next() {\nif err := rows.Scan(&a); err != nil { continue }\n}\n" +
				"return out, rows.Err()",
			wantSilent: false, wantViaRows: true, wantMatch: true,
		},
		{
			name:       "Scan で飛ばし、誰も rows.Err() を見ない",
			body:       "for rows.Next() {\nif err := rows.Scan(&a); err != nil { continue }\n}\nreturn out",
			wantSilent: true, wantViaRows: true, wantMatch: true,
		},
		{
			// Err() が別の結果セットのものだと、この rows の失敗は出ません。
			name: "別の rows の Err() を見ている",
			body: "for rows.Next() {\nif err := rows.Scan(&a); err != nil { continue }\n}\n" +
				"if err := other.Err(); err != nil { return err }",
			wantSilent: true, wantViaRows: true, wantMatch: true,
		},
		{
			name:       "Unmarshal で飛ばす",
			body:       "for _, r := range rs {\nif err := json.Unmarshal(r, &c); err != nil { continue }\n}",
			wantSilent: true, wantViaRows: false, wantMatch: true,
		},
		{
			name:       "HTTP の失敗で飛ばす",
			body:       "for _, a := range as {\nif err := c.get(ctx, p, &v); err != nil { continue }\n}",
			wantSilent: true, wantViaRows: false, wantMatch: true,
		},
		{
			name: "Scan の代わりに helper を通す",
			body: "for rows.Next() {\nif err := scanSchedule(sc, rows); err != nil { continue }\n}\n" +
				"if err := rows.Err(); err != nil { return nil, err }",
			wantSilent: false, wantViaRows: true, wantMatch: true,
		},
		{
			// rows の Err() は見ているが、飛ばしているのは Scan ではない。
			// 「pgx が閉じてくれる」はこの失敗には効きません。
			name: "同じ rows の別のメソッドで飛ばす",
			body: "for rows.Next() {\nif err := rows.Values(); err != nil { continue }\n}\n" +
				"if err := rows.Err(); err != nil { return err }",
			wantSilent: true, wantViaRows: false, wantMatch: true,
		},
		{
			name:      "重複判定の continue は誤りではない",
			body:      "for _, k := range ks {\nif _, dup := seen[k]; dup { continue }\n}",
			wantMatch: false,
		},
		{
			name:       "記録してから飛ばすのは対象外",
			body:       "for rows.Next() {\nif err := rows.Scan(&a); err != nil { log(err); continue }\n}",
			wantMatch:  false,
			wantSilent: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, silent, viaRows, matched := classify(t, tc.body)
			if matched != tc.wantMatch {
				t.Fatalf("matched = %v (want %v)", matched, tc.wantMatch)
			}
			if matched && silent != tc.wantSilent {
				t.Errorf("silent = %v (want %v)", silent, tc.wantSilent)
			}
			// viaRows は answered_with_a_value_test.go が「二重に数えない」
			// ために使います。ここが甘いと、あちらの continue の件数が
			// 実際より小さく出ます。
			if matched && viaRows != tc.wantViaRows {
				t.Errorf("viaRows = %v (want %v)", viaRows, tc.wantViaRows)
			}
		})
	}
}

// pgx の挙動そのものを言葉にしておきます。この検査が「Scan の continue は
// 黙っていない」と言えるのは、Scan の失敗が結果セットを閉じるからです。
// もし将来この前提が変わったら、上の分類ごと間違いになります。
func TestScanFailureClosesTheResultSetInPgx(t *testing.T) {
	src, err := os.ReadFile(pgxRowsPath(t))
	if err != nil {
		t.Skipf("pgx のソースを読めません: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		"func (rows *baseRows) fatal(err error) {",
		"rows.err = err\n\trows.Close()",
		"func (rows *baseRows) Next() bool {\n\tif rows.closed {\n\t\treturn false",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("pgx の前提が変わっています。見つからない断片:\n%s\n"+
				"Scan の失敗が結果セットを閉じなくなったなら、"+
				"`continue` は本当に次の行へ進み、一覧は黙って短くなります", want)
		}
	}
}

func pgxRowsPath(t *testing.T) string {
	t.Helper()
	base := os.Getenv("GOMODCACHE")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("GOMODCACHE が分かりません")
		}
		base = filepath.Join(home, "go", "pkg", "mod")
	}
	matches, err := filepath.Glob(filepath.Join(base, "github.com/jackc/pgx/v5@*/rows.go"))
	if err != nil || len(matches) == 0 {
		t.Skip("pgx のソースが見つかりません")
	}
	sort.Strings(matches)
	return matches[len(matches)-1]
}
