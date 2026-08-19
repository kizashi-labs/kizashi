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

// 失敗した分岐が、値を作って先へ進む形。
//
// empty_on_failure_test.go は `if err != nil { … c.JSON(200, <空>) }` を
// 探します。分岐の中に応答があることが前提です。ところがこの形は違います:
//
//	if err := agentRow.Scan(&stats.AgentsOnline); err != nil {
//		stats.AgentsOnline = 0
//	}
//	…
//	c.JSON(http.StatusOK, stats)     ← 200 はここ
//
// 分岐は応答を返しません。ゼロを入れて落ちるだけで、200 は通常の経路が
// 返します。だから「空で返している実装」を探す検査には一切映りません。
// これが /api/v1/dashboard/summary の4つの数字すべてで起きていました。
// SOC が最初に開く画面の「オンライン0台・未対応アラート0件・未解決
// インシデント0件・重大アラート0件」です。落ち着いた朝と見分けが付きません。
//
// フロントエンド側でこれと同じ形を3回続けて見つけました。規則が見ている形
// より、コードのほうがいつも1つ多い。ここでは形ではなく、branch が何を
// しているかで数えます —— 値を作るだけで、err に触れないもの。
//
// 3つの家族に分かれます。直し方が違うので、別々に数えます:
//
//	assign   失敗を数字や空リストに置き換えて先へ進む。ゼロで固定。
//	return   何も報告せずに戻る。別のエラーに翻訳して返すものは含めません
//	         （それは報告です）。残るのは、エラーを返せない関数の中で
//	         ゼロ値を返して戻るものです。
//	continue ループの中で、読めなかった行を飛ばす。ただしこの家族は
//	         見た目ほど悪くありません —— pgx は Scan の失敗で結果セットを
//	         閉じるので、そのあとの rows.Err() が答えます。黙っているのは
//	         その検査が無いものだけで、それは skipped_row_test.go が
//	         0 で固定しています。
//
// continue が一番多く（364箇所）、直し方も一番重い —— rows.Scan が失敗する
// のは列の型が合っていないときなので、その行だけでなく同じ形の行すべてが
// 落ちます。つまり一覧は恒久的に一部を欠いたまま返り続けます。上限で
// 止めて、段階的に下げます。

type answerSite struct {
	file string
	fn   string
	line int
	kind string
	src  string
	// nilErr marks the sharpest shape: the function has an error result and
	// the branch puts nil in it. The caller is told the call succeeded.
	nilErr bool
}

// nilInErrorSlot reports whether ret puts nil where fn returns its error.
//
// これを分けるのは、`return` の家族が2つに割れるからです。
//
//	return nil, fmt.Errorf("not found")    ← 別のエラーに翻訳している。報告。
//	return []IOC{}, nil                    ← 成功として返している。捏造。
//
// 前者は「err に触れていない」ので、触れているかどうかだけで数えると
// 同じ箱に入ります。実際にはまったく別の話です。
func nilInErrorSlot(fn *ast.FuncDecl, ret *ast.ReturnStmt) bool {
	if fn.Type.Results == nil {
		return false
	}
	pos, i := -1, 0
	for _, r := range fn.Type.Results.List {
		n := len(r.Names)
		if n == 0 {
			n = 1
		}
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			pos = i
		}
		i += n
	}
	if pos < 0 {
		return false
	}
	if len(ret.Results) == 0 {
		return false // naked return of named results — not decided here
	}
	if pos >= len(ret.Results) {
		return false
	}
	id, ok := ret.Results[pos].(*ast.Ident)
	return ok && id.Name == "nil"
}

// errIdents returns the identifiers compared against nil in `if x != nil`,
// keeping only ones plausibly holding an error.
func errIdents(cond ast.Expr) map[string]bool {
	out := map[string]bool{}
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.BinaryExpr:
			if v.Op == token.NEQ {
				if id, ok := v.X.(*ast.Ident); ok {
					if nl, ok2 := v.Y.(*ast.Ident); ok2 && nl.Name == "nil" {
						l := strings.ToLower(id.Name)
						if l == "err" || l == "e" || strings.HasSuffix(l, "err") {
							out[id.Name] = true
						}
					}
				}
			}
			if v.Op == token.LAND || v.Op == token.LOR {
				walk(v.X)
				walk(v.Y)
			}
		case *ast.ParenExpr:
			walk(v.X)
		}
	}
	walk(cond)
	return out
}

// touches reports whether n references any of the given identifiers.
func touches(n ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// answersOnly reports whether the block only produces a value: every statement
// is a return / continue / break / a call-free assignment, and none of them
// mention the error.
//
// A branch that calls something — slog.Error, c.JSON, a retry — is doing
// something with the failure, and what it does is a separate question. A branch
// that names its error is likewise handling it. What is left is the branch that
// answers.
func answersOnly(b *ast.BlockStmt, errs map[string]bool) (string, bool) {
	if len(b.List) == 0 {
		return "empty", true
	}
	kind := ""
	for _, st := range b.List {
		switch s := st.(type) {
		case *ast.ReturnStmt:
			if touches(s, errs) {
				return "", false
			}
			// 新しいエラーに翻訳して返すのも報告です。
			//
			//	return nil, fmt.Errorf("ユーザーが見つかりません")
			//
			// err に触れていないので「答えている」に見えますが、呼び出し側は
			// 失敗を受け取ります。触れているかどうかだけで数えると、
			// store/users.Authenticate のような正しい書き方が違反として並び、
			// 上限の数字が意味を失います。
			if returnsAnError(s) {
				return "", false
			}
			kind = "return"
		case *ast.BranchStmt:
			if s.Tok != token.CONTINUE && s.Tok != token.BREAK {
				return "", false
			}
			kind = strings.ToLower(s.Tok.String())
		case *ast.AssignStmt:
			if touches(s, errs) {
				return "", false
			}
			hasCall := false
			ast.Inspect(s, func(x ast.Node) bool {
				if _, ok := x.(*ast.CallExpr); ok {
					hasCall = true
				}
				return !hasCall
			})
			if hasCall {
				return "", false
			}
			kind = "assign"
		case *ast.ExprStmt:
			// 記録して値を返すのは、まだ値で答えています。
			//
			// この分岐を default に落としていたあいだ、slog.Error を1行
			// 足すだけでその箇所は数から消えました。実際に消しました。
			// 黙って値を返すより良いのは確かですが、呼び出し側が受け取る
			// ものは1文字も変わりません。数が下がって直ったように見える
			// のがいちばん高くつくので、記録だけの分岐は数え続けます。
			//
			// 記録以外の呼び出し（後始末、再試行の登録、別経路への通知）は
			// これまで通り「答えるだけではない」として数から外します。
			if !isLoggingCall(s.X) {
				return "", false
			}
		default:
			return "", false
		}
	}
	if kind == "" {
		// 記録だけして、続きの処理に落ちる分岐。値では答えていません。
		return "", false
	}
	return kind, true
}

// isLoggingCall reports whether an expression is only writing a log line.
//
// slog.Error(...) / log.Printf(...) / h.logger.Warn(...) のような形。
// 受け手はいません。運用者がログを見に行ったときにだけ届きます。
func isLoggingCall(x ast.Expr) bool {
	call, ok := x.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Debug", "Info", "Warn", "Error", "Print", "Printf", "Println",
		"DebugContext", "InfoContext", "WarnContext", "ErrorContext":
	default:
		return false
	}
	// 受け手が slog / log / …logger… であること。err.Error() のような
	// 同名メソッドを巻き込まないための確認です。
	recv := ""
	switch r := sel.X.(type) {
	case *ast.Ident:
		recv = r.Name
	case *ast.SelectorExpr:
		recv = r.Sel.Name
	}
	recv = strings.ToLower(recv)
	return recv == "slog" || recv == "log" || strings.Contains(recv, "logger") ||
		strings.Contains(recv, "log")
}

// returnsAnError reports whether any returned expression is plausibly a
// non-nil error: errors.New(...), fmt.Errorf(...), or a package-level sentinel
// named errXxx / ErrXxx.
func returnsAnError(ret *ast.ReturnStmt) bool {
	for _, r := range ret.Results {
		switch v := r.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				pkg, _ := sel.X.(*ast.Ident)
				if pkg != nil && (pkg.Name == "errors" && sel.Sel.Name == "New" ||
					pkg.Name == "fmt" && sel.Sel.Name == "Errorf") {
					return true
				}
			}
		case *ast.Ident:
			n := v.Name
			if n != "nil" && len(n) > 3 &&
				(strings.HasPrefix(n, "err") || strings.HasPrefix(n, "Err")) {
				return true
			}
		}
	}
	return false
}

// callName is the name of the function whose error this branch handles.
func callName(e ast.Expr) string {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// PARAMETER_PARSING are the sources whose failure genuinely means "the caller
// did not say", not "we could not find out".
//
//	limit, err := strconv.Atoi(c.Query("limit"))
//	if err != nil || limit <= 0 { limit = 50 }
//
// An absent ?limit= is an empty string, and Atoi rejects it. Defaulting there
// is the endpoint's contract, not a swallowed failure. Nothing about the
// answer is invented — the caller asked for the default by not asking.
//
// This is deliberately a short list. Anything that reads data (Scan, Query,
// Unmarshal) or reads what the caller actually sent (ShouldBindJSON) is not
// here, because for those the failure does mean we could not find out.
var parameterParsing = map[string]bool{
	"Atoi": true, "ParseInt": true, "ParseFloat": true, "ParseBool": true,
	"ParseDuration": true,

	// Ping はここでは値の捏造ではありません。
	//
	//	if err := h.pool.Ping(ctx); err != nil { dbStatus = "down" }
	//
	// 死活を調べる処理にとって、失敗そのものが答えです。"down" は作った値
	// ではなく、測った結果です。
	"Ping": true,
}

// nilErrExceptions are the two places where returning a value with a nil error
// is the right answer, each with the reason and the guard that makes it so.
//
// 「例外」と書くだけでは足りません。どちらも、失敗が別の道で呼び出し側に
// 届いているから許されています。その道が消えたら例外は成り立たないので、
// 下の TestTheNilErrorExceptionsStillHold がその道を確かめます。
var nilErrExceptions = map[string]string{
	"aiassist/assistant.go": "戻り値に Unavailable と UnavailableReason を立てて返します。" +
		"error ではなく値で報告しているので、呼び出し側と画面はそれを読みます",
	"license/manager.go": "読めないライセンスを FREE（いちばん小さいプラン）に落とします。" +
		"方向が逆なら、読めないだけで機能が開きます。usage_honesty_test.go が向きを留めています",
}

// TestTheNilErrorExceptionsStillHold checks the reason, not just the name.
func TestTheNilErrorExceptionsStillHold(t *testing.T) {
	for file, needles := range map[string][]string{
		"../../aiassist/assistant.go": {"Unavailable:       true", "UnavailableReason: reason"},
		"../../license/manager.go":    {"return defaultLicense(), nil"},
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s を読めません: %v", file, err)
			continue
		}
		for _, n := range needles {
			if !strings.Contains(string(b), n) {
				t.Errorf("%s: 例外の根拠 (%s) が見当たりません。"+
					"根拠が消えたなら、この例外はもう成り立ちません", file, n)
			}
		}
	}
}

// errSourceOf names the call whose error this if-statement is checking.
func errSourceOf(ifs *ast.IfStmt, errs map[string]bool, fn *ast.FuncDecl) string {
	if as, ok := ifs.Init.(*ast.AssignStmt); ok && len(as.Rhs) == 1 {
		if n := callName(as.Rhs[0]); n != "" {
			return n
		}
	}
	best := ""
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || as.Pos() >= ifs.Pos() || len(as.Rhs) != 1 {
			return true
		}
		for _, l := range as.Lhs {
			if id, ok := l.(*ast.Ident); ok && errs[id.Name] {
				if nm := callName(as.Rhs[0]); nm != "" {
					best = nm
				}
			}
		}
		return true
	})
	return best
}

func findAnswerSites(t *testing.T, roots ...string) []answerSite {
	t.Helper()
	var out []answerSite
	for _, root := range roots {
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
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					// クロージャの中の return は、そのクロージャの返り値です。
					// 外側の関数の error 位置とは関係がありません。
					if _, isLit := n.(*ast.FuncLit); isLit {
						return false
					}
					ifs, ok := n.(*ast.IfStmt)
					if !ok || ifs.Else != nil {
						return true
					}
					errs := errIdents(ifs.Cond)
					if len(errs) == 0 {
						return true
					}
					if parameterParsing[errSourceOf(ifs, errs, fn)] {
						return true
					}

					// nil を error の位置に置く return は、分岐が他に何を
					// していても捏造です。ログを1行足しても、呼び出し側は
					// 成功を受け取ります。だから answersOnly とは独立に見ます。
					nilErr := false
					if len(ifs.Body.List) > 0 {
						if r, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ReturnStmt); ok {
							nilErr = nilInErrorSlot(fn, r)
						}
					}

					kind, only := answersOnly(ifs.Body, errs)
					if !only && !nilErr {
						return true
					}
					out = append(out, answerSite{
						file: rel, fn: fn.Name.Name,
						line: fset.Position(ifs.Pos()).Line, kind: kind,
						src:    strings.Join(strings.Fields(exprText(fset, ifs)), " "),
						nilErr: nilErr,
					})
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out
}

func exprText(fset *token.FileSet, n ast.Node) string {
	p, e := fset.Position(n.Pos()), fset.Position(n.End())
	b, err := os.ReadFile(p.Filename)
	if err != nil || e.Offset > len(b) {
		return ""
	}
	s := string(b[p.Offset:e.Offset])
	if len(s) > 140 {
		s = s[:140]
	}
	return s
}

// returnExceptions は「値で答えるのが正しい」箇所です。キーは file:fn。
//
// **件数はここに書きません。** 「28箇所です」と書いてあったのが 45 に
// なっていました —— 増やすたびに文章を直す約束は守られません。数は
// TestReturnExceptionCountIsPinned が留めます。
//
// 値だけの上限は「あと何件残っているか」しか言いません。0 にするには、
// 残った1件ずつに「なぜ値で答えるのが正しいのか」を書くしかありません。
// 書けないものは例外ではなく、直す対象です。実際、書こうとして書けな
// かった26件はこの2コミットで直しました。
//
// 3つの型に分かれます。
//
//	(a) 「該当なし」を表す戻り値で、失敗も同じ値になるが、失敗した
//	    ことは別の道で伝わっている
//	(b) 内部の構造体を json.Marshal する分岐。chan・func・NaN を含まない
//	    限り encoding/json は失敗しないので、実際には到達しません
//	(c) 「分からない」と言うのが正しい答え
//
// (b) は「たぶん到達しない」です。crypto/rand で一度これを間違えて、
// 到達しない分岐にエラー処理を足しました。消すのではなく、到達しない
// 理由を書いて残します。到達したら値が壊れているので、そのときは
// 型が変わっているはずで、コンパイルが先に落ちます。
var returnExceptions = map[string]string{
	// **`false` を返すことが、この失敗の答えです。**
	//
	// `pgxpool` の `AfterRelease` は「この接続をプールに戻すか」を
	// bool で答えます。`app.tenant_id` を消せなかった接続は戻しません
	// —— 戻すと、次にテナントを持たない呼び出し（起動時の初期化や
	// 背景の仕事）がその接続を引いたとき、**前のテナントの値のまま**
	// そのテナントに絞られた結果を読みます。呼び出し側は pgx で、
	// error を受け取る口がありません。
	"store/postgres.go:clearConnTenant": "(c) 消せなかった接続を捨てる、" +
		"という判断そのものです。`slog.Warn` は理由を残すためで、" +
		"応答ではありません",

	// **これは「値で答える」ことそのものが直しです。**
	//
	// 確認に失敗したとき `false`（＝「そのテーブルは無い」）を返して
	// いたのが元の形で、呼び出し側 193 箇所はそれを受けて 200 の空・
	// 404・503 を返していました。**DB に届かないだけで「その機能は
	// 使われていません」と同じ姿になります。**
	//
	// 実測 (2026-08-12): `bas_scenarios` に 120,400 行、
	// `statement_timeout` 1ms で `/api/v1/admin/bas/scenarios` は
	// **200 の空**でした。いまは 500 です。
	//
	// `true` を返すのは、**本物のクエリに答えさせる**ためです ——
	// DB 障害ならそのハンドラ自身の失敗時の答え方が、テーブルが本当に
	// 無いなら 42P01 を `absent()` が見分けて空を返します。
	"store/table_probe.go:ProbeAnswer": "(c) 確認の失敗を「無い」に" +
		"倒さないための true です。失敗そのものは slog.Warn に出し、" +
		"応答は本物のクエリが決めます",

	// ── (a) 失敗は別の道で伝わる ────────────────────────────────────
	"api/handlers/phishing_handler.go:loadSMTPConfig": "(c) 応答が " +
		"smtp_ready:false / sending:false を返すので、送っていないことは呼び出し側に伝わります。" +
		"「メール連携が未設定」と「設定を読めなかった」が同じ false になりますが、" +
		"どちらでも「送っていない」は正しく、偽の送信済みは出ません",
	"ingestion/handler.go:parseDeviceEvent": "(a) 呼び出し側 insertDeviceEvents が " +
		"false のたびに slog.Warn で「保存をスキップします」と記録します。" +
		"取りこぼしは黙っていません",
	"intel/taxii.go:taxiiObjectToEntry": "(a) bool は「指標ではない」を表し、" +
		"TAXII の束の大半は指標ではないので false が正常です。壊れた JSON のときだけ " +
		"slog.Warn で記録します",
	"api/handlers/enrollment_handler.go:checkAutoApprove": "(c) false は" +
		"「自動承認しない」＝手動承認へ。読めなかったときも同じ方向に倒れますが、" +
		"勝手に登録を通すより安全です。倒したことは slog.Error で記録します",
	// `alert_enrichment_pipeline.go:enrich` は直しました (2026-08-12) ——
	// `tick.Run` で回している仕事なので `tick.Fail` に届きます。
	"api/handlers/mdm_enrollment_handler.go:bridgeIOSAppInventory": "(a) " +
		"ack 処理の副作用。応答は別に返るので、ここから報告する相手がいません。" +
		"「普通の ack」と「読めなかった」は分けて記録済みです",
	// `cloud/poller.go:publishCloudEvent` は直しました (2026-08-12) ——
	// `tick.Run` で回している仕事なので `tick.Fail` に届きます。
	// **この2つは直しました (2026-08-12)。** darkweb は `fail` で回に、
	// realtime_correlator は回の外なので `metrics.BackgroundFailed` に
	// 出しています —— 例外から消さないと、次に同じ形が生えたときに
	// 黙って通ります（この一覧の staleness 検査が教えてくれました）。
	"triage/context.go:fetchRawEvent": "(a) 読めなかったことは記録し、" +
		"指標抽出を省きます。トリアージ全体を止めるほどの材料ではありません",
	"store/alert_assign_store.go:FindMatch": "(c) false は「自動割り当ての規則に" +
		"一致しなかった」。読めなかったときも一致なしに倒れますが、行き先は" +
		"人による振り分けです。誤って誰かに割り当てるより安全な方向で、" +
		"アラート自体は消えません",
	"suppression/engine.go:conditionMatches": "(c) 壊れた正規表現は「一致しない」。" +
		"抑制条件なので、一致しなければアラートは出ます。" +
		"逆に倒すと、書き損じた正規表現1本でアラートが消えます",
	"detection/engine.go:ptraceModeIsAttach": "(c) 解釈できない ptrace 引数は " +
		"true（＝抑制しない）。コメントに fail-open と明記されています。" +
		"逆に倒すと、読めなかった引数の分だけ検知が黙ります",
	"notification/webhook.go:classifyAttempt": "(c) 送信時のエラーは " +
		"outcomeRetryable。相手が答えなかったので、答えを知らない。" +
		"再送するのが正しい扱いです",

	// ── 意図して値で答えるもの（背景ワーカーの整理後に残った9件）──
	"api/handlers/websocket_handler.go:Handle": "(a) upgrader.Upgrade は" +
		"失敗時に自分で HTTP 応答を書きます。相手には既に届いているので、" +
		"ここから返せるものはありません",
	"auth/usercache.go:IsActive": "(c) DB障害のときは通します。認証基盤が" +
		"読めないことを理由に全員を締め出す方が損が大きいという判断で、" +
		"コメントに fail-open と明記し、slog.Error で記録しています。" +
		"行が無い（＝削除された利用者）とは分けてあります",
	"compliance/scorer.go:countCheck": "(c) (件数, 判定できたか) の組で返し、" +
		"呼び出し側は Check.Assessed に載せます。1本も判定できなければ " +
		"ErrNothingAssessed。0件を「準拠している」と読ませない作りで、" +
		"scorer_honesty_test.go が向きを留めています",
	"license/manager.go:GetCurrentLicense": "(c) 読めないライセンスは FREE" +
		"（いちばん小さいプラン）に倒します。逆向きなら、読めないだけで" +
		"機能が開きます。usage_honesty_test.go が向きを留めています",
	"mdm/apns_push.go:systemRoots": "(c) 読めなければ nil。空の CertPool を" +
		"返すと「プラットフォーム既定の証明書で検証している」ように見えて、" +
		"実際は何も検証しません。nil なら crypto/tls が既定に落ちます。" +
		"apns_roots_test.go が形を留めています",
	"notification/websocket.go:generateWSID": "(c) crypto/rand は Go 1.24 以降" +
		"エラーを返しません（失敗時は panic します）。到達しない分岐ですが、" +
		"math/rand に落ちていないことが重要なので残してあります",
	"store/alerts.go:decodeTags": "(c) 壊れたタグは空のタグとして返します。" +
		"ここで失敗を上げると Scan がその行を落とし、誰かが付けたラベルの" +
		"せいでアラートが一覧から消えます。タグが消えるのと、アラートが" +
		"消えるのとでは重さが違います",
	"yara/engine.go:matchString": "(c) 読めない16進文字列・壊れた正規表現は" +
		"「一致しない」。ルール単位で slog.Error に残し、そのルールが一度も" +
		"発火しないことが分かるようにしてあります。ここで評価を止めると、" +
		"1本の書き損じで YARA 全体が止まります",

	// ── (b) json.Marshal — 到達しない分岐 ──────────────────────────
	"wsbus/hub.go:marshal": "(b) 送信するのは自前の Message 構造体。" +
		"chan・func・NaN を含まないので encoding/json は失敗しません",
	"notification/websocket.go:Broadcast":        "(b) 同上。SSE に流す前の Marshal",
	"notification/websocket.go:BroadcastCloud":   "(b) 同上",
	"notification/websocket.go:BroadcastBilling": "(b) 同上",
	"notification/websocket.go:BroadcastToAgent": "(b) 同上",
	"api/handlers/metrics_history_handler.go:metricsEncodeDimensions": "(b) " +
		"map[string]interface{} を JSONB 列に入れるための変換。" +
		"入るのは API から受けた JSON 由来の値だけで、Marshal できない型は通りません",
	"api/handlers/metrics_report_handler.go:toJSON": "(b) fallback を引数で" +
		"受け取る形で、呼び出し側が「失敗したらこれ」を明示しています",

	// ── (c) 「分からない」が正しい答え ────────────────────────────
	"api/handlers/chaos_handler.go:displayName": "(c) 表示名を引けなければ " +
		"user_id を出します。誰なのかは同じだけ分かり、偽名は出ません",
	"api/handlers/backup_handler.go:buildPgDumpCmd": "(c) 接続URLを分解でき" +
		"なければ、そのまま --dbname に渡します。pg_dump 自身の方が解釈に" +
		"詳しいので、こちらの解釈失敗で諦める理由がありません",
	"geoip/locator.go:lookupFromRawData": "(c) raw_data から dst_ip を取り出す" +
		"だけの関数。取り出せなければ空文字で、呼び出し側は宛先IPの無い行として" +
		"読み飛ばします",
	"hunting/query_engine.go:parseRawData": "(c) 解釈できない raw_data は " +
		"{\"_raw\": <元の文字列>} として返します。捨てずに、解釈していないと" +
		"分かる形で渡しています",
	"triage/context.go:extractIndicatorCandidates": "(c) 解釈できないイベント" +
		"からは候補を出しません。読めなかったことは呼び出し元の fetchRawEvent が" +
		"記録します",
	"detection/commandline_normalize.go:decodeEncodedPowerShell": "(c) " +
		"base64 として読めない文字列は復号しません。元の文字列は呼び出し側に" +
		"残っていて、そちらで照合されます",
	"detection/cryptominer.go:Observe": "(c) 解釈できない process_stats からは" +
		"所見を出しません。次のスナップショットで測り直します",
	"detection/curate_category.go:RuleCategory": "(c) \"(unparseable)\" を" +
		"返します。分からないと書いてあるので、分類として読まれません",
	"detection/curate_builtin_coverage.go:sigmaTechniques": "(c) 解釈できない" +
		"ルールからは技術IDを出しません。重複判定に使う関数で、" +
		"重複と判定しない側に倒れます",
	"detection/field_support.go:RuleSelectedFields": "(c) 解釈できないルールが" +
		"選択するフィールドは無い。実際そのルールは1件も評価されません",
	"detection/field_support.go:RuleFieldSupportWith": "(c) 解釈できないルールは" +
		"field-support 無しとして扱います。curate はこれを inert として隔離するので、" +
		"「対応済み」に数えられることはありません",
	"detection/rules/condition_wildcard.go:expandAllOfWildcards": "(c) 展開" +
		"できなければ元の内容をそのまま返します。壊すよりは触らない",
	"mdm/apple_dep.go:stripPEMEnvelope": "(c) PEM の中身を base64 として読め" +
		"なければ nil。呼び出し側は復号できなかったトークンとして扱います",
	"api/handlers/export_handler.go:exportValue": "(a) 返す値そのものが報告です。" +
		"復号できなかったセルには「[復号できませんでした]」と書いて出します。" +
		"空欄にすれば「生データの無い行」と同じ姿になり、ciphertext をそのまま" +
		"出せば嘘の中身が出ます。**出力を受け取った人の手元に、出せなかったことが" +
		"残る形です。** 鍵の不一致などの詳細は slog.Error 側に置き、" +
		"エクスポートには載せません",
	"ws/subscription.go:ParseSubscribeMessage": "(c) 購読メッセージとして" +
		"読めないものは (nil, false)。WebSocket の相手が送ってくる文字列なので、" +
		"読めないことは日常的に起こります",
}

// TestNoReturnExceptionHasGoneStale checks the other direction of the list.
//
// 上限を下げるだけでは、直した箇所の理由が残り続けます。古い理由は、
// 読んだ人にまだ壊れていると思わせるので、消えた箇所の項目は落とします。
func TestNoReturnExceptionHasGoneStale(t *testing.T) {
	sites := findAnswerSites(t, answerRoots...)
	found := map[string]bool{}
	for _, s := range sites {
		if s.kind != "return" {
			continue
		}
		found[s.file+":"+s.fn] = true
	}
	for key := range returnExceptions {
		if !found[key] {
			t.Errorf("%s: 例外として残していますが、実測に見当たりません。"+
				"直したのなら理由も消してください", key)
		}
	}
}

// assignExceptions は「値を入れて進むのが正しい」1箇所です。
//
// 代入で片付けるのは、直し方がはっきりしていて例外の余地が小さい形です
// （失敗を表示用の値に置き換える）。上限を 0 にできたのは、残った1件が
// 「代入そのものが報告になっている」ためです。
var assignExceptions = map[string]string{
	"api/handlers/alert_enrichment_pipeline.go:enrichAlert": "complete = false " +
		"は、この代入が報告そのものです。呼び出し側がこれを見て status を " +
		"done ではなく pending にするので、そのアラートは次の周回で" +
		"取り直されます。値を入れて握り潰しているのではなく、" +
		"値を入れることで残しています",
}

// TestNoAssignExceptionHasGoneStale — 直した箇所の理由が残り続けないこと。
func TestNoAssignExceptionHasGoneStale(t *testing.T) {
	found := map[string]bool{}
	for _, s := range findAnswerSites(t, answerRoots...) {
		if s.kind == "assign" {
			found[s.file+":"+s.fn] = true
		}
	}
	for key := range assignExceptions {
		if !found[key] {
			t.Errorf("%s: 例外として残していますが、実測に見当たりません。"+
				"直したのなら理由も消してください", key)
		}
	}
}

// 上限。下げるだけ。
//
// assign は 0 で固定します。失敗を表示用の値に置き換えるのは、直し方が
// はっきりしていて例外の余地がありません（parameterParsing は上で外して
// あります）。残り2つは段階的に下げます。
const (
	// 失敗したのに、呼び出し側には成功として返す形。0 で固定。
	//
	//	func FetchURLhaus(ctx) ([]IOC, error) {
	//	    …
	//	    if err != nil { return []IOC{}, nil }   ← このフィードは0件でした
	//
	// 取り込み側は0件を正常として記録するので、フィードが何日落ちていても
	// 誰も気づきません。同じ形で、更新ポリシーの読み取り失敗が
	// 「RolloutPercent: 100」を返し、10%の段階配信の設定を無視して
	// 全端末に配信していました。
	answerNilErrCeiling = 0

	// 2026-08-10、上の答え合わせの規則を直したときに全部上がりました。
	// 数字が悪化したのではなく、それまで数えていなかったものが見えました。
	//
	//	assign    0 → 6
	//	return   43 → 166（理由を書いた40箇所を除いた後）
	//	continue 364 → 432
	//	break     1 → 2
	//
	// 原因は answersOnly が *ast.ExprStmt を default に落としていたことです。
	// slog.Error を1行足すと、その分岐は数から消えました。このセッション
	// でも実際に消しました — enrollment、scheduler、cloud/poller、triage、
	// taxii は「記録するようにした」だけで、呼び出し側が受け取る値は
	// 1文字も変わっていないのに、件数は下がりました。
	//
	// 記録は黙っているよりましですが、直したことにはなりません。物差しを
	// 直したので、以前このファイルが報告した数（return 57 など）は
	// すべて過小です。
	// return は 0 になりました。59 → 0 の内訳:
	//
	//   43件  背景の loop / subscriber。scheduler の外なので fail は使えず、
	//         metrics.BackgroundFailed(component, err, …) に置き換えました。
	//         edr_background_failures_total{component} が経路ごとに数えます。
	//         届かなかった Webhook、送られなかった通知、Elasticsearch に
	//         流れなかったドキュメント — 運用者から見えるのはどれも「無い」
	//         で、送るものが無かったのかは分かりませんでした。
	//    7件  呼び出し側が実在するので error を返すよう直しました
	//    9件  意図して値で答えるもの。returnExceptions に理由を書きました
	//
	// 0 は「もう起きない」ではありません。理由を書けないものが1件も無い、
	// という意味です。新しく増えれば、理由を書くか直すかを迫られます。
	//
	// ログを足して数を下げるのとは別のことです。ログは見に行った人にだけ
	// 届きます。指標は、見ていない人にも届きます。
	// metrics/background_failed_test.go が BackgroundFailed の中身を留めます。
	//
	// continue も 0 になりました。432 → 73 → 0。
	//
	// 途中で数え方が変わっているので、下がった分は「直した数」ではあり
	// ません。順に、行スキャンを skipped_row_test.go 側の担当に移し、
	// その skipped_row_test.go 自身の判定が狭かったのを2度直しました
	// （代入を1行前に出した形・Scan を代わりに呼ぶヘルパー・switch の
	// case 節、そして「記録してから飛ばす」形）。最後の1つは
	// answered_with_a_value_test.go で直したのとまったく同じ見落としで、
	// こちらの写しには残っていました。判定を1つ直しても、写しは直りません。
	//
	// 残りを 0 にしたのは、飛ばした1件を数える先を作ったからです。
	// 出すと決めたアラートが出なかった分は edr_alerts_dropped_total、
	// それ以外は edr_background_failures_total{component}。
	// 制御は変えていません — 飛ばすこと自体が正しい判断の箇所も多く、
	// 変えたのは「飛ばしたことが外から見えるか」だけです。
	// assign 6 → 0。5件は直し、1件は理由を書きました。
	//
	// 直した5件は、失敗のあとに続く処理が「その値で正しい」前提で書かれて
	// いたものです。AI 調査が関連イベント無しで結論を出す、ベースラインが
	// 誰も選んでいない期間で作り直される、CIS スコア 0 が時刻付きで
	// compliance_scores に保存される、プレイブックの実行が「何もしなかった
	// 実行」として履歴に並ぶ。どれも、あとから見た人には正常な記録に
	// 見えます。
	// 0 → 2 / 0 → 8 (main 取り込み)。**上限を上げたのは、どれも
	// 「その値で正しい」前提では書かれていないと確かめた分だけ**です:
	//
	//   assign  cloud_posture:TriggerScan  対象台数を数え損ねた回。0 台として
	//                                      進むが、開始できないことは応答に出る
	//           compliance/checker:AssessAgent  patchKnown=false を立てる。
	//                                      直後に unknown に倒れるので、
	//                                      「未対応 0 件 = 良好」にはならない
	//   return  uninstall_protection:GuardMaterialForHeartbeat  今回の便に
	//                                      保護設定を載せないだけ。端末は
	//                                      手持ちの設定を保持し、次便で届く
	//           update_handler:resolveUpdate  要求されたビルド版が無いので
	//                                      更新を提示しない（誤った版を
	//                                      配るより出さない）
	//           ingestion:commandToProto ×6  payload が壊れたコマンドは
	//                                      送らない。送ると端末で何が
	//                                      起きるか決まらない
	// 2 → 3 / 8 → 10 (#757/#760/#761 の取り込み)。増えた分も「その値で
	// 正しい」前提では書かれていないことを確かめてある:
	//
	//   assign  awsscan/iam_policy:parsePolicyDocument  URL エンコードされて
	//           いない文書がそのまま返ることがあるので、素の JSON として
	//           読み直す。復号の失敗ではなく形式の分岐
	//   return  detection/engine:applyRuleBasedResponse  自動隔離の失敗。
	//           Gatekeeper が response_actions に残すので、ここで戻っても
	//           記録は消えない
	//   return  ingestion:commandToProto  payload が壊れたコマンドは送らない
	//
	// 3 → 4 / 10 → 12 (#543/#764 の取り込み)。同じ確認をしてある:
	//
	//   assign  health_handler:Status  マイグレーション状態を読めなかった回。
	//           applied/latest の代わりに {"error":"unavailable"} を入れる。
	//           **数字を出さないことがそのまま答え**で、古い版を「最新」と
	//           言わない
	//   return  scheduler/agent_health_alerter:resolveRecoveredSensorAlerts /
	//           checkDegradedSensors  telemetry_mode 列が無い（357/365 未適用）
	//           ときの分岐。列が無ければ降格アラートも上がっていないので、
	//           閉じる対象も降格中の端末も存在しない
	//
	// 12 → 13 (#770 の取り込み)。増えた 1 件は
	// detection/self_remediation_suppression:IsSelfInflicted。直近の封じ込め
	// 操作を照会できなかったときに false（＝抑止しない）を返す分岐で、
	// **失敗を「該当なし」に化けさせる形と逆向き**です —— 分からないときに
	// アラートを消すと検知が静かに止まるので、残す側へ倒している。
	// その判断は関数のコメントにも書いてある。
	answerAssignCeiling = 4
	answerReturnCeiling = 13
	// continue の 0 は、一度これを書いた時点では嘘でした。
	//
	// 二重計上を避けるために skipCovered で行スキャンを外していたのですが、
	// findSkipSites は `if err != nil { continue }` を**すべて**返します
	// （あちらは「黙って飛ばしているか」を見るので、それで足ります）。
	// 結果、実測 380 件が 380 件とも外れ、上限0は「失敗を continue で
	// 片付けている箇所は無い」と読めていました。実際に言えていたのは
	// 「どれかがログを書いている」までです。
	//
	// 外すのを、失敗したのが回している rows 自身のもの（viaRows）だけに
	// 絞ると、残りは10箇所でした。10箇所とも skipExceptions に理由が
	// 書いてあり、その一覧をここでも使っています。いまの0は
	// 「rows.Err() が拾わない continue には、すべて理由が書いてある」です。
	//
	// 見つけたのは、この判定を変異させたときです。metrics の呼び出しを
	// ログに戻す変異が生き残り、なぜ数に出ないのかを追ったら、
	// **continue の系統がまるごと数から外れていました。**
	//
	// ── 0 は、まだ嘘でした (2026-08-12) ──────────────────────────────
	//
	// viaRows で絞ったあとも、**「そのあとの rows.Err() が答える」の
	// 「答える」を確かめていませんでした。** 確かめていたのは
	// 「rows.Err() を見ているか」までで、見たうえでログに書いて先へ進む
	// 関数がその大半でした。
	//
	// 実測 (2026-08-12): `internal/api/handlers` で rows.Err() を捨てて
	// いる関数は 190 個、その中の continue は 143 箇所。`internal/` 全体
	// では 174 箇所が、**誰もしない報告を根拠に外れていました。**
	//
	// **0 から 174 に上げます。** 直したから増えたのではなく、
	// 数えられていなかった分が見えるようになっただけです。ここからは
	// 下げる一方です —— 下げ方は2つで、`rows.Err()` を報告する形に
	// 変えるか（そのハンドラが応答を返せるなら）、その continue に理由を
	// 書くかです。書き出し（ファイルとして残るもの）は先に片付けました。
	//
	// ── 174 → 85 (2026-08-12) ──────────────────────────────────────
	//
	// `rows_err_policy_test.go` の1つめの規則 ——「`rows.Err()` の処理は、
	// **そのハンドラ自身がクエリ失敗にどう答えるか**に合わせる」——
	// を、揃っていない側に当てました。
	//
	// 実測: `internal/api/handlers` で `rows.Err()` を捨てている 289 箇所の
	// うち、**そのハンドラ自身はクエリ失敗で戻る**ものが 146 ありました。
	// そこは「半分だけ読めた」も同じ意味のはずです。146 箇所を、番人の
	// 本文をそのまま写す形で揃えました（応答の文言も状態も、その
	// エンドポイントが既に決めていたものです）。
	//
	// 写さなかったもの:
	//
	//   - 番人が 2xx で答えるもの。**写すと、読めていた行を捨てて空の
	//     200 を返すことになり、ログに落とすより悪くなります。**
	//   - 番人が応答しないもの（合成ページ）。写すと二重応答です。
	//   - 流しながら書く CSV。状態コードはもう出ています。
	//
	// 残りは、その3つのどれかです。**ここから先は、画面ごとに
	// 「途中まで見せるのが正しいか」を決める作業**で、`docs/判断待ちの
	// 一覧.md` に置いてあります。
	//
	// 85 → 80 (2026-08-12)。`internal/api/handlers` の外で、`error` を
	// 返せるのに `rows.Err()` を捨てていた **7 か所**を報告する形に
	// しました —— 抑制ルールの読み込み、ベースラインの読み出し、異常候補の
	// 走査、MITRE 網羅率（2か所）、プロセス木、レポートの MITRE 集計です。
	// **文字で数えたときは 3 でしたが、構文木で数え直したら 7 でした。**
	// main 取り込み後も 75。増えた 2 件 (cloud_posture の取得元
	// フォールバックと applyCommandAcks) は skipExceptions に理由を
	// 書いたので、ここには乗らない。
	answerContinueCeiling = 75
	// 2 → 3 (main 取り込み)。増えた 1 件は detectionmetrics/tracker.go の
	// MITRE 網羅表で、**break したあと mitreRows.Err() を見て error を
	// 返している** —— 途中までの網羅表を「いま検知できる範囲」として
	// 返さないための break なので、握り潰しではない。
	//
	// 3 → 6 (#543/#764 の取り込み)。3 件とも同じ形で、**break の直後に
	// rows.Err() を報告している**ことを確かめてある。continue と違って
	// 「残りも読めたことにする」余地が無いので、この系統は増えてよい:
	//
	//   compliance_export:Export / ExportSummary  切り詰めた統制一覧を
	//       ファイルとして渡さず 500。統制が「未確認」なのか「読めなかった」
	//       なのかは、書き出したファイルからは区別できない
	//   reports/generator:GenerateComplianceReport  部分集計を全体の
	//       準拠率として出さない（分母が欠けると「良好」に見える）
	answerBreakCeiling = 6
)

func ceilingComplaint(kind string, actual, ceiling int) string {
	if actual > ceiling {
		return fmt.Sprintf(
			"失敗を %s で片付けている箇所が %d から %d に増えています。"+
				"分岐そのものが応答を返さないので、空で返す実装を探す検査には映りません",
			kind, ceiling, actual)
	}
	if actual < ceiling {
		return fmt.Sprintf(
			"失敗を %s で片付けている箇所が %d まで減りました。上限を %d に下げてください",
			kind, actual, actual)
	}
	return ""
}

// internal/ 全体。ハンドラだけを見ると、同じ形が store や scheduler に
// 残ったまま「0件」と言えてしまいます。
var answerRoots = []string{"../.."}

// functionsThatReportRowsErr — rows.Err() を持ち、そのすべてを報告して
// いる関数の集合。
//
// **1つでも捨てているものがあれば入れません。** その関数の中の continue が
// どの rows のものかまでは追わないので、**外す側は狭い方に倒します** ——
// 外しすぎると、continue の件数が実際より小さく出ます。
func functionsThatReportRowsErr(t *testing.T, root string) map[string]bool {
	t.Helper()
	has := map[string]bool{}
	discards := map[string]bool{}
	for _, s := range findRowsErrSites(t, root) {
		key := s.file + ":" + s.fn
		has[key] = true
		if s.discarded {
			discards[key] = true
		}
	}
	out := map[string]bool{}
	for key := range has {
		if !discards[key] {
			out[key] = true
		}
	}
	return out
}

func TestFailuresAreNotAnsweredWithAValue(t *testing.T) {
	sites := findAnswerSites(t, answerRoots...)
	if len(sites) < 100 {
		t.Fatalf("走査が届いていません: %d 箇所しか見つかりません", len(sites))
	}

	// skipped_row_test.go が見ている行スキャンの位置。
	//
	// **viaRows のものだけです。** findSkipSites は `if err != nil { continue }`
	// をすべて返します（あちらは「黙って飛ばしているか」を見るので、それで
	// 足ります）。ここでその全部を外していたので、continue の実測 380 が
	// 380 件とも消え、上限0が「失敗を continue で片付けている箇所は無い」
	// と読める状態になっていました。実際に言えていたのは「どれかがログを
	// 書いている」までです。
	//
	// 外してよいのは、失敗したのが回している rows 自身で、ループのあとの
	// rows.Err() が同じ失敗を報告する箇所だけです。**JSON の解析や別の
	// クエリが失敗しての continue は、rows.Err() には出ません。**
	// **viaRows だけでも足りませんでした。**
	//
	// 「そのあとの rows.Err() が答える」は、その関数が rows.Err() を
	// **報告している**ときにしか成り立ちません。ログに書いて先へ進む
	// 関数の中では、誰も答えていません。
	//
	// 実測 (2026-08-12): `internal/api/handlers` で rows.Err() を捨てて
	// いる関数は 190 個、その中の continue は 143 箇所ありました。
	// **その 143 箇所は、誰もしない報告を根拠に外れていました。**
	reportsRowsErr := functionsThatReportRowsErr(t, answerRoots[0])
	skipCovered := map[string]bool{}
	for _, sk := range findSkipSites(t, answerRoots[0]) {
		if !sk.viaRows {
			continue
		}
		if !reportsRowsErr[sk.file+":"+sk.fn] {
			continue
		}
		skipCovered[fmt.Sprintf("%s:%d", sk.file, sk.line)] = true
	}

	// rows.Err() が拾わない continue の総数。理由を書いたものも含みます。
	//
	// 上限の 0 は「理由が書いてある」までしか言いません。**理由の一覧が
	// 空でも、外す側（viaRows）を緩めれば 0 になります** — 実際、緩んで
	// いたのを見つけたのがこの直前です。そちらが動いていないことを、
	// 理由リストとは別に、この数で押さえます。
	// 10 → 184 → 95 → 90 (2026-08-12)。**外す条件に「報告しているか」を
	// 足した**ときに 184 まで見えるようになり、146 箇所を揃えて 95、
	// handlers の外の7か所を揃えて 90 です。
	// 差の10は、いまも `skipExceptions` に理由が書いてあるものです。
	// 84 → 86 (main 取り込み)。増えた 2 件は cloud_posture の取得元
	// フォールバックと applyCommandAcks で、どちらも skipExceptions に
	// 理由を書いてある。
	// 86 → 88 (#543/#764 の取り込み)。増えた 2 件は
	// agent_health_alerter の resolveRecoveredSensorAlerts /
	// checkDegradedSensors の行走査。**`internal/scheduler` の他の 21 か所と
	// 同じ形**（pgx が結果セットを終えるので continue の先は無く、直後の
	// `rows.Err()` が `fail` に出す）なので、ここだけ break に替えると
	// 揃っていたものが崩れる。理由は skipExceptions と
	// `tick/tracked_workers_test.go` の silentErrorBranchReasons にある。
	const continueOutsideRowsErr = 88
	outside := 0
	for _, s := range sites {
		if s.kind == "continue" && !skipCovered[fmt.Sprintf("%s:%d", s.file, s.line)] {
			outside++
		}
	}
	if outside != continueOutsideRowsErr {
		t.Errorf("rows.Err() が拾わない continue が %d 箇所です（%d のはず）。"+
			"増えたなら理由を書くか直してください。減ったなら定数を %d に下げてください。"+
			"0 に近づいたときは、外す側（viaRows）が緩んでいないかを先に見てください",
			outside, continueOutsideRowsErr, outside)
	}

	byKind := map[string][]answerSite{}
	for _, s := range sites {
		if s.kind == "" {
			continue // counted only under the nil-error rule below
		}
		// 理由を書いた箇所は上限から外します。件数ではなく理由が根拠に
		// なるので、外すには returnExceptions に1行書く必要があります。
		if s.kind == "return" {
			if _, ok := returnExceptions[s.file+":"+s.fn]; ok {
				continue
			}
		}
		if s.kind == "assign" {
			if _, ok := assignExceptions[s.file+":"+s.fn]; ok {
				continue
			}
		}
		// 行スキャンの continue は skipped_row_test.go が上限0で見ています。
		// ここで二重に数えると、423 という数字が「423箇所が黙っている」
		// ように読めます。実際に黙っているのは、どちらの検査も見ていない
		// 分だけです。
		if s.kind == "continue" && skipCovered[fmt.Sprintf("%s:%d", s.file, s.line)] {
			continue
		}
		// rows.Err() が拾わない continue のうち、理由を書いたもの。
		// 一覧は skipExceptions を共有します。同じ判断のための理由を2つの
		// 一覧に分けて持つと、片方だけが古くなり、どちらが本当か分から
		// なくなります（TestNoSkipExceptionHasGoneStale が古い項目を落とします）。
		if s.kind == "continue" {
			if _, ok := skipExceptions[s.file+":"+s.fn]; ok {
				continue
			}
		}
		byKind[s.kind] = append(byKind[s.kind], s)
	}

	nilErr := 0
	var nilErrSites []answerSite
	for _, s := range sites {
		if !s.nilErr {
			continue
		}
		if _, ok := nilErrExceptions[s.file]; ok {
			continue
		}
		nilErr++
		nilErrSites = append(nilErrSites, s)
	}
	if msg := ceilingComplaint("nil を error の位置に置く return", nilErr, answerNilErrCeiling); msg != "" {
		detail := ""
		for i, s := range nilErrSites {
			if i == 12 {
				break
			}
			detail += fmt.Sprintf("\n  %s:%d %s — %s", s.file, s.line, s.fn, s.src)
		}
		t.Errorf("%s%s", msg, detail)
	}

	for _, c := range []struct {
		kind    string
		ceiling int
	}{
		{"assign", answerAssignCeiling},
		{"return", answerReturnCeiling},
		{"continue", answerContinueCeiling},
		{"break", answerBreakCeiling},
	} {
		got := byKind[c.kind]
		if msg := ceilingComplaint(c.kind, len(got), c.ceiling); msg != "" {
			detail := ""
			if len(got) > 0 && len(got) <= 12 {
				for _, s := range got {
					detail += fmt.Sprintf("\n  %s:%d %s — %s", s.file, s.line, s.fn, s.src)
				}
			}
			t.Errorf("%s%s", msg, detail)
		}
	}
}

// 通常状態では上のどの分岐も肯定側に入りません。判定を直接動かします。
func TestTheAnswerRuleFires(t *testing.T) {
	parse := func(t *testing.T, body string) (*ast.IfStmt, *ast.FuncDecl) {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("parse: %v (%s)", err, body)
		}
		fn := f.Decls[0].(*ast.FuncDecl)
		var ifs *ast.IfStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if v, ok := n.(*ast.IfStmt); ok && ifs == nil {
				ifs = v
			}
			return true
		})
		return ifs, fn
	}

	for _, tc := range []struct {
		name string
		body string
		kind string
		want bool
	}{
		{"別のエラーに翻訳して返す", "if err != nil { return nil, fmt.Errorf(\"見つかりません\") }", "", false},
		{"errors.New で返す", "if err != nil { return errors.New(\"だめ\") }", "", false},
		{"番兵エラーを返す", "if err != nil { return nil, ErrNotFound }", "", false},
		{"ゼロを入れて進む", "if err != nil { n = 0 }", "assign", true},
		{"空のリストを入れて進む", "if err != nil { items = nil }", "assign", true},
		{"err を返さずに戻る", "if err != nil { return nil, nil }", "return", true},
		{"行を捨てる", "for {\nif err != nil { continue }\n}", "continue", true},
		{"抜ける", "for {\nif err != nil { break }\n}", "break", true},
		{"空の分岐", "if err != nil { }", "empty", true},
		{"err を返す", "if err != nil { return nil, err }", "", false},
		{"err を包んで返す", "if err != nil { return fmt.Errorf(\"x: %w\", err) }", "", false},
		{"記録するだけ", "if err != nil { slog.Error(\"x\", \"error\", err) }", "", false},
		// 記録してから値を返すのは、まだ値で答えています。この行が無いあいだ、
		// slog.Error を1行足すだけで箇所が数から消えました。
		{"記録してから値を返す",
			"if err != nil { slog.Error(\"x\", \"error\", err) ; return nil }", "return", true},
		{"記録してから飛ばす",
			"if err != nil { slog.Warn(\"x\") ; continue }", "continue", true},
		{"記録以外の呼び出しを挟むものは対象外",
			"if err != nil { tx.Rollback() ; return nil }", "", false},
		// gin の c.Error はミドルウェアに届くので、記録ではなく報告です。
		// 受け手を確かめずに名前だけで判定すると、これを見逃します。
		{"gin の c.Error は記録ではない",
			"if err != nil { c.Error(err) ; return nil }", "", false},
		{"span.RecordError も記録ではない",
			"if err != nil { span.Error(err) ; return nil }", "", false},
		{"err.Error() は記録ではない",
			"if err != nil { _ = err.Error() ; return nil }", "", false},
		{"応答を返す", "if err != nil { c.JSON(500, gin.H{}) ; return }", "", false},
		{"呼び出しを含む代入は仕事をしている", "if err != nil { v = fallback() }", "", false},
		{"else があるものは対象外", "if err != nil { n = 0 } else { n = 1 }", "", false},
		{"err ではない比較は対象外", "if x != nil { n = 0 }", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ifs, _ := parse(t, tc.body)
			if ifs == nil {
				t.Fatal("if が見つかりません")
			}
			if tc.name == "else があるものは対象外" {
				if ifs.Else == nil {
					t.Fatal("else を読めていません")
				}
				return
			}
			errs := errIdents(ifs.Cond)
			if tc.name == "err ではない比較は対象外" {
				if len(errs) != 0 {
					t.Fatalf("err でない識別子を拾っています: %v", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("err を読めていません: %s", tc.body)
			}
			kind, only := answersOnly(ifs.Body, errs)
			if only != tc.want {
				t.Fatalf("answersOnly = %v (want %v)", only, tc.want)
			}
			if only && kind != tc.kind {
				t.Errorf("kind = %q, want %q", kind, tc.kind)
			}
		})
	}
}

// パラメータの既定値と、読み取りの失敗を取り違えないこと。
func TestParameterDefaultsAreNotSwallowedFailures(t *testing.T) {
	fset := token.NewFileSet()
	srcText := `package p
func f() {
	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil || limit <= 0 { limit = 50 }
	var n int
	if err := row.Scan(&n); err != nil { n = 0 }
}`
	f, perr := parser.ParseFile(fset, "x.go", srcText, 0)
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	fn := f.Decls[0].(*ast.FuncDecl)

	var srcs []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		errs := errIdents(ifs.Cond)
		if len(errs) == 0 {
			return true
		}
		srcs = append(srcs, errSourceOf(ifs, errs, fn))
		return true
	})

	if len(srcs) != 2 {
		t.Fatalf("2つの分岐を読めていません: %v", srcs)
	}
	if !parameterParsing[srcs[0]] {
		t.Errorf("Atoi の既定値を握りつぶしとして数えています (src=%q)", srcs[0])
	}
	if parameterParsing[srcs[1]] {
		t.Errorf("Scan の失敗をパラメータの既定値として見逃しています (src=%q)", srcs[1])
	}
}

// nil を error の位置に置いたかどうかの判定。通常状態では 0 件なので、
// 走査からは一度も肯定側に入りません。
func TestNilInTheErrorSlotIsRecognised(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"(T, error) に nil", "func f() ([]int, error) { if err != nil { return []int{}, nil }; return nil, nil }", true},
		{"error だけに nil", "func f() error { if err != nil { return nil }; return nil }", true},
		{"error を返している", "func f() ([]int, error) { if err != nil { return nil, err }; return nil, nil }", false},
		{"別のエラーに翻訳", "func f() ([]int, error) { if err != nil { return nil, fmt.Errorf(\"x\") }; return nil, nil }", false},
		{"エラーを返さない関数", "func f() []int { if err != nil { return []int{} }; return nil }", false},
		{"error が第1返り値", "func f() (error, int) { if err != nil { return nil, 0 }; return nil, 0 }", true},
		{"裸の return は判定しない", "func f() (out []int, err error) { if err != nil { return }; return }", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, "x.go", "package p\n"+tc.src+"\n", 0)
			if perr != nil {
				t.Fatalf("parse: %v", perr)
			}
			fn := f.Decls[0].(*ast.FuncDecl)
			var ret *ast.ReturnStmt
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if is, ok := n.(*ast.IfStmt); ok && ret == nil && len(is.Body.List) > 0 {
					ret, _ = is.Body.List[0].(*ast.ReturnStmt)
				}
				return true
			})
			if ret == nil {
				t.Fatal("if の中の return を読めていません")
			}
			if got := nilInErrorSlot(fn, ret); got != tc.want {
				t.Errorf("nilInErrorSlot = %v (want %v)", got, tc.want)
			}
		})
	}
}

func TestTheCeilingComplaintRatchets(t *testing.T) {
	for _, tc := range []struct {
		actual, ceiling int
		want            string
	}{
		{0, 0, ""},
		{1, 0, "増えています"},
		{5, 10, "下げてください"},
		{11, 10, "増えています"},
	} {
		got := ceilingComplaint("assign", tc.actual, tc.ceiling)
		if tc.want == "" {
			if got != "" {
				t.Errorf("%d/%d: %q (want 無言)", tc.actual, tc.ceiling, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%d/%d: %q が %q を含みません", tc.actual, tc.ceiling, got, tc.want)
		}
	}
}

// /api/v1/dashboard/summary だけは名指しで留めます。
//
// 上の全体集計はゼロで固定してあるので、この1件を消しても健全なコードでは
// 何も落ちません。逆に、この endpoint だけが戻ったときは全体集計が 1 に
// 増えて落ちます。二重に見ているのは、この画面が SOC の最初の1枚だからです。
// 「オンライン0台・未対応0件」は、静かな朝の表示とまったく同じ形をしています。
func TestTheDashboardSummaryDoesNotAnswerZeroOnFailure(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "dashboard_stats_handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var summary *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "Summary" {
			summary = fn
		}
	}
	if summary == nil {
		t.Fatal("Summary が見つかりません。走査が届いていません")
	}

	checked := 0
	ast.Inspect(summary.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || len(errIdents(ifs.Cond)) == 0 {
			return true
		}
		checked++
		if _, only := answersOnly(ifs.Body, errIdents(ifs.Cond)); only {
			t.Errorf("dashboard_stats_handler.go:%d の分岐が値を作って先へ進んでいます: %s\n"+
				"  この4つは SOC が最初に開く画面の数字です。0 を入れて 200 を返すと、"+
				"静かな朝と区別が付きません",
				fset.Position(ifs.Pos()).Line, strings.Join(strings.Fields(exprText(fset, ifs)), " "))
		}
		if !endsInReturnStmt(ifs.Body) {
			t.Errorf("dashboard_stats_handler.go:%d の分岐が return で終わっていません。"+
				"通常の経路が 200 を返してしまいます", fset.Position(ifs.Pos()).Line)
		}
		return true
	})
	if checked == 0 {
		t.Fatal("Summary の中に err の分岐が1つも見つかりません。走査が壊れています")
	}
}

func endsInReturnStmt(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

// 区画のポリシー一覧が、黙って短くならないこと。
//
// loadPolicies は以前、読み取りが途中で終わっても「そこまでに読めた分」を
// 返していました。呼び出し側はそれを 200 で返すので、画面には「ポリシー
// 3件」と出ます。実際に何件あるのかは誰にも分かりません。区切りを守る
// ための設定なので、欠けたまま見せるのと見せないのとでは意味が違います。
//
// 上限の集計はこの戻り方を見分けられません（err に触れている分岐なので
// 「答えているだけ」に当てはまらない）。名指しで留めます。
func TestSegmentationAnswersWithAllItsPoliciesOrWithNone(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "network_segmentation_handler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	seen := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		body := strings.Join(strings.Fields(exprText(fset, fn.Body)), " ")
		if !strings.Contains(body, "h.loadPolicies(ctx)") {
			continue
		}
		seen++
		if !strings.Contains(body, "ReadFailure(c,") {
			t.Errorf("%s: loadPolicies の失敗を応答にしていません。"+
				"欠けたポリシー一覧が 200 で返ります", fn.Name.Name)
		}
	}
	if seen == 0 {
		t.Fatal("loadPolicies を使うハンドラが見つかりません。走査が届いていません")
	}
}

// 理由つきで外した件数を留めます。
//
// **理由の一覧は、増えるほど「上限0」の意味が薄くなります。**
// 0 は「残りゼロ」ではなく「残りは全部、理由が書いてある」です。
// 何件に理由を書いたのかが見えないと、その差が隠れます。
func TestReturnExceptionCountIsPinned(t *testing.T) {
	// 実測 (2026-08-12)。**増やすときは、ここも動かしてください。**
	const want = 42
	if got := len(returnExceptions); got != want {
		t.Errorf("理由つきで外した return が %d 件です（%d のはず）。"+
			"増やしたなら定数を %d に。減らしたなら下げてください ——"+
			"**上限0は「残りゼロ」ではなく「残りは全部、理由が書いてある」です**",
			got, want, got)
	}
}
