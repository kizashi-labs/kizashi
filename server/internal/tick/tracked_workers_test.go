package tick_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/tick"
)

// **周期的に回る仕事が、回ったことを残すこと。**
//
// 実測 (2026-08-12): `server/internal` に ticker を持つ箇所は 73。
// うち `internal/scheduler` が 36、**その外が 37 で、1つも run を記録して
// いませんでした。**
//
// **走査は `server/internal` の全部を見ます（`internal/scheduler` を
// 含みます）。** 対象 76、うち `internal/scheduler` が 39。
//
// `internal/scheduler` には既にこの仕組みがありました。「40 のワーカーの
// うち、計測を出していたのは3つ」という実測から作られたもので、
// **その仕事は package の中で止まっていました。** 外のワーカーは、
// 動いているのか一度も動いていないのかを、外から区別できません ——
// `heartbeat.go` の言い方を借りれば、「起きて何もなかった」と
// 「一度も動いていない」が同じ観測になります。
//
// ここは「周期の合図を持つ関数」を数え、**回ごとの仕事を `tick.Run`
// （`internal/scheduler` では `trackRun`）に通していない枝を挙げます。**
// 通さなくてよいものには理由が要ります。

// **`tick.Run` を通さなくてよい ticker。** 理由が要ります。
//
// 大きく2種類です。**接続ごと・要求ごとのもの**（利用者が見ていて、
// 止まればその場で分かる）と、**メモリの掃除**（DB を触らず、
// 止まっても静かに壊れることがない）です。
var untrackedTickerReasons = map[string]string{
	// 1 回のスキャンの中で、AWS がレポートを生成し終わるのを待つだけの
	// 有界ポーリング（上限 credReportMaxWait）。周期ワーカーではないので
	// 「回ったこと」を残す相手がいない。待ちきれなければ error を返し、
	// 呼び出し元のスキャン（cspm_scanner）が trackRun 越しに記録する。
	"cspm/awsscan/credential_report.go:credentialReport": "1 スキャン内の" +
		"有界待ち。周期の仕事ではなく、失敗は呼び出し元のスキャンに返る。",
	// ── 接続ごと・要求ごと ──────────────────────────────────────────
	"notification/websocket.go:HandleCloudEvents":                "接続ごとの keepalive。切れれば利用者の画面に出ます。",
	"notification/websocket.go:handleSSE":                        "同上。",
	"notification/websocket.go:HandleBillingEvents":              "同上。",
	"api/handlers/websocket_handler.go:Handle":                   "同上。",
	"api/handlers/live_response_handler.go:StreamOutput":         "1回の実行の出力を流すあいだだけの ticker。",
	"api/handlers/event_stream_handler.go:streamNATSUnavailable": "NATS が無いときに接続を保つだけ。",
	"ingestion/handler.go:EventStream":                           "エージェントとの1本のストリームごと。",

	// ── メモリの掃除（DB を触りません） ─────────────────────────────
	"auth/ratelimit.go:cleanupLoop":        "メモリ上のカウンタの掃除。DB を触りません。",
	"auth/blocklist.go:StartCleanup":       "同上。",
	"cache/cache.go:New":                   "メモリキャッシュの追い出し。",
	"api/middleware/rate_limit.go:cleanup": "同上。",
	"audit/logger.go:Start":                "メモリ上の緩衝の書き出し。**失敗はその場で slog に出ます** —— 回として数えるかは、監査ログの欠落をどう扱うかの判断なので `docs/判断待ちの一覧.md` に置いてあります。",

	// ── 周期の仕事ではないもの ───────────────────────────────────────
	//
	// **待つのが枝で、仕事が本体にある形**（work-then-wait）です。
	// 周期ではなく再送・待ち合わせの間合いなので、「回」に当たるものが
	// ありません。3つとも、以前は**枝が空だという理由だけで黙って
	// 通っていました** —— 理由が要る形にしてあります。
	"notification/webhook.go:deliver": "1通の通知の再送ごとの待ち。" +
		"周期ではなく、通知1件の中の間合いです（結果は attempt ごとに" +
		"記録されます）。",
	"webhooks/dispatcher.go:send": "同上（webhook 1件の再送）。",
	"detection/engine.go:monitorConsumerLag": "NATS のラグを計測するだけで、" +
		"自身が計測を出しています。",
	"updater/health_checker.go:Wait": "更新のあとの待ち合わせで、周期の仕事では" +
		"ありません（一度きり、健全になるまで待ちます）。",
}

// **`internal/scheduler` も対象です（2026-08-12 に入れました）。**
//
// それまでは「あちらは `heartbeat_coverage_test.go` が見ている」として
// 丸ごと外していました。**あちらが見ているのはファイル単位です** ——
// 「そのファイルのどこかに `trackRun(ctx, "名前", …)` があるか」。
// 実測: `dead_agent_cleanup.go` は 5 分のタイマーと 24 時間の ticker の
// 2つの枝を持っていて、**24 時間の枝（日次の掃除そのもの）から
// `trackRun` を外しても、あちらは緑のままでした。**
//
// これは、この検査が前に自分で直したのと同じ穴です —— 起動時の1回だけ
// 包めば通る形。片方の枝だけ包んでも通ります。ここは枝ごとに見るので、
// 同じ走査を両側に当てます。`trackRun` は `tick.Run` への1行の委譲で、
// そのことは `TestTheOnlyTrackRunIsTheSchedulerDelegation` が見ています。

const workerRoot = ".."

// 実測 (2026-08-12): `server/internal` に周期の合図を持つ関数は 76。
// 内訳は `internal/scheduler` の外が 37（`time.NewTicker` だけを見て
// いたときは 34 —— `for` の中の `time.After` を数え始めて 3 つ増えました）、
// **`internal/scheduler` の中が 39。**
const minUntrackedCandidates = 60

// 走査が届いたか。**床ちょうどは「届いた」側です。**
//
// 判定をここに出しているのは、緑のツリーでは走査がいつも届いていて、
// 境界に一度も触れないからです（下の TestTheWorkerScanFloorNoticesAnEmptyWalk）。
func walkReachedTheFloor(candidates int) bool {
	return candidates >= minUntrackedCandidates
}

func TestEveryPeriodicWorkerRecordsThatItRan(t *testing.T) {
	fset := token.NewFileSet()
	type site struct {
		file string
		fn   string
		line int
	}
	var bad []site
	candidates := 0

	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if strings.HasPrefix(rel, "tick/") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !hasTicker(fn.Body) {
				continue
			}
			candidates++
			if !isUntrackedWorker(fn.Body, rel, fn.Name.Name, untrackedTickerReasons) {
				continue
			}
			bad = append(bad, site{rel, fn.Name.Name, fset.Position(fn.Pos()).Line})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !walkReachedTheFloor(candidates) {
		t.Fatalf("走査が届いていません: 周期の合図を持つ関数が %d 個しか"+
			"見えません（実測 76、床 %d）", candidates, minUntrackedCandidates)
	}
	t.Logf("周期の合図を持つ関数: %d 個 / 理由つきで外したもの: %d",
		candidates, len(untrackedTickerReasons))

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	for _, s := range bad {
		t.Errorf("%s:%d %s が、回ったことを残していません。"+
			"**動いているのか、一度も動いていないのかが外から区別できません** —— "+
			"`tick.Run(ctx, \"名前\", 仕事)` で包むか、包まない理由を書いてください",
			s.file, s.line, s.fn)
	}
}

// hasTicker — その関数が周期の合図を持っているか。
//
// **合図の形は1つではありません。**
//
//	time.NewTicker / time.Tick     一定の間隔で鳴り続けるもの
//	for の中の time.After/NewTimer 毎周ごとに張り直すもの
//
// 後者は「次は 02:00」のように**間隔が一定でない周期**に使います。
// `time.NewTicker` しか見ていなかったので、**毎日 02:00 に回る
// `internal/compliance/scheduler.go` が丸ごと走査から外れていました** ——
// この検査自身が、前に何度も直したのと同じ「狭く探して、無かったことに
// する」をしていたわけです。
//
// **ループの外の `time.After` は数えません。** それは待ち合わせの
// タイムアウトで、周期の仕事ではありません（`ingestion/handler.go` の
// グレースフル停止がその形です）。
func hasTicker(body *ast.BlockStmt) bool {
	if usesTimeFunc(body, "NewTicker", "Tick") {
		return true
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		var loop *ast.BlockStmt
		switch v := n.(type) {
		case *ast.ForStmt:
			loop = v.Body
		case *ast.RangeStmt:
			loop = v.Body
		default:
			return true
		}
		if pacesTheLoop(loop) {
			found = true
		}
		return true
	})
	return found
}

// pacesTheLoop — **そのループ自身が待っている**合図か。
//
// **入れ子の関数リテラルの中は数えません。** `go func(){ <-time.After(d) }()`
// はそのループを待たせません —— 一度きりの遅延実行です。実際
// `internal/remediation/engine.go` の `executeRule` がこの形で、
// アクションごとに遅らせて投げているだけの、周期の仕事ではないものです。
// 数えると「回ったことを残せ」と言う先が無くなります。
func pacesTheLoop(body *ast.BlockStmt) bool {
	return findTimeFunc(body, true, []string{"After", "NewTimer"})
}

// usesTimeFunc — `time.名前(...)` がその中に現れるか。
func usesTimeFunc(n ast.Node, names ...string) bool {
	return findTimeFunc(n, false, names)
}

func findTimeFunc(n ast.Node, skipFuncLit bool, names []string) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found {
			return false
		}
		if _, ok := m.(*ast.FuncLit); ok && skipFuncLit {
			return false
		}
		sel, ok := m.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "time" {
			return true
		}
		for _, name := range names {
			if sel.Sel.Name == name {
				found = true
			}
		}
		return true
	})
	return found
}

// tracked — **周期の枝が1つ残らず** `tick.Run` を通しているか。
//
// 「関数のどこかに `tick.Run` があればよい」にしていたら、**起動時の1回だけ
// 包んで、毎回の枝を素通しに戻す変更が通りました**（変異が生き残りました）。
// 記録されるのは起動の1回だけになり、そのあと何年止まっていても
// last_success は動いたままです。
// **合図の受け取り方も1つではありません。** `select` の枝のほかに
// `for range ticker.C { … }` があります。実測 (2026-08-12): その形が4つ
// ——どれも理由つきで外してあるものでしたが、**`select` の枝しか見て
// いなかったので、理由は一度も参照されていませんでした。** つまり
// 「理由があるから通っている」ではなく「見ていないから通っている」
// でした。DB を触るワーカーをこの形で書けば、黙って素通りします。
func tracked(body *ast.BlockStmt) bool {
	branches := 0
	wrapped := 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.RangeStmt:
			if !rangesOverTicker(v.X) || !branchDoesWork(v.Body.List) {
				return true
			}
			branches++
			if callsTickRun(v.Body) {
				wrapped++
			}
		case *ast.ForStmt:
			b, w := workThenWaitBranches(v)
			branches += b
			wrapped += w
		case *ast.CommClause:
			// `case <-ticker.C:` の枝だけを見ます（`case <-ctx.Done():` は除く）。
			//
			// **`for` の中とは限りません。** `c.Stream(func(w io.Writer) bool {
			// select { … } })` のように、繰り返すのが呼び出し先という形が
			// あります（`api/handlers/event_stream_handler.go`）。`for` から
			// 辿る形にしたときに、この1つが走査から外れました。
			if v.Comm == nil || !receivesFromTicker(v.Comm) {
				return true
			}
			// **何も呼んでいない枝は数えません。** トークンの補充のように
			// チャネルへ書くだけの枝があり、そこには記録するほどの「仕事」が
			// ありません（`internal/enrichment/virustotal.go` の
			// レートリミット補充がそれです）。**仕事がループ本体にある形は
			// `workThenWaitBranches` が拾います。**
			if !branchDoesWork(v.Body) {
				return true
			}
			branches++
			for _, stmt := range v.Body {
				if callsTickRun(stmt) {
					wrapped++
					break
				}
			}
		}
		return true
	})
	// **仕事をする枝が1つも無ければ、包む対象がありません。**
	// （`branches == 0` は「見落とした」ではなく「無い」です ——
	// 下の `branchDoesWork` がそこを分けています。）
	return branches == wrapped
}

// workThenWaitBranches — **枝が空で、仕事がループ本体にある**周期の枝。
//
// **待つのが枝で、仕事が本体にある形があります。**
//
//	for {
//	    work()                       ← 仕事はここ
//	    select {
//	    case <-ctx.Done(): return
//	    case <-ticker.C:             ← 枝は空
//	    }
//	}
//
// 枝の中しか見ていなかったので、この形は「仕事をする枝が無い」＝
// 「包む対象が無い」と読まれて**黙って通っていました**。実測 (2026-08-12):
// その形が3つ（webhook の再送2つと、更新後の健全性待ち1つ）。どれも
// 周期のワーカーではありませんでしたが、**そう読めたのは偶然で、
// 検査がそう判定したからではありません** —— DB を触るワーカーを
// この順で書けば、同じように素通りします。いまは枝として数え、
// 理由を書かせます。
func workThenWaitBranches(f *ast.ForStmt) (branches, wrapped int) {
	// **`select` は本体の直下とは限りません。** `if attempt > 0 { select … }`
	// のように条件の中にあります（webhook の再送がその形）。深さで
	// 探すのをやめると、その形が丸ごと外れます。
	var empty []*ast.CommClause
	loopWorks := false
	loopWrapped := false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectStmt:
			for _, cl := range v.Body.List {
				comm, ok := cl.(*ast.CommClause)
				if !ok || comm.Comm == nil || !receivesFromTicker(comm.Comm) {
					continue
				}
				// 仕事をしている枝は `tracked` の走査が数えます。ここは空の枝だけ。
				if !branchDoesWork(comm.Body) {
					empty = append(empty, comm)
				}
			}
			return false // select の中は「本体の仕事」ではありません
		case *ast.CallExpr:
			loopWorks = true
			if callsTickRun(v) {
				loopWrapped = true
			}
		}
		return true
	})
	if !loopWorks {
		return 0, 0
	}
	for range empty {
		branches++
		if loopWrapped {
			wrapped++
		}
	}
	return branches, wrapped
}

// receivesFromTicker — `case <-何か.C:` の形か。
//
// **`case now := <-ticker.C:` も同じ形です。** 受け取った値に名前を付けて
// いるだけで、周期の合図であることは変わりません。`ExprStmt` だけを見て
// いたので `internal/reports/scheduler.go` が走査から外れていました ——
// **1文字の違いで、ワーカーが1つ丸ごと見えなくなります。**
func receivesFromTicker(s ast.Stmt) bool {
	var x ast.Expr
	switch v := s.(type) {
	case *ast.ExprStmt:
		x = v.X
	case *ast.AssignStmt:
		if len(v.Rhs) != 1 {
			return false
		}
		x = v.Rhs[0]
	default:
		return false
	}
	un, ok := x.(*ast.UnaryExpr)
	if !ok || un.Op != token.ARROW {
		return false
	}
	switch inner := un.X.(type) {
	case *ast.SelectorExpr:
		return inner.Sel.Name == "C"
	case *ast.CallExpr:
		// **`case <-time.After(time.Until(next)):` も周期の枝です。**
		// 合図を毎周ごとに張り直しているだけで、`ticker.C` と同じ役です。
		return usesTimeFunc(inner.Fun, "After")
	}
	return false
}

// rangesOverTicker — `for range ticker.C {` の形か。
func rangesOverTicker(x ast.Expr) bool {
	sel, ok := x.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "C"
}

// branchDoesWork — その枝が何かを呼んでいるか。
func branchDoesWork(body []ast.Stmt) bool {
	found := false
	for _, stmt := range body {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if _, ok := n.(*ast.CallExpr); ok {
				found = true
			}
			return !found
		})
	}
	return found
}

// callsTickRun — その枝が回を記録しているか。
//
// **綴りは2つあります。** `tick.Run(...)` と、`internal/scheduler` の中の
// `trackRun(...)`（`tick.Run` への1行の委譲）。後者を知らないと、
// **あちらの 39 の枝が全部「包んでいない」に数えられます。**
// 委譲がほどけていないことは `TestTheOnlyTrackRunIsTheSchedulerDelegation`
// が見ています。
func callsTickRun(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		call, ok := m.(*ast.CallExpr)
		if !ok || found {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == trackRunName {
			found = true
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "tick" && sel.Sel.Name == "Run" {
			found = true
		}
		return true
	})
	return found
}

// `internal/scheduler` の中の呼び名。
const trackRunName = "trackRun"

// **`trackRun` が1つだけで、それが `tick.Run` への委譲であること。**
//
// 上の走査は裸の `trackRun(...)` を「記録した」と読みます。どこかの
// package が自前の `trackRun` を持てば、**中身が空でも全部通ります** ——
// 「包んだ」と「包んだ名前の関数を書いた」が同じ形になります。
// `trackRun` を置いてよい唯一の場所。
const trackRunHome = "scheduler/heartbeat.go"

// trackRunVerdict — その `trackRun` の定義が受け入れられるか。空文字なら可。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま定義は1つしかなく、それは正しいので、**判定を `if false` に潰しても
// 木がきれいなあいだは誰も気づけません。** 下の
// `TestTheTrackRunVerdictRecognisesTheRealThing` が見本を食わせます。
func trackRunVerdict(rel string, body *ast.BlockStmt) string {
	if rel != trackRunHome {
		return "ここに `" + trackRunName + "` は置けません（" + trackRunHome + " だけです）"
	}
	if !callsTickRun(body) {
		return "`tick.Run` を呼んでいません"
	}
	return ""
}

func TestTheOnlyTrackRunIsTheSchedulerDelegation(t *testing.T) {
	found := 0
	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		fn := findFunc(f, trackRunName)
		if fn == nil || fn.Body == nil {
			return nil
		}
		found++
		if why := trackRunVerdict(rel, fn.Body); why != "" {
			t.Errorf("%s の `%s`: %s。**あちらの 39 の枝が、中身の無い"+
				"名前で通ります**", rel, trackRunName, why)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	if found != 1 {
		t.Errorf("`%s` の定義が %d 個です、1個を期待。**走査が届いて"+
			"いないか、自前の %s が増えています**", trackRunName, found, trackRunName)
	}
}

func TestTheTrackRunVerdictRecognisesTheRealThing(t *testing.T) {
	delegation := parseBody(t, `tick.Run(ctx, name, fn)`)
	empty := parseBody(t, `slog.Info("ran", "name", name)`)

	if why := trackRunVerdict(trackRunHome, delegation); why != "" {
		t.Errorf("本物の委譲を拒んでいます: %s", why)
	}
	if trackRunVerdict(trackRunHome, empty) == "" {
		t.Error("**中身が `tick.Run` を指していない `trackRun` を" +
			"通しています。** 名前だけで 39 の枝が「包んである」に" +
			"なります")
	}
	if trackRunVerdict("detection/engine.go", delegation) == "" {
		t.Error("**別の package の自前の `trackRun` を通しています。** " +
			"中身が本物でも、増えれば次は中身が変わります")
	}
}

func parseBody(t *testing.T, body string) *ast.BlockStmt {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go",
		"package p\nfunc f() {\n"+body+"\n}\n", 0)
	if err != nil {
		t.Fatalf("見本を解析できません: %v", err)
	}
	return f.Decls[0].(*ast.FuncDecl).Body
}

// 探し方が効くこと。
func TestTheWorkerDetectorRecognisesTheRealThing(t *testing.T) {
	if !hasTicker(parseBody(t, `ticker := time.NewTicker(d.interval)`)) {
		t.Error("**`time.NewTicker` を周期の合図と見ていません。** " +
			"見落とすと、そのワーカーが走査から外れます")
	}
	if !hasTicker(parseBody(t, `c := time.Tick(time.Minute)`)) {
		t.Error("`time.Tick` を周期の合図と見ていません")
	}
	if hasTicker(parseBody(t, `t := time.NewTimer(time.Minute)`)) {
		t.Error("1回きりのタイマーを周期の合図に数えています")
	}
	if hasTicker(parseBody(t, `x := other.NewTicker(1)`)) {
		t.Error("`time` 以外の NewTicker を数えています")
	}

	// **毎周ごとに張り直す形も周期の合図です。**
	// 「次は 02:00」のように間隔が一定でない周期に使います。
	if !hasTicker(parseBody(t, `for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(nextRunTime())):
			s.runEvaluation(ctx)
		}
	}`)) {
		t.Error("**`for` の中の `time.After` を周期の合図と見ていません。** " +
			"毎日 02:00 に回る `internal/compliance/scheduler.go` が、" +
			"丸ごと走査から外れていました")
	}
	if !hasTicker(parseBody(t, `for {
		t := time.NewTimer(d.every)
		select {
		case <-t.C:
			s.work(ctx)
		}
	}`)) {
		t.Error("`for` の中の `time.NewTimer` を周期の合図と見ていません")
	}
	// **ループの外の `time.After` は待ち合わせです。** 周期の仕事では
	// ありません（`ingestion/handler.go` のグレースフル停止がこの形）。
	if hasTicker(parseBody(t, `select {
	case <-stopped:
	case <-time.After(gracefulStopTimeout):
		srv.Stop()
	}`)) {
		t.Error("**待ち合わせのタイムアウトを周期の合図に数えています。** " +
			"一度きりの待ちに「回ったことを残せ」と言うことになります")
	}
	// **入れ子の関数リテラルの中の `time.After` は、そのループを
	// 待たせません。** 一度きりの遅延実行です。
	if hasTicker(parseBody(t, `for _, action := range rule.Actions {
		go func() {
			select {
			case <-time.After(action.Delay):
				e.dispatchAction(ctx, action)
			case <-ctx.Done():
			}
		}()
	}`)) {
		t.Error("**アクションごとの遅延実行を周期の仕事に数えています** " +
			"（`internal/remediation/engine.go` の `executeRule` がこの形）。" +
			"ループを待たせていないので、「回」に当たるものがありません")
	}
	// ただし、そのループ自身が待っていれば、関数リテラルの中でも周期です。
	if !hasTicker(parseBody(t, `go func() {
		for {
			select {
			case <-time.After(d.every):
				d.work(ctx)
			}
		}
	}()`)) {
		t.Error("**関数リテラルごと外しています。** " +
			"`go func(){ for { … } }()` は普通の書き方で、" +
			"そのループは合図を待っています")
	}

	loop := func(inner string) *ast.BlockStmt {
		return parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			`+inner+`
		}
	}`)
	}
	if !tracked(loop(`tick.Run(ctx, "w", d.work)`)) {
		t.Error("**`tick.Run` を「記録している」と見ていません。** " +
			"包んだワーカーが違反として並びます")
	}
	if tracked(loop(`tick.Fail(ctx, err, "x")`)) {
		t.Error("`tick` の別の関数を「記録している」と数えています")
	}
	// **`internal/scheduler` の綴りは `trackRun` です**（`tick.Run` への
	// 1行の委譲）。知らないと、あちらの 39 の枝が全部違反として並びます。
	if !tracked(loop(`trackRun(ctx, "w", d.work)`)) {
		t.Error("**`trackRun` を「記録している」と見ていません。** " +
			"`internal/scheduler` の 39 の枝が全部違反として並びます")
	}
	if tracked(loop(`s.trackRunLocal(ctx, "w", d.work)`)) {
		t.Error("レシーバ付きの別関数を `trackRun` と数えています")
	}
	if tracked(loop(`d.work(ctx)`)) {
		t.Error("**ただの呼び出しを「記録している」と数えています。** " +
			"それが直す前の姿です")
	}
	// **`case now := <-ticker.C:` も周期の合図です。**
	// 受け取った値に名前を付けているだけで、見なくてよい理由になりません。
	if !tracked(parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		select {
		case now := <-ticker.C:
			tick.Run(ctx, "w", func(ctx context.Context) { d.work(ctx, now) })
		}
	}`)) {
		t.Error("包んだ `case now := <-ticker.C:` を「包んでいない」と数えています")
	}
	if tracked(parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		select {
		case now := <-ticker.C:
			d.work(ctx, now)
		}
	}`)) {
		t.Error("**`case now := <-ticker.C:` の形を見ていません。** " +
			"1文字の違いで、ワーカーが1つ丸ごと走査から外れます " +
			"（`internal/reports/scheduler.go` がその形でした）")
	}

	// **`case <-time.After(...):` も周期の枝です。**
	after := func(inner string) *ast.BlockStmt {
		return parseBody(t, `for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(nextRunTime())):
			`+inner+`
		}
	}`)
	}
	if !tracked(after(`tick.Run(ctx, "w", s.runEvaluation)`)) {
		t.Error("包んだ `case <-time.After(...):` を「包んでいない」と数えています")
	}
	if tracked(after(`s.runEvaluation(ctx)`)) {
		t.Error("**`case <-time.After(...):` の枝を見ていません。** " +
			"合図を毎周ごとに張り直しているだけで、`ticker.C` と同じ役です " +
			"（`internal/compliance/scheduler.go` がその形でした）")
	}

	// **`for range ticker.C {` も合図の受け取り方です。**
	rangeLoop := func(inner string) *ast.BlockStmt {
		return parseBody(t, `ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		`+inner+`
	}`)
	}
	if tracked(rangeLoop(`c.evictExpired()`)) {
		t.Error("**`for range ticker.C {` の形を見ていません。** " +
			"この形のワーカーは、理由が書いてあるかどうかに関係なく" +
			"素通りします —— 実測でこの形が4つあり、**理由は一度も" +
			"参照されていませんでした**")
	}
	if !tracked(rangeLoop(`tick.Run(ctx, "w", c.evictExpired)`)) {
		t.Error("包んだ `for range ticker.C {` を「包んでいない」と数えています")
	}
	if !tracked(parseBody(t, `for range items {
		c.evictExpired()
	}`)) {
		t.Error("**ただの range を周期の枝に数えています。** " +
			"合図ではないものに「回ったことを残せ」と言うことになります")
	}
	if !tracked(parseBody(t, `for _, r := range d.rules {
		d.apply(ctx, r)
	}`)) {
		t.Error("**`.C` 以外を range しているだけのループを周期の枝に" +
			"数えています。** ただの繰り返しに「回ったことを残せ」と" +
			"言うことになります")
	}

	// **何も呼んでいない枝は、包む対象ではありません。**
	if !tracked(loop(`select {
			case e.tokens <- struct{}{}:
			default:
			}`)) {
		t.Error("チャネルへ書くだけの枝を「包んでいない」と数えています")
	}
}

// **待つのが枝で、仕事が本体にある形。**
//
//	for {
//	    work()
//	    select { case <-ctx.Done(): return; case <-ticker.C: }
//	}
//
// 枝の中しか見ていなかったので、この形は「仕事をする枝が無い」＝
// 「包む対象が無い」と読まれ、**理由も要らずに黙って通っていました。**
func TestWorkThenWaitLoopsAreSeen(t *testing.T) {
	body := func(inner string) *ast.BlockStmt {
		return parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		`+inner+`
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}`)
	}
	if tracked(body(`d.work(ctx)`)) {
		t.Error("**仕事を先にして、空の枝で待つ形を見ていません。** " +
			"枝が空だという理由だけで「包む対象が無い」と読まれ、" +
			"理由も要らずに通ります")
	}
	if !tracked(body(`tick.Run(ctx, "w", d.work)`)) {
		t.Error("**包んだ work-then-wait を違反にしています。**")
	}

	// **`select` は本体の直下とは限りません。**
	// `if attempt > 0 { select … }` の形が実際にあります（webhook の再送）。
	retry := func(inner string) *ast.BlockStmt {
		return parseBody(t, `for attempt := 0; attempt <= max; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff(attempt)):
			}
		}
		`+inner+`
	}`)
	}
	if tracked(retry(`w.attempt(ctx, target)`)) {
		t.Error("**条件の中の `select` を見ていません。** " +
			"深さで探すのをやめると、その形が丸ごと外れます")
	}
	if !tracked(retry(`tick.Run(ctx, "w", w.attempt)`)) {
		t.Error("包んだ形を違反にしています")
	}

	// **本体が何もしていないなら、包む対象はありません。**
	if !tracked(parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}`)) {
		t.Error("**仕事が1つも無いループを違反にしています。** " +
			"包む先がありません")
	}
	// **枝の中の仕事を、本体の仕事と二重に数えないこと。**
	if !tracked(parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		d.prepare()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "w", d.work)
		}
	}`)) {
		t.Error("**包んだ枝を、本体に仕事があるという理由で" +
			"もう一度数えています。**")
	}
}

// 理由の一覧が古くなっていないこと。
func TestNoUntrackedTickerReasonHasGoneStale(t *testing.T) {
	fset := token.NewFileSet()
	for key := range untrackedTickerReasons {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			t.Errorf("理由の鍵の形が違います: %q", key)
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(workerRoot, parts[0]), nil, 0)
		if err != nil {
			t.Errorf("%s を読めません: %v", parts[0], err)
			continue
		}
		if !declaresFunc(f, parts[1]) {
			t.Errorf("理由が書いてある %s が見つかりません。**消えた分は"+
				"一覧からも消してください**", key)
		}
	}
}

// **理由が、本当に何かを留めていること。**
//
// 理由の宛先が実在するかは上で見ました。**ですがそれだけでは、理由が
// 効いているかは分かりません。** 実測 (2026-08-12): `for range ticker.C {`
// の形の4つは、走査がその形を見ていなかったので**理由を消しても緑の
// まま**でした —— 「理由があるから通っている」ではなく「見ていないから
// 通っている」です。この2つは外から同じ形に見えます。
//
// ここは逆から確かめます。**理由を全部取り上げたら、その関数は違反として
// 挙がらなければなりません。** 挙がらないなら、その理由は何も留めて
// いません（包まれたか、走査から外れたかのどちらかです）。
func TestEveryUntrackedTickerReasonIsHoldingSomethingBack(t *testing.T) {
	fset := token.NewFileSet()
	for key := range untrackedTickerReasons {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue // 鍵の形は上の検査が見ています
		}
		f, err := parser.ParseFile(fset, filepath.Join(workerRoot, parts[0]), nil, 0)
		if err != nil {
			// **飛ばすと、その理由は無条件で通ります。** 理由の宛先が
			// 消えた（file 名を変えた・消した）のか、parse できない
			// だけなのかも、飛ばした側からは区別できません。
			t.Errorf("%s の宛先 %s を parse できません: %v", key, parts[0], err)
			continue
		}
		fn := findFunc(f, parts[1])
		if fn == nil || fn.Body == nil {
			continue
		}
		switch reasonVerdict(fn.Body, parts[0], parts[1]) {
		case verdictNoTicker:
			t.Errorf("%s は走査の対象になっていません。**理由を書いても"+
				"書かなくても通ります** —— 周期の合図が無くなったなら、"+
				"理由も一覧から消してください", key)
		case verdictNoViolation:
			t.Errorf("%s の理由は何も留めていません（理由を取り上げても"+
				"違反になりません）。**包んだのなら一覧から消してください** —— "+
				"残しておくと、次に誰かが外したときに気づけません", key)
		}
	}
}

const (
	verdictNoTicker    = "走査の対象ですらありません"
	verdictNoViolation = "理由が無くても違反になりません"
)

// reasonVerdict — その理由が何を留めているか。空文字なら留めています。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま留めていない理由は 0 件なので、`if false` に潰しても挙がる件数は
// 変わりません —— 木がきれいなあいだは、検査を切ったことに誰も
// 気づけません。下の `TestTheInertReasonJudgementRecognisesTheRealThing`
// が、違反する見本を食わせて確かめます。
func reasonVerdict(body *ast.BlockStmt, file, fn string) string {
	if !hasTicker(body) {
		return verdictNoTicker
	}
	if !isUntrackedWorker(body, file, fn, nil) {
		return verdictNoViolation
	}
	return ""
}

func TestTheInertReasonJudgementRecognisesTheRealThing(t *testing.T) {
	for _, c := range []struct {
		name, body, want string
	}{
		{"合図が無い", `d.work(ctx)`, verdictNoTicker},
		{"包んである", `ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				tick.Run(ctx, "w", d.work)
			}
		}`, verdictNoViolation},
		{"包んでいない", `ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				d.work(ctx)
			}
		}`, ""},
	} {
		if got := reasonVerdict(parseBody(t, c.body), "a.go", "F"); got != c.want {
			t.Errorf("%s: 判定 = %q, want %q。**この判定を潰すと、"+
				"何も留めていない理由が一覧に残り続けます**", c.name, got, c.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 仕組みそのもの
// ─────────────────────────────────────────────────────────────────────────────

// **`Fail` が届くこと。** 届かないなら、`slog.Warn` のままと変わりません。
func TestFailReachesTheRun(t *testing.T) {
	ctx := tick.WithState(context.Background())
	if n := tick.Failures(ctx); n != 0 {
		t.Fatalf("始めから %d 件になっています", n)
	}
	tick.Fail(ctx, errors.New("読み出しが途中で切れました"), "走査が途中で終わりました")
	if n := tick.Failures(ctx); n != 1 {
		t.Errorf("記録 = %d 件, 1件を期待。**届かないなら、`slog.Warn` の"+
			"ままと変わりません**", n)
	}
	if !tick.Failing(ctx) {
		t.Error("`Failing` が false です")
	}
}

// **回の外から呼ばれても落ちないこと。** 起動時の初期化など、`Run` を
// 通らない経路があります。
func TestFailOutsideARunIsQuietButDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	tick.Fail(ctx, errors.New("x"), "回の外です")
	if tick.Failing(ctx) {
		t.Error("記録先が無いのに `Failing` が true です")
	}
	if n := tick.Failures(ctx); n != 0 {
		t.Errorf("記録先が無いのに %d 件になっています", n)
	}
}

// **`Run` が、回ごとに新しい記録を渡すこと。**
// 使い回すと、前の回の失敗が次の回にも残ります。
func TestRunGivesEachRunItsOwnRecord(t *testing.T) {
	var seen []int
	for i := 0; i < 2; i++ {
		tick.Run(context.Background(), "tick_test_worker", func(ctx context.Context) {
			if i == 0 {
				tick.Fail(ctx, errors.New("一度目だけ失敗"), "一度目")
			}
			seen = append(seen, tick.Failures(ctx))
		})
	}
	if len(seen) != 2 {
		t.Fatalf("回数 = %d", len(seen))
	}
	if seen[0] != 1 {
		t.Errorf("1回目の記録 = %d, 1件を期待", seen[0])
	}
	if seen[1] != 0 {
		t.Errorf("2回目の記録 = %d, 0件を期待。**前の回の失敗が残っています** ——"+
			"一度失敗したワーカーが、そのあと永久に失敗し続けている姿になります",
			seen[1])
	}
}

// isUntrackedWorker — その関数が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするため**です。
// いま違反は 0 件なので、`if true` に潰しても挙がる件数は変わりません。
func isUntrackedWorker(body *ast.BlockStmt, file, fn string, reasons map[string]string) bool {
	if tracked(body) {
		return false
	}
	return reasons[file+":"+fn] == ""
}

// declaresFunc — そのファイルがその名前の関数を宣言しているか。
func declaresFunc(f *ast.File, name string) bool {
	return findFunc(f, name) != nil
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func TestDeclaresFuncComparesTheName(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go",
		"package p\nfunc Alpha() {}\n", 0)
	if err != nil {
		t.Fatalf("見本を解析できません: %v", err)
	}
	if !declaresFunc(f, "Alpha") {
		t.Error("在る関数を見つけられません")
	}
	if declaresFunc(f, "Beta") {
		t.Error("**無い関数を「在る」と答えています。** " +
			"消えた宛先の理由が、一覧に残り続けます")
	}
}

// 違反の判定が効くこと。**違反する見本を食わせて確かめます。**
func TestUntrackedWorkerJudgementRecognisesTheRealThing(t *testing.T) {
	loop := func(inner string) *ast.BlockStmt {
		return parseBody(t, `ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			`+inner+`
		}
	}`)
	}
	reasons := map[string]string{"a.go:Excused": "理由が書いてあります"}

	if !isUntrackedWorker(loop(`d.work(ctx)`), "a.go", "NoReason", reasons) {
		t.Error("**包んでいないワーカーを、違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if isUntrackedWorker(loop(`tick.Run(ctx, "w", d.work)`), "a.go", "NoReason", reasons) {
		t.Error("**包んだワーカーを違反にしています。**")
	}
	if isUntrackedWorker(loop(`d.work(ctx)`), "a.go", "Excused", reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}
}

// **起動時の1回だけ包んで、毎回の枝を素通しに戻す**のを止めること。
func TestStartupOnlyWrappingIsNotEnough(t *testing.T) {
	body := parseBody(t, `tick.Run(ctx, "w", d.work)
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			d.work(ctx)
		}
	}`)
	if tracked(body) {
		t.Error("**起動時の1回だけ包んだものを「記録している」と見ています。** " +
			"記録されるのは起動の1回だけで、そのあと何年止まっていても " +
			"last_success は動いたままになります")
	}
}

// 床の判定が効くこと。
//
// **以前ここは `minUntrackedCandidates >= minUntrackedCandidates` を見て
// いました。定数を自分自身と比べているので常に真で、`t.Error` には一度も
// 届きません。** 床が効いているかを確かめるつもりの検査が、何も確かめて
// いませんでした（staticcheck の SA4000 が CI で見つけました）。
// 判定を関数に出して、境界の 3 点を直接当てます。
func TestTheWorkerScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if minUntrackedCandidates < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
	if walkReachedTheFloor(0) {
		t.Error("1件も見えていないのに「走査が届いた」と言っています")
	}
	if walkReachedTheFloor(minUntrackedCandidates - 1) {
		t.Error("床を1つ下回っても「走査が届いた」と言っています")
	}
	if !walkReachedTheFloor(minUntrackedCandidates) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 綴りの選び方
// ─────────────────────────────────────────────────────────────────────────────

// **`Run` で回している仕事の中では、`metrics.BackgroundFailed` を直に
// 呼ばないこと。**
//
// 実測 (2026-08-12)。失敗を報告する綴りは3つありました:
//
//	fail(ctx, err, msg)                  147 箇所（internal/scheduler の中だけ）
//	metrics.BackgroundFailed(comp, ...)   72 箇所（12 package）
//	tick.Fail(ctx, err, msg)              10 箇所
//
// どれも「失敗を報告する」ですが、答える問いが違います —— 前者は
// 「この部品が失敗した」、後者は「この回が仕事を終えられなかった」です。
//
// **`Run` の中で `BackgroundFailed` だけを使うと、失敗は数えられるのに、
// その回は成功として刻まれます。** 実測: `Run` の中で `BackgroundFailed`
// を呼んだあと、この回の記録は 0 件のままでした（`tick.Fail` なら 1 件）。
// `last_success` が更新されるので、**毎回失敗しているワーカーが健全な
// ワーカーと同じ姿**になります。
//
// 実測: `Run` で回している 14 の仕事のうち **13 が `BackgroundFailed` を
// 使っていました**（6つはそれだけ、7つは `Fail` と混在）。
// `tick.FailComponent` が両方します。
func TestTrackedWorkersDoNotReportPastTheRun(t *testing.T) {
	fset := token.NewFileSet()
	names := trackedWorkerNames(t, fset)
	if len(names) < minTrackedWorkerNames {
		t.Fatalf("走査が届いていません: `tick.Run` から到達する関数が %d 個しか"+
			"見えません（実測 186、床 %d）", len(names), minTrackedWorkerNames)
	}
	t.Logf("`tick.Run`/`trackRun` から到達する関数: %d 個（%d 段）", len(names), trackedCallDepth)

	type site struct {
		file string
		fn   string
		line int
	}
	var bad []site
	matched := 0
	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {
				continue
			}
			matched++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if !callsBackgroundFailed(n) {
					return true
				}
				bad = append(bad, site{rel, fn.Name.Name, fset.Position(n.Pos()).Line})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	// **鍵が合っていること。** 名前の集合は `package|関数名` で、走査側も
	// 同じ形で引きます。**片方だけ変えると、照合が全部外れて 0 件を
	// 検査して緑になります**（実際そうなり、変異が生き残って気づけました）。
	if matched < minMatchedWorkerDecls {
		t.Fatalf("名前の集合と宣言が %d 個しか照合していません（床 %d）。"+
			"**鍵の形が合っていません**", matched, minMatchedWorkerDecls)
	}

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	for _, s := range bad {
		t.Errorf("%s:%d %s は `tick.Run` で回している仕事なのに "+
			"`metrics.BackgroundFailed` を直に呼んでいます。"+
			"**失敗は数えられますが、その回は成功として刻まれます** —— "+
			"`tick.FailComponent(ctx, ...)` を使ってください", s.file, s.line, s.fn)
	}
}

// **呼ばれる先も見ます。** `tick.Run` に直に渡している関数しか見て
// いなかったので、そこから呼ばれる関数は漏れていました ——
// `detection/correlation.go:upsertCase` がそれで、インシデントの自動
// 作成に失敗しても、その回は成功として刻まれていました。
//
// 実測 (2026-08-12): 3段たどると 8 か所（`shipper.Flush` 2・
// `wazuh.SyncAgents` 2・`compliance.EvaluateAll`・
// `heartbeat_monitor.createOfflineAlert`・`virustotal` 2）。
// どれも `tick.FailComponent` に移しました。
const trackedCallDepth = 3

// 実測 (2026-08-12): `tick.Run`/`trackRun` から 3 段で到達する関数は 186 個
// （直に渡しているのは 46）。床は下に。
const minTrackedWorkerNames = 120

// 実測 (2026-08-12): 名前の集合と実際の宣言が照合するのは 178 個。
const minMatchedWorkerDecls = 120

// **クロージャで包んだワーカーも種に入ること。**
// `tick.Run(ctx, "es", func(ctx context.Context) { s.Flush(ctx) })` の形は、
// 直に渡している関数として見えません。実測でその形が2つ
// （`shipper.Flush` と `reports.checkAndRun`）あり、`Flush` は
// `metrics.BackgroundFailed` を2つ持ったまま通っていました。
func TestTheMatchedDeclFloorIsNotHollowedOut(t *testing.T) {
	if minMatchedWorkerDecls < 1 {
		t.Fatal("床が 0 以下です。**鍵の形が合っていなくても「照合した」と" +
			"言います** —— 0 件を検査して緑になります")
	}
}

func TestClosureWrappedWorkersAreSeeded(t *testing.T) {
	names := trackedWorkerNames(t, token.NewFileSet())
	for _, want := range []string{"shipper|Flush", "reports|checkAndRun"} {
		if !names[want] {
			t.Errorf("%s が種に入っていません。**クロージャで包んだワーカーが"+
				"丸ごと走査から外れます**", want)
		}
	}
}

// trackedWorkerNames — `tick.Run(ctx, "名前", これ)` から**到達する**関数。
//
// 鍵は `package のパス|関数名` です。直に渡している関数から、同じ
// package の中を `trackedCallDepth` 段たどります。**同じ package に
// 限るのは、名前だけで辿ると別の package の同名関数まで引き込むから**
// です（`Close` のような名前で全部が対象になります）。
func trackedWorkerNames(t *testing.T, fset *token.FileSet) map[string]bool {
	t.Helper()
	bodies := map[string]*ast.BlockStmt{} // "pkg|name" → 本体
	seeds := map[string]bool{}

	walkErr := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				bodies[pkg+"|"+fn.Name.Name] = fn.Body
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 3 || !isRunCall(call.Fun) {
				return true
			}
			switch a := call.Args[2].(type) {
			case *ast.SelectorExpr:
				seeds[pkg+"|"+a.Sel.Name] = true
			case *ast.FuncLit:
				// **クロージャで包むと、走査から外れていました。**
				// `tick.Run(ctx, "es", func(ctx context.Context) { s.Flush(ctx) })`
				// の `Flush` がその形で、`metrics.BackgroundFailed` を
				// 2つ持ったまま通っていました。
				for _, name := range calledNames(a) {
					seeds[pkg+"|"+name] = true
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("走査できません: %v", walkErr)
	}

	reached := map[string]bool{}
	frontier := seeds
	for depth := 0; depth < trackedCallDepth && len(frontier) > 0; depth++ {
		next := map[string]bool{}
		for key := range frontier {
			if reached[key] {
				continue
			}
			reached[key] = true
			body, ok := bodies[key]
			if !ok {
				continue
			}
			pkg := strings.SplitN(key, "|", 2)[0]
			for _, name := range calledNames(body) {
				k := pkg + "|" + name
				if !reached[k] {
					if _, ok := bodies[k]; ok {
						next[k] = true
					}
				}
			}
		}
		frontier = next
	}
	return reached
}

// calledNames — その中で呼んでいる関数名（`x.Foo()` は Foo）。
func calledNames(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(m ast.Node) bool {
		call, ok := m.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch v := call.Fun.(type) {
		case *ast.Ident:
			out = append(out, v.Name)
		case *ast.SelectorExpr:
			out = append(out, v.Sel.Name)
		}
		return true
	})
	return out
}

// isRunCall — `tick.Run` か、`internal/scheduler` の `trackRun` か。
//
// **`tick.Run` だけを見ていたので、あちらの 26 の仕事が「回している仕事」
// に数えられていませんでした** —— そこに `metrics.BackgroundFailed` を
// 書いても、この検査は何も言いません（いまは 0 件ですが、それは
// 「見ていないから 0」でした）。
func isRunCall(fun ast.Expr) bool {
	if id, ok := fun.(*ast.Ident); ok {
		return id.Name == trackRunName
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "tick"
}

// callsBackgroundFailed — `metrics.BackgroundFailed(...)` の呼び出しか。
func callsBackgroundFailed(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "BackgroundFailed" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "metrics"
}

// 綴りの見分けが効くこと。
func TestTheSpellingDetectorRecognisesTheRealThing(t *testing.T) {
	expr := func(src string) ast.Node {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.ExprStmt).X
	}
	if !callsBackgroundFailed(expr(`metrics.BackgroundFailed("c", err, "m")`)) {
		t.Error("**`metrics.BackgroundFailed` を見つけられません。** " +
			"見落とすと、回が成功として刻まれる箇所が走査から外れます")
	}
	if callsBackgroundFailed(expr(`tick.FailComponent(ctx, "c", err, "m")`)) {
		t.Error("**直したものを違反にしています。** `FailComponent` は" +
			"両方します")
	}
	if callsBackgroundFailed(expr(`metrics.AlertDropped("c")`)) {
		t.Error("`metrics` の別の関数を数えています")
	}
	if callsBackgroundFailed(expr(`other.BackgroundFailed("c", err, "m")`)) {
		t.Error("`metrics` 以外の同名関数を数えています")
	}

	// **「回している仕事」の綴りも2つです。**
	fun := func(src string) ast.Expr {
		return expr(src).(*ast.CallExpr).Fun
	}
	if !isRunCall(fun(`tick.Run(ctx, "w", s.work)`)) {
		t.Error("`tick.Run` を見つけられません")
	}
	if !isRunCall(fun(`trackRun(ctx, "w", s.work)`)) {
		t.Error("**`trackRun` を「回している仕事」と見ていません。** " +
			"`internal/scheduler` の 26 の仕事がこの検査の外に出ます —— " +
			"そこに `metrics.BackgroundFailed` を書いても何も言いません")
	}
	if isRunCall(fun(`s.trackRun(ctx, "w", s.work)`)) {
		t.Error("レシーバ付きの呼び出しを数えています")
	}
	if isRunCall(fun(`tick.Fail(ctx, err, "m")`)) {
		t.Error("`tick` の別の関数を数えています")
	}
	if isRunCall(fun(`other.Run(ctx, "w", s.work)`)) {
		t.Error("`tick` 以外の Run を数えています")
	}
}

// **`FailComponent` が、両方すること。**
//
// 片方だけでは足りません —— 回だけ落とすと部品ごとの件数（既に見ている
// 人がいる `edr_background_failures_total`）が消え、部品だけ数えると
// `last_success` が動いたままになります。
func TestFailComponentMarksTheRunAsWellAsTheComponent(t *testing.T) {
	ctx := tick.WithState(context.Background())
	tick.FailComponent(ctx, "tick_test_component", errors.New("読み出しが途中で切れました"),
		"この回は仕事を終えられませんでした")
	if n := tick.Failures(ctx); n != 1 {
		t.Errorf("この回の記録 = %d 件, 1件を期待。**部品の件数だけ数えて"+
			"回を落としていないなら、`last_success` は動いたままです**", n)
	}

	// **部品ごとの件数も残すこと。**
	//
	// 値を読むには `prometheus/testutil` が要り、それは
	// `client_model` を直接の依存に格上げします。**この1行を確かめる
	// ために依存を増やしません** —— `internal/scheduler` の
	// `fail_reaches_someone_test.go` と同じやり方で、実装が本当に
	// 呼んでいることを読みます。
	src, err := os.ReadFile("tick.go")
	if err != nil {
		t.Fatalf("tick.go を読めません: %v", err)
	}
	body := funcSource(string(src), "FailComponent")
	if body == "" {
		t.Fatal("FailComponent の定義が見つかりません")
	}
	if missing := missingFrom(body, failComponentNeeds); len(missing) > 0 {
		t.Errorf("`FailComponent` が %v を持っていません。**片方だけでは"+
			"足りません** —— 回だけ落とすと "+
			"`edr_background_failures_total` を見ている人には何も変わって"+
			"見えず、部品だけ数えると `last_success` が動いたままです",
			missing)
	}

	// 逆向きの確認。**求めるものの一覧が骨抜きになっていると、上の判定は
	// どんな実装でも通ります。** 件数ではなく「何が足りないか」まで見ます
	// —— 一覧から1項目落としても、数だけなら合ったままになるためです。
	for _, c := range []struct {
		name, stub string
		want       []string
	}{
		{"部品しか数えない", `metrics.BackgroundFailed(component, err, msg)`,
			[]string{"st.add()"}},
		{"回しか落とさない", `st.add()`,
			[]string{"metrics.BackgroundFailed("}},
		{"どちらもしない", `slog.Error(msg)`,
			[]string{"metrics.BackgroundFailed(", "st.add()"}},
	} {
		got := missingFrom(c.stub, failComponentNeeds)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s実装の不足 = %v, want %v。"+
				"**求めるものの一覧から項目が落ちています**", c.name, got, c.want)
		}
	}
}

// `FailComponent` が持っていなければならないもの。
//
// **一覧にしてあるのは、逆向きに確かめるためです。**
// `if !strings.Contains(…)` をそのまま並べると、木がきれいなあいだは
// `if false` に潰しても誰も気づけません（実際に変異が生き残りました）。
var failComponentNeeds = []string{
	"metrics.BackgroundFailed(", // 部品ごとの件数
	"st.add()",                  // この回を「終えられなかった」に
}

func missingFrom(body string, needs []string) []string {
	var out []string
	for _, n := range needs {
		if !strings.Contains(body, n) {
			out = append(out, n)
		}
	}
	return out
}

// funcSource は関数の定義本文をそのまま返します。
func funcSource(src, name string) string {
	at := strings.Index(src, "func "+name+"(")
	if at < 0 {
		return ""
	}
	rest := src[at:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}

// 対象の床の判定が効くこと。
func TestTheTrackedWorkerNameFloorNoticesAnEmptyWalk(t *testing.T) {
	if minTrackedWorkerNames < 1 {
		t.Fatal("床が 0 以下です。**`tick.Run` に渡している関数を1つも" +
			"覚えなくても、走査は「届いた」と言います**")
	}
	if 0 >= minTrackedWorkerNames {
		t.Error("0 でも床を満たしています")
	}
}

// **`tick.Run` から届く `slog.Error` が、回にも届くこと。**
//
// `metrics.BackgroundFailed` を3段たどって 10 か所直したあと、**同じ
// 到達判定で `slog.Error` を探したら 11 か所**出ました —— どれも
// 「回っているが何もできていない」がログにしか出ない箇所です:
//
//	alert_enrichment  テーブル確認の失敗
//	cloud/poller      設定を読めない統合／イベントを組み立てられない
//	shipper           **ES が受け取らなかった文書**（送信自体は成功）
//	risk_action       **自動隔離の失敗**（成功時だけアラートが立ちます）
//	sync/wazuh        端末ごとの脆弱性取得
//	updater/applier   ロールバック記録の失敗
//
// `internal/scheduler` の中は対象外です —— あちらは
// `bare_log_and_return_test.go` が理由つきで留めています。
var reachableSlogErrorReasons = map[string]string{
	// #764: 広すぎる抑制ルールを適用せずに弾いたことの報告。回そのものは
	// 成功しており、弾いた事実は運用者が直すべき設定の話。tick.Fail に
	// すると「抑制エンジンが落ちている」と読まれる。
	"detection/suppression_matcher.go:load": "広すぎる抑制ルールを弾いた報告。" +
		"回の失敗ではなく、直すべきは設定のほう。",
	// **名前でたどったための取り違えです。** `pool.Query(…)` の呼び出しが、
	// 同じ package の `Query` という名前のメソッド（このハンドラ）に
	// 当たります。**到達判定は package までしか見ないので、ここは
	// 消せません** —— ハンドラなので `c.JSON` で 500 を返しており、
	// 回の話ではありません。
	"api/handlers/metrics_history_handler.go:Query": "`pool.Query` と" +
		"同名のハンドラ。到達判定の取り違えで、周期の仕事ではありません。",
}

// 実測 (2026-08-12): 直したあと 2 か所 —— どちらも上の取り違えの
// 関数の中（`rows.Err()` を2回見ています）。
// 2 → 3 (#764)。増えた 1 件は抑制ルールの広さ判定で、理由は上に書いた。
const reachableSlogErrorSites = 3

func TestTrackedWorkersDoNotReportOnlyToTheLog(t *testing.T) {
	found := reachableLogSites(t, "Error", slogScanSkip)

	if len(found) != reachableSlogErrorSites {
		t.Errorf("`tick.Run` から届く `slog.Error` が %d か所です"+
			"（留めているのは %d）", len(found), reachableSlogErrorSites)
	}
	seen := map[string]bool{}
	for _, s := range found {
		key := s.file + ":" + s.fn
		seen[key] = true
		if siteNeedsClassifying(key, reachableSlogErrorReasons) {
			t.Errorf("%s:%d %s は `tick.Run` で回している仕事なのに、"+
				"`slog.Error` にしか出していません。**回っているが何も"+
				"できていないことが、外から見えません** —— "+
				"`tick.Fail(ctx, err, …)` を使ってください", s.file, s.line, s.fn)
		}
	}
	for _, key := range staleClassificationKeys(reachableSlogErrorReasons, seen) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください**", key)
	}
}

type logSite struct {
	file string
	fn   string
	line int
}

// reachableLogSites — `tick.Run` から到達する関数の中の `slog.<level>`。
func reachableLogSites(t *testing.T, level string, skip []string) []logSite {
	t.Helper()
	fset := token.NewFileSet()
	names := trackedWorkerNames(t, fset)

	var found []logSite
	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if isSkippedFromSlogScan(rel, skip) {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if !callsSlogAt(n, level) {
					return true
				}
				found = append(found, logSite{rel, fn.Name.Name, fset.Position(n.Pos()).Line})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].file < found[j].file })
	return found
}

// **走査から外してよい package。**
//
// `slog.Error` は `internal/scheduler` も含めて全部見ます（2026-08-12 に
// 13 か所を `fail` に移して 0 にしました）。
//
// `slog.Warn` も `internal/scheduler` を含めて全部見ます
// （2026-08-12）—— 54 か所のうち **error を持っていた 45 を `fail` に
// 移し**、残り 9 の宛先に理由を書きました。
//
// 「黙って捨てる」も `internal/scheduler` を含めて全部見ます
// （2026-08-12）—— 21 か所を読み、**どれも直後の `rows.Err()` が
// `fail` に出していました。**
// あちらには `bare_log_and_return_test.go` が別の角度から
// （`slog` の直後が `return` の形で）29 か所を理由つきで留めています。
var slogScanSkip = []string{}
var warnScanSkip = []string{}

// 「黙って捨てる」はまだ `internal/scheduler` を外しています（実測 21）。
var silentScanSkip = []string{}

func isSkippedFromSlogScan(rel string, skip []string) bool {
	for _, p := range skip {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// **外している package が増えていないこと。**
// 増やすと「探したが無かった」が「無かった」になります。
func TestTheSlogScanSkipListIsExactlyTheScheduler(t *testing.T) {
	// `slog.Error` は全部見ます。
	if got := strings.Join(slogScanSkip, ","); got != "" {
		t.Errorf("`slog.Error` の走査から外している package = %q, "+
			"want なし。**全部見るのが 0 件の意味です**", got)
	}
	// 3つとも全部見ます。
	if got := strings.Join(warnScanSkip, ","); got != "" {
		t.Errorf("走査から外している package = %q, want \"scheduler/\"。"+
			"**増やすなら、そこを見る検査を先に用意してください**", got)
	}
	if got := strings.Join(silentScanSkip, ","); got != "" {
		t.Errorf("「黙って捨てる」の走査から外している package = %q, "+
			"want なし。**3つの段とも全部見るのが 0 件の意味です**", got)
	}
	if isSkippedFromSlogScan("scheduler/backup_scheduler.go", silentScanSkip) {
		t.Error("**外すべきでない package を外しています。**")
	}
	if !isSkippedFromSlogScan("scheduler/x.go", []string{"scheduler/"}) {
		t.Error("外す仕組み自体が効いていません")
	}
}

// callsSlogAt — `slog.<level>(…)` の呼び出しか。
func callsSlogAt(n ast.Node, level string) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != level {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "slog"
}

func callsSlogError(n ast.Node) bool { return callsSlogAt(n, "Error") }

func TestTheSlogErrorDetectorRecognisesTheRealThing(t *testing.T) {
	expr := func(src string) ast.Node {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.ExprStmt).X
	}
	if !callsSlogError(expr(`slog.Error("x", "error", err)`)) {
		t.Error("**`slog.Error` を見つけられません。** " +
			"見落とすと、ログ止まりの箇所が走査から外れます")
	}
	if callsSlogError(expr(`slog.Warn("x")`)) {
		t.Error("`slog.Warn` を数えています")
	}
	if callsSlogError(expr(`tick.Fail(ctx, err, "x")`)) {
		t.Error("**直したものを違反にしています。**")
	}
	if callsSlogError(expr(`log.Error("x")`)) {
		t.Error("`slog` 以外を数えています")
	}
}

// **`tick.Run` から届く `slog.Warn` も、回に届くこと。**
//
// `slog.Error` を 0（＋取り違え2件）にしたあと、同じ到達判定で `Warn` を
// 探したら **30 か所**ありました。**`Warn` は運用の設定で最初に切られる
// 段です** —— このセッションでも、`Error` を `Warn` に落とす変更が検査を
// 通ったことがありました。
//
// 19 か所を `tick.Fail` に移しました:
//
//	cloud/poller       ポーリング失敗／エラー状態の保存／同期状態の保存／
//	                   NATS 送信（**送れなかったイベントは検知に届きません**）
//	reports/scheduler  レポート生成／メール送信／次回時刻の計算
//	                   （計算に失敗すると 24 時間後に倒れます）
//	enrichment         保存／VT のハッシュ照会・IP 照会
//	sync/wazuh         エージェント同期／脆弱性同期
//	updater/db_poller  適用失敗
//	detection          行スキャン ×3・アラート保存
//	compliance         レポートの保存
//	threatintel        IOC の保存
//	alert_enrichment   クエリ失敗 ×2
var reachableSlogWarnReasons = map[string]string{
	// #764: 絞り込みの弱い抑制ルールの注意喚起。適用はしている。
	"detection/suppression_matcher.go:load": "絞り込みの弱い抑制ルールの注意喚起。" +
		"適用はしており、回は完了している。",
	// 引受情報が不正なアカウントは飛ばして次へ進む。回そのものは仕事を
	// 終えているので `tick.Fail` ではない。飛ばした事実は
	// SetScanStatus(…, "error", …) で cspm_accounts に残り、画面から見える
	// （記録にも失敗した場合は、その下で `fail` に落としている）。
	"scheduler/cspm_scanner.go:sweep": "アカウント単位の skip。" +
		"回は完了しており、状態は cspm_accounts.scan_status に残る。",
	// 期限切れにした件数の通知。失敗ではなく、配送経路の健全性を示す指標
	// そのもの（0 件なら何も出ない）。
	"scheduler/response_action_timeout.go:sweep": "期限切れ件数の通知。" +
		"回の失敗ではなく、継続的に鳴ること自体が配送経路の指標。",
	// ── すでに回に届いています（error を返す／直後に報告） ───────────
	"threatintel/public_feeds.go:FetchAbuseIPDB": "3 か所とも直後に " +
		"`return nil, err` で、呼び出し側の `syncPublicFeeds` が " +
		"`tick.FailComponent` に出します。",
	"threatintel/public_feeds.go:FetchURLhaus": "直後に " +
		"`tick.FailComponent` を呼んでいます（飛ばした行数つき）。",
	"updater/applier.go:Apply": "3 か所とも `return err` か、直後の " +
		"`failWithReason`／`MarkRolledBack` が記録します。",

	// ── 回の話ではないもの ───────────────────────────────────────────
	"api/handlers/errs.go:dbErrMsg": "応答に出す前にサーバ側へ残すための" +
		"ログ。**到達判定の取り違えでもあります**（同じ package の" +
		"名前に当たります）。",
	"api/handlers/alert_enrichment_pipeline.go:enrichAlert": "位置情報を" +
		"引けなかった1件。**`complete = false` で次の周回にやり直します** —— " +
		"回そのものは未完了として扱われています。",

	// ── `internal/scheduler`（2026-08-12 に走査へ入れました） ────────
	//
	// **error を持っている 45 か所は `fail` に移しました。** 残るのは
	// 「見つけたこと」を書いている Warn です —— 失敗ではありません。
	"scheduler/curate_scheduler.go:tick": "サイレント inert・false green・" +
		"field gap の**検出結果**。ルールが効いていないことを見つけた" +
		"報告で、この回の失敗ではありません。",
	"scheduler/retro_ioc_hunter.go:hunt": "過去のイベントに IOC 一致を" +
		"**検出**／読み切れなかったので watermark を進めない、という判断の" +
		"記録（読めなかったこと自体は読み出し側が `fail` に出します）。",
	"scheduler/retro_rule_hunter.go:hunt": "同上（ルール一致の検出）。",
	"scheduler/darkweb_scheduler.go:syncRansomwareLive": "監視キーワードの" +
		"**検出**。",
	"scheduler/hunt_scheduler.go:runScheduledHunts": "`scheduled` 列が無い" +
		"配置での案内。**この検査の元になった欠陥そのもの**で、" +
		"「動いているが0件」を見えるようにするための行です。",
	"scheduler/hunt_scheduler.go:executeHunt": "ハント結果0件の記録。",
	"scheduler/report_scheduler.go:deliver": "SMTP 未設定のためメールを" +
		"送らない、という設定の話。",
	"scheduler/baseline_rebuilder.go:Run": "テーブルがまだ無い配置。",

	// `cert_expiry_checker.go:checkDomainCert` はここにありました。
	// **error 値を持たない失敗が2つ**（TLS の型アサーション失敗と
	// ピア証明書0件）で、`fail` に渡すものが無いので Warn に残って
	// いました。名前のある error を2つ作って `fail` に移したので、
	// この一覧から消えています。**「渡す error が無い」は、Warn に
	// 留まってよい理由ではありませんでした。**
}

// 実測 (2026-08-12): 30 → 9、`internal/scheduler` を入れて 24、
// `cert_expiry_checker` の2つを `fail` に移して 22。
// 24 → 25 (#764)。同上。
const reachableSlogWarnSites = 25

func TestTrackedWorkersDoNotDowngradeToWarn(t *testing.T) {
	found := reachableLogSites(t, "Warn", warnScanSkip)

	if len(found) != reachableSlogWarnSites {
		t.Errorf("`tick.Run` から届く `slog.Warn` が %d か所です"+
			"（留めているのは %d）", len(found), reachableSlogWarnSites)
	}
	seen := map[string]bool{}
	for _, s := range found {
		key := s.file + ":" + s.fn
		seen[key] = true
		if siteNeedsClassifying(key, reachableSlogWarnReasons) {
			t.Errorf("%s:%d %s は `tick.Run` で回している仕事なのに、"+
				"`slog.Warn` にしか出していません。**Warn は運用の設定で"+
				"最初に切られる段です** —— その回が仕事を終えられなかった"+
				"なら `tick.Fail(ctx, err, …)` を、そうでないなら理由を"+
				"書いてください", s.file, s.line, s.fn)
		}
	}
	for _, key := range staleClassificationKeys(reachableSlogWarnReasons, seen) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください**", key)
	}
}

// **`tick.Run` から届く「黙って捨てた error」を挙げること。**
//
// `slog.Error` と `slog.Warn` は回に届くようにしました。**残るのは、
// error を受け取って何も言わずに次へ進む形**です:
//
//	if err != nil {
//		continue      // ← 何も報告しない
//	}
//
// これは「回っているが何もできていない」の中でもいちばん静かな形で、
// **ログにすら出ません。**
// **実測 (2026-08-12): 4 か所。どれも「そのあとでまとめて報告している」
// 形でした。**
//
// 4つとも `for rows.Next()` の中の `rows.Scan` です。**pgx では Scan が
// 失敗した時点で結果セットが終わる**ので、`continue` は1行を飛ばすの
// ではなく、そこで走査が終わります —— そして直後の `rows.Err()` が
// `tick.Fail` / `tick.FailComponent` に出しています。
//
// `FetchURLhaus` だけは形が違い、飛ばした行を `skipped` に数えて、
// 最後に `tick.FailComponent` で件数ごと報告しています。
var silentErrorBranchReasons = map[string]string{
	"scheduler/agent_health_alerter.go:resolveRecoveredSensorAlerts": "`rows.Scan` の" +
		"失敗。**pgx はそこで結果セットを終えるので**、直後の `rows.Err()` が " +
		"`fail` に出します。",
	"scheduler/agent_health_alerter.go:checkDegradedSensors": "`rows.Scan` の失敗。" +
		"**pgx はそこで結果セットを終えるので**、直後の `rows.Err()` が " +
		"`fail` に出します。",
	"api/handlers/mobile_compliance_scanner.go:scan": "`rows.Scan` の失敗。" +
		"**pgx はそこで結果セットを終えるので**、直後の `rows.Err()` が " +
		"`tick.FailComponent` に出します。",
	"dedup/alert_dedup.go:deduplicate": "`rows.Scan` の失敗。**pgx は" +
		"そこで結果セットを終えるので**、直後の `rows.Err()` が " +
		"`tick.Fail` に出します。",
	"dedup/alert_dedup.go:deduplicateByTechnique": "同上（technique 単位の" +
		"`rows.Scan`）。",
	"dedup/alert_dedup.go:add": "**重複を閉じる UPDATE の失敗を群ごとに" +
		"数える枝**です（`closeOutcome.add`）。1件ずつ報告すると DB が" +
		"応答しないときログが群の数だけ溢れるので、数えておいて、群の" +
		"終わりで1回 `tick.Fail` に出します —— その1回は " +
		"`needsReporting()` が決めていて、`alert_dedup_close_test.go` が" +
		"見ています。",
	"threatintel/public_feeds.go:FetchURLhaus": "CSV の読めない行。" +
		"`skipped` に数えて、最後に `tick.FailComponent` で件数ごと" +
		"報告します。",

	// ── `internal/scheduler`（2026-08-12 に走査へ入れました） ────────
	//
	// **21 か所を読み、どれも `for rows.Next()` の中の `rows.Scan` でした。**
	// pgx は Scan が失敗した時点で結果セットを終えるので、`continue` は
	// 1行を飛ばすのではなく走査が終わります —— そして**どの関数でも
	// 直後の `rows.Err()` が `fail(ctx, …)` に出しています**（前の回で
	// 揃えたものです）。
	"scheduler/agent_health_alerter.go:checkCPUMemory":          "同上。",
	"scheduler/agent_health_alerter.go:checkStaleAgents":        "同上。",
	"scheduler/api_key_rotator.go:warnExpiringKeys":             "同上。",
	"scheduler/asset_criticality_scorer.go:calculate":           "同上。",
	"scheduler/backup_scheduler.go:pruneOldBackups":             "同上。",
	"scheduler/billing_grace_notifier.go:check":                 "同上。",
	"scheduler/cert_expiry_checker.go:checkCerts":               "同上。",
	"scheduler/compliance_scorer.go:calculate":                  "同上。",
	"scheduler/heartbeat_monitor.go:check":                      "同上。",
	"scheduler/mdm_credential_expiry_checker.go:check":          "同上。",
	"scheduler/network_anomaly_detector.go:detectTrafficSpike":  "同上。",
	"scheduler/network_anomaly_detector.go:detectHighBeaconing": "同上。",
	"scheduler/report_scheduler.go:generateReport":              "同上（5 か所）。",
	"scheduler/threat_feed_importer.go:importAll":               "同上。",
	"scheduler/vulnerability_scanner.go:scan":                   "同上。",

	// ── 形が違うもの ─────────────────────────────────────────────────
	"scheduler/hunt_scheduler.go:executeHunt": "`execErr = err` で受けて" +
		"います。**捨てていません** —— 呼び出し側がそれを記録します。",
	"scheduler/darkweb_scheduler.go:syncRansomwareLive": "発見日時の" +
		"パース失敗を「古いデータ」として飛ばす、という判断（コメントに" +
		"書いてあります）。",
}

// 実測 (2026-08-12): 4 か所 → `internal/scheduler` を入れて 25。
// すべて理由つきです。
// 26 → 28 (#543)。増えた 2 件は agent_health_alerter の行走査で、
// どちらも直後の rows.Err() が fail に出す（理由は上の一覧）。
const silentErrorBranchSites = 28

func TestTrackedWorkersDoNotSwallowErrorsSilently(t *testing.T) {
	found := reachableSilentErrorBranches(t)

	if len(found) != silentErrorBranchSites {
		t.Errorf("`tick.Run` から届く「黙って捨てた error」が %d か所です"+
			"（留めているのは %d）", len(found), silentErrorBranchSites)
	}
	seen := map[string]bool{}
	for _, s := range found {
		key := s.file + ":" + s.fn
		seen[key] = true
		if siteNeedsClassifying(key, silentErrorBranchReasons) {
			t.Errorf("%s:%d %s は `tick.Run` で回している仕事なのに、"+
				"error を受け取って何も報告していません。**ログにすら"+
				"出ません** —— `tick.Fail(ctx, err, …)` を使うか、"+
				"理由を書いてください", s.file, s.line, s.fn)
		}
	}
	for _, key := range staleClassificationKeys(silentErrorBranchReasons, seen) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。", key)
	}
}

// reachableSilentErrorBranches — 回している仕事の中の、報告しない err 分岐。
func reachableSilentErrorBranches(t *testing.T) []logSite {
	t.Helper()
	fset := token.NewFileSet()
	names := trackedWorkerNames(t, fset)

	var found []logSite
	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if isSkippedFromSlogScan(rel, silentScanSkip) {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || !isErrNotNil(ifs.Cond) || !swallowsSilently(ifs.Body) {
					return true
				}
				found = append(found, logSite{rel, fn.Name.Name, fset.Position(ifs.Pos()).Line})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].file < found[j].file })
	return found
}

// isErrNotNil — `err != nil` の形か（名前に err を含む変数）。
func isErrNotNil(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	id, ok := bin.X.(*ast.Ident)
	if !ok || !strings.Contains(strings.ToLower(id.Name), "err") {
		return false
	}
	nilIdent, ok := bin.Y.(*ast.Ident)
	return ok && nilIdent.Name == "nil"
}

// swallowsSilently — その分岐が、報告も受け渡しもしないか。
//
// **`return err` は「呼び出し側が受け取る」ので黙ってはいません。**
// 呼び出し（ログ・`tick.Fail`・`metrics`・その他なんでも）が1つでも
// あれば、そこで何かしていると見ます —— **緩い方に倒しています**。
// 挙がるのは「値のない return / continue / break だけ」の分岐です。
func swallowsSilently(body *ast.BlockStmt) bool {
	silent := true
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			silent = false
		case *ast.ReturnStmt:
			if len(v.Results) > 0 {
				silent = false
			}
		}
		return silent
	})
	return silent
}

// 判定が効くこと。**違反する見本を食わせて確かめます。**
func TestTheSilentErrorJudgementRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.IfStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\nfor {\n"+src+"\n}\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out *ast.IfStmt
		ast.Inspect(f, func(n ast.Node) bool {
			if ifs, ok := n.(*ast.IfStmt); ok && out == nil {
				out = ifs
			}
			return true
		})
		if out == nil {
			t.Fatal("if が見つかりません")
		}
		return out
	}

	if !isErrNotNil(parse("if err != nil {\ncontinue\n}").Cond) {
		t.Error("**`err != nil` を見つけられません。**")
	}
	if !isErrNotNil(parse("if scanErr != nil {\ncontinue\n}").Cond) {
		t.Error("`scanErr != nil` を見つけられません")
	}
	if isErrNotNil(parse("if n != nil {\ncontinue\n}").Cond) {
		t.Error("error でない変数まで数えています")
	}
	if isErrNotNil(parse("if err == nil {\ncontinue\n}").Cond) {
		t.Error("`== nil` を数えています")
	}

	if !swallowsSilently(parse("if err != nil {\ncontinue\n}").Body) {
		t.Error("**黙って捨てている分岐を見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if !swallowsSilently(parse("if err != nil {\nreturn\n}").Body) {
		t.Error("値のない return も黙っています")
	}
	if swallowsSilently(parse("if err != nil {\nreturn err\n}").Body) {
		t.Error("**`return err` を「黙っている」に数えています。** " +
			"呼び出し側が受け取ります")
	}
	if swallowsSilently(parse("if err != nil {\ntick.Fail(ctx, err, \"x\")\ncontinue\n}").Body) {
		t.Error("**報告している分岐を違反にしています。**")
	}
	if swallowsSilently(parse("if err != nil {\nslog.Warn(\"x\")\ncontinue\n}").Body) {
		t.Error("ログを書いている分岐を違反にしています（そこは別の検査です）")
	}
}

// **「回」の中では、書き込みを捨てないこと。**
//
// `internal/api/handlers/discarded_write_reasons_test.go` は 39 か所を
// 4つに分類しています。そのうち `has-run`（周期の仕事の中）は
// **0 件であるべき**で、そこは手で書いた分類でした —— **手で書いた
// 「0 件です」は、次に生えた1件を止めません。**
//
// ここは同じことを走査で言います。`tick.Run` から届く関数の中の
// `_, _ = ….Exec(…)` を挙げ、0 を留めます。**回があるなら、書けなかった
// ことは `tick.Fail` に出せます** —— 出さなければ、その回は成功として
// 刻まれ、`last_success` が動きます。
//
// 実測 (2026-08-12): 5 か所ありました。3つの関数（`cloud/poller.go` の
// `publishCloudEvent`、`dedup/alert_dedup.go` の `deduplicate` と
// `deduplicateByTechnique`）で、**どれも同じ関数の中で既に `tick.Fail` を
// 使っていました。** この書き込みだけが黙っていました:
//
//	cloud/poller.go     `cloud_events` への保存。**検知には送れていても、
//	                    一覧には出ません。**
//	alert_dedup.go      統合先への印（**次の周回が同じ群をもう一度
//	                    まとめようとします**）と、重複側の `resolved` 化
//	                    （**画面には重複が並んだままです**）。

// discardsAWriteHere — `_, _ = <なにか>.Exec(…)` か。
// **`internal/api/handlers` の判定と同じ形です。** あちらは package が
// 違うので参照できず、ここに置いています —— 形が分かれたら、下の
// `TestTheDiscardedWriteRecogniserHereMatchesTheOtherOne` が落ちます。
func discardsAWriteHere(n ast.Node) bool {
	as, ok := n.(*ast.AssignStmt)
	if !ok || len(as.Lhs) == 0 || len(as.Rhs) != 1 {
		return false
	}
	for _, l := range as.Lhs {
		if id, lok := l.(*ast.Ident); !lok || id.Name != "_" {
			return false
		}
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Exec", "SendBatch", "CopyFrom":
		return true
	}
	return false
}

func reachableDiscardedWrites(t *testing.T) []logSite {
	t.Helper()
	fset := token.NewFileSet()
	names := trackedWorkerNames(t, fset)
	found, err := discardedWritesUnder(workerRoot, fset, names)
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return found
}

// discardedWritesUnder is the walk, taking its root so a test can point it at
// a tree it built. **parse できない file を黙って飛ばさないこと**を
// 確かめるには、壊れた file を1つ食わせるしかありません —— 本物の木は
// どの file も parse できるので、`return nil` と `return parseErr` は
// 同じに見えます（その変異が生き残りました）。
func discardedWritesUnder(root string, fset *token.FileSet, names map[string]bool) ([]logSite, error) {
	var found []logSite
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			return parseErr
		}
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if !discardsAWriteHere(n) {
					return true
				}
				found = append(found, logSite{rel, fn.Name.Name, fset.Position(n.Pos()).Line})
				return true
			})
		}
		return nil
	})
	sort.Slice(found, func(i, j int) bool { return found[i].file < found[j].file })
	return found, err
}

// 実測 (2026-08-12): 5 → 0。**0 が規則です。**
const reachableDiscardedWriteSites = 0

func TestTrackedWorkersDoNotDiscardWrites(t *testing.T) {
	found := reachableDiscardedWrites(t)
	if len(found) != reachableDiscardedWriteSites {
		t.Errorf("`tick.Run` から届く関数の中で、書き込みを捨てている箇所が"+
			"%d か所です（留めているのは %d）", len(found), reachableDiscardedWriteSites)
	}
	for _, s := range found {
		t.Errorf("%s:%d %s が書き込みを捨てています。**この回は成功として"+
			"刻まれ、`last_success` が動きます** —— "+
			"`if _, err := …; err != nil { tick.Fail(ctx, err, …) }` に"+
			"してください", s.file, s.line, s.fn)
	}
}

// 走査が本物を読めていること。**0 を留める検査は、走査が壊れても 0 です。**
func TestTheDiscardedWriteRecogniserHereMatchesTheOtherOne(t *testing.T) {
	parse := func(src string) ast.Node {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out ast.Node
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
		{"捨てている", "_, _ = p.Exec(ctx, `DELETE FROM x`)", true},
		{"SendBatch", "_, _ = p.SendBatch(ctx, b)", true},
		{"CopyFrom", "_, _ = p.CopyFrom(ctx, a, b, c)", true},
		{"error を受けている", "_, err := p.Exec(ctx, `DELETE FROM x`)", false},
		{"読み取り", "_ = p.QueryRow(ctx, `SELECT 1`).Scan(&n)", false},
		{"別の関数", "_, _ = p.Publish(ctx, m)", false},
		{"片方だけ捨てる", "n, _ := p.Exec(ctx, `DELETE FROM x`)", false},
		// **右辺が2つある代入。** `len(as.Rhs) != 1` を `< 1` に緩める
		// 変異が、この見本を足すまで生き残りました。
		{"右辺が2つ", "_, _ = p.Exec(ctx, `DELETE FROM x`), q", false},
	} {
		if got := discardsAWriteHere(parse(c.src)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	// **走査が届いていること。** `tick.Run` から届く関数を1つも見つけて
	// いなければ、上の 0 は「無かった」ではなく「探していない」です。
	fset := token.NewFileSet()
	if n := len(trackedWorkerNames(t, fset)); n < minTrackedWorkerNames {
		t.Fatalf("`tick.Run` から届く名前が %d 個しかありません（床 %d）",
			n, minTrackedWorkerNames)
	}
}

// **parse できない file は「問題の無い file」ではありません。**
//
// 走査は file ごとに parse します。失敗を黙って飛ばすと、その file は
// 走査から消え、**中に何が書いてあっても 0 件**になります。変異検査で
// それが出ました —— 元の実装に戻す変異が3つ、この形のせいで
// 「直っている」と読まれていました（構文を壊した file は `go test` の
// 対象 package でなければコンパイルも走りません）。
func TestAFileThatDoesNotParseIsAFailureNotAnAbsence(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "broken")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const src = `package broken

func work(ctx context.Context) {
	_, _ = p.Exec(ctx, ` + "`DELETE FROM x`" + `)
}
`
	if err := os.WriteFile(filepath.Join(pkgDir, "ok.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"broken|work": true}

	// まず、読めている状態で1件見つかること。見つからないなら、
	// この検査は壊れた側でも 0 件になり、何も言えません。
	got, err := discardedWritesUnder(root, token.NewFileSet(), names)
	if err != nil {
		t.Fatalf("読める木で失敗しています: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("読める木で %d 件です（1 のはずです）: %v", len(got), got)
	}

	// 同じ file を壊す。
	if err := os.WriteFile(filepath.Join(pkgDir, "ok.go"),
		[]byte(src+"\nfunc broken( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = discardedWritesUnder(root, token.NewFileSet(), names)
	if err == nil {
		t.Errorf("parse できない file を黙って飛ばしています（%d 件を返しました）。"+
			"**壊れた file が「捨てている書き込みが無い file」と同じ扱いに"+
			"なります**", len(got))
	}
}
