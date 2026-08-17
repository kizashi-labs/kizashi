package scheduler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// **ログを書いて戻るだけの箇所に、理由が要ること。**
//
// この package のワーカーには報告する相手がいません。呼び出し側は次の
// 周回です。`fail(ctx, err, …)` はその行き先で、`trackRun` が
// `edr_scheduler_failures_total` と `last_success` に落とすので、
// 「回っているが何もできていない」が外から見えます。
//
// **`slog` を書いて `return` するだけの箇所は、そこへ届きません。**
// 以前は上限（34）で押さえていました。増える方向にだけ落ちる形です。
// **上限は「これ以上増やすな」しか言いません** —— いま在る 34 が
// 届かなくてよいものなのかは、誰も見ていませんでした。
//
// 実測 (2026-08-12): 34 か所を1つずつ読み、**5 か所は本当に「この回は
// 仕事を終えられなかった」でした**:
//
//	backup_scheduler     pg_dump 失敗 / 整合性検証の失敗
//	                     （DB の backups 行には failed が残りますが、
//	                     それを見に行く人がいなければ外からは「回った」だけ）
//	darkweb_scheduler    照合対象を読めなかった / キャッシュを解釈できなかった
//	                     （**「何も出ていない」が正常な画面**なので、
//	                     動いていないことと区別がつきません）
//	api_key_rotator      列の存在確認の error を `_ =` で捨てていて、
//	                     **DB が応答しないだけで「列が無い」**になっていました
//
// もう1つ、`realtime_correlator` のアラート解釈失敗は**回の外**（NATS の
// 購読コールバック）だったので、`metrics.BackgroundFailed` に出しました。
//
// 残りには理由が要ります。理由の無い新しい箇所は、ここで落ちます。

// **ログを書いて戻ってよい箇所。** 鍵は `ファイル名:関数名` です。
var bareLogAndReturnReasons = map[string]string{
	// telemetry_mode 列が無い環境 (migration 357/365 未適用)。その状態では
	// センサー降格アラート自体が立たないので、閉じるべきものも無い。
	"agent_health_alerter.go:resolveRecoveredSensorAlerts": "telemetry_mode が" +
		"無い環境。降格アラートが立たないので閉じる対象も存在しない。",
	// ── 仕事が無い ───────────────────────────────────────────────────
	"agent_cert_renewer.go:checkAndRenew":     "更新が必要な証明書が0件。仕事が無いだけです。",
	"baseline_rebuilder.go:rebuild":           "アクティブなエージェントが0件。",
	"hunt_scheduler.go:runScheduledHunts":     "テーブルが無い（存在確認の失敗は `fail` に出ます）／実行すべきハントが0件。",
	"vulnerability_scanner.go:scan":           "ソフトウェアインベントリが空。照合する対象がありません。",
	"darkweb_scheduler.go:syncRansomwareLive": "監視キーワードが0件。照合する対象がありません。",
	"billing_grace_worker.go:check":           "有効な購読があるので降格しない、という正しい読み飛ばしです。",

	// ── 機能が入っていない・切ってある ───────────────────────────────
	//
	// **テーブル／列が無い**という答えは、存在確認そのものが失敗した
	// ときとは違います。確認の失敗はどれも `fail` に出ています
	// （`api_key_rotator.go` の列の確認だけ `_ =` で捨てていたので直しました）。
	"ai_triage_scheduler.go:Run":                  "Claude API キーが未設定。機能が有効になっていません。",
	"digest_scheduler.go:Run":                     "SMTP／宛先が未設定。",
	"darkweb_scheduler.go:Run":                    "DARKWEB_MONITOR_ENABLED=false。",
	"api_key_rotator.go:rotate":                   "api_keys テーブルが無い（確認の失敗は `fail` に出ます）。",
	"api_key_rotator.go:warnExpiringKeys":         "expires_at 列が無い（同上）。",
	"baseline_rebuilder.go:Run":                   "agent_behavioral_baselines テーブルが無い（`store.TableIsThere` は確認できなければ「無い」とは答えません）。",
	"dead_agent_cleanup.go:cleanup":               "agents テーブルが無い（確認の失敗は `fail` に出ます）。",
	"mdm_credential_expiry_checker.go:check":      "credential_expiry 列が無い（同上）。",
	"billing_grace_notifier.go:notify":            "SMTP 未設定／宛先の管理者にメールアドレスが無い。**通知は届きませんが、この回の失敗ではなく設定の話です。**",
	"license_expiry_notifier.go:sendNotification": "同上。",
	// #768。スキャンは終わっていて所見も保存済みで、通知チャンネルが
	// 0 件なだけ。上の 2 件とまったく同じ形なので同じ扱いにする。
	//
	// **`fail` に出さないのは、これが「設定していない」であって
	// 「壊れた」ではないから。** 通知先を作っていないテナントでは毎周期
	// 立ち続けるので、`fail` に出すと背景処理の失敗が設定漏れで埋まり、
	// 本当に終えられなかった回が見えなくなる。
	"cspm_notify.go:notifyCSPM": "通知チャンネルが0件。スキャンは完了し所見も保存済みで、この回の失敗ではなく設定の話です。",

	// ── 重複の抑止（意図した読み飛ばし） ─────────────────────────────
	"agent_health_alerter.go:maybeCreateAlert":          "同じ内容のアラートが既にあるので作りません。",
	"cert_expiry_checker.go:maybeCreateCertAlert":       "同上。",
	"mdm_credential_expiry_checker.go:maybeCreateAlert": "同上。",
	"sigma_sync_scheduler.go:runOnce":                   "前回の同期が実行中。**前回が固まったままなら永久に読み飛ばし続けます** —— それを見張るかは `docs/判断待ちの一覧.md` に置いてあります。",
	"yara_sync_scheduler.go:runOnce":                    "同上。",

	// ── 停止（ctx.Done） ─────────────────────────────────────────────
	"insider_threat_detector.go:Run":  "ctx が終了しての停止。失敗ではありません。",
	"network_anomaly_detector.go:Run": "同上。",
	"realtime_correlator.go:Run":      "同上。",

	// ── 失敗は既に報告済みで、ここはその結果 ─────────────────────────
	//
	// **二重に数えません。** 読めなかったこと自体は `loadNewIOCs` /
	// `huntField` が `fail` に出しています。ここは「だから watermark を
	// 進めない」という判断の記録です。
	"retro_ioc_hunter.go:hunt": "読み切れなかったことは読み出し側が `fail` に出しています。ここはその結果（watermark を進めない）の記録です。",
}

// 実測 (2026-08-12): 直したあと 29 か所。
const minBareLogAndReturnSites = 20

// **件数も留めます。** 理由の鍵は `ファイル名:関数名` なので、同じ関数に
// もう1つ増やしても鍵は変わりません（`hunt_scheduler` や
// `billing_grace_notifier` のように、1つの関数に2か所あるものがあります）。
// 29 → 30 (#543)。増えた 1 件は resolveRecoveredSensorAlerts で、
// telemetry_mode が無い環境では閉じる対象も無い（理由は一覧に記載）。
// 30 → 31 (#768)。増えた 1 件は notifyCSPM で、通知チャンネルが 0 件
// （同上）。
const bareLogAndReturnSiteCount = 31

type bareSite struct {
	file string
	fn   string
	line int
	lvl  string
}

func (s bareSite) key() string { return s.file + ":" + s.fn }

func TestEveryBareLogAndReturnHasAReason(t *testing.T) {
	sites := bareLogAndReturnSites(t, schedulerDir)

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if len(sites) < minBareLogAndReturnSites {
		t.Fatalf("走査が届いていません: ログを書いて戻るだけの箇所が %d 個しか"+
			"見えません（実測 29、床 %d）", len(sites), minBareLogAndReturnSites)
	}
	t.Logf("ログを書いて戻るだけの箇所: %d / 理由: %d 件",
		len(sites), len(bareLogAndReturnReasons))

	for _, s := range sites {
		if bareSiteNeedsAReason(s, bareLogAndReturnReasons) {
			t.Errorf("%s:%d %s が、ログを書いて戻るだけです（%s）。"+
				"**呼び出し側は次の周回なので、これは誰にも届きません** —— "+
				"この回が仕事を終えられなかったなら `fail(ctx, err, …)` を、"+
				"そうでないなら理由を書いてください",
				s.file, s.line, s.fn, s.lvl)
		}
	}

	if len(sites) != bareLogAndReturnSiteCount {
		t.Errorf("ログを書いて戻るだけの箇所が %d か所です（留めているのは %d）。"+
			"**増えたなら、それが誰かに届かなくてよいかを読んでください。"+
			"減らしたなら数を下げてください** —— 理由の鍵は関数までなので、"+
			"同じ関数に増えた分は鍵の検査では見えません",
			len(sites), bareLogAndReturnSiteCount)
	}

	// **理由の側も、宛先が実在すること。** 直した箇所の理由が残ると、
	// 次に同じ場所が生えたときに黙って通ります。
	for _, key := range staleReasonKeys(bareLogAndReturnReasons, sites) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください** —— 残しておくと、"+
			"次に同じ場所が生えたときに黙って通ります", key)
	}
}

// staleReasonKeys — 宛先の消えた理由。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま古い理由は 0 件なので、走査を潰しても挙がる件数は変わりません。
func staleReasonKeys(reasons map[string]string, sites []bareSite) []string {
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.key()] = true
	}
	var stale []string
	for key := range reasons {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

func TestTheStaleReasonScanRecognisesTheRealThing(t *testing.T) {
	sites := []bareSite{{file: "a.go", fn: "Live"}}
	got := staleReasonKeys(map[string]string{
		"a.go:Live": "在ります",
		"a.go:Gone": "**もう在りません**",
		"z.go:Gone": "同上",
	}, sites)
	want := "a.go:Gone,z.go:Gone"
	if strings.Join(got, ",") != want {
		t.Errorf("古い理由 = %v, want %s。**宛先の消えた理由を挙げられない"+
			"なら、次に同じ場所が生えたときに黙って通ります**", got, want)
	}
	if len(staleReasonKeys(map[string]string{"a.go:Live": "在ります"}, sites)) != 0 {
		t.Error("**在る宛先の理由を「古い」と言っています。**")
	}
}

// bareSiteNeedsAReason — その箇所が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま違反は 0 件なので、`if false` に潰しても挙がる件数は変わりません。
func bareSiteNeedsAReason(s bareSite, reasons map[string]string) bool {
	return reasons[s.key()] == ""
}

func TestTheBareLogAndReturnJudgementRecognisesTheRealThing(t *testing.T) {
	reasons := map[string]string{"a.go:Excused": "理由が書いてあります"}
	if !bareSiteNeedsAReason(bareSite{file: "a.go", fn: "NoReason"}, reasons) {
		t.Error("**理由の無い箇所を違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if bareSiteNeedsAReason(bareSite{file: "a.go", fn: "Excused"}, reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}
	if !bareSiteNeedsAReason(bareSite{file: "b.go", fn: "Excused"}, reasons) {
		t.Error("**別のファイルの同名関数を、書いてある理由で通しています。**")
	}
}

// bareLogAndReturnSites — `slog.X(…)` の直後が値なしの `return` である箇所。
//
// **正規表現から AST に変えました。** 行を数えるだけでは、どの関数の中か
// が分からず、理由を書く相手を指せません（上限だけなら数えられます）。
func bareLogAndReturnSites(t *testing.T, dir string) []bareSite {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Strings(files)

	var out []bareSite
	for _, path := range files {
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") || base == "heartbeat.go" {
			continue
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("%s を読めません: %v", path, readErr)
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます** ——
			// 中に何が書いてあっても 0 件になります。
			t.Fatalf("%s を parse できません: %v", path, parseErr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, s := range logThenReturn(fn.Body) {
				out = append(out, bareSite{
					file: base,
					fn:   fn.Name.Name,
					line: fset.Position(s.Pos()).Line,
					lvl:  s.Fun.(*ast.SelectorExpr).Sel.Name,
				})
			}
		}
	}
	return out
}

// logThenReturn — その本体の中の「`slog.X(…)` の直後に値なしの `return`」。
//
// **文の並びは `BlockStmt` だけではありません。** `case`（`CaseClause`）と
// `select` の枝（`CommClause`）は自分で文の並びを持ちます —— そこを見ないと、
// `switch` の中の書き捨てが丸ごと外れます。
func logThenReturn(body *ast.BlockStmt) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch v := n.(type) {
		case *ast.BlockStmt:
			list = v.List
		case *ast.CaseClause:
			list = v.Body
		case *ast.CommClause:
			list = v.Body
		default:
			return true
		}
		for i := 0; i+1 < len(list); i++ {
			call := slogCall(list[i])
			if call == nil {
				continue
			}
			ret, ok := list[i+1].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 0 {
				continue
			}
			out = append(out, call)
		}
		return true
	})
	return out
}

// slogCall — その文が `slog.X(…)` だけか。
func slogCall(s ast.Stmt) *ast.CallExpr {
	es, ok := s.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "slog" {
		return nil
	}
	return call
}

// 走査が効くこと。**違反する見本を食わせて確かめます** —— 通っている木の上
// では、判定を潰しても挙がる件数は変わりません。
func TestTheBareLogAndReturnScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	for _, c := range []struct {
		name, src string
		want      int
	}{
		{"ログして戻る", "slog.Warn(\"x\")\nreturn", 1},
		{"ログしてから続ける", "slog.Warn(\"x\")\ng()", 0},
		{"値を返す", "slog.Warn(\"x\")\nreturn nil", 0},
		{"fail してから戻る", "fail(ctx, err, \"x\")\nreturn", 0},
		{"slog 以外", "log.Warn(\"x\")\nreturn", 0},
		{"switch の中", "switch n {\ncase 1:\n\tslog.Warn(\"x\")\n\treturn\n}", 1},
		{"select の枝の中", "select {\ncase <-c:\n\tslog.Warn(\"x\")\n\treturn\n}", 1},
		{"入れ子のブロック", "if n > 0 {\n\tslog.Warn(\"x\")\n\treturn\n}", 1},
		{"2つ", "slog.Warn(\"a\")\nreturn\n", 1},
	} {
		if got := len(logThenReturn(parse(c.src))); got != c.want {
			t.Errorf("%s: %d 件, want %d 件", c.name, got, c.want)
		}
	}
}

// 床の判定が効くこと。
func TestTheBareLogAndReturnFloorNoticesAnEmptyWalk(t *testing.T) {
	if minBareLogAndReturnSites < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}

// 理由の数が、実測とかけ離れていないこと。
func TestTheBareLogAndReturnReasonsCoverTheMeasuredSites(t *testing.T) {
	sites := bareLogAndReturnSites(t, schedulerDir)
	keys := map[string]bool{}
	for _, s := range sites {
		keys[s.key()] = true
	}
	if len(keys) != len(bareLogAndReturnReasons) {
		t.Errorf("箇所の宛先 %d 件に対して理由が %d 件です。"+
			"**数が合わないなら、どちらかが古くなっています**",
			len(keys), len(bareLogAndReturnReasons))
		var missing []string
		for k := range keys {
			if bareLogAndReturnReasons[k] == "" {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("理由の無い宛先: %s", strings.Join(missing, ", "))
		}
	}
}
