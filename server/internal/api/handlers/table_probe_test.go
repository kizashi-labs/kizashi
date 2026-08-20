package handlers

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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// テーブルの存在確認が、**「読めなかった」を「無い」に倒さない**こと。
//
// この確認は、まだマイグレーションが当たっていない機能の画面を 500 に
// しないために置かれています。ところが 49 個すべてが、確認そのものの
// 失敗を「無い」と同じに扱っていました:
//
//	return err == nil && exists   // 24 個
//	return exists                 // 18 個（err はログだけ、あるいは捨てる）
//	return ok                     // 7 個（`_ =` で捨てる）
//
// 呼び出し側 193 箇所は、それを受けて 200 の空（76）・404（62）・
// 503（54）を返します。
//
// 実測 (2026-08-12)。`bas_scenarios` に 120,400 行、`statement_timeout`
// 1ms で `/api/v1/admin/bas/scenarios`:
//
//	直す前  200  {"scenarios":[],"total":0}   ← 「1件も無い」と同じ姿
//	直した後 500  {"error":"データベース操作に失敗しました"}
//
// テーブルが**本当に**無いときは、直す前後どちらも 200 の空です
// （移行していない別DBで確認しました）。変わるのは失敗したときだけです。

// 判断そのもの。**DB は要りません。**
func TestProbeAnswerNeverTurnsAFailureIntoAbsence(t *testing.T) {
	if !probeAnswer(false, errors.New("dial tcp: connection refused")) {
		t.Error("**確認に失敗したのに「無い」と答えました。** " +
			"呼び出し側はそれを受けて 200 の空を返します —— " +
			"120,400 行あるテーブルが、1行も無いのと同じ姿になります")
	}
	if !probeAnswer(true, errors.New("timeout")) {
		t.Error("失敗したときは、走査できなかった変数の値に関わらず「在る」です")
	}
}

// **本当に無いときは「無い」と答えること。**
//
// ここが崩れると、移行前の機能の画面が 500 になります —— この確認が
// 置かれている理由そのものが失われます。
func TestProbeAnswerStillReportsRealAbsence(t *testing.T) {
	if probeAnswer(false, nil) {
		t.Error("**テーブルが本当に無いのに「在る」と答えました。** " +
			"移行がまだの機能の画面が 500 になります")
	}
	if !probeAnswer(true, nil) {
		t.Error("在るテーブルを「無い」と答えました")
	}
}

// **確認に失敗したら「在る」と答えること。**
//
// 届かない先へ向けたプールで確かめます —— DB は要りません。
func TestTableProbeFailureIsNotAbsence(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://nobody@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("設定を作れません: %v", err)
	}
	cfg.ConnConfig.ConnectTimeout = 2 * time.Second
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("プールを作れません: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !tableIsThere(ctx, pool, "bas_scenarios") {
		t.Error("**確認に失敗したのに「無い」と答えました。** " +
			"呼び出し側はそれを受けて 200 の空を返します —— " +
			"120,400 行あるテーブルが、1行も無いのと同じ姿になります")
	}
}

// 期限切れの ctx でも同じこと。**「間に合わなかった」も「無い」では
// ありません。**
func TestTableProbeTimeoutIsNotAbsence(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://nobody@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("設定を作れません: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("プールを作れません: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !tableIsThere(ctx, pool, "bas_scenarios") {
		t.Error("**打ち切られた確認を「無い」と答えました。**")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 確認が1か所に集まっていること
// ─────────────────────────────────────────────────────────────────────────────

// `information_schema` を直に引いてよい場所。
//
// **走査を狭めずに、理由を書いて外します。** 狭めると、狭めた範囲に
// 入った新しい確認が黙って外れます。
var informationSchemaReasons = map[string]string{
	"store/table_probe.go:TableIsThere": "ここが本物です。**「読めなかった」を「無い」に" +
		"倒さない**判断そのものが、この1か所に入っています。",

	// 以下は、確認の失敗を**呼び出し側に返している**ものです。
	// `tableIsThere` は bool しか返さないので、こちらの方が細かく
	// 答えられます。**倒していないので、直す先がありません。**
	"api/handlers/stix_handler.go:iocEntriesTableExists": "`(bool, error)` を返します。" +
		"外部ツールに空のバンドルを渡すと「指標が1件も無い」と読まれるので、" +
		"失敗はそのまま呼び出し側へ返しています。",
	"api/handlers/sandbox_handler.go:correlateIOCs": "確認に失敗したら `err` を返します。" +
		"**「照合したが一致なし」と「照合できなかった」を分ける**ためで、" +
		"関数の頭にその理由が書いてあります。",
	"api/handlers/tip_integration_handler.go:platformsFromThreatFeeds": "確認に失敗したら " +
		"`err` を返します。0件と出すと、設定済みのフィードが消えたように見え、" +
		"入れ直そうとした人が既にある設定を作り直します。",
	"api/handlers/alert_enrichment_pipeline.go:enrich": "確認に失敗したら `slog.Error` を" +
		"出して**そのまま戻ります**。「テーブルが無い」と「確認できなかった」を" +
		"関数の中で分けていて、その理由も書いてあります。",
	"api/handlers/export_handler.go:tableExists": "`(bool, error)` を返します。書き出しの" +
		"入口なので、確認できなかったことを呼び出し側が知る必要があります。",
	"api/handlers/predictive_analytics_handler.go:fetchStats": "確認に失敗したら " +
		"`fmt.Errorf` で包んで返します。",
	"updater/applier.go:dumpRoleBlocked": "テーブルの有無ではなく、**ダンプ用ロールが RLS を" +
		"迂回できるか**を見ています。`tableIsThere` は bool しか返さないので、" +
		"ここが必要とする3つの結果（迂回できる／できない／確認自体ができなかった）を" +
		"表せません。**倒していません** —— 確認できなかった場合は " +
		"`tick.Fail` で報告したうえで先へ進め、pg_dump 自身に答えさせます" +
		"（pipefail が入ったので、その失敗はもう握り潰されません）。",

	// ── 以下は、確認の失敗を `fail(ctx, err, ...)` か `error` で
	//    **報告している**ものです。`TableIsThere` は Warn を出すだけなので、
	//    こちらの方が細かく答えられます。**倒していないので、直す先が
	//    ありません。**
	"remediation/engine.go:LoadExclusionsFromDB":        "`error` を返します。関数の頭に「捨てると除外リストが空のまま残り、『触るな』と指定されたホストが全部自動修復の対象になる」と書いてあります。",
	"scheduler/api_key_rotator.go:rotate":               "`fail(ctx, err, ...)` で報告してから戻ります。",
	"scheduler/api_key_rotator.go:warnExpiringKeys":     "同上。",
	"scheduler/asset_criticality_scorer.go:calculate":   "`fail(ctx, err, ...)` で報告してから戻ります。",
	"scheduler/compliance_scorer.go:calculate":          "同上。",
	"scheduler/dead_agent_cleanup.go:cleanup":           "同上。「無い」ときだけ Debug で飛ばします。",
	"scheduler/hunt_scheduler.go:runScheduledHunts":     "同上。",
	"scheduler/insider_threat_detector.go:createAlert":  "同上。**アラートを作れないことを黙りません。**",
	"scheduler/mdm_credential_expiry_checker.go:check":  "同上。",
	"scheduler/network_anomaly_detector.go:createAlert": "同上。",
	"scheduler/realtime_correlator.go:loadRules":        "同上。「ルールは1件も読み込まれません」と書いて報告します。",
	"scheduler/threat_feed_importer.go:importAll":       "同上。「無い」ときだけ静かに戻ります。",
	"scheduler/threat_feed_importer.go:importFeed":      "同上。",
	"scheduler/vulnerability_scanner.go:scan":           "同上。",

	"api/handlers/iot_ot_handler.go:ListDevices": "テーブルではなく**列**の有無を見ています" +
		"（`information_schema.columns`）。読めなければ狭い方の問い合わせに" +
		"落ちるだけで、「無い」とは答えません。",
}

// asksTheCatalogue — その文字列がテーブル目録を引いているか。
//
// **切り出してあるのは、探し方を狭める変異を殺せるようにするため**です。
// いま違反は 0 件なので、`information_schema.zzz` に変えても挙がる件数は
// 変わりません（変異が生き残りました）。
func asksTheCatalogue(lit string) bool {
	// **目録は1つではありません。** 前回 `information_schema.tables` だけを
	// 見て「49 個すべて片付いた」と書きましたが、`pg_tables` を引く確認が
	// **30 個**残っていました。同じ欠陥が、別の表の名前で隠れていました。
	for _, catalogue := range tableCatalogues {
		if strings.Contains(lit, catalogue) {
			return true
		}
	}
	return false
}

// テーブルの有無を訊く先。**狭めると、その言い方で書かれた確認が
// 数から消えます。**
var tableCatalogues = []string{
	"information_schema.tables",
	"information_schema.columns",
	"pg_tables",
	"pg_class",
	"to_regclass",
}

// isOwnTableProbe — その関数が「自前の確認」として挙がるべきか。
//
// **切り出してあるのは、理由の照合を潰す変異を殺せるようにするため**です。
func isOwnTableProbe(uses bool, file, fn string, reasons map[string]string) bool {
	if !uses {
		return false
	}
	return reasons[file+":"+fn] == ""
}

// 探し方と、外し方の判断が効くこと。
func TestTheTableProbeDetectorRecognisesTheRealThing(t *testing.T) {
	for _, lit := range []string{
		"`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`",
		"`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=$1)`",
		"`SELECT to_regclass('public.alerts')`",
		"`SELECT 1 FROM pg_class WHERE relname=$1`",
	} {
		if !asksTheCatalogue(lit) {
			t.Errorf("**本物の確認を見つけられません: %s** 探し方を狭めると、"+
				"その言い方で書かれた確認が黙って外れます", lit)
		}
	}
	// **一覧が痩せていないこと。** 前回はここが1つしかなく、`pg_tables` を
	// 引く 30 個が数から外れていました。
	if len(tableCatalogues) < 5 {
		t.Errorf("目録の一覧が %d 件です。**減らすと、その先で書かれた確認が"+
			"見えなくなります**", len(tableCatalogues))
	}
	if asksTheCatalogue("`SELECT * FROM alerts`") {
		t.Error("関係ない SQL を確認に数えています")
	}

	reasons := map[string]string{"a.go:Excused": "理由が書いてあります"}
	if !isOwnTableProbe(true, "a.go", "NoReason", reasons) {
		t.Error("**理由の無い自前の確認を、違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if isOwnTableProbe(true, "a.go", "Excused", reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}
	if isOwnTableProbe(false, "a.go", "NoReason", reasons) {
		t.Error("確認を含まない関数を違反にしています")
	}
}

// **`internal/api/handlers` だけでは足りません。**
//
// 同じ確認が scheduler / reports / remediation / detection / ldap にも
// あり、そちらは 24 個が失敗を「無い」に倒していました。走査を
// `server/internal` 全体に広げます。
const tableProbeRoot = "../.."

// 実測 (2026-08-12): `server/internal` の .go は 603 個。床は下に。
const minHandlerFilesScanned = 500

// 床の判定が効くこと。**別の定数なので、別に確かめます。**
func TestTheHandlerScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if rowsErrScanReached(0, minHandlerFilesScanned) {
		t.Error("**0 ファイルでも「届いた」と言っています。**")
	}
	if rowsErrScanReached(minHandlerFilesScanned-1, minHandlerFilesScanned) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !rowsErrScanReached(minHandlerFilesScanned, minHandlerFilesScanned) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minHandlerFilesScanned < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}

func TestNoHandlerAsksInformationSchemaOnItsOwn(t *testing.T) {
	fset := token.NewFileSet()

	type site struct {
		file string
		fn   string
		line int
	}
	var bad []site
	seen := map[string]bool{}
	scanned := 0

	walkErr := filepath.WalkDir(tableProbeRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := filepath.ToSlash(strings.TrimPrefix(path, tableProbeRoot+string(filepath.Separator)))
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		scanned++
		// **早い脱出は置きません。**
		//
		// ここに `if !strings.Contains(src, "information_schema")` を
		// 置いていました。目録の一覧を広げたときにここだけ古いままで、
		// `pg_tables` しか出てこないファイルが丸ごと走査から外れ、検査は
		// 緑を返していました。**探し方を2か所に分けて持つと、片方だけが
		// 古くなります。** 速さのためだけの分岐なので、消しました。
		f, parseErr := parser.ParseFile(fset, name, src, 0)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", name, parseErr)
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			uses := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if asksTheCatalogue(lit.Value) {
						uses = true
					}
				}
				return true
			})
			if uses {
				seen[name+":"+fn.Name.Name] = true
			}
			if !isOwnTableProbe(uses, name, fn.Name.Name, informationSchemaReasons) {
				continue
			}
			bad = append(bad, site{name, fn.Name.Name, fset.Position(fn.Pos()).Line})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("走査できません: %v", walkErr)
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !rowsErrScanReached(scanned, minHandlerFilesScanned) {
		t.Fatalf("走査が届いていません: %d ファイルしか見えません（床 %d）",
			scanned, minHandlerFilesScanned)
	}
	t.Logf("走査したファイル: %d", scanned)

	// **理由の宛先に、走査が届いていること。**
	//
	// 届いていない理由は、外しているのではなく**見えていない**だけです。
	// ここが無いと、走査を狭める変更（早い脱出を古い一覧で戻すなど）が
	// 何も落とさずに通ります（実際に変異が生き残りました）。
	for key := range informationSchemaReasons {
		if !seen[key] {
			t.Errorf("理由を書いてある %s に、走査が届いていません。"+
				"**外しているのではなく、見えていないだけです**", key)
		}
	}

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	for _, s := range bad {
		t.Errorf("%s:%d %s が `information_schema` を直に引いています。"+
			"**`tableIsThere` を使ってください** —— 確認に失敗したときに"+
			"「無い」と答えると、DB 障害が「その機能は未設定」になります",
			s.file, s.line, s.fn)
	}
}

// 理由の一覧が古くなっていないこと。
//
// **消えた関数の理由が残っていると、次に同じ名前が生えたとき黙って
// 外れます。**
func TestNoInformationSchemaReasonHasGoneStale(t *testing.T) {
	fset := token.NewFileSet()
	for key := range informationSchemaReasons {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			t.Errorf("理由の鍵の形が違います: %q", key)
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(tableProbeRoot, parts[0]), nil, 0)
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

// declaresFunc — そのファイルがその名前の関数を宣言しているか。
//
// **切り出してあるのは、名前の照合を外す変異を殺せるようにするため**です。
// 「どれか関数があれば見つかったことにする」に潰しても、いま全部の宛先が
// 実在するので結果は変わりません（変異が生き残りました）。
func declaresFunc(f *ast.File, name string) bool {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return true
		}
	}
	return false
}

// 名前の照合が効くこと。
func TestDeclaresFuncActuallyComparesTheName(t *testing.T) {
	src := "package p\nfunc Alpha() {}\nfunc Beta() {}\n"
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("見本を解析できません: %v", err)
	}
	if !declaresFunc(f, "Alpha") {
		t.Error("在る関数を見つけられません")
	}
	if declaresFunc(f, "Gamma") {
		t.Error("**無い関数を「在る」と答えています。** " +
			"消えた宛先の理由が、一覧に残り続けます")
	}
}
