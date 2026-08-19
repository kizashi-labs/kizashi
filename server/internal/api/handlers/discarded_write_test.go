package handlers

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// **書き込みを捨てたまま「保存しました」と答えないこと。**
//
// 読み取りの `_ = QueryRow(…).Scan(…)` は 338 → 16 まで下げました。
// **書き込みの `_, _ = Exec(…)` は一度も測っていませんでした。**
//
// 実測 (2026-08-12): `server/internal` に 122 か所。**うち 55 は、
// そのあと 200/201/202 で答える関数の中**にありました —— 状態を変えたと
// 答えながら、1行も書いていないことがあります:
//
//	software_vulnerability:UpdateStatus  UPDATE を捨てて
//	                                     `{"status": 変更後}` を返す
//	dns_security:DeleteBlocklistEntry    DELETE を捨てて
//	                                     `{"message": "entry removed"}`
//	recovery_code:Generate               **利用者が控える復旧コード**を、
//	                                     保存を確かめずに返す（MFA の
//	                                     最後の手段です）
//	identity_handler:SaveConfig          INSERT が失敗したときの UPDATE を
//	                                     捨てる —— どちらも書けずに「保存」
//
// `WriteOK(c, err)` に通しました。**`ReadOK` と違って「まだ無い」を
// 通しません** —— 読み取りなら「テーブルがまだ無い」は事実ですが、
// 書き込みでそれが起きたら、書けていないのに「保存しました」と答える
// ことになります。
//
// **成功として答える関数の中は 0 件に留めます。** 残り 44 は、答えを
// 返さない経路（goroutine の後始末、ベストエフォートの記録など）です。
//
// `internal/scheduler` の 10 か所は `fail(ctx, err, …)` に通しました
// —— **周期の仕事には「回」があるので、書けなかったことが
// `last_success` に出ます**:
//
//	backup_scheduler      完了の記録（**書けないと、取れたバックアップが
//	                      「実行中」のまま残り、しかも SLO の成功時刻は
//	                      押されます**）／失敗の記録
//	darkweb_scheduler     被害の検知行 ×2（**アラートと通知は出るのに、
//	                      一覧には無い**）／投稿キャッシュ／死活 ×2
//	heartbeat_monitor     オフライン化（**落ちている端末が画面では
//	                      「オンライン」のまま**）
//	retro_rule_hunter     watermark
//	version_checker       バージョン分布 —— ここだけ 42P01 を通します
//	                      （`system_metadata` は任意のテーブルです）

// **`internal` 全体です。** この package は `internal/api/handlers` なので
// 2つ上がります —— 最初 `..` にしていて、`internal/api` しか見ずに
// 5 か所しか見つけませんでした（床が落としてくれました）。
const writeScanRoot = "../.."

// **成功として答える関数の中の、捨てた書き込み。** 0 件です。
const discardedWritesThatClaimSuccess = 0

// 実測 (2026-08-12): 122 → 54 → `internal/scheduler` の 10 か所を
// `fail(ctx, err, …)` に通して 44 → **「回」の中にあった 7 か所**を
// `tick.Fail` に通して 37。周期の仕事には「回」があるので、書けなかった
// ことが `last_success` に出ます。
//
// **さらに 11 か所**を直して 26。呼び出し側が error を受け取れるもの、
// および「同じ1つの変更」だったものです:
//
//	store/postgres.go            テナントを設定できない接続を「使える」と
//	                             答えていた ×2（**RLS が全件を通します**）
//	store/users.go               MFA 復旧コードの使用済みの印
//	                             （**書けなくても true を返していました**）
//	reports/scheduler.go ×3      記憶を先に変えて DB を捨てる
//	threatintel/feed.go ×2       同上
//	agentconfig/profile.go ×2    既定の一意性 —— transaction に入れました
//	store/alerts.go              MTTR の履歴 —— 同上
//
// **7 のうち 2 は、手で書いた分類が間違っていました。**
// `internal/tick` の走査（`TestTrackedWorkersDoNotDiscardWrites`）が
// `reports/scheduler.go:runReport` と `threatintel/feed.go:FetchFeed` を
// 挙げました —— どちらも `restart` に入れていましたが、`tick.Run` から
// 届きます。**手で書いた分類は、走査で裏を取るまで信用できません。**
//
// **9 → 1 (2026-08-12)。** 残り 9 を1つずつ読んで、全部答えました
// （`discarded_write_reasons_test.go` に何をどう答えたか書いてあります）。
// 残る 1 は `ldap/connector.go` の `CREATE TABLE IF NOT EXISTS` で、
// **失敗すれば直後の upsert が全件失敗し、そちらが報告します。**
//
// **ここでも1つ、手で書いた分類が間違っていました。**
// `detection/curate_service.go:RunRound` を `restart` に入れていましたが、
// `curate_scheduler` の `trackRun` から届きます —— **3つ目の
// 「回があるのに黙っていた」箇所**でした。
//
// **走査が届かなかった理由は段数ではありません。** `internal/tick` の
// 走査は3段たどりますが、**同じ package の中だけ**です（名前だけで
// 辿ると別 package の同名関数まで引き込むため）。`curate_scheduler` は
// `internal/scheduler`、`RunRound` は `internal/detection` なので、
// 1段目で越境して見えませんでした —— **package をまたぐ呼び出しの先は、
// いまの走査からは見えません。**
const discardedWritesTotal = 0

func TestNoDiscardedWriteIsAnsweredWithSuccess(t *testing.T) {
	claims, total := discardedWriteSites(t)

	if len(claims) != discardedWritesThatClaimSuccess {
		t.Errorf("成功として答えている関数の中の、捨てた書き込みが %d か所です"+
			"（留めているのは %d）", len(claims), discardedWritesThatClaimSuccess)
		for _, w := range claims {
			t.Errorf("%s が書き込みを捨てたまま、200/201 で答えています。"+
				"**状態を変えたと答えながら、1行も書いていないことが"+
				"あります** —— `if _, err := …; !WriteOK(c, err) { return }` "+
				"を使ってください", w)
		}
	}
	if total > discardedWritesTotal {
		t.Errorf("捨てている書き込みが %d から %d に増えました",
			discardedWritesTotal, total)
	}
	if total < discardedWritesTotal {
		t.Errorf("捨てている書き込みが %d まで減りました。**留めている数を"+
			" %d に下げてください**", total, total)
	}
	t.Logf("捨てている書き込み: %d か所（成功として答えているもの: %d）",
		total, len(claims))
}

// allDiscardedWriteSites — 捨てている書き込みの `パス:関数名` を全部。
//
// **走査の写しではありません。** 下の `discardedWriteSites` と同じ一度の
// 走査から出ています —— 写しにすると、分類の一覧が本物とずれても
// 誰も気づけません。
func allDiscardedWriteSites(t *testing.T) []string {
	t.Helper()
	_, keys, _, _ := scanDiscardedWrites(t)
	return keys
}

// discardedWriteSites — `_, _ = …Exec(…)` の箇所と、そのうち
// 200/201/202 で答える関数の中にあるもの。
func discardedWriteSites(t *testing.T) (claims []string, total int) {
	t.Helper()
	claims, _, total, _ = scanDiscardedWrites(t)
	return claims, total
}

func scanDiscardedWrites(t *testing.T) (claims, keys []string, total, funcs int) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(writeScanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, writeScanRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			// 変異検査でそれが出ました —— 構文を壊した file が
			// 「捨てている書き込みが無い file」と同じ扱いになります。
			return parseErr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs++
			success := answersWithSuccess(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || !discardsAWrite(as) {
					return true
				}
				total++
				keys = append(keys, rel+":"+fn.Name.Name)
				if success {
					claims = append(claims, rel+":"+fn.Name.Name+":"+
						strconv.Itoa(fset.Position(as.Pos()).Line))
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Strings(claims)
	sort.Strings(keys)
	return claims, keys, total, funcs
}

// discardsAWrite — `_, _ = <なにか>.Exec(…)` か。
func discardsAWrite(as *ast.AssignStmt) bool {
	if len(as.Lhs) == 0 || len(as.Rhs) != 1 {
		return false
	}
	for _, l := range as.Lhs {
		if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
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

// answersWithSuccess — その関数が 200/201/202 で答えるか。
func answersWithSuccess(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 1 || found {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		st, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch st.Sel.Name {
		case "StatusOK", "StatusCreated", "StatusAccepted":
			found = true
		}
		return true
	})
	return found
}

// 走査が効くこと。**違反する見本を食わせて確かめます** —— いま違反は
// 0 件なので、判定を潰しても挙がる件数は変わりません。
func TestTheDiscardedWriteScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f(c *gin.Context) {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	first := func(b *ast.BlockStmt) *ast.AssignStmt {
		var out *ast.AssignStmt
		ast.Inspect(b, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && out == nil {
				out = as
			}
			return true
		})
		return out
	}

	if !discardsAWrite(first(parse("_, _ = p.Exec(ctx, `DELETE FROM x WHERE id=$1`, id)"))) {
		t.Error("**捨てている書き込みを見つけられません。**")
	}
	if discardsAWrite(first(parse("_, err := p.Exec(ctx, `DELETE FROM x`)"))) {
		t.Error("**error を受け取っているものを違反にしています。**")
	}
	if discardsAWrite(first(parse("_ = p.QueryRow(ctx, `SELECT 1`).Scan(&n)"))) {
		t.Error("読み取りを書き込みに数えています")
	}

	if !answersWithSuccess(parse("c.JSON(http.StatusOK, gin.H{\"ok\": true})")) {
		t.Error("**200 を成功と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if !answersWithSuccess(parse("c.JSON(http.StatusCreated, gin.H{\"id\": id})")) {
		t.Error("201 を成功と見ていません")
	}
	if answersWithSuccess(parse("c.JSON(http.StatusInternalServerError, gin.H{\"error\": e})")) {
		t.Error("**500 を成功に数えています。** " +
			"失敗として答えている関数まで違反になります")
	}
	if answersWithSuccess(parse("slog.Info(\"done\")")) {
		t.Error("答えていない関数を「成功として答えた」と数えています")
	}
}

// 走査が届いていること。
//
// **床は違反の数ではなく、歩いた関数の数です。** 元は「捨てている
// 書き込みが 5 か所以上見えること」でした —— 違反を 1 まで減らした日に
// その床は成り立たなくなります。**残りを直すほど、走査が壊れたことに
// 気づけなくなる床**でした。歩いた関数の数なら、直しても減りません。
func TestTheDiscardedWriteWalkReachesTheTree(t *testing.T) {
	_, _, _, funcs := scanDiscardedWrites(t)
	const floor = 2000
	if funcs < floor {
		t.Fatalf("走査が届いていません: 関数が %d 個しか見えません（床 %d）",
			funcs, floor)
	}
	if floor < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}

// **`WriteOK` が、書けたときだけ「書けた」と答えること。**
//
// 直した 68 か所はどれもこの1行に乗っているので、**ここが素通しになれば
// 全部そのまま元に戻ります。**
func TestWriteOKDoesNotForgiveAnything(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, c := range []struct {
		name   string
		err    error
		want   bool
		status int // 0 = 何も書かない
	}{
		{"書けた", nil, true, 0},
		{"書けなかった", errors.New("dial tcp: connection refused"), false, http.StatusInternalServerError},
		// **`ReadOK` と違うのはここです。** 読み取りなら「テーブルがまだ
		// 無い」は事実ですが、書き込みでそれが起きたら書けていません。
		{"テーブルがまだ無い", &pgconn.PgError{Code: "42P01"}, false, http.StatusInternalServerError},
		{"行が無い", pgx.ErrNoRows, false, http.StatusInternalServerError},
		{"制約違反", &pgconn.PgError{Code: "23505"}, false, http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		if got := WriteOK(ctx, c.err); got != c.want {
			t.Errorf("%s: WriteOK = %v, want %v。**true を返すと、"+
				"書けていないのに「保存しました」と答えます**", c.name, got, c.want)
		}
		if c.status == 0 && w.Code != http.StatusOK {
			t.Errorf("%s: 応答を書いています (%d)", c.name, w.Code)
		}
		if c.status != 0 && w.Code != c.status {
			t.Errorf("%s: 応答 = %d, want %d", c.name, w.Code, c.status)
		}
	}
}
