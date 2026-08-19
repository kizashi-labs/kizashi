package handlers_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 空のテーブルを数えると、0 ではなく NULL が返ります。
//
// PostgreSQL の `SUM` と `AVG` は、**GROUP BY の無い問い合わせで対象が
// 1行も無いとき、行を1つ返して値を NULL にします。** それを Go の `int` や
// `float64` に読むと:
//
//	can't scan into dest[1] (col: sum): cannot scan NULL into *int
//
// つまり **新規インストール直後、まだ何も無い状態でだけ 500 になります。**
// 画面には「データベース操作に失敗しました」と出るので、読んだ人は障害だと
// 考えます —— 本当は「まだ 0 件」です。いちばん最初に触る人が、いちばん
// 確実に踏みます。
//
// 実測 (2026-08-13): CI がデータベース付きで走って初めて出ました。
// `/ap/stats`・`/ci/stats`・patch の集計が 500 で、いずれもこの形です。
// **この環境には Postgres が無いので、手元では一度も再現できていません。**
// だから、実行ではなく走査で留めます。
//
// GROUP BY のある問い合わせは対象外です。グループが1つも無ければ行自体が
// 返らないので、NULL を読むことがありません（`QueryRow` で読むと ErrNoRows に
// なりますが、それは `ReadOK` が「まだ無い」として通します）。
const nullAggregateViolations = 0

// 走査が届いていることの床。**0件を検査して緑を返すのがいちばん高くつきます。**
const (
	minAggregateFiles   = 200
	minAggregateQueries = 20
)

// 問い合わせの側では守られていないが、読む側が NULL を受けられるもの。
//
// **理由を書けないものは、ここに入れないでください。**
var nullableAggregateReasons = map[string]string{
	"api/handlers/cspm_enhanced_handler.go": "平均スコアを `*float64` に読み、" +
		"nil のときは値を出しません。**「まだ 1 台もスキャンしていない」と" +
		"「平均 0 点」は別で、0 に潰すと未計測が最悪スコアとして表示されます**",
	"detectionmetrics/tracker.go": "MTTR を `*float64` に読み、`if mttrHours != nil` で" +
		"分けています。**「まだ解決したアラートが無い」と「0 時間」は別なので、" +
		"ここは 0 に潰さないのが正しい**",
}

// insideCoalesce は、位置 at が COALESCE(...) の内側かを答えます。
//
// **直前が `COALESCE(` かどうかでは足りません。** 実在の例:
//
//	COALESCE(ROUND(EXTRACT(EPOCH FROM AVG(resolved_at - created_at))/60.0,2),0)
//
// AVG の直前は `FROM ` ですが、外側の COALESCE がちゃんと守っています。
// 開いたままの括弧をたどって、そのどれかが COALESCE なら守られている、
// と見ます。
func insideCoalesce(upper string, at int) bool {
	var stack []bool // 各階層が COALESCE か
	for i := 0; i < at; i++ {
		switch upper[i] {
		case '(':
			before := strings.TrimSpace(upper[:i])
			stack = append(stack, strings.HasSuffix(before, "COALESCE"))
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	for _, isCoalesce := range stack {
		if isCoalesce {
			return true
		}
	}
	return false
}

// aggregateRisk は、その問い合わせが NULL を読み得るかを答えます。
//
// 判定をここに出しているのは、**違反 0 件の木では、下の検査が肯定側の
// 分岐に一度も入らないから**です。合成入力で直接当てます。
func aggregateRisk(query string) []string {
	upper := strings.ToUpper(query)
	if !strings.Contains(upper, "SELECT") {
		return nil
	}
	if strings.Contains(upper, "GROUP BY") {
		return nil
	}
	var bad []string
	for _, fn := range []string{"SUM(", "AVG("} {
		for i := 0; ; {
			j := strings.Index(upper[i:], fn)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(fn)
			if insideCoalesce(upper, at) {
				continue
			}
			bad = append(bad, strings.TrimSuffix(fn, "("))
		}
	}
	return bad
}

// 集計を含む問い合わせがどれだけ見えているか、と、そのうち守られていないもの。
func scanAggregates(root string) (files, queries int, violations []string, err error) {
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return werr
		}
		files++
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **握りつぶすと、その file は走査から消えます。** 中に何が
			// 書いてあっても 0 件になり、走査が届かなくなったことと
			// 「違反が無い」ことが同じ顔をします。この検査を書いた当日に
			// 自分でやっていて、`TestNoScanSwallowsAParseFailure` が
			// 見つけました。
			return fmt.Errorf("%s を読めません: %w", path, perr)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			up := strings.ToUpper(lit.Value)
			if !strings.Contains(up, "SELECT") ||
				(!strings.Contains(up, "SUM(") && !strings.Contains(up, "AVG(")) {
				return true
			}
			queries++
			if _, excused := nullableAggregateReasons[rel]; excused {
				return true
			}
			for _, agg := range aggregateRisk(lit.Value) {
				violations = append(violations,
					fmt.Sprintf("%s:%d %s", rel, fset.Position(lit.Pos()).Line, agg))
			}
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return
}

func TestAggregatesOverAnEmptyTableAnswerZeroNotNull(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("走査の起点を解決できません: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("走査の起点がありません: %v", err)
	}

	// 免除は、対象が実在するときだけ有効です。**file が消えたり動いたり
	// したら、免除は黙って「何も免除していない」ではなく、赤にします。**
	for rel := range nullableAggregateReasons {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("免除に書かれた %s がありません。動いたか消えたなら、"+
				"免除も書き直してください", rel)
		}
	}

	files, queries, violations, err := scanAggregates(root)
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	if files < minAggregateFiles {
		t.Fatalf("走査が届いていません: %d file しか見えません（床 %d）", files, minAggregateFiles)
	}
	if queries < minAggregateQueries {
		t.Fatalf("集計を含む問い合わせが %d 本しか見えません（床 %d）。"+
			"**探し方が壊れると、違反 0 件と同じ顔になります**", queries, minAggregateQueries)
	}
	t.Logf("走査: %d file / 集計を含む問い合わせ %d 本 / 理由つきで外したもの %d",
		files, queries, len(nullableAggregateReasons))

	// **0 が規則です。** 上限にすると、上限を上げる変更が素通りします
	// （実測 0 に対して上限 5 は、上限として見れば真です）。
	if nullAggregateViolations != 0 {
		t.Fatal("規則が 0 でなくなっています。**空のテーブルで 500 になる" +
			"問い合わせを許す、という意味です**")
	}
	if len(violations) != nullAggregateViolations {
		t.Errorf("GROUP BY の無い集計が COALESCE で包まれていません（%d 件）:\n  %s\n"+
			"**まだ何も無い状態でだけ 500 になります。**"+
			"`COALESCE(SUM(…), 0)` で包むか、`*int`/`*float64` で受けて"+
			"理由を書いてください",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// 緑の木では上の判定に届かないので、合成入力で直接見ます。
func TestAggregateRiskJudgement(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"GROUP BY があれば対象外", `SELECT a, SUM(b) FROM t GROUP BY a`, 0},
		{"包まれていない SUM", `SELECT COUNT(*), SUM(x) FROM t`, 1},
		{"包まれた SUM", `SELECT COUNT(*), COALESCE(SUM(x), 0) FROM t`, 0},
		{"AVG も同じ", `SELECT AVG(score) FROM t`, 1},
		{"2つとも包まれていない", `SELECT SUM(a), AVG(b) FROM t`, 2},
		{"片方だけ包まれている", `SELECT COALESCE(SUM(a), 0), SUM(b) FROM t`, 1},
		{"改行を挟んでも包まれている", "SELECT\n\tCOALESCE(\n\t\tSUM(a), 0)\nFROM t", 0},
		{"**外側の COALESCE でも守られている**",
			`SELECT COALESCE(ROUND(EXTRACT(EPOCH FROM AVG(b - a))/60.0,2),0) FROM t`, 0},
		{"**閉じた COALESCE は守らない**",
			`SELECT COALESCE(x, 0), SUM(y) FROM t`, 1},
		{"SELECT でなければ見ない", `UPDATE t SET x = SUM(y)`, 0},
		{"集計が無ければ見ない", `SELECT a FROM t`, 0},
	}
	for _, tc := range cases {
		if got := len(aggregateRisk(tc.query)); got != tc.want {
			t.Errorf("%s: %d 件、want %d（%q）", tc.name, got, tc.want, tc.query)
		}
	}
}
