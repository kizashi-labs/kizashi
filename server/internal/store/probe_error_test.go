package store_test

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

// **存在確認の error を捨てないこと。**
//
// `SELECT EXISTS (… information_schema …)` を `_ =` で受けると、
// **「確認できなかった」が「無い」になります。** DB が一時的に応答しない
// だけで、機能ごと読み飛ばされます —— しかもログは「テーブルがありません」
// です。`TableIsThere`/`ProbeAnswer` はそのために在ります（確認できなければ
// 「在る」と答え、続くクエリが本当の error を返します）。
//
// 実測 (2026-08-12): `server/internal` に残っていた 3 か所:
//
//	scheduler/api_key_rotator.go   expires_at 列 —— **期限切れ間近の
//	                               API キーの通知が丸ごと飛びます**
//	scheduler/compliance_scorer.go audit_logs —— **ISO 27001 のスコアが
//	                               20 点低いまま履歴に書かれます**
//	                               （監査ログは在るのに「A.12.4 未達」）
//	api/handlers/iot_ot_handler.go protocol 列 —— 縮小版のクエリに落ち、
//	                               機器の protocol / network_zone が
//	                               既定値で画面に並びます
//
// どれも「テーブル／列が無いときは静かに読み飛ばす」という正しい意図の
// 隣にありました。**読み飛ばしてよいのは、無いと確かめられたときだけです。**

const probeRoot = ".."

// 実測 (2026-08-12): `information_schema`／`pg_tables` を含む代入は 23。
// 床は、走査が届いていることの確認です。
const minProbeQueries = 15

func TestNoExistenceProbeThrowsAwayItsError(t *testing.T) {
	fset := token.NewFileSet()
	var bad []string
	probes := 0

	err := filepath.WalkDir(probeRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, probeRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, rel, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			sql := stringLiteralsIn(as)
			if !looksLikeExistenceProbe(sql) {
				return true
			}
			probes++
			if !discardsTheAnswer(as) {
				return true
			}
			bad = append(bad, rel+":"+itoaLine(fset, as.Pos()))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if probes < minProbeQueries {
		t.Fatalf("走査が届いていません: 存在確認らしいクエリが %d 個しか"+
			"見えません（床 %d）", probes, minProbeQueries)
	}
	t.Logf("存在確認らしい代入: %d 個", probes)

	sort.Strings(bad)
	for _, where := range bad {
		t.Errorf("%s が、存在確認の error を捨てています。"+
			"**「確認できなかった」が「無い」になります** —— "+
			"DB が応答しないだけで機能ごと読み飛ばされ、ログには"+
			"「テーブル／列がありません」と出ます。"+
			"`store.TableIsThere` / `store.ProbeAnswer` を使うか、"+
			"error を受けて報告してください", where)
	}
}

// discardsTheAnswer — `_ = …` で受けているか。
func discardsTheAnswer(as *ast.AssignStmt) bool {
	if len(as.Lhs) != 1 {
		return false
	}
	id, ok := as.Lhs[0].(*ast.Ident)
	return ok && id.Name == "_"
}

// looksLikeExistenceProbe — そのクエリがテーブル／列の存在確認か。
func looksLikeExistenceProbe(sql string) bool {
	low := strings.ToLower(sql)
	return strings.Contains(low, "information_schema") || strings.Contains(low, "pg_tables")
}

func stringLiteralsIn(n ast.Node) string {
	var b strings.Builder
	ast.Inspect(n, func(m ast.Node) bool {
		if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			b.WriteString(lit.Value)
		}
		return true
	})
	return b.String()
}

func itoaLine(fset *token.FileSet, pos token.Pos) string {
	return strconv.Itoa(fset.Position(pos).Line)
}

// 判定が効くこと。**違反する見本を食わせて確かめます** —— いま違反は 0 件
// なので、判定を潰しても挙がる件数は変わりません。
func TestTheProbeErrorJudgementRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.AssignStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out *ast.AssignStmt
		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && out == nil {
				out = as
			}
			return true
		})
		if out == nil {
			t.Fatal("代入が見つかりません")
		}
		return out
	}

	discarded := parse("_ = p.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns)`).Scan(&x)")
	kept := parse("err := p.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns)`).Scan(&x)")
	other := parse("_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&x)")

	if !looksLikeExistenceProbe(stringLiteralsIn(discarded)) {
		t.Error("**存在確認のクエリを見つけられません。** " +
			"見落とすと、捨てている箇所が走査から外れます")
	}
	if looksLikeExistenceProbe(stringLiteralsIn(other)) {
		t.Error("**存在確認でないクエリを数えています。** " +
			"普通の集計まで違反になります")
	}
	if !discardsTheAnswer(discarded) {
		t.Error("**`_ =` で捨てているのを見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if discardsTheAnswer(kept) {
		t.Error("**error を受け取っているものを違反にしています。**")
	}
}

// 床の判定が効くこと。
func TestTheProbeScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if minProbeQueries < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}
