package store

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// このファイルは「対応アクションの成否が嘘をつけない」ことを DB 無しで守るためのテスト。
//
// 直した欠陥: Record が success を
//     success := status != "failure"
// で決めていたため、まだ何も起きていない "pending" の行まで success = true として
// 記録されていた。response_actions.success は常に真で、証拠能力が無かった。
//
// migration 379 で success を status_text からの生成列にしたので、アプリから直接
// 書くことはできない。ただし SQL は文字列なので、コンパイラは守ってくれない。
// 以下の 2 つで機械的に固定する。

const migrationsDir = "../../migrations"

// checkVocabulary は migration の CHECK 制約に書かれた status_text の語彙を返す。
func checkVocabulary(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(migrationsDir, "*_response_actions_truthful_status.sql"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("status_text の CHECK を定義した migration が見つかりません: %v", err)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("migration を読めません: %v", err)
	}
	// CHECK (status_text IN ('a', 'b', ...)) から中身を取り出す
	re := regexp.MustCompile(`(?s)CHECK\s*\(status_text IN\s*\((.*?)\)\)`)
	m := re.FindSubmatch(body)
	if m == nil {
		t.Fatalf("%s に status_text の CHECK 制約が見つかりません", matches[0])
	}
	var out []string
	for _, lit := range regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(string(m[1]), -1) {
		out = append(out, lit[1])
	}
	sort.Strings(out)
	return out
}

// TestStatusVocabularyMatchesMigration は Go 側の定数と DB の CHECK 制約が
// 食い違わないことを確かめる。
//
// 片方だけに状態を足すと、実行時に 23514 で INSERT が静かに拒否される。
// このリポジトリでは events_event_type_check で同じ壊れ方を 3 回繰り返している
// （DB は拒否するのに検知は鳴るので「保存されていない」ことに気づけない）。
func TestStatusVocabularyMatchesMigration(t *testing.T) {
	inGo := []string{
		StatusPending, StatusDispatched, StatusRunning, StatusSuccess,
		StatusFailure, StatusTimeout, StatusWarning, StatusCancelled,
	}
	sort.Strings(inGo)

	inSQL := checkVocabulary(t)

	if strings.Join(inGo, ",") != strings.Join(inSQL, ",") {
		t.Errorf("状態の語彙が食い違っています。\n  Go : %v\n  SQL: %v\n"+
			"どちらか一方にだけ状態を足すと、実行時に CHECK 違反で静かに記録が落ちます。",
			inGo, inSQL)
	}
}

// TestApplicationNeverWritesSuccessColumn は、アプリが success 列に書き込もうと
// していないことを確かめる。
//
// success は生成列なので、書こうとすれば実行時にエラーになる。だが SQL は文字列
// なのでコンパイル時には分からず、その経路が実際に叩かれるまで露見しない。
// 対応の記録は「叩かれるまで沈黙する」典型なので、静的に止める。
func TestApplicationNeverWritesSuccessColumn(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("ソースを列挙できません: %v", err)
	}
	if len(files) < 10 {
		t.Fatalf("走査できたのが %d ファイルだけです。パスが壊れており、"+
			"このテストは何も検査せずに通ってしまいます", len(files))
	}

	// INSERT INTO response_actions (...) の列リスト、または
	// UPDATE response_actions SET ... の代入部を取り出す
	insertRe := regexp.MustCompile(`(?s)INSERT INTO response_actions\s*\(([^)]*)\)`)
	updateRe := regexp.MustCompile(`(?s)UPDATE response_actions\s+SET\s+(.*?)WHERE`)

	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(body)
		for _, m := range insertRe.FindAllStringSubmatch(src, -1) {
			checked++
			for _, col := range strings.Split(m[1], ",") {
				if strings.TrimSpace(col) == "success" {
					t.Errorf("%s: INSERT が success 列に書き込んでいます。"+
						"success は status_text から導出される生成列です (migration 379)。"+
						"status_text に正しい状態を書いてください。", f)
				}
			}
		}
		for _, m := range updateRe.FindAllStringSubmatch(src, -1) {
			checked++
			if regexp.MustCompile(`\bsuccess\s*=`).MatchString(m[1]) {
				t.Errorf("%s: UPDATE が success 列を書き換えています。"+
					"status_text を更新してください。", f)
			}
		}
	}

	if checked == 0 {
		t.Fatal("response_actions への書き込みが 1 つも見つかりませんでした。" +
			"正規表現が実装と合っておらず、このテストは無意味に通っています")
	}
}
