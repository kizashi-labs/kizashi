package backup

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// バックアップは「途中まで」を残してはいけません。
//
// 以前 CreateBackup は、テーブルのクエリが落ちると RecordCount[table] = 0 を
// 書いて次のテーブルに進み、rows.Values() が落ちるとその行だけ飛ばして
// 続けていました。どちらも完了として保存されます。マニフェストには
// 「yara_rules: 0件」と残り、あとで見た人にはルールが1本も無かった時点の
// バックアップに見えます。復元すれば、実際にそうなります。
//
// これは DB を要する経路なので、単体では動かせません。ここで留めているのは
// 「読めなかったときに続行しない」という制御の形です。弱い検査であることは
// 承知のうえで、変異が素通りするよりはましだという判断です。

func createBackupBody(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatalf("manager.go を読めません: %v", err)
	}
	at := strings.Index(string(src), "func (m *Manager) CreateBackup(")
	if at < 0 {
		t.Fatal("CreateBackup の定義が見つかりません")
	}
	body := string(src)[at:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	return body
}

// 「読めなかった直後に continue している」箇所を数えます。
// エラー分岐で続行するのは、抜けたまま完了扱いにするのと同じです。
func continuesAfterAnError(body string) int {
	pat := regexp.MustCompile(`(?m)^\s*if err(?: :?= [^;]*)? != nil \{\n(?:[^\n]*\n)*?\s*continue\n`)
	return len(pat.FindAllString(body, -1))
}

func TestABackupDoesNotContinuePastAnUnreadableTable(t *testing.T) {
	body := createBackupBody(t)

	if n := continuesAfterAnError(body); n != 0 {
		t.Errorf("CreateBackup がエラーのあと %d 箇所で続行しています。"+
			"抜けたバックアップは、件数まで整合して見えます", n)
	}
	// 読めなかったときに中止していること。上の検査だけだと、
	// エラー分岐そのものを消した実装でも通ります。
	for _, needle := range []string{
		"バックアップ中止",
		"return nil, nil, fmt.Errorf",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("CreateBackup に %q がありません。"+
				"読めなかったときに中止していない可能性があります", needle)
		}
	}

	// 逆向きの確認。判定が何も見ていないと、上は常に通ります。
	stub := "if err != nil {\n\t\tcontinue\n"
	if continuesAfterAnError(stub) != 1 {
		t.Error("エラーのあとの continue を見つけられていません。判定が効いていません")
	}
}

// 復元は、入らなかった行を黙って落としてはいけません。
//
// upsertJSON は「n件復元しました」とだけ返していました。JSON にできな
// かった行も、INSERT が落ちた行も、n に入らないだけで、どこにも出ません。
// 復元後のデータが元と違うことに、次に困るまで気づけません。
func TestARestoreReportsTheRowsItCouldNotWrite(t *testing.T) {
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatalf("manager.go を読めません: %v", err)
	}
	at := strings.Index(string(src), "func (m *Manager) upsertJSON(")
	if at < 0 {
		t.Fatal("upsertJSON の定義が見つかりません")
	}
	body := string(src)[at:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	for _, needle := range []string{"skipped++", "復元できませんでした"} {
		if !strings.Contains(body, needle) {
			t.Errorf("upsertJSON が %q を持っていません。"+
				"入らなかった行が呼び出し側に伝わりません", needle)
		}
	}
}
