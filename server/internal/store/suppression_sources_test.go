package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 抑制ルールの入れ物が **2つのテーブル** に分かれていて、片方は誰も
// 読んでいません。
//
//	suppression_rules         server-detect が読み、**実際にアラートを
//	                          落とします**（storeAdapter.ListActiveSuppressions）
//	alert_suppression_rules   コンソールの「アラート抑制ルール」画面
//	                          (/admin/suppression-rules) が読み書きします。
//	                          **読む側がどこにもありません**
//
// つまり、担当者が画面から抑制ルールを作っても**アラートは落ちません。**
// 画面の `suppressed_count` は 0 のままで、これは「何にも一致しなかった」
// と読めます —— 実際は「一度も参照されていない」です。
//
// **どちらに寄せるかは製品の判断です**（画面をもう一方のテーブルに向ける／
// 適用する側を足す／画面を畳む）。判断待ちの一覧に置いてあります。
// ここでやるのは、**いまの状態を留めること**だけです ——
// 誰かが読む側を足したら、この検査が落ちて、この注記を消す番だと分かります。

var (
	sqlRefRe   = regexp.MustCompile(`(?i)\balert_suppression_rules\b`)
	commentRe  = regexp.MustCompile(`(?m)^\s*(//|--)`)
	skipSuffix = []string{"_test.go"}
)

// 参照が許されている場所。**ここ以外から参照が増えたら落とします。**
var allowedAlertSuppressionRefs = map[string]string{
	"internal/store/suppression_rule_store.go":   "CRUD そのもの",
	"migrations/083_alert_suppression_rules.sql": "テーブル定義",
}

func TestTheConsoleSuppressionTableStillHasNoReader(t *testing.T) {
	root := findServerRoot(t)
	found := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".sql" {
			return nil
		}
		for _, s := range skipSuffix {
			if strings.HasSuffix(path, s) {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			// **注記は数えません。** この検査自身の説明が参照に化けます。
			if commentRe.MatchString(line) {
				continue
			}
			if sqlRefRe.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				found[filepath.ToSlash(rel)] = true
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査に失敗しました: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("alert_suppression_rules への参照が1件も見つかりません。" +
			"**走査が届いていません** —— 0件を検査して緑を返すのが" +
			"いちばん高くつきます")
	}

	for path := range found {
		if _, ok := allowedAlertSuppressionRefs[path]; !ok {
			t.Errorf("alert_suppression_rules を新しく参照しています: %s。"+
				"**読む側ができたのなら、この検査と判断待ちの一覧の注記を"+
				"消してください** —— 古い注記は、読んだ人にまだ壊れていると"+
				"思わせます", path)
		}
	}
	for path, why := range allowedAlertSuppressionRefs {
		if !found[path] {
			t.Errorf("%s (%s) が alert_suppression_rules を参照しなくなりました。"+
				"移したのなら、この一覧を直してください", path, why)
		}
	}
}

// findServerRoot walks up to the directory holding go.mod.
func findServerRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod が見つかりません")
	return ""
}
