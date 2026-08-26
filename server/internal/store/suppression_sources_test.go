package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 抑制ルールの入れ物が **2つのテーブル** に分かれていて、片方は誰も
// 読んでいませんでした。
//
//	suppression_rules         server-detect と AlertPipeline が読み、**実際に
//	                          アラートを落とします**
//	alert_suppression_rules   コンソールの「アラート抑制ルール」画面
//	                          (/admin/suppression-rules) が読み書きしていました。
//	                          **読む側がどこにもありませんでした**
//
// つまり、担当者が画面から抑制ルールを作っても**アラートは落ちませんでした。**
// 画面の `suppressed_count` は 0 のままで、これは「何にも一致しなかった」
// と読めます —— 実際は「一度も参照されていない」でした。
//
// **2026-08-18、画面ごと撤去して実働の1本に寄せました**（migration 456。**本流では 450 でしたが、公開版との収束で振り直しました**）。
// 行は `suppression_rules` へ**無効な状態で**移送してあります（移送した瞬間に
// 効き始めると、今まで一度も適用されていなかったルールが本当にアラートを
// 消し始めるため）。表そのものは、移送結果を実環境で確認する材料として
// 残してあります。
//
// この検査が留めるのは**撤去後の状態**です。`alert_suppression_rules` に
// 触ってよいのは表の定義と移送の 2 つの migration だけで、**Go から触るものは
// 1つもありません**。書き手が生えれば、行けるが読まれない場所へまた書き始めます。
var (
	sqlRefRe  = regexp.MustCompile(`(?i)\balert_suppression_rules\b`)
	commentRe = regexp.MustCompile(`(?m)^\s*(//|--)`)
	// COMMENT ON TABLE の本文に表名が出るのは参照ではなく説明文なので、
	// 行頭注記と同じ扱いで数えない…とはしない。**数えた上で許可一覧に
	// 載せる**。除外の条件を増やすほど、走査は静かに何も見なくなる。
	skipSuffix = []string{"_test.go"}
)

// 参照が許されている場所。**ここ以外から参照が増えたら落とします。**
var allowedAlertSuppressionRefs = map[string]string{
	"migrations/083_alert_suppression_rules.sql": "表の定義（廃止済み・DROP はしていない）",
	"migrations/456_suppression_single_path.sql": "実働の表への移送",
}

func TestTheRetiredSuppressionTableHasNoReaderAndNoWriter(t *testing.T) {
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
			t.Errorf("廃止した alert_suppression_rules を参照しています: %s。"+
				"**この表に書いたものは誰も読みません** —— 抑制は "+
				"suppression_rules (conditions は object 形式) に書いてください。"+
				"表を復活させる判断をしたのなら、この検査の注記を直す番です", path)
		}
		if strings.HasSuffix(path, ".go") {
			t.Errorf("Go から廃止した表を参照しています: %s。"+
				"**保存はできて、検知は一度も見ません** —— "+
				"画面から作った抑制が効かない状態がまた始まります", path)
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
