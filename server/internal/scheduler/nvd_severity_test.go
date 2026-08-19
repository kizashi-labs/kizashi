package scheduler

import "testing"

// NVD の深刻度を製品の区分に寄せる judgement。
//
// **`internal/api/handlers` の検査ファイルにあった CVSS の帯の表を
// ここへ置き換えたものです。** 向こうの表は製品のどこにも無い規則で、
// 表を作った本人が表を確かめていました。こちらは本物を呼びます。
func TestNormalizeNVDSeverityKeepsTheThreeItKnows(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium"} {
		if got := normalizeNVDSeverity(sev); got != sev {
			t.Errorf("normalizeNVDSeverity(%q) = %q, そのまま残るはずです", sev, got)
		}
	}
}

// **`low` が消えないこと。** 落とすと、その脆弱性が一覧から丸ごと
// 抜けます。寄せ先は medium です。
func TestNormalizeNVDSeverityFoldsLowIntoMedium(t *testing.T) {
	if got := normalizeNVDSeverity("low"); got != "medium" {
		t.Errorf("normalizeNVDSeverity(\"low\") = %q, want medium", got)
	}
}

// **知らない語も消えないこと。** NVD が新しい区分を返してきたとき、
// 空文字を返すと `severity` の CHECK 制約に弾かれ、その CVE は
// 1件も保存されません —— 「脆弱性なし」と同じ姿になります。
func TestNormalizeNVDSeverityNeverReturnsSomethingTheSchemaRejects(t *testing.T) {
	allowed := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	for _, sev := range []string{"", "low", "none", "informational", "SEVERE", "critical "} {
		got := normalizeNVDSeverity(sev)
		if !allowed[got] {
			t.Errorf("normalizeNVDSeverity(%q) = %q —— vulnerabilities.severity の"+
				"CHECK 制約が受け付けない値です。その CVE は保存されません", sev, got)
		}
	}
}

// **すべてを medium に倒す実装では通らないこと。**
// 上の3本だけだと「常に medium を返す」で緑になります。
func TestNormalizeNVDSeverityDoesNotFlattenEverything(t *testing.T) {
	if normalizeNVDSeverity("critical") == normalizeNVDSeverity("low") {
		t.Error("critical と low が同じ区分になっています。**深刻度の差が消えます**")
	}
}
