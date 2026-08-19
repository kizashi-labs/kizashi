package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// 脆弱性ステータスのデフォルト値テスト
// ─────────────────────────────────────────────

// vulnDefaultStatus は vulnerabilities_handler.go の Create ハンドラー内にある
// ステータスのデフォルト補完ロジックを純粋関数として抽出して検証する。
func vulnDefaultStatus(status string) string {
	if status == "" {
		return "open"
	}
	return status
}

func TestVulnDefaultStatus_EmptyBecomesOpen(t *testing.T) {
	// 空文字列のステータスは "open" にデフォルト補完されることを確認
	got := vulnDefaultStatus("")
	want := "open"
	if got != want {
		t.Errorf("vulnDefaultStatus(\"\") = %q, want %q", got, want)
	}
}

func TestVulnDefaultStatus_NonEmptyPreserved(t *testing.T) {
	// 空でないステータスはそのまま保持されることを確認
	statuses := []string{"open", "closed", "in_progress", "accepted_risk", "false_positive"}
	for _, s := range statuses {
		t.Run(s, func(t *testing.T) {
			got := vulnDefaultStatus(s)
			if got != s {
				t.Errorf("vulnDefaultStatus(%q) = %q, want %q", s, got, s)
			}
		})
	}
}

// ─────────────────────────────────────────────
// 脆弱性 severity バリデーションのテスト
// ─────────────────────────────────────────────

// isValidVulnSeverity は vulnerabilities_handler.go の Create に実装されている
// severity バリデーションロジックを関数として抽出したもの。
func isValidVulnSeverity(sev string) bool {
	validSev := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	return validSev[sev]
}

func TestIsValidVulnSeverity_ValidValues(t *testing.T) {
	// critical/high/medium/low はすべて有効なseverity
	valid := []string{"critical", "high", "medium", "low"}
	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			if !isValidVulnSeverity(s) {
				t.Errorf("isValidVulnSeverity(%q) = false, want true", s)
			}
		})
	}
}

func TestIsValidVulnSeverity_InvalidValues(t *testing.T) {
	// 有効でないseverity値はすべて false を返すことを確認
	invalid := []string{
		"",
		"extreme",
		"CRITICAL", // 大文字は無効
		"High",     // 先頭大文字は無効
		"info",
		"unknown",
		"none",
		"0",
		"1",
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			if isValidVulnSeverity(s) {
				t.Errorf("isValidVulnSeverity(%q) = true, want false (無効な値)", s)
			}
		})
	}
}

func TestIsValidVulnSeverity_CaseSensitive(t *testing.T) {
	// バリデーションは大文字小文字を区別することを確認
	if isValidVulnSeverity("CRITICAL") {
		t.Error("isValidVulnSeverity(\"CRITICAL\") = true, 大文字は無効のはず")
	}
	if isValidVulnSeverity("Critical") {
		t.Error("isValidVulnSeverity(\"Critical\") = true, 先頭大文字は無効のはず")
	}
	if !isValidVulnSeverity("critical") {
		t.Error("isValidVulnSeverity(\"critical\") = false, 小文字は有効のはず")
	}
}

// ─────────────────────────────────────────────
// CVE-ID フォーマットのバリデーションテスト
// ─────────────────────────────────────────────

// isValidCVEIDFormat は CVE-ID の基本フォーマット (CVE-YYYY-NNNNN) を検証する
// 純粋な補助関数。handlers パッケージの慣習に合わせ、ここで定義する。
func isValidCVEIDFormat(cveID string) bool {
	if len(cveID) < 9 {
		return false
	}
	if !strings.HasPrefix(cveID, "CVE-") {
		return false
	}
	rest := cveID[4:] // "YYYY-NNNNN" の部分
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 {
		return false
	}
	year, seq := parts[0], parts[1]
	if len(year) != 4 || len(seq) < 4 {
		return false
	}
	for _, ch := range year {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	for _, ch := range seq {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func TestIsValidCVEIDFormat_ValidIDs(t *testing.T) {
	// 正しい形式のCVE-IDは有効と判定されることを確認
	valid := []string{
		"CVE-2021-44228", // Log4Shell
		"CVE-2023-0001",
		"CVE-2024-12345",
		"CVE-1999-0001",
	}
	for _, id := range valid {
		t.Run(id, func(t *testing.T) {
			if !isValidCVEIDFormat(id) {
				t.Errorf("isValidCVEIDFormat(%q) = false, want true", id)
			}
		})
	}
}

func TestIsValidCVEIDFormat_InvalidIDs(t *testing.T) {
	// 不正な形式のCVE-IDは無効と判定されることを確認
	invalid := []string{
		"",
		"cve-2021-1234", // 小文字
		"CVE-21-1234",   // 年が2桁
		"CVE-2021-12",   // シーケンス番号が短すぎ
		"CVE2021-1234",  // ハイフンなし
		"CVE-ABCD-1234", // 年が数字でない
		"CVE-2021-ABCD", // シーケンスが数字でない
		"MS-2021-1234",  // プレフィックス不正
	}
	for _, id := range invalid {
		t.Run(id, func(t *testing.T) {
			if isValidCVEIDFormat(id) {
				t.Errorf("isValidCVEIDFormat(%q) = true, want false (不正な形式)", id)
			}
		})
	}
}

// ─────────────────────────────────────────────
// CVSSスコアの範囲チェックテスト
// ─────────────────────────────────────────────

// isValidCVSSScore は CVSS スコア (0.0 ～ 10.0) の範囲を検証する。
func isValidCVSSScore(score float64) bool {
	return score >= 0.0 && score <= 10.0
}

func TestIsValidCVSSScore_ValidRange(t *testing.T) {
	// 0.0〜10.0 の値はすべて有効
	valid := []float64{0.0, 1.0, 5.0, 7.5, 9.8, 10.0}
	for _, score := range valid {
		if !isValidCVSSScore(score) {
			t.Errorf("isValidCVSSScore(%v) = false, want true", score)
		}
	}
}

func TestIsValidCVSSScore_InvalidRange(t *testing.T) {
	// 0.0 未満や 10.0 超の値は無効
	invalid := []float64{-0.1, -1.0, 10.1, 11.0, 100.0}
	for _, score := range invalid {
		if isValidCVSSScore(score) {
			t.Errorf("isValidCVSSScore(%v) = true, want false (範囲外)", score)
		}
	}
}

func TestIsValidCVSSScore_BoundaryValues(t *testing.T) {
	// 境界値 0.0 と 10.0 が有効であることを確認
	if !isValidCVSSScore(0.0) {
		t.Error("isValidCVSSScore(0.0) = false, 下限値は有効のはず")
	}
	if !isValidCVSSScore(10.0) {
		t.Error("isValidCVSSScore(10.0) = false, 上限値は有効のはず")
	}
}

// severity と CVSS の対応付けについて。
//
// **ここには「critical は 9.0〜10.0、high は 7.0〜8.9 …」という表が
// 置いてあり、その表を自分で作って自分で確かめていました。**
// 製品にはその対応付けがありません —— `internal/scheduler` の
// 脆弱性取り込みは NVD が返す `baseSeverity` の文字列をそのまま使い、
// CVSS の点数から区分を導きません。**製品が持っていない規則を、
// 検査だけが持っていました。**
//
// 実在する規則は「NVD の語をこの製品の区分に寄せる」方です。
// `normalizeNVDSeverity` に切り出して、`internal/scheduler` の検査が
// そちらを試します。ここには繋ぐ先がないので置きません。
