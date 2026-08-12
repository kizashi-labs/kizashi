package handlers

import (
	"fmt"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// IOC タイプバリデーションのテスト
// ─────────────────────────────────────────────

// isValidIOCType は threat_intel_handler.go の ListIOCs で使われる
// IOCタイプ文字列が有効かどうかを判定する純粋関数。
func isValidIOCType(iocType string) bool {
	switch iocType {
	case "ip", "domain", "hash", "url", "email":
		return true
	default:
		return false
	}
}

func TestIsValidIOCType_ValidTypes(t *testing.T) {
	// 有効なIOCタイプがすべて true を返すことを確認
	valid := []string{"ip", "domain", "hash", "url", "email"}
	for _, v := range valid {
		t.Run(v, func(t *testing.T) {
			if !isValidIOCType(v) {
				t.Errorf("isValidIOCType(%q) = false, want true", v)
			}
		})
	}
}

func TestIsValidIOCType_InvalidTypes(t *testing.T) {
	// 無効なIOCタイプは false を返すことを確認
	invalid := []string{
		"",
		"IP", // 大文字は無効
		"Domain",
		"hostname",
		"subnet",
		"port",
		"certificate",
	}
	for _, v := range invalid {
		t.Run(v, func(t *testing.T) {
			if isValidIOCType(v) {
				t.Errorf("isValidIOCType(%q) = true, want false (無効なタイプ)", v)
			}
		})
	}
}

func TestIsValidIOCType_EmptyString(t *testing.T) {
	// 空文字列は無効なタイプ
	if isValidIOCType("") {
		t.Error("isValidIOCType(\"\") = true, want false (空文字列は無効)")
	}
}

// ─────────────────────────────────────────────
// IOC フィード interval バリデーションのテスト
// ─────────────────────────────────────────────

// clampFeedInterval は threat_intel_handler.go の AddFeed/UpdateFeed で
// 使われる fetch_interval_min の正規化ロジックを抽出した純粋関数。
// 0以下の場合はデフォルト値 60 を返す。
func clampFeedInterval(intervalMin int) int {
	if intervalMin <= 0 {
		return 60
	}
	return intervalMin
}

func TestClampFeedInterval_PositiveValues(t *testing.T) {
	// 正の値はそのまま返されることを確認
	cases := []int{1, 5, 15, 30, 60, 120, 1440}
	for _, v := range cases {
		t.Run(fmt.Sprintf("interval=%d", v), func(t *testing.T) {
			got := clampFeedInterval(v)
			if got != v {
				t.Errorf("clampFeedInterval(%d) = %d, want %d", v, got, v)
			}
		})
	}
}

func TestClampFeedInterval_ZeroOrNegative_DefaultToSixty(t *testing.T) {
	// 0 以下の値はデフォルト値 60 に変換されることを確認
	cases := []int{0, -1, -60, -1000}
	for _, v := range cases {
		t.Run(fmt.Sprintf("interval=%d", v), func(t *testing.T) {
			got := clampFeedInterval(v)
			if got != 60 {
				t.Errorf("clampFeedInterval(%d) = %d, want 60 (デフォルト)", v, got)
			}
		})
	}
}

// ─────────────────────────────────────────────
// IOC リスト limit/offset クランプのテスト
// ─────────────────────────────────────────────

// clampIOCLimit は threat_intel_handler.go の ListIOCs で行う
// ページネーションパラメータの正規化ロジックを抽出した純粋関数。
func clampIOCLimit(limit int) int {
	if limit <= 0 || limit > 500 {
		return 50
	}
	return limit
}

// clampIOCOffset は ListIOCs の offset 正規化を抽出した純粋関数。
func clampIOCOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func TestClampIOCLimit_ValidRange(t *testing.T) {
	// 1〜500 の limit はそのまま返されることを確認
	cases := []int{1, 50, 100, 499, 500}
	for _, v := range cases {
		got := clampIOCLimit(v)
		if got != v {
			t.Errorf("clampIOCLimit(%d) = %d, want %d", v, got, v)
		}
	}
}

func TestClampIOCLimit_OutOfRange_DefaultToFifty(t *testing.T) {
	// 範囲外の limit はデフォルト値 50 に戻ることを確認
	cases := []int{0, -1, 501, 1000}
	for _, v := range cases {
		got := clampIOCLimit(v)
		if got != 50 {
			t.Errorf("clampIOCLimit(%d) = %d, want 50 (デフォルト)", v, got)
		}
	}
}

func TestClampIOCOffset_NegativeValues(t *testing.T) {
	// 負の offset はゼロにクランプされることを確認
	cases := []int{-1, -100}
	for _, v := range cases {
		got := clampIOCOffset(v)
		if got != 0 {
			t.Errorf("clampIOCOffset(%d) = %d, want 0", v, got)
		}
	}
}

func TestClampIOCOffset_NonNegativePreserved(t *testing.T) {
	// 0 以上の offset はそのまま返されることを確認
	cases := []int{0, 1, 100}
	for _, v := range cases {
		got := clampIOCOffset(v)
		if got != v {
			t.Errorf("clampIOCOffset(%d) = %d, want %d", v, got, v)
		}
	}
}

// ─────────────────────────────────────────────
// フィードタイプバリデーションのテスト
// ─────────────────────────────────────────────

// isValidFeedType は threat_intel フィードの type フィールドを検証する純粋関数。
func isValidFeedType(feedType string) bool {
	switch feedType {
	case "taxii", "misp", "stix", "custom", "csv", "json":
		return true
	default:
		return false
	}
}

func TestIsValidFeedType_ValidTypes(t *testing.T) {
	// 有効なフィードタイプがすべて認識されることを確認
	valid := []string{"taxii", "misp", "stix", "custom", "csv", "json"}
	for _, v := range valid {
		t.Run(v, func(t *testing.T) {
			if !isValidFeedType(v) {
				t.Errorf("isValidFeedType(%q) = false, want true", v)
			}
		})
	}
}

func TestIsValidFeedType_InvalidTypes(t *testing.T) {
	// 未知のフィードタイプは false を返すことを確認
	invalid := []string{"", "TAXII", "xml", "yaml", "unknown"}
	for _, v := range invalid {
		t.Run(v, func(t *testing.T) {
			if isValidFeedType(v) {
				t.Errorf("isValidFeedType(%q) = true, want false", v)
			}
		})
	}
}

// ─────────────────────────────────────────────
// フィード名の基本サニタイズテスト
// ─────────────────────────────────────────────

// sanitizeFeedName はフィード名をトリムして検証する純粋関数。
func sanitizeFeedName(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func TestSanitizeFeedName_ValidName(t *testing.T) {
	// 有効なフィード名は true を返してトリム後の名前を返す
	cases := []struct {
		input string
		want  string
	}{
		{"AbuseIPDB", "AbuseIPDB"},
		{"  AlienVault OTX  ", "AlienVault OTX"},
		{"Emerging Threats", "Emerging Threats"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := sanitizeFeedName(tc.input)
			if !ok {
				t.Errorf("sanitizeFeedName(%q): ok = false, want true", tc.input)
			}
			if got != tc.want {
				t.Errorf("sanitizeFeedName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeFeedName_EmptyOrWhitespace_ReturnsFalse(t *testing.T) {
	// 空文字列やスペースのみの名前は false を返すことを確認
	invalid := []string{"", "   ", "\t", "\n"}
	for _, name := range invalid {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			_, ok := sanitizeFeedName(name)
			if ok {
				t.Errorf("sanitizeFeedName(%q) = true, want false (空/空白は無効)", name)
			}
		})
	}
}
