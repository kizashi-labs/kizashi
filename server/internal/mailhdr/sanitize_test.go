package mailhdr

import "testing"

// TestSanitize_StripsHeaderInjection は注入の実パターンを落とすこと。
func TestSanitize_StripsHeaderInjection(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"CRLF で Bcc を追加", "Acme\r\nBcc: attacker@example.com", "AcmeBcc: attacker@example.com"},
		{"LF のみ", "Acme\nBcc: attacker@example.com", "AcmeBcc: attacker@example.com"},
		{"CR のみ", "Acme\rBcc: attacker@example.com", "AcmeBcc: attacker@example.com"},
		{"NUL", "Acme\x00evil", "Acmeevil"},
		{"折り返し (obs-fold) も許さない", "long\r\n subject", "long subject"},
		{"本文まで注入", "S\r\n\r\n<script>alert(1)</script>", "S<script>alert(1)</script>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSanitize_LeavesCleanValuesUntouched は正常な値を変えないこと。
// ここで内容が変わると、日本語の件名や記号を含む組織名が壊れる。
func TestSanitize_LeavesCleanValuesUntouched(t *testing.T) {
	for _, s := range []string{
		"",
		"admin@example.com",
		"[EDR Platform] 緊急 アラート: powershell.exe",
		"株式会社サンプル",
		"a@b.com, c@d.com",
		"タブ\tは許す", // ヘッダ値として合法
	} {
		if got := Sanitize(s); got != s {
			t.Errorf("Sanitize(%q) = %q, 変更されている", s, got)
		}
	}
}

// TestSanitizeAll は複数値をまとめて処理すること。
func TestSanitizeAll(t *testing.T) {
	got := SanitizeAll([]string{"a@x.com", "b@x.com\r\nBcc: e@x.com"})
	if len(got) != 2 {
		t.Fatalf("件数 = %d, want 2", len(got))
	}
	if got[0] != "a@x.com" {
		t.Errorf("got[0] = %q", got[0])
	}
	if got[1] != "b@x.comBcc: e@x.com" {
		t.Errorf("got[1] = %q (CRLF が残っている)", got[1])
	}
}

// TestSanitizeAll_NilIsEmpty は nil でも落ちないこと。
func TestSanitizeAll_NilIsEmpty(t *testing.T) {
	if got := SanitizeAll(nil); len(got) != 0 {
		t.Errorf("SanitizeAll(nil) = %v, want 空", got)
	}
}
