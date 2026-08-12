package scheduler

import "testing"

// normaliseIOCType は各種フィードのIOC種別表記を内部正規形 (ip/domain/url/hash) に
// 変換する。検知マッチングの正しさに直結するため、既知の別名と未知値のフォールバックを検証する。
func TestNormaliseIOCType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ip", "ip"},
		{"ip_address", "ip"},
		{"IP_ADDRESS", "ip"}, // 大文字小文字非依存
		{"domain", "domain"},
		{"hostname", "domain"},
		{"url", "url"},
		{"URL", "url"}, // 大文字小文字非依存(URL 表記)
		{"hash", "hash"},
		{"sha256", "hash"},
		{"hash_sha256", "hash"},
		{"md5", "hash"},
		{"sha1", "hash"},
		{"unknown", "ip"}, // 未知値は plain IP フィード向けに ip へフォールバック
		{"", "ip"},
	}
	for _, tc := range cases {
		if got := normaliseIOCType(tc.in); got != tc.want {
			t.Errorf("normaliseIOCType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// mispTypeToIOCType は MISP の attribute type を内部正規形へ変換する。
// normaliseIOCType と異なり、未知値は空文字 (=対象外) を返す点を検証する。
func TestMISPTypeToIOCType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ip-dst", "ip"},
		{"ip-src", "ip"},
		{"ip-dst|port", "ip"},
		{"domain", "domain"},
		{"hostname", "domain"},
		{"url", "url"},
		{"sha256", "hash"},
		{"md5", "hash"},
		{"sha1", "hash"},
		{"unknown-type", ""}, // 未知値は空文字 (取り込み対象外)
		{"", ""},
		{"IP-DST", ""}, // MISP側は大文字小文字を区別する (完全一致のみ)
	}
	for _, tc := range cases {
		if got := mispTypeToIOCType(tc.in); got != tc.want {
			t.Errorf("mispTypeToIOCType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
