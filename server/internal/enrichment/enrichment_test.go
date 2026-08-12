package enrichment

import (
	"testing"
)

// ─── extractHash ─────────────────────────────────────────────────────────────

func TestExtractHash_SHA256(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := extractHash("file hash: " + sha256 + " detected")
	if got != sha256 {
		t.Errorf("SHA256: got %q, want %q", got, sha256)
	}
}

func TestExtractHash_SHA1(t *testing.T) {
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	got := extractHash("SHA1: " + sha1)
	if got != sha1 {
		t.Errorf("SHA1: got %q, want %q", got, sha1)
	}
}

func TestExtractHash_MD5(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	got := extractHash("MD5=" + md5)
	if got != md5 {
		t.Errorf("MD5: got %q, want %q", got, md5)
	}
}

func TestExtractHash_PrefersLonger(t *testing.T) {
	// SHA256 と MD5 が同時に含まれる場合、SHA256 が優先される
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	got := extractHash(md5 + " " + sha256)
	if got != sha256 {
		t.Errorf("SHA256優先: got %q, want %q", got, sha256)
	}
}

func TestExtractHash_UppercaseNormalized(t *testing.T) {
	sha256upper := "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	got := extractHash(sha256upper)
	if got != extractHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Error("ハッシュは小文字に正規化されるべきです")
	}
}

func TestExtractHash_NoHash_ReturnsEmpty(t *testing.T) {
	got := extractHash("no hash here, just some text")
	if got != "" {
		t.Errorf("ハッシュなし: got %q, want empty", got)
	}
}

func TestExtractHash_Empty_ReturnsEmpty(t *testing.T) {
	got := extractHash("")
	if got != "" {
		t.Errorf("空文字列: got %q, want empty", got)
	}
}

// ─── extractIP ────────────────────────────────────────────────────────────────

func TestExtractIP_PublicIP(t *testing.T) {
	got := extractIP("connected to 8.8.8.8 on port 53")
	if got != "8.8.8.8" {
		t.Errorf("パブリックIP: got %q, want 8.8.8.8", got)
	}
}

func TestExtractIP_SkipsPrivate_10x(t *testing.T) {
	got := extractIP("src: 10.0.0.1 dst: 203.0.113.5")
	if got != "203.0.113.5" {
		t.Errorf("プライベートIPスキップ: got %q, want 203.0.113.5", got)
	}
}

func TestExtractIP_SkipsPrivate_192168(t *testing.T) {
	got := extractIP("192.168.1.100 → 1.1.1.1")
	if got != "1.1.1.1" {
		t.Errorf("192.168スキップ: got %q, want 1.1.1.1", got)
	}
}

func TestExtractIP_SkipsLoopback(t *testing.T) {
	got := extractIP("127.0.0.1 is loopback, public: 93.184.216.34")
	if got != "93.184.216.34" {
		t.Errorf("ループバックスキップ: got %q, want 93.184.216.34", got)
	}
}

func TestExtractIP_NoPublicIP_ReturnsEmpty(t *testing.T) {
	got := extractIP("only private: 192.168.1.1 and 10.0.0.1")
	if got != "" {
		t.Errorf("パブリックIPなし: got %q, want empty", got)
	}
}

func TestExtractIP_NoIP_ReturnsEmpty(t *testing.T) {
	got := extractIP("no ip address found here")
	if got != "" {
		t.Errorf("IPなし: got %q, want empty", got)
	}
}

// ─── sumStats ─────────────────────────────────────────────────────────────────

func TestSumStats_AllFields(t *testing.T) {
	stats := map[string]interface{}{
		"malicious":        float64(3),
		"suspicious":       float64(2),
		"harmless":         float64(40),
		"undetected":       float64(10),
		"failure":          float64(1),
		"type-unsupported": float64(4),
	}
	got := sumStats(stats)
	if got != 60 {
		t.Errorf("sumStats: got %v, want 60", got)
	}
}

func TestSumStats_PartialFields(t *testing.T) {
	stats := map[string]interface{}{
		"malicious": float64(5),
		"harmless":  float64(45),
	}
	got := sumStats(stats)
	if got != 50 {
		t.Errorf("sumStats 部分フィールド: got %v, want 50", got)
	}
}

func TestSumStats_EmptyMap(t *testing.T) {
	got := sumStats(map[string]interface{}{})
	if got != 0 {
		t.Errorf("空マップ: got %v, want 0", got)
	}
}

func TestSumStats_NonFloatValuesIgnored(t *testing.T) {
	stats := map[string]interface{}{
		"malicious": "not-a-float",
		"harmless":  float64(10),
	}
	got := sumStats(stats)
	if got != 10 {
		t.Errorf("非float値は無視されるべきです: got %v, want 10", got)
	}
}
