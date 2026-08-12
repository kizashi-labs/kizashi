package virustotal

import (
	"testing"
)

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_NilWhenNoAPIKey(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	c := New()
	if c != nil {
		t.Error("API キーなしの場合 nil を返すべき")
	}
}

func TestNew_NonNilWithAPIKey(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "testapikey1234567890")
	c := New()
	if c == nil {
		t.Fatal("API キーありの場合 nil でないべき")
	}
}

func TestNew_HTTPClientTimeout(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "testapikey")
	c := New()
	if c == nil {
		t.Fatal("non-nil expected")
	}
	if c.httpClient == nil {
		t.Error("httpClient が初期化されているべき")
	}
	if c.httpClient.Timeout == 0 {
		t.Error("httpClient のタイムアウトが設定されているべき")
	}
}

// ─── FileReport 構造体の基本確認 ─────────────────────────────────────────────

func TestFileReport_VerdictValues(t *testing.T) {
	// FileReport の Verdict フィールドが期待する値を受け入れること
	validVerdicts := []string{"malicious", "suspicious", "undetected", "unknown"}
	for _, v := range validVerdicts {
		r := FileReport{Verdict: v}
		if r.Verdict != v {
			t.Errorf("Verdict = %q, want %q", r.Verdict, v)
		}
	}
}

func TestFileReport_ScoreRange(t *testing.T) {
	// Score は 0〜100 の範囲
	r := FileReport{Score: 75, DetectionCount: 30, TotalEngines: 72}
	if r.Score < 0 || r.Score > 100 {
		t.Errorf("Score = %d, 範囲外 (0-100)", r.Score)
	}
}

func TestFileReport_EmptySignatures(t *testing.T) {
	r := FileReport{}
	if r.Signatures != nil {
		t.Error("未初期化 Signatures は nil のはず")
	}
}

// ─── NetworkIndicator 構造体確認 ──────────────────────────────────────────────

func TestNetworkIndicator_Types(t *testing.T) {
	validTypes := []string{"ip", "domain", "url"}
	for _, typ := range validTypes {
		ni := NetworkIndicator{Type: typ, Value: "192.168.1.1"}
		if ni.Type != typ {
			t.Errorf("Type = %q, want %q", ni.Type, typ)
		}
	}
}
