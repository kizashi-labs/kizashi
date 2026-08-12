package dedup

import (
	"strings"
	"testing"
)

// ─── DedupKey ─────────────────────────────────────────────────────────────────

func TestDedupKey_SameInputSameKey(t *testing.T) {
	k1 := DedupKey("Suspicious Login", "high", "syslog", "agent-abc")
	k2 := DedupKey("Suspicious Login", "high", "syslog", "agent-abc")
	if k1 != k2 {
		t.Errorf("同じ入力からは同じキーが生成されるべきです: k1=%q, k2=%q", k1, k2)
	}
}

func TestDedupKey_DifferentTitleDifferentKey(t *testing.T) {
	k1 := DedupKey("Login Failure", "high", "syslog", "agent-1")
	k2 := DedupKey("Malware Detected", "high", "syslog", "agent-1")
	if k1 == k2 {
		t.Error("タイトルが異なる場合、異なるキーが生成されるべきです")
	}
}

func TestDedupKey_DifferentSeverityDifferentKey(t *testing.T) {
	k1 := DedupKey("Alert", "high", "syslog", "agent-1")
	k2 := DedupKey("Alert", "critical", "syslog", "agent-1")
	if k1 == k2 {
		t.Error("重大度が異なる場合、異なるキーが生成されるべきです")
	}
}

func TestDedupKey_DifferentSourceDifferentKey(t *testing.T) {
	k1 := DedupKey("Alert", "high", "syslog", "agent-1")
	k2 := DedupKey("Alert", "high", "edr-agent", "agent-1")
	if k1 == k2 {
		t.Error("ソースが異なる場合、異なるキーが生成されるべきです")
	}
}

func TestDedupKey_DifferentAgentDifferentKey(t *testing.T) {
	k1 := DedupKey("Alert", "high", "syslog", "agent-1")
	k2 := DedupKey("Alert", "high", "syslog", "agent-2")
	if k1 == k2 {
		t.Error("AgentIDが異なる場合、異なるキーが生成されるべきです")
	}
}

func TestDedupKey_CaseInsensitiveTitle(t *testing.T) {
	k1 := DedupKey("Suspicious Login", "high", "syslog", "agent-1")
	k2 := DedupKey("SUSPICIOUS LOGIN", "high", "syslog", "agent-1")
	if k1 != k2 {
		t.Error("タイトルは大文字小文字を区別しないハッシュを生成するべきです")
	}
}

func TestDedupKey_CaseInsensitiveSeverity(t *testing.T) {
	k1 := DedupKey("Alert", "HIGH", "syslog", "agent-1")
	k2 := DedupKey("Alert", "high", "syslog", "agent-1")
	if k1 != k2 {
		t.Error("重大度は大文字小文字を区別しないハッシュを生成するべきです")
	}
}

func TestDedupKey_WhitespaceTrimmed(t *testing.T) {
	k1 := DedupKey("  Alert  ", "high", "syslog", "agent-1")
	k2 := DedupKey("Alert", "high", "syslog", "agent-1")
	if k1 != k2 {
		t.Error("タイトルの前後空白はトリムされてから同じキーを生成するべきです")
	}
}

func TestDedupKey_ReturnsHexString(t *testing.T) {
	key := DedupKey("test", "low", "src", "id")
	// MD5は32文字の16進数文字列
	if len(key) != 32 {
		t.Errorf("DedupKeyは32文字のMD5ハッシュを返すべきです: len=%d, val=%q", len(key), key)
	}
	for _, ch := range key {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Errorf("DedupKeyは16進数文字のみで構成されるべきです: got %q", key)
			break
		}
	}
}

func TestDedupKey_EmptyAgentID(t *testing.T) {
	// 空のAgentIDでもパニックしない
	k1 := DedupKey("Alert", "high", "syslog", "")
	k2 := DedupKey("Alert", "high", "syslog", "")
	if k1 != k2 {
		t.Error("空のAgentIDでも決定論的なキーを返すべきです")
	}
}

// ─── TechniqueDedupKey (cross-engine) ─────────────────────────────────────────

func TestTechniqueDedupKey_SameTechniqueAndAgentSameKey(t *testing.T) {
	k1 := TechniqueDedupKey("T1021.002", "agent-1")
	k2 := TechniqueDedupKey("t1021.002", "agent-1") // case-insensitive technique
	if k1 != k2 {
		t.Errorf("同一technique+agentは同一キーであるべき: %q vs %q", k1, k2)
	}
}

func TestTechniqueDedupKey_DistinguishesTechniqueAndAgent(t *testing.T) {
	base := TechniqueDedupKey("T1003.002", "agent-1")
	if base == TechniqueDedupKey("T1003.001", "agent-1") {
		t.Error("異なるtechniqueは異なるキーであるべき")
	}
	if base == TechniqueDedupKey("T1003.002", "agent-2") {
		t.Error("異なるagentは異なるキーであるべき")
	}
	// Must NOT collide with the title-based DedupKey scheme.
	if base == DedupKey("T1003.002", "", "", "agent-1") {
		t.Error("technique用キーはtitle用キーと衝突してはならない")
	}
}
