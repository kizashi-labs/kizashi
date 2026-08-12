package netanalysis

import (
	"testing"
)

// ─── deriveFlags ──────────────────────────────────────────────────────────────

func TestDeriveFlags_CommonPort_NoUnusualPortFlag(t *testing.T) {
	// ポート 443 は commonPorts に含まれる
	flags := deriveFlags(443, 10)
	for _, f := range flags {
		if f == "unusual_port" {
			t.Error("commonPort 443 に unusual_port フラグは付かないはずです")
		}
	}
}

func TestDeriveFlags_Port80_NoUnusualPortFlag(t *testing.T) {
	flags := deriveFlags(80, 10)
	for _, f := range flags {
		if f == "unusual_port" {
			t.Error("commonPort 80 に unusual_port フラグは付かないはずです")
		}
	}
}

func TestDeriveFlags_UncommonHighPort_HasUnusualPortFlag(t *testing.T) {
	// ポート 12345 は commonPorts にない高ポート
	flags := deriveFlags(12345, 10)
	found := false
	for _, f := range flags {
		if f == "unusual_port" {
			found = true
		}
	}
	if !found {
		t.Error("未知の高ポートには unusual_port フラグが付くはずです")
	}
}

func TestDeriveFlags_Port1024OrBelow_NoUnusualPortFlag(t *testing.T) {
	// ポート 1024 は条件 port > 1024 を満たさない
	flags := deriveFlags(1024, 10)
	for _, f := range flags {
		if f == "unusual_port" {
			t.Error("ポート 1024 に unusual_port フラグは付かないはずです")
		}
	}
}

func TestDeriveFlags_HighPacketCount_HasHighFrequencyFlag(t *testing.T) {
	// 501 パケット > 500 のしきい値
	flags := deriveFlags(443, 501)
	found := false
	for _, f := range flags {
		if f == "high_frequency" {
			found = true
		}
	}
	if !found {
		t.Error("501 パケットには high_frequency フラグが付くはずです")
	}
}

func TestDeriveFlags_ExactlyAt500Packets_NoHighFrequency(t *testing.T) {
	// 500 パケット = しきい値境界 (> 500 なので含まない)
	flags := deriveFlags(443, 500)
	for _, f := range flags {
		if f == "high_frequency" {
			t.Error("ちょうど500パケットには high_frequency フラグは付かないはずです")
		}
	}
}

func TestDeriveFlags_BothConditions_HasBothFlags(t *testing.T) {
	// 高ポート + 大量パケット → 2つのフラグ
	flags := deriveFlags(9999, 1000)
	flagSet := map[string]bool{}
	for _, f := range flags {
		flagSet[f] = true
	}
	if !flagSet["unusual_port"] {
		t.Error("高ポート+大量パケット: unusual_port フラグが付くはずです")
	}
	if !flagSet["high_frequency"] {
		t.Error("高ポート+大量パケット: high_frequency フラグが付くはずです")
	}
}

func TestDeriveFlags_NormalConditions_NoFlags(t *testing.T) {
	// commonPort + 少ないパケット → フラグなし
	flags := deriveFlags(443, 5)
	if len(flags) != 0 {
		t.Errorf("通常の接続にフラグは付かないはずです: %v", flags)
	}
}

// ─── calculateThreatScore ─────────────────────────────────────────────────────

func TestCalculateThreatScore_NoFlags_ReturnsZero(t *testing.T) {
	score := calculateThreatScore([]string{})
	if score != 0 {
		t.Errorf("フラグなし: score got %d, want 0", score)
	}
}

func TestCalculateThreatScore_TorExit_Returns40(t *testing.T) {
	score := calculateThreatScore([]string{"tor_exit"})
	if score != 40 {
		t.Errorf("tor_exit: score got %d, want 40", score)
	}
}

func TestCalculateThreatScore_KnownC2_Returns50(t *testing.T) {
	score := calculateThreatScore([]string{"known_c2"})
	if score != 50 {
		t.Errorf("known_c2: score got %d, want 50", score)
	}
}

func TestCalculateThreatScore_UnusualPort_Returns20(t *testing.T) {
	score := calculateThreatScore([]string{"unusual_port"})
	if score != 20 {
		t.Errorf("unusual_port: score got %d, want 20", score)
	}
}

func TestCalculateThreatScore_HighFrequency_Returns15(t *testing.T) {
	score := calculateThreatScore([]string{"high_frequency"})
	if score != 15 {
		t.Errorf("high_frequency: score got %d, want 15", score)
	}
}

func TestCalculateThreatScore_AllFlags_CappedAt100(t *testing.T) {
	// tor_exit(40) + known_c2(50) + unusual_port(20) + high_frequency(15) = 125 → 100
	score := calculateThreatScore([]string{"tor_exit", "known_c2", "unusual_port", "high_frequency"})
	if score != 100 {
		t.Errorf("全フラグ: score got %d, want 100 (capped)", score)
	}
}

func TestCalculateThreatScore_TorAndC2_Returns90(t *testing.T) {
	// tor_exit(40) + known_c2(50) = 90
	score := calculateThreatScore([]string{"tor_exit", "known_c2"})
	if score != 90 {
		t.Errorf("tor_exit+known_c2: score got %d, want 90", score)
	}
}

func TestCalculateThreatScore_UnknownFlag_IgnoredNoChange(t *testing.T) {
	// 未知フラグはスコアに影響しない
	score := calculateThreatScore([]string{"unknown_flag"})
	if score != 0 {
		t.Errorf("未知フラグ: score got %d, want 0", score)
	}
}

func TestCalculateThreatScore_CombinedUnusualAndFrequency_Returns35(t *testing.T) {
	// unusual_port(20) + high_frequency(15) = 35
	score := calculateThreatScore([]string{"unusual_port", "high_frequency"})
	if score != 35 {
		t.Errorf("unusual_port+high_frequency: score got %d, want 35", score)
	}
}

// ─── portRiskLevel ────────────────────────────────────────────────────────────

func TestPortRiskLevel_CommonPort_ReturnsLow(t *testing.T) {
	level := portRiskLevel(443, true, 1000)
	if level != "low" {
		t.Errorf("commonPort 443: level got %q, want low", level)
	}
}

func TestPortRiskLevel_UncommonHighPortHighCount_ReturnsHigh(t *testing.T) {
	// port > 1024 && count > 200 → high
	level := portRiskLevel(8888, false, 201)
	if level != "high" {
		t.Errorf("未知高ポート+大量接続: level got %q, want high", level)
	}
}

func TestPortRiskLevel_UncommonHighPortLowCount_ReturnsMedium(t *testing.T) {
	// port > 1024, count <= 200 → medium
	level := portRiskLevel(8888, false, 100)
	if level != "medium" {
		t.Errorf("未知高ポート+少数接続: level got %q, want medium", level)
	}
}

func TestPortRiskLevel_UncommonLowPort_ReturnsLow(t *testing.T) {
	// port <= 1024 で not common → low
	level := portRiskLevel(900, false, 500)
	if level != "low" {
		t.Errorf("低ポート(not common): level got %q, want low", level)
	}
}

func TestPortRiskLevel_ExactlyAt200Count_ReturnsMedium(t *testing.T) {
	// count = 200 は > 200 を満たさない → medium
	level := portRiskLevel(9000, false, 200)
	if level != "medium" {
		t.Errorf("count=200(境界値): level got %q, want medium", level)
	}
}

func TestPortRiskLevel_CommonPortIgnoresHighCount(t *testing.T) {
	// isCommon=true なら count に関わらず low
	level := portRiskLevel(80, true, 9999)
	if level != "low" {
		t.Errorf("commonPort+高count: level got %q, want low", level)
	}
}

// ─── commonPorts ──────────────────────────────────────────────────────────────

func TestCommonPorts_Contains443(t *testing.T) {
	if !commonPorts[443] {
		t.Error("commonPorts に 443 が含まれていません")
	}
}

func TestCommonPorts_Contains80(t *testing.T) {
	if !commonPorts[80] {
		t.Error("commonPorts に 80 が含まれていません")
	}
}

func TestCommonPorts_Contains53(t *testing.T) {
	if !commonPorts[53] {
		t.Error("commonPorts に 53 (DNS) が含まれていません")
	}
}

func TestCommonPorts_DoesNotContain12345(t *testing.T) {
	if commonPorts[12345] {
		t.Error("commonPorts に 12345 は含まれないはずです")
	}
}
