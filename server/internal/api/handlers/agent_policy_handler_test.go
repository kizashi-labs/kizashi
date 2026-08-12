package handlers

import (
	"reflect"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// validatePolicy のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidatePolicy_Valid(t *testing.T) {
	// 全フィールドが有効な場合、エラーなし
	req := policyRequest{
		Name:            "テストポリシー",
		ScanIntervalMin: 60,
		FullScanHour:    3,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "info",
	}
	if got := validatePolicy(&req); got != "" {
		t.Errorf("有効なリクエストでエラーが返りました: %q", got)
	}
}

func TestValidatePolicy_EmptyName(t *testing.T) {
	// name が空のとき必須エラーが返る
	req := policyRequest{
		Name:            "",
		ScanIntervalMin: 60,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "info",
	}
	want := "name は必須です"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_WhitespaceName(t *testing.T) {
	// name がスペースのみの場合も必須エラー
	req := policyRequest{
		Name:            "   \t  ",
		ScanIntervalMin: 60,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "info",
	}
	want := "name は必須です"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_ScanIntervalTooLow(t *testing.T) {
	// scan_interval_min が 5 未満のときエラー
	req := policyRequest{
		Name:            "Policy",
		ScanIntervalMin: 4,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "info",
	}
	want := "scan_interval_min は 5〜1440 の範囲で指定してください"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_ScanIntervalTooHigh(t *testing.T) {
	// scan_interval_min が 1440 超過のときエラー
	req := policyRequest{
		Name:            "Policy",
		ScanIntervalMin: 1441,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "info",
	}
	want := "scan_interval_min は 5〜1440 の範囲で指定してください"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_FullScanHourOutOfRange(t *testing.T) {
	// full_scan_hour が 0〜23 範囲外のときエラー
	tests := []struct {
		name string
		hour int
	}{
		{"負の時刻", -1},
		{"24時", 24},
		{"100時", 100},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{
				Name:            "Policy",
				ScanIntervalMin: 60,
				FullScanHour:    tc.hour,
				CPULimitPct:     20,
				MemLimitMB:      256,
				LogLevel:        "info",
			}
			want := "full_scan_hour は 0〜23 の範囲で指定してください"
			if got := validatePolicy(&req); got != want {
				t.Errorf("full_scan_hour=%d: validatePolicy() = %q, want %q", tc.hour, got, want)
			}
		})
	}
}

func TestValidatePolicy_CPULimitOutOfRange(t *testing.T) {
	// cpu_limit_pct が 5〜80 範囲外のときエラー
	tests := []struct {
		name string
		pct  int
	}{
		{"4パーセント(下限未満)", 4},
		{"81パーセント(上限超過)", 81},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{
				Name:            "Policy",
				ScanIntervalMin: 60,
				FullScanHour:    0,
				CPULimitPct:     tc.pct,
				MemLimitMB:      256,
				LogLevel:        "info",
			}
			want := "cpu_limit_pct は 5〜80 の範囲で指定してください"
			if got := validatePolicy(&req); got != want {
				t.Errorf("cpu_limit_pct=%d: validatePolicy() = %q, want %q", tc.pct, got, want)
			}
		})
	}
}

func TestValidatePolicy_MemLimitTooLow(t *testing.T) {
	// mem_limit_mb が 64 未満のときエラー
	req := policyRequest{
		Name:            "Policy",
		ScanIntervalMin: 60,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      63,
		LogLevel:        "info",
	}
	want := "mem_limit_mb は 64 以上を指定してください"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_InvalidLogLevel(t *testing.T) {
	// 無効な log_level のときエラー
	req := policyRequest{
		Name:            "Policy",
		ScanIntervalMin: 60,
		FullScanHour:    0,
		CPULimitPct:     20,
		MemLimitMB:      256,
		LogLevel:        "verbose",
	}
	want := "log_level は debug/info/warn/error のいずれかを指定してください"
	if got := validatePolicy(&req); got != want {
		t.Errorf("validatePolicy() = %q, want %q", got, want)
	}
}

func TestValidatePolicy_ValidLogLevels(t *testing.T) {
	// debug/info/warn/error はすべて有効
	for _, level := range []string{"debug", "info", "warn", "error"} {
		req := policyRequest{
			Name:            "Policy",
			ScanIntervalMin: 60,
			FullScanHour:    0,
			CPULimitPct:     20,
			MemLimitMB:      256,
			LogLevel:        level,
		}
		if got := validatePolicy(&req); got != "" {
			t.Errorf("log_level=%q: validatePolicy() = %q, want empty", level, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// applyDefaults のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyDefaults_ZeroValues(t *testing.T) {
	// ゼロ値のリクエストにデフォルト値が補完されることを確認
	req := policyRequest{}
	applyDefaults(&req)

	if req.ScanIntervalMin != 60 {
		t.Errorf("ScanIntervalMin デフォルト = %d, want 60", req.ScanIntervalMin)
	}
	if req.CPULimitPct != 20 {
		t.Errorf("CPULimitPct デフォルト = %d, want 20", req.CPULimitPct)
	}
	if req.MemLimitMB != 256 {
		t.Errorf("MemLimitMB デフォルト = %d, want 256", req.MemLimitMB)
	}
	if req.LogLevel != "info" {
		t.Errorf("LogLevel デフォルト = %q, want %q", req.LogLevel, "info")
	}
	if len(req.MonitoredExtensions) == 0 {
		t.Error("MonitoredExtensions デフォルトが空です")
	}
	if req.ExcludedPaths == nil {
		t.Error("ExcludedPaths デフォルトが nil です")
	}
}

func TestApplyDefaults_NonZeroPreserved(t *testing.T) {
	// 既に値が設定されている場合は上書きしない
	req := policyRequest{
		ScanIntervalMin:     120,
		CPULimitPct:         30,
		MemLimitMB:          512,
		LogLevel:            "warn",
		MonitoredExtensions: []string{".go"},
	}
	applyDefaults(&req)

	if req.ScanIntervalMin != 120 {
		t.Errorf("ScanIntervalMin が上書きされました: got %d, want 120", req.ScanIntervalMin)
	}
	if req.CPULimitPct != 30 {
		t.Errorf("CPULimitPct が上書きされました: got %d, want 30", req.CPULimitPct)
	}
	if req.MemLimitMB != 512 {
		t.Errorf("MemLimitMB が上書きされました: got %d, want 512", req.MemLimitMB)
	}
	if req.LogLevel != "warn" {
		t.Errorf("LogLevel が上書きされました: got %q, want %q", req.LogLevel, "warn")
	}
	if !reflect.DeepEqual(req.MonitoredExtensions, []string{".go"}) {
		t.Errorf("MonitoredExtensions が上書きされました: got %v", req.MonitoredExtensions)
	}
}

func TestApplyDefaults_DefaultMonitoredExtensions(t *testing.T) {
	// デフォルトの拡張子リストに必須エントリが含まれることを確認
	req := policyRequest{}
	applyDefaults(&req)

	requiredExts := []string{".exe", ".dll", ".sh", ".ps1", ".py"}
	for _, ext := range requiredExts {
		found := false
		for _, e := range req.MonitoredExtensions {
			if e == ext {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("デフォルト MonitoredExtensions に %q が含まれていません", ext)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// buildEnabledModules のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildEnabledModules_NoneEnabled(t *testing.T) {
	// どちらのモジュールも無効の場合、空スライスが返る
	p := &store.AgentPolicy{MonitorNetwork: false, MonitorDNS: false}
	got := buildEnabledModules(p)
	if len(got) != 0 {
		t.Errorf("モジュールなし: got %v, want []", got)
	}
}

func TestBuildEnabledModules_NetworkOnly(t *testing.T) {
	// network のみ有効
	p := &store.AgentPolicy{MonitorNetwork: true, MonitorDNS: false}
	got := buildEnabledModules(p)
	if len(got) != 1 || got[0] != "network" {
		t.Errorf("network のみ: got %v, want [network]", got)
	}
}

func TestBuildEnabledModules_DNSOnly(t *testing.T) {
	// dns のみ有効
	p := &store.AgentPolicy{MonitorNetwork: false, MonitorDNS: true}
	got := buildEnabledModules(p)
	if len(got) != 1 || got[0] != "dns" {
		t.Errorf("dns のみ: got %v, want [dns]", got)
	}
}

func TestBuildEnabledModules_BothEnabled(t *testing.T) {
	// 両モジュールが有効の場合、両方含まれる
	p := &store.AgentPolicy{MonitorNetwork: true, MonitorDNS: true}
	got := buildEnabledModules(p)
	if len(got) != 2 {
		t.Fatalf("両モジュール有効: got %v (len=%d), want 2 entries", got, len(got))
	}
	hasNetwork, hasDNS := false, false
	for _, m := range got {
		if m == "network" {
			hasNetwork = true
		}
		if m == "dns" {
			hasDNS = true
		}
	}
	if !hasNetwork {
		t.Error("モジュールリストに 'network' が含まれていません")
	}
	if !hasDNS {
		t.Error("モジュールリストに 'dns' が含まれていません")
	}
}
