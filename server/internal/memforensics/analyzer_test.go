package memforensics

import (
	"context"
	"testing"
)

// ─── NewAnalyzer ──────────────────────────────────────────────────────────────

func TestNewAnalyzer_NotNil(t *testing.T) {
	a := NewAnalyzer(nil)
	if a == nil {
		t.Fatal("NewAnalyzer は nil を返すべきではありません")
	}
}

func TestNewAnalyzer_PoolStored(t *testing.T) {
	a := NewAnalyzer(nil)
	if a.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── DetectInjection (pool=nil) ──────────────────────────────────────────────

func TestDetectInjection_NilPool_ReturnsEmptySlice(t *testing.T) {
	a := NewAnalyzer(nil)
	artifacts, err := a.DetectInjection(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectInjection (pool=nil): 予期しないエラー: %v", err)
	}
	if artifacts == nil {
		t.Fatal("DetectInjection: nil ではなく空スライスを返すべきです")
	}
	if len(artifacts) != 0 {
		t.Errorf("DetectInjection (pool=nil): got %d artifacts, want 0", len(artifacts))
	}
}

func TestDetectInjection_NilPool_NoError(t *testing.T) {
	a := NewAnalyzer(nil)
	_, err := a.DetectInjection(context.Background(), 1)
	if err != nil {
		t.Errorf("DetectInjection (pool=nil): エラーなしのはずが: %v", err)
	}
}

// ─── DetectReflectiveLoad (pool=nil) ─────────────────────────────────────────

func TestDetectReflectiveLoad_NilPool_ReturnsEmptySlice(t *testing.T) {
	a := NewAnalyzer(nil)
	artifacts, err := a.DetectReflectiveLoad(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectReflectiveLoad (pool=nil): 予期しないエラー: %v", err)
	}
	if artifacts == nil {
		t.Fatal("DetectReflectiveLoad: nil ではなく空スライスを返すべきです")
	}
	if len(artifacts) != 0 {
		t.Errorf("DetectReflectiveLoad (pool=nil): got %d artifacts, want 0", len(artifacts))
	}
}

func TestDetectReflectiveLoad_NilPool_NoError(t *testing.T) {
	a := NewAnalyzer(nil)
	_, err := a.DetectReflectiveLoad(context.Background(), 48)
	if err != nil {
		t.Errorf("DetectReflectiveLoad (pool=nil): エラーなしのはずが: %v", err)
	}
}

// ─── GetArtifacts (pool=nil) ──────────────────────────────────────────────────

func TestGetArtifacts_NilPool_ReturnsEmptySlice(t *testing.T) {
	a := NewAnalyzer(nil)
	artifacts, err := a.GetArtifacts(context.Background(), "", 24)
	if err != nil {
		t.Fatalf("GetArtifacts (pool=nil): 予期しないエラー: %v", err)
	}
	if artifacts == nil {
		t.Fatal("GetArtifacts: nil ではなく空スライスを返すべきです")
	}
	if len(artifacts) != 0 {
		t.Errorf("GetArtifacts (pool=nil): got %d artifacts, want 0", len(artifacts))
	}
}

func TestGetArtifacts_NilPool_WithAgentID(t *testing.T) {
	a := NewAnalyzer(nil)
	artifacts, err := a.GetArtifacts(context.Background(), "agent-001", 24)
	if err != nil {
		t.Fatalf("GetArtifacts (agentID指定, pool=nil): 予期しないエラー: %v", err)
	}
	if len(artifacts) != 0 {
		t.Errorf("GetArtifacts (pool=nil): got %d artifacts, want 0", len(artifacts))
	}
}

// ─── GetStats (pool=nil) ──────────────────────────────────────────────────────

func TestGetStats_NilPool_ReturnsStats(t *testing.T) {
	a := NewAnalyzer(nil)
	stats := a.GetStats(context.Background())
	// pool=nil 時は早期リターンするので ByType は初期化済み
	if stats.ByType == nil {
		t.Error("GetStats (pool=nil): ByType は初期化されているべきです")
	}
}

func TestGetStats_NilPool_TotalArtifactsZero(t *testing.T) {
	a := NewAnalyzer(nil)
	stats := a.GetStats(context.Background())
	if stats.TotalArtifacts != 0 {
		t.Errorf("GetStats (pool=nil): TotalArtifacts got %d, want 0", stats.TotalArtifacts)
	}
}

func TestGetStats_NilPool_HighRiskCountZero(t *testing.T) {
	a := NewAnalyzer(nil)
	stats := a.GetStats(context.Background())
	if stats.HighRiskCount != 0 {
		t.Errorf("GetStats (pool=nil): HighRiskCount got %d, want 0", stats.HighRiskCount)
	}
}

func TestGetStats_NilPool_LastDetectedNil(t *testing.T) {
	a := NewAnalyzer(nil)
	stats := a.GetStats(context.Background())
	if stats.LastDetected != nil {
		t.Error("GetStats (pool=nil): LastDetected は nil であるべきです")
	}
}

// ─── MemoryArtifact 構造体フィールド ──────────────────────────────────────────

func TestMemoryArtifact_Fields(t *testing.T) {
	art := &MemoryArtifact{
		ID:           "art-1",
		AgentID:      "agent-001",
		ArtifactType: "injected_dll",
		Confidence:   0.75,
		RiskScore:    75,
		MITRETech:    "T1055.001",
	}
	if art.ID != "art-1" {
		t.Errorf("ID: got %q, want art-1", art.ID)
	}
	if art.Confidence != 0.75 {
		t.Errorf("Confidence: got %f, want 0.75", art.Confidence)
	}
	if art.RiskScore != 75 {
		t.Errorf("RiskScore: got %d, want 75", art.RiskScore)
	}
	if art.MITRETech != "T1055.001" {
		t.Errorf("MITRETech: got %q, want T1055.001", art.MITRETech)
	}
}

// ─── MemForensicsStats 構造体フィールド ───────────────────────────────────────

func TestMemForensicsStats_ByTypeMap(t *testing.T) {
	stats := MemForensicsStats{
		ByType: map[string]int{
			"injected_dll":    3,
			"reflective_load": 2,
		},
		TotalArtifacts: 5,
		HighRiskCount:  2,
	}
	if stats.ByType["injected_dll"] != 3 {
		t.Errorf("ByType[injected_dll]: got %d, want 3", stats.ByType["injected_dll"])
	}
	if stats.ByType["reflective_load"] != 2 {
		t.Errorf("ByType[reflective_load]: got %d, want 2", stats.ByType["reflective_load"])
	}
	if stats.TotalArtifacts != 5 {
		t.Errorf("TotalArtifacts: got %d, want 5", stats.TotalArtifacts)
	}
}
