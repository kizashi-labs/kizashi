package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRegression(t *testing.T) {
	// 5技中: cur=4 technique / base=5 technique → 解析検知率が 100%→80% に低下。
	cur := kpiSummary{N: 5, Vis: 5, Det: 4, Ana: 4}
	base := kpiSummary{N: 5, Vis: 5, Det: 5, Ana: 5}

	// 許容0pt → 低下を回帰として検出。
	if reg, _ := checkRegression(cur, base, 0); !reg {
		t.Error("率低下(検知100→80, 解析100→80)は tol=0 で回帰検出されるべき")
	}
	// 許容25pt → 20pt の低下は許容内 → 回帰なし。
	if reg, _ := checkRegression(cur, base, 25); reg {
		t.Error("20pt 低下は tol=25pt で回帰扱いされないべき")
	}
	// 改善(率上昇)は回帰でない。
	if reg, _ := checkRegression(base, cur, 0); reg {
		t.Error("率上昇は回帰でないべき")
	}
}

func TestLoadBaselineKPI(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scorecard.csv")
	// writeScorecardCSV 形式: rank 列(4=Technique,1=Telemetry)から再構成。
	content := "technique,test_name,rank,rank_name,latency_sec,matched_by,exit_code\n" +
		"T1059.001,ps,4,Technique,0.5,x,0\n" +
		"T1003.001,lsass,4,Technique,1.2,y,0\n" +
		"T1069.001,netlg,1,Telemetry,,,0\n" // 可視のみ(未検知)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	k, err := loadBaselineKPI(p)
	if err != nil {
		t.Fatal(err)
	}
	if k.N != 3 || k.Vis != 3 || k.Det != 2 || k.Ana != 2 {
		t.Errorf("KPI = %+v, want {N:3 Vis:3 Det:2 Ana:2}", k)
	}
	// 率も検証。
	if got := rate(k.Ana, k.N); got < 66.6 || got > 66.7 {
		t.Errorf("解析検知率 = %.2f, want ~66.67", got)
	}
}

func TestLoadBaselineKPI_NoRankColumn(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(p, []byte("technique,test_name\nT1059,ps\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaselineKPI(p); err == nil || !strings.Contains(err.Error(), "rank") {
		t.Fatalf("rank 列欠落を検出すべき: %v", err)
	}
}
