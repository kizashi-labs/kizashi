package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 定点観測 / 回帰ゲート。スプリント毎にスコアカードを保存し、次回測定で
// -baseline に渡すと、可視性率 / 検知率 / 解析検知率が baseline を許容幅(pt)を
// 超えて下回ったときに回帰として非ゼロ終了する。CI で P1 のルール増加・P2 の
// 採点変更による退行を自動検出するための仕組み。

// kpiSummary は回帰比較用の件数ベース集計。
type kpiSummary struct {
	N, Vis, Det, Ana int // 対象数 / 可視(>=Telemetry) / 検知(>=Tactic) / 解析(Technique)
}

// summarize は採点結果から KPI を集計する(printScorecard と同じ閾値)。
func summarize(results []result) kpiSummary {
	s := kpiSummary{N: len(results)}
	for _, r := range results {
		if r.rank >= rankTelemetry {
			s.Vis++
		}
		if r.rank >= rankGeneral {
			s.Det++
		}
		if r.rank >= rankTechnique {
			s.Ana++
		}
	}
	return s
}

func rate(a, n int) float64 {
	if n == 0 {
		return 0
	}
	return 100 * float64(a) / float64(n)
}

// loadBaselineKPI は過去の scorecard.csv(writeScorecardCSV 形式)の rank 列から
// KPI を再構成する。これにより baseline は別途集計を保存せずスコアカードCSVだけで足りる。
func loadBaselineKPI(path string) (kpiSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return kpiSummary{}, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return kpiSummary{}, err
	}
	if len(rows) < 2 {
		return kpiSummary{}, fmt.Errorf("ヘッダ+1行以上が必要です")
	}
	ri := -1
	for i, h := range rows[0] {
		if strings.ToLower(strings.TrimSpace(h)) == "rank" {
			ri = i
			break
		}
	}
	if ri < 0 {
		return kpiSummary{}, fmt.Errorf("rank 列がありません")
	}
	var s kpiSummary
	for _, row := range rows[1:] {
		if ri >= len(row) {
			continue
		}
		rk, err := strconv.Atoi(strings.TrimSpace(row[ri]))
		if err != nil {
			continue
		}
		s.N++
		if rk >= rankTelemetry {
			s.Vis++
		}
		if rk >= rankGeneral {
			s.Det++
		}
		if rk >= rankTechnique {
			s.Ana++
		}
	}
	return s, nil
}

// checkRegression は現在と baseline の率を比較する。いずれかの率が tol(ポイント)を
// 超えて低下していれば regressed=true。report は人間可読のテーブル。
func checkRegression(cur, base kpiSummary, tol float64) (regressed bool, report string) {
	type metric struct {
		name      string
		cur, base float64
	}
	ms := []metric{
		{"可視性率", rate(cur.Vis, cur.N), rate(base.Vis, base.N)},
		{"検知率", rate(cur.Det, cur.N), rate(base.Det, base.N)},
		{"解析検知率", rate(cur.Ana, cur.N), rate(base.Ana, base.N)},
	}
	var b strings.Builder
	fmt.Fprintf(&b, "=== 回帰チェック (baseline比, 許容低下 %.1fpt) ===\n", tol)
	for _, m := range ms {
		delta := m.cur - m.base
		flag := "OK"
		if delta < -tol {
			flag = "▼ 回帰"
			regressed = true
		}
		fmt.Fprintf(&b, "  %-10s %5.1f%% (baseline %5.1f%%, Δ%+.1fpt) %s\n", m.name, m.cur, m.base, delta, flag)
	}
	return regressed, b.String()
}
