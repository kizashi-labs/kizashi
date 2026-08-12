package scheduler

import (
	"context"
	"testing"
)

// itoa / fmtScore は strconv を避けるための自前フォーマッタ。コンプライアンス
// スコア表示に使われるため、境界値(0・負数・ゼロ埋め)を明示的に検証する。

func TestItoa(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{5, "5"},
		{42, "42"},
		{1000, "1000"},
		{-1, "-1"},
		{-42, "-42"},
	}
	for _, tc := range cases {
		if got := itoa(tc.in); got != tc.want {
			t.Errorf("itoa(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFmtScore(t *testing.T) {
	// すべて IEEE754 で厳密に表現できる値を使い、浮動小数の丸れによる
	// テストの脆さを避ける。
	cases := []struct {
		in   float64
		want string
	}{
		{0.0, "0.00"},
		{85.0, "85.00"},
		{85.25, "85.25"},
		{2.0625, "2.06"}, // 小数部が 1 桁 (6) のときのゼロ埋め
		{-3.5, "-3.50"},  // 負数
	}
	for _, tc := range cases {
		if got := fmtScore(tc.in); got != tc.want {
			t.Errorf("fmtScore(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── 組織全体スコアの永続化 ───────────────────────────────────
//
// 以前は compliance_scores (agent_id NOT NULL / UNIQUE(agent_id, framework))
// へ agent_id 無しで INSERT しており、mitre / cis / nist / iso27001 の
// 4 フレームワークとも毎回 NOT NULL 制約違反で落ちていた。エラーは
// slog.Error に出るだけでスコアラーは動き続けるため、「計算しているのに
// 画面に出ない」状態が続いていた。
//
// 列を足すだけでは直らない。UNIQUE(agent_id, framework) がある限り同じ
// framework の 2 行目を入れられず、30 日分の履歴を持てないため。
// 用途ごとにテーブルを分けた (migration 367) ことの回帰ガード。

// TestComplianceScorer_PersistsAllFrameworks は 1 回の実行で 4 つの
// フレームワークすべてが履歴テーブルに残ること。
func TestComplianceScorer_PersistsAllFrameworks(t *testing.T) {
	pool := darkwebTestPool(t) // TEST_DATABASE_URL 前提の共有ヘルパ
	ctx := context.Background()

	clean := func() { _, _ = pool.Exec(ctx, `DELETE FROM compliance_score_history`) }
	clean()
	t.Cleanup(clean)

	NewComplianceScorer(pool).calculate(ctx)

	rows, err := pool.Query(ctx,
		`SELECT framework, COUNT(*) FROM compliance_score_history GROUP BY framework`)
	if err != nil {
		t.Fatalf("確認クエリ: %v", err)
	}
	defer rows.Close()

	got := map[string]int{}
	for rows.Next() {
		var fw string
		var n int
		if err := rows.Scan(&fw, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[fw] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	for _, fw := range []string{"mitre", "cis", "nist", "iso27001"} {
		if got[fw] == 0 {
			t.Errorf("%s のスコアが保存されていない (保存済み=%v)", fw, got)
		}
	}
}

// TestComplianceScorer_KeepsHistory は同じ framework を 2 回書けること。
// compliance_scores の UNIQUE(agent_id, framework) では成立しなかった要件で、
// テーブルを分けた理由そのもの。
func TestComplianceScorer_KeepsHistory(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()

	clean := func() { _, _ = pool.Exec(ctx, `DELETE FROM compliance_score_history`) }
	clean()
	t.Cleanup(clean)

	s := NewComplianceScorer(pool)
	s.calculate(ctx)
	s.calculate(ctx)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM compliance_score_history WHERE framework = 'cis'`).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n < 2 {
		t.Errorf("cis の履歴件数 = %d, want 2 以上 (履歴が積めていない)", n)
	}
}

// TestComplianceScorer_MitreScoreCountsTactics は MITRE スコアが
// アラートの mitre_technique からタクティクを数えること。
//
// 以前は存在しない alerts.mitre_tags を unnest しており、クエリが毎回
// 失敗して coveredTactics=0 → MITRE スコアは常に 0 だった。
// 「計算しているのに常に 0」は握りつぶしの典型で、テストが無いと気付けない。
func TestComplianceScorer_MitreScoreCountsTactics(t *testing.T) {
	pool := darkwebTestPool(t)
	ctx := context.Background()

	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM compliance_score_history`)
		_, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE title LIKE 'ITestMitre%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE hostname = 'itest-mitre-host'`)
	}
	clean()
	t.Cleanup(clean)

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, status) VALUES ('itest-mitre-host','linux','online')
		RETURNING id`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	// 別タクティクのテクニックを 2 つ。T1059 = execution、T1486 = impact。
	for i, tech := range []string{"T1059", "T1486"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, severity, status, title, mitre_technique)
			VALUES ($1::uuid, 5, 'open', $2, $3)`,
			agentID, "ITestMitre-"+itoa(i), tech); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}

	NewComplianceScorer(pool).calculate(ctx)

	var score int
	if err := pool.QueryRow(ctx,
		`SELECT score FROM compliance_score_history WHERE framework='mitre'
		 ORDER BY calculated_at DESC LIMIT 1`).Scan(&score); err != nil {
		t.Fatalf("MITREスコア取得: %v", err)
	}
	// 2 タクティク / 14 * 100 = 14 (整数切り捨て)。0 でないことが要点。
	if score == 0 {
		t.Error("MITRE スコアが 0 (タクティクが数えられていない)")
	}
}
