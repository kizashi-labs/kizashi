package suppression

// 抑制ルールの DB 往復。
//
// LoadFromDB は「テーブルがまだ無いかもしれない」という理由でクエリ失敗を
// Debug ログに落として nil を返す。列名が違っていても起動は成功し、
// 抑制ルールが 0 件のまま静かに動き続ける — 実際にそうなっていた
// (duration_seconds が存在せず、読み込みも保存も全滅していた)。
//
// ここでは実 DB に書いて読み戻し、往復が成立することを確かめる。列名がずれたら
// 「0 件」ではなくテスト失敗として出る。

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed suppression tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cleanupRules は本テストが作ったルールだけを消す。
func cleanupRules(t *testing.T, pool *pgxpool.Pool, namePrefix string) {
	t.Helper()
	del := func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM suppression_rules WHERE name LIKE $1`, namePrefix+"%")
	}
	del()
	t.Cleanup(del)
}

// TestAddRule_ThenLoadFromDB は保存 → 読み込みの往復が成立すること。
// 列名がずれていると AddRule がエラーを返すか、LoadFromDB が 0 件になる。
func TestAddRule_ThenLoadFromDB(t *testing.T) {
	pool := testPool(t)
	cleanupRules(t, pool, "ITestSup")

	e := NewEngine(pool)
	rule := &SuppressionRule{
		Name:        "ITestSup-roundtrip",
		Description: "往復テスト",
		Enabled:     true,
		Duration:    90 * time.Minute,
		Conditions:  []Condition{{Field: "rule_name", Operator: "eq", Value: "benign-scanner"}},
	}
	if err := e.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if rule.ID == "" {
		t.Fatal("AddRule が ID を返していない")
	}

	// 別のエンジンで読み直す (メモリ上のキャッシュではなく DB を見る)。
	fresh := NewEngine(pool)
	if err := fresh.LoadFromDB(context.Background()); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	var got *SuppressionRule
	for _, r := range fresh.rules {
		if r.Name == rule.Name {
			got = r
			break
		}
	}
	if got == nil {
		t.Fatalf("保存したルールが読み戻せない (読み込み件数 %d)", len(fresh.rules))
	}
	if got.Duration != 90*time.Minute {
		t.Errorf("Duration = %v, want 90m (秒精度が保持されていない)", got.Duration)
	}
	if got.Description != rule.Description {
		t.Errorf("Description = %q, want %q", got.Description, rule.Description)
	}
	if !got.Enabled {
		t.Error("Enabled が false で読み戻された")
	}
}

// TestUpdateRule_PersistsDuration は更新が DB に反映されること。
func TestUpdateRule_PersistsDuration(t *testing.T) {
	pool := testPool(t)
	cleanupRules(t, pool, "ITestSup")

	e := NewEngine(pool)
	rule := &SuppressionRule{
		Name:       "ITestSup-update",
		Enabled:    true,
		Duration:   time.Hour,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "x"}},
	}
	if err := e.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	updated := &SuppressionRule{
		Name:       rule.Name,
		Enabled:    true,
		Duration:   30 * time.Minute,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "y"}},
	}
	if err := e.UpdateRule(rule.ID, updated); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	var secs int
	if err := pool.QueryRow(context.Background(),
		`SELECT duration_seconds FROM suppression_rules WHERE id = $1`, rule.ID).Scan(&secs); err != nil {
		t.Fatalf("確認クエリ: %v", err)
	}
	if secs != 1800 {
		t.Errorf("duration_seconds = %d, want 1800", secs)
	}
}

// TestLoadFromDB_SkipsDisabledRules は無効なルールを読み込まないこと。
// 無効化したはずのルールが効き続けると、アラートが理由不明に消える。
func TestLoadFromDB_SkipsDisabledRules(t *testing.T) {
	pool := testPool(t)
	cleanupRules(t, pool, "ITestSup")

	e := NewEngine(pool)
	off := &SuppressionRule{
		Name:       "ITestSup-disabled",
		Enabled:    false,
		Duration:   time.Hour,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "z"}},
	}
	if err := e.AddRule(off); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	fresh := NewEngine(pool)
	if err := fresh.LoadFromDB(context.Background()); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
	for _, r := range fresh.rules {
		if r.Name == off.Name {
			t.Error("無効なルールが読み込まれている")
		}
	}
}
