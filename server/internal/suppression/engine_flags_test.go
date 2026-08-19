package suppression

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Engine が書く旗と、実際に適用される側が読む旗が別でした。
//
//	enabled     Engine の AddRule / UpdateRule が書き、LoadFromDB が読みます
//	is_active   コンソールの抑制ルール画面が書き、**server-detect が読みます**
//
// どちらも既定は TRUE です。**Engine で無効なルールを作っても、
// is_active は TRUE のまま残り、検知エンジンはそれを適用します。**
// 抑制されたアラートは送られません —— 担当者から見ると、攻撃されて
// いない端末とまったく同じです。
//
// ここでは Engine 側の2つを留めます: 書くときに両方揃えること、
// 読むときに両方見ること。

func engineTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB suppression tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func flagsOf(t *testing.T, pool *pgxpool.Pool, id string) (enabled, isActive bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		"SELECT enabled, is_active FROM suppression_rules WHERE id = $1", id).
		Scan(&enabled, &isActive)
	if err != nil {
		t.Fatalf("旗を読めません: %v", err)
	}
	return
}

func dropRule(t *testing.T, pool *pgxpool.Pool, name string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM suppression_rules WHERE name = $1", name)
	})
}

// 無効なルールを作ったら、両方の旗が落ちていること。
func TestAddRuleWritesBothFlags(t *testing.T) {
	pool := engineTestPool(t)
	const name = "engflags-add-disabled"
	dropRule(t, pool, name)

	e := NewEngine(pool)
	r := &SuppressionRule{Name: name, Enabled: false,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "probe"}}}
	if err := e.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	enabled, isActive := flagsOf(t, pool, r.ID)
	if enabled || isActive {
		t.Errorf("無効として作ったのに enabled=%v is_active=%v。"+
			"**書かなかった側は既定の TRUE のまま残り、検知エンジンは"+
			"それを適用します**", enabled, isActive)
	}
}

// 更新で無効にしたら、両方の旗が落ちていること。
func TestUpdateRuleWritesBothFlags(t *testing.T) {
	pool := engineTestPool(t)
	const name = "engflags-update-disable"
	dropRule(t, pool, name)

	e := NewEngine(pool)
	r := &SuppressionRule{Name: name, Enabled: true,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "probe"}}}
	if err := e.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if enabled, isActive := flagsOf(t, pool, r.ID); !enabled || !isActive {
		t.Fatalf("有効として作ったのに enabled=%v is_active=%v", enabled, isActive)
	}

	off := &SuppressionRule{Name: name, Enabled: false,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "probe"}}}
	if err := e.UpdateRule(r.ID, off); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	enabled, isActive := flagsOf(t, pool, r.ID)
	if enabled || isActive {
		t.Errorf("無効に更新したのに enabled=%v is_active=%v。"+
			"**画面では止まっていて、アラートは落とされ続けます**",
			enabled, isActive)
	}
}

// 読み込みが、両方の旗を見ていること。
//
// もう片方だけを落としたルールが、読み込まれないこと。
func TestLoadFromDBHonoursBothFlags(t *testing.T) {
	pool := engineTestPool(t)
	ctx := context.Background()
	const name = "engflags-load-isactive-off"
	dropRule(t, pool, name)

	e := NewEngine(pool)
	r := &SuppressionRule{Name: name, Enabled: true,
		Conditions: []Condition{{Field: "rule_name", Operator: "eq", Value: "probe"}}}
	if err := e.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	loaded := func() bool {
		fresh := NewEngine(pool)
		if err := fresh.LoadFromDB(ctx); err != nil {
			t.Fatalf("LoadFromDB: %v", err)
		}
		for _, x := range fresh.GetRules() {
			if x.ID == r.ID {
				return true
			}
		}
		return false
	}

	if !loaded() {
		t.Fatal("有効なルールが読み込まれていません")
	}

	// **コンソール側だけで無効にします。** Engine の enabled は TRUE のまま。
	if _, err := pool.Exec(ctx,
		"UPDATE suppression_rules SET is_active = FALSE WHERE id = $1", r.ID); err != nil {
		t.Fatal(err)
	}
	if loaded() {
		t.Error("is_active を落としたルールがまだ読み込まれます。" +
			"**画面で止めたルールを、Engine は有効として数え続けます**")
	}
}
