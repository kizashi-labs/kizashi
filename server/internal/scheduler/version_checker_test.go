package scheduler

// エージェントバージョン分布の集計。
//
// check() はクエリ失敗を握って return するだけなので、列名がずれていても
// 起動も動作も成功したように見える。実際 agents に version という列は無く
// (正しくは agent_version)、分布は一度も出ていなかった。
//
// ここでは実 DB に agents を仕込んで、分布が system_metadata に書かれる
// ところまで通す。列名がずれたら「何も起きない」ではなくテスト失敗になる。

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedAgent は集計対象のエージェントを 1 台入れる。
func seedAgent(t *testing.T, pool *pgxpool.Pool, hostname, version, status string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (hostname, agent_version, status, os_type)
		VALUES ($1, $2, $3, 'linux')`, hostname, version, status); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
}

func cleanupAgents(t *testing.T, pool *pgxpool.Pool, prefix string) {
	t.Helper()
	del := func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM agents WHERE hostname LIKE $1`, prefix+"%")
	}
	del()
	t.Cleanup(del)
}

// TestVersionChecker_CountsOnlineAgentsByVersion は online のエージェントを
// バージョン別に数え、system_metadata に保存すること。
func TestVersionChecker_CountsOnlineAgentsByVersion(t *testing.T) {
	pool := darkwebTestPool(t) // TEST_DATABASE_URL 前提の共有ヘルパ
	cleanupAgents(t, pool, "itest-ver-")

	ctx := context.Background()
	_, _ = pool.Exec(ctx,
		`DELETE FROM system_metadata WHERE key = 'agent_version_distribution'`)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM system_metadata WHERE key = 'agent_version_distribution'`)
	})

	// バージョン文字列はこのテスト固有にする。agents は他テストと共有で、
	// 汎用的な値 ("1.0.0" など) を使うと残留行と衝突して落ちる。
	seedAgent(t, pool, "itest-ver-a", "0.0.1-itest-new", "online")
	seedAgent(t, pool, "itest-ver-b", "0.0.1-itest-new", "online")
	seedAgent(t, pool, "itest-ver-c", "0.0.1-itest-old", "online")
	// offline は集計対象外。ここを数えると「更新が必要な台数」が水増しされる。
	seedAgent(t, pool, "itest-ver-d", "0.0.1-itest-off", "offline")

	NewVersionChecker(pool).check(ctx)

	var raw string
	if err := pool.QueryRow(ctx,
		`SELECT value FROM system_metadata WHERE key = 'agent_version_distribution'`,
	).Scan(&raw); err != nil {
		t.Fatalf("分布が保存されていない: %v", err)
	}

	var dist map[string]int
	if err := json.Unmarshal([]byte(raw), &dist); err != nil {
		t.Fatalf("保存された値が JSON でない (%q): %v", raw, err)
	}

	if dist["0.0.1-itest-new"] != 2 {
		t.Errorf("新バージョンの台数 = %d, want 2 (分布=%v)", dist["0.0.1-itest-new"], dist)
	}
	if dist["0.0.1-itest-old"] != 1 {
		t.Errorf("旧バージョンの台数 = %d, want 1 (分布=%v)", dist["0.0.1-itest-old"], dist)
	}
	if _, ok := dist["0.0.1-itest-off"]; ok {
		t.Errorf("offline のエージェントが集計されている (分布=%v)", dist)
	}
}
