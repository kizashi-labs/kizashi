package main

// dedup が統合済みの写しを誤検知として二重計上していた件の再発防止。
//
// 検知は 2 プロセスに分かれており、PR #647 で rules テーブルが api 経路にも
// 繋がったため、DB ルールは server-detect ("[SIGMA] X") と server-api
// ("[Sigma] X") の両方が評価する。1 つの検知が 2 行になる。
//
// dedup.AlertDeduplicator は生存側に dedup_key を立て、統合された側を
// status='resolved' にするが行は消さない。fetchAlerts は status を見て
// いなかったので写しまで数えており、集計キーが [SIGMA]/[Sigma] を畳む結果
// 1 ルールの件数が倍になっていた (実測: RDP ルールが 6 → 12)。

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func dedupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed fetchAlerts test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestFetchAlerts_ExcludesMergedDuplicates(t *testing.T) {
	pool := dedupTestPool(t)
	ctx := context.Background()

	const hostname = "fpsoak-dedup-itest"
	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, status)
		VALUES ($1, 'linux', 'online') RETURNING id::text`, hostname).Scan(&agentID); err != nil {
		t.Skipf("agents table unavailable: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1::uuid`, agentID); err != nil {
			t.Errorf("後片付けに失敗しました (alerts): %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM agents WHERE id = $1::uuid`, agentID); err != nil {
			t.Errorf("後片付けに失敗しました (agents): %v", err)
		}
	})

	// 4 行を用意する。数えてよいのは前半 3 行だけ。
	for _, a := range []struct {
		title     string
		status    string
		dedupKey  *string
		mustCount bool
		why       string
	}{
		{"[SIGMA] itest rule", "open", ptr("k1"), true,
			"dedup の生存側。dedup_key は付くが数える"},
		{"[Sigma] itest other", "open", nil, true,
			"重複していない普通のアラート"},
		{"[Sigma] itest analyst-resolved", "resolved", nil, true,
			"解析者が手で解決したもの。dedup_key が無いので数える"},
		{"[Sigma] itest rule", "resolved", ptr("k1"), false,
			"dedup が統合した写し。これだけ除く"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, severity, status, title, description, dedup_key, created_at)
			VALUES ($1::uuid, 5, $2, $3, 'fpsoak dedup itest', $4, NOW())`,
			agentID, a.status, a.title, a.dedupKey); err != nil {
			t.Fatalf("seed alert (%s / %s): %v", a.title, a.status, err)
		}
	}

	got, err := fetchAlerts(ctx, pool, []string{agentID}, window{
		from: time.Now().Add(-1 * time.Hour),
		to:   time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("fetchAlerts: %v", err)
	}

	if len(got) != 3 {
		titles := make([]string, 0, len(got))
		for _, a := range got {
			titles = append(titles, a.Title)
		}
		t.Fatalf("件数 = %d, want 3 (dedup が統合した写しを除く): %v", len(got), titles)
	}

	// 統合された写しが残っていると、集計キーが [SIGMA]/[Sigma] を畳むため
	// "itest rule" が 2 件に見えてしまう。1 件であることを直接確かめる。
	n := 0
	for _, a := range got {
		if a.Title == "[SIGMA] itest rule" || a.Title == "[Sigma] itest rule" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("同一検知の件数 = %d, want 1 (両エンジンの写しが二重計上されている)", n)
	}
}

func ptr(s string) *string { return &s }
