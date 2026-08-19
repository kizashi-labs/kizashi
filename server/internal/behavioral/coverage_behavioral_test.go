package behavioral

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema) and returns a
// pool, skipping when the var is unset so pure-logic runs stay green. These
// tests drive the DB-backed baseline builders against empty-but-real tables:
// the queries find nothing, so the builder helpers traverse their empty-result
// paths — exercising the query/guard code that pure tests cannot reach.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping behavioral coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// 登録されていない端末は、障害ではありません。
//
// **この検査は「その端末 ID で成功すること」を期待していました。** 端末は
// agents に無いので、ホスト名の読み出しが ErrNoRows になり、`数えられません
// でした` が返っていました —— そして
// `POST /admin/behavioral/baselines/:agent_id` は 500 と「データベース操作に
// 失敗しました」を返していました。**ID を打ち間違えただけで、障害が起きた
// ように見えます。** いまは ErrAgentNotFound で、画面には 404 が出ます。
func TestBuildBaselineSaysTheAgentIsUnknown(t *testing.T) {
	pool := covPool(t)
	e := NewEngine(pool)

	_, err := e.BuildBaseline(context.Background(), "00000000-0000-0000-0000-0000000000ab", 14)
	if !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("BuildBaseline = %v、want ErrAgentNotFound。**「端末が無い」と"+
			"「データベースが落ちている」が同じ答えになっています**", err)
	}
	if !strings.Contains(err.Error(), "00000000-0000-0000-0000-0000000000ab") {
		t.Errorf("どの端末なのかが書かれていません: %v", err)
	}
}

func TestEngine_BaselineBuilders_DB(t *testing.T) {
	pool := covPool(t)
	e := NewEngine(pool)
	ctx := context.Background()
	agentID := "00000000-0000-0000-0000-0000000000ab"

	// 端末を登録します。**ここが無かったので、この検査は
	// 「登録済みの端末で、履歴が空」という本来の道を一度も通っていません
	// でした。** 通っていたのは「端末が無い」だけです。
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id, hostname, os_type, status)
		 VALUES ($1::uuid, 'baseline-cov', 'linux', 'offline')
		 ON CONFLICT (id) DO NOTHING`, agentID); err != nil {
		t.Fatalf("端末を登録できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id = $1::uuid`, agentID)
	})

	// BuildBaseline over an empty event history returns a baseline (or a
	// not-enough-data path) without error and populates the in-memory map.
	if _, err := e.BuildBaseline(ctx, agentID, 14); err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}

	// BuildEnrichedBaseline drives buildHeatmap / buildTypicalProcesses /
	// buildTypicalDests / buildTypicalDirs / buildRecentDeviations against the
	// empty tables.
	if _, err := e.BuildEnrichedBaseline(ctx, agentID, 30, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("BuildEnrichedBaseline: %v", err)
	}
	// lookbackDays<=0 exercises the default branch.
	if _, err := e.BuildEnrichedBaseline(ctx, agentID, 0, nil); err != nil {
		t.Fatalf("BuildEnrichedBaseline default: %v", err)
	}

	// In-memory accessors.
	_, _ = e.GetBaseline(agentID)
	_ = e.GetAllBaselines()
	_ = e.GetRecentAnomalies(10)
}
