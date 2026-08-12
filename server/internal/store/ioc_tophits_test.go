package store_test

// IOCStore.TopHits の突き合わせ。
//
// 以前は alerts.src_ip / dst_ip / file_hash / domain を見ていたが、alerts に
// その 4 列は存在せず、毎回 `column a.src_ip does not exist` で失敗していた。
//
// 実際の結び付けは detection.AlertPipeline.createAlertFromIOC が作る title
// ("Known IOC detected: " + 値) しかない。ここではその書式でアラートを投入し、
// TopHits が拾えることと、件数・順序・30 日窓が効くことを確認する。
//
// 書式が両者でずれるとエラーにはならず件数が黙って 0 になるため、
// detection 側にも同じ意図のコメントを置いてある。

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// iocAlertTitle は createAlertFromIOC と同じ書式。
func iocAlertTitle(value string) string {
	return fmt.Sprintf("Known IOC detected: %s", value)
}

func topHitsTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed IOC tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// topHitsAgentID は alerts.agent_id の FK を満たすための共有エージェント。
const topHitsAgentID = "de0de0de-0000-4000-8000-000000000001"

// ensureTopHitsAgent は FK 先のエージェントを 1 台用意する。
func ensureTopHitsAgent(t *testing.T, db *store.DB) {
	t.Helper()
	if err := store.NewAgentStore(db).UpsertAgent(context.Background(), &store.AgentRow{
		ID: topHitsAgentID, Hostname: "tophits-itest-host", OSType: "linux",
		OSVersion: "22.04", AgentVersion: "1.0.0",
		IPAddresses: []string{"10.6.6.6"}, Status: "online",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
}

// seedIOCWithAlerts は IOC を 1 件と、それにマッチしたアラートを n 件用意する。
// ageDays はアラートの作成時刻を何日前にするか。
func seedIOCWithAlerts(t *testing.T, db *store.DB, value, iocType string, n, ageDays int) {
	t.Helper()
	ctx := context.Background()
	title := iocAlertTitle(value)

	ensureTopHitsAgent(t, db)

	cleanup := func() {
		_, _ = db.Pool().Exec(ctx, `DELETE FROM alerts WHERE title = $1`, title)
		_, _ = db.Pool().Exec(ctx, `DELETE FROM ioc_entries WHERE value = $1`, value)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active)
		VALUES ($1, $2, 'tophits itest', 7, true)`, iocType, value); err != nil {
		t.Fatalf("seed ioc_entries: %v", err)
	}
	if n == 0 {
		return
	}
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO alerts (agent_id, severity, status, title, description, created_at)
		SELECT $4::uuid, 7, 'open', $1, 'tophits itest',
		       NOW() - ($2 || ' days')::INTERVAL
		FROM generate_series(1, $3)`, title, fmt.Sprint(ageDays), n, topHitsAgentID); err != nil {
		t.Fatalf("seed alerts: %v", err)
	}
}

func TestIOCStore_TopHits_CountsAlertsByTitle(t *testing.T) {
	db := topHitsTestDB(t)
	s := store.NewIOCStore(db)
	ctx := context.Background()

	const value = "203.0.113.201"
	seedIOCWithAlerts(t, db, value, "ip", 3, 1)

	hits, err := s.TopHits(ctx, 50)
	if err != nil {
		t.Fatalf("TopHits: %v (alerts との突き合わせが壊れている可能性がある)", err)
	}

	var found bool
	for _, h := range hits {
		if h.Value != value {
			continue
		}
		found = true
		if h.HitCount != 3 {
			t.Errorf("HitCount = %d, want 3", h.HitCount)
		}
		if h.Type != "ip" {
			t.Errorf("Type = %q, want ip", h.Type)
		}
		if h.LastSeen.IsZero() {
			t.Error("LastSeen がゼロ値")
		}
	}
	if !found {
		t.Fatalf("投入した IOC %q が結果に含まれていない (総数 %d)", value, len(hits))
	}
}

// TestIOCStore_TopHits_ExcludesOldAlerts は 30 日窓が効くことを見る。
func TestIOCStore_TopHits_ExcludesOldAlerts(t *testing.T) {
	db := topHitsTestDB(t)
	s := store.NewIOCStore(db)

	const value = "203.0.113.202"
	// 45 日前 = 30 日窓の外。
	seedIOCWithAlerts(t, db, value, "ip", 2, 45)

	hits, err := s.TopHits(context.Background(), 50)
	if err != nil {
		t.Fatalf("TopHits: %v", err)
	}
	for _, h := range hits {
		if h.Value == value {
			t.Errorf("30 日より古いアラートが集計されている (HitCount=%d)", h.HitCount)
		}
	}
}

// TestIOCStore_TopHits_InactiveIOCExcluded は is_active=false の IOC を
// 集計しないことを見る。
func TestIOCStore_TopHits_InactiveIOCExcluded(t *testing.T) {
	db := topHitsTestDB(t)
	s := store.NewIOCStore(db)
	ctx := context.Background()

	const value = "203.0.113.203"
	seedIOCWithAlerts(t, db, value, "ip", 2, 1)

	if _, err := db.Pool().Exec(ctx,
		`UPDATE ioc_entries SET is_active = false WHERE value = $1`, value); err != nil {
		t.Fatalf("無効化: %v", err)
	}

	hits, err := s.TopHits(ctx, 50)
	if err != nil {
		t.Fatalf("TopHits: %v", err)
	}
	for _, h := range hits {
		if h.Value == value {
			t.Errorf("無効な IOC が集計されている (HitCount=%d)", h.HitCount)
		}
	}
}

// TestIOCStore_TopHits_OrdersByHitCount は件数の多い順に並ぶことを見る。
func TestIOCStore_TopHits_OrdersByHitCount(t *testing.T) {
	db := topHitsTestDB(t)
	s := store.NewIOCStore(db)

	const few, many = "203.0.113.204", "203.0.113.205"
	seedIOCWithAlerts(t, db, few, "ip", 2, 1)
	seedIOCWithAlerts(t, db, many, "ip", 5, 1)

	hits, err := s.TopHits(context.Background(), 50)
	if err != nil {
		t.Fatalf("TopHits: %v", err)
	}

	posFew, posMany := -1, -1
	for i, h := range hits {
		switch h.Value {
		case few:
			posFew = i
		case many:
			posMany = i
		}
	}
	if posFew < 0 || posMany < 0 {
		t.Fatalf("投入した IOC が両方は見つからない (few=%d, many=%d)", posFew, posMany)
	}
	if posMany > posFew {
		t.Errorf("件数の多い IOC が後ろに並んでいる (many=%d件目, few=%d件目)", posMany, posFew)
	}
}

// TestIOCStore_TopHits_LimitApplies は limit と、limit<=0 の既定値 10 を見る。
func TestIOCStore_TopHits_LimitApplies(t *testing.T) {
	db := topHitsTestDB(t)
	s := store.NewIOCStore(db)
	ctx := context.Background()

	if hits, err := s.TopHits(ctx, 1); err != nil {
		t.Fatalf("TopHits(1): %v", err)
	} else if len(hits) > 1 {
		t.Errorf("件数 = %d, limit 1 を超えている", len(hits))
	}

	if hits, err := s.TopHits(ctx, 0); err != nil {
		t.Fatalf("TopHits(0): %v", err)
	} else if len(hits) > 10 {
		t.Errorf("件数 = %d, 既定 limit 10 を超えている", len(hits))
	}
}
