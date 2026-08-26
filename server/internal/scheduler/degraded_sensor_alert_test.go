package scheduler

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCheckDegradedSensors_OnlyAlertsOnRealDegradation pins the gating of the
// sensor-degradation alarm.
//
// The alarm exists because a Linux endpoint ran for days with its eBPF file and
// network monitors absent — port scans structurally undetectable, ransomware
// detection without process attribution — while the fleet view showed a healthy
// agent. The data was being reported the whole time; nothing looked at it.
//
// What makes such an alarm useful is what it stays QUIET about. NULL means the
// platform does not report a mode (Windows/macOS, older agents) and 'off' means a
// sensor is disabled by configuration; neither is a degradation. An alarm that
// fires on those would be muted within a week, which is the same outcome as not
// having it.
func TestCheckDegradedSensors_OnlyAlertsOnRealDegradation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL 未設定のためスキップ（CI では設定される）")
	}
	ctx := context.Background()
	pool, cleanup := scopedPool(t, dsn, "degraded_sensor_test")
	defer cleanup()
	if _, err := pool.Exec(ctx, `
		CREATE TABLE agents (
			id               UUID PRIMARY KEY,
			hostname         TEXT NOT NULL,
			status           TEXT NOT NULL,
			telemetry_mode   TEXT,
			telemetry_detail TEXT
		);
		INSERT INTO agents (id, hostname, status, telemetry_mode, telemetry_detail) VALUES
			('11111111-1111-1111-1111-111111111111', 'degraded-linux', 'online', 'poll',
			 'file=poll(eBPF非対応) network=poll(eBPF非対応) process=ebpf'),
			('22222222-2222-2222-2222-222222222222', 'healthy-linux',  'online', 'ebpf', 'process=ebpf'),
			('33333333-3333-3333-3333-333333333333', 'windows-box',    'online', NULL,   NULL),
			('44444444-4444-4444-4444-444444444444', 'sensors-off',    'online', 'off',  'process=off'),
			('55555555-5555-5555-5555-555555555555', 'retired-linux',  'offline','poll', 'network=poll');`); err != nil {
		t.Fatalf("agents 準備失敗: %v", err)
	}

	got := (&AgentHealthAlerter{pool: pool}).checkDegradedSensors(ctx)

	if len(got) != 1 {
		var names []string
		for _, g := range got {
			names = append(names, g.hostname)
		}
		t.Fatalf("降格として報告されたのは %v。'poll' を報告する online の1台だけであるべきです", names)
	}
	if got[0].hostname != "degraded-linux" {
		t.Errorf("報告されたホストが違います: %q", got[0].hostname)
	}
	// The alert must carry the per-sensor breakdown, otherwise the operator still
	// has to log onto the host to learn which sensor fell back.
	if !strings.Contains(got[0].description, "network=poll") {
		t.Errorf("センサー別の内訳がアラート本文にありません: %q", got[0].description)
	}
	if got[0].dedupFor != degradedSensorDedupWindow {
		t.Errorf("dedup 窓が %v。恒常的な状態なので %v であるべきです", got[0].dedupFor, degradedSensorDedupWindow)
	}
	// Distinct title = distinct dedup identity: a CPU spike must not suppress this.
	if got[0].title == "" || got[0].title == "エージェント degraded-linux ヘルス警告" {
		t.Errorf("タイトルが CPU/ステール警告と同一です (%q)。互いに抑制し合います", got[0].title)
	}
}

// scopedPool returns a pool whose every connection is pinned to a throwaway schema,
// plus a cleanup. search_path must be set on the CONNECTION CONFIG rather than with
// a `SET` statement: pgxpool hands out arbitrary connections, so a `SET` applies to
// one of them and later queries silently run against the default schema. That makes
// a test pass or fail on which connection it happens to draw.
func scopedPool(t *testing.T, dsn, schema string) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("接続失敗: %v", err)
	}
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatalf("スキーマ作成失敗: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("DSN 解析失敗: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatalf("スキーマ固定プールの作成失敗: %v", err)
	}
	return pool, func() {
		pool.Close()
		admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`) //nolint:errcheck
		admin.Close()
	}
}
