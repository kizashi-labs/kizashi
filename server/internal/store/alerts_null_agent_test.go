package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestListAlertsSurvivesNullAgentID guards a silent data-loss bug measured live on
// 2026-08-03 (ip-10-0-0-10).
//
// GET /api/v1/alerts reported `total: 56, per_page: 100, has_more: false` and then
// returned 18 rows. The 18 were the newest ones; the cut fell exactly before an
// alert with agent_id NULL (an MDM "device not reporting" alert, which has no
// endpoint agent behind it). Everything older than that row — 38 alerts — vanished
// from the API while sitting untouched in the table.
//
// Two defects compounded:
//
//  1. StoredAlert.AgentID/Hostname/OS are plain strings, but al.agent_id is
//     nullable and the LEFT JOIN on agents yields NULL hostname/os_type whenever
//     the agent row is absent. Scanning NULL into string fails.
//  2. The scan error was handled with `continue`. That reads as "skip this one
//     row", but pgx v5 marks the rows fatal and closes them on a Scan error, so
//     the next Next() returns false and the REST OF THE PAGE is dropped. total
//     comes from a separate COUNT(*), so the response still claimed 56.
//
// The cost was not theoretical: it made an ATT&CK detection-rate measurement read
// 13.6% when the product had actually raised 58 correctly-attributed alerts (86.4%
// on the prior run). In the SOC console the same bug hides every alert older than
// the first NULL-agent alert, with nothing to indicate anything is missing.
//
// Set TEST_DATABASE_URL to run (CI provides Postgres).
func TestListAlertsSurvivesNullAgentID(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL 未設定のためスキップ（CI では設定される）")
	}
	ctx := context.Background()
	pool, cleanup := alertScopedPool(t, dsn, "alerts_null_agent_test")
	defer cleanup()

	// Only the columns ListAlerts touches. A throwaway schema keeps the real
	// tables out of reach.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE agents (
			id UUID PRIMARY KEY, hostname TEXT, os_type TEXT);
		CREATE TABLE rules (
			id UUID PRIMARY KEY, name TEXT);
		CREATE TABLE users (
			id UUID PRIMARY KEY, full_name TEXT);
		CREATE TABLE alerts (
			id UUID PRIMARY KEY,
			rule_id UUID, agent_id UUID,
			severity INT NOT NULL DEFAULT 5,
			status TEXT NOT NULL DEFAULT 'open',
			title TEXT NOT NULL,
			description TEXT,
			mitre_technique TEXT,
			anomaly_score DOUBLE PRECISION,
			ai_analyzed BOOLEAN NOT NULL DEFAULT false,
			ai_is_threat BOOLEAN, ai_severity INT, ai_confidence DOUBLE PRECISION,
			ai_threat_name TEXT, ai_summary TEXT, ai_report TEXT,
			ai_attack_chain JSONB, ai_mitre_tags TEXT[],
			-- migration 435 の列。ListAlerts が al.tags を読むので、
			-- 「ListAlerts が触る列だけ」という上の約束に含まれる。
			-- 抜けると 42703 で落ち、**NULL agent_id の話とは無関係の理由で
			-- この検査が赤くなる**。
			tags JSONB NOT NULL DEFAULT '[]'::jsonb,
			assigned_to TEXT, resolved_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
		CREATE TABLE alert_comments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), alert_id UUID);

		INSERT INTO agents (id, hostname, os_type)
			VALUES ('11111111-1111-1111-1111-111111111111', 'ip-10-0-0-10', 'linux');

		-- Newest first, mirroring the live ordering: two ordinary alerts, then the
		-- NULL-agent MDM alert, then the ones that disappeared behind it.
		INSERT INTO alerts (id, agent_id, title, mitre_technique, created_at, updated_at) VALUES
			('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111',
			 '[SIGMA] Curl Usage on Linux',            'T1105',     now() - interval '1 min', now()),
			('aaaaaaaa-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111',
			 '[HEURISTIC] ポートスキャン検知',           'T1046',     now() - interval '2 min', now()),
			('aaaaaaaa-0000-0000-0000-000000000003', NULL,
			 '管理デバイスが長期未報告',                  'T1629.003', now() - interval '3 min', now()),
			('aaaaaaaa-0000-0000-0000-000000000004', '11111111-1111-1111-1111-111111111111',
			 '[DISCOVERY] 短時間に複数種の探索コマンド',   'T1016',     now() - interval '4 min', now()),
			('aaaaaaaa-0000-0000-0000-000000000005', '11111111-1111-1111-1111-111111111111',
			 '[SIGMA] Base64 Obfuscation Command Exec', 'T1140',     now() - interval '5 min', now());`,
	); err != nil {
		t.Fatalf("スキーマ/データ準備失敗: %v", err)
	}

	s := &AlertStore{pool: pool}
	alerts, total, err := s.ListAlerts(ctx, AlertFilter{Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("ListAlerts が失敗しました: %v", err)
	}

	if total != 5 {
		t.Errorf("total=%d, want 5", total)
	}
	// The heart of the bug: total and the returned page disagreed, and nothing
	// in the response said so.
	if len(alerts) != total {
		t.Fatalf("返却 %d 件 / total %d 件 — ページが黙って切り詰められています。"+
			"NULL の agent_id で Scan が落ち、pgx が結果セットを閉じたことによる"+
			"取りこぼしです（2026-08-03 の実機事象と同じ）", len(alerts), total)
	}

	// The techniques behind the NULL-agent row are the ones a measurement or an
	// analyst would silently lose.
	got := map[string]bool{}
	for _, a := range alerts {
		if a.MITRETech != nil {
			got[*a.MITRETech] = true
		}
	}
	for _, want := range []string{"T1105", "T1046", "T1629.003", "T1016", "T1140"} {
		if !got[want] {
			t.Errorf("%s のアラートが API から消えています", want)
		}
	}

	// The NULL row itself must come back usable, not merely be counted.
	for _, a := range alerts {
		if a.MITRETech != nil && *a.MITRETech == "T1629.003" {
			if a.AgentID != "" {
				t.Errorf("agent_id NULL の行が %q になっています（空文字であるべき）", a.AgentID)
			}
			if a.Hostname != "" {
				t.Errorf("hostname が %q になっています（空文字であるべき）", a.Hostname)
			}
		}
	}
}

// alertScopedPool creates a throwaway schema and returns a pool pinned to it.
//
// search_path is set through ConnConfig.RuntimeParams rather than `SET search_path`:
// a pool hands out an arbitrary connection, so a SET applies to whichever connection
// happened to run it and the next query may land elsewhere.
func alertScopedPool(t *testing.T, dsn, schema string) (*pgxpool.Pool, func()) {
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
