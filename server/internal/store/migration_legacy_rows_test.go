package store_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestEventTypeConstraintMigrationsSurviveLegacyRows guards the failure that took
// the API down and hid 20+ rule migrations for days.
//
// events.event_type has a CHECK constraint that successive migrations widen. A
// migration that adds a VALIDATED constraint makes PostgreSQL check every existing
// row, so ONE legacy row carrying a type the new list omits aborts the migration.
// The API runs migrations at startup and exits on failure, so the result is not a
// degraded feature but a restart loop — and every later migration stops being
// applied. Observed live 2026-08-03: 15 rows written by a different branch
// (wmi_activity, named_pipe) blocked migration 353, and the deployment silently ran
// for days without migrations 352-363.
//
// Legacy rows like those exist because the constraint was added NOT VALID at some
// point, so rows predating it were never checked. Any deployment that has been
// upgraded across branches can hold values no current migration knows about. The
// constraint migrations must therefore tolerate them: they widen what is accepted
// going forward without asserting anything about the past.
//
// Set TEST_DATABASE_URL to run (CI does; the workflow already provides Postgres).
func TestEventTypeConstraintMigrationsSurviveLegacyRows(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL 未設定のためスキップ（CI では設定される）")
	}
	ctx := context.Background()
	// A throwaway schema so the test never touches a real events table.
	pool, cleanup := scopedPool(t, dsn, "constraint_guard_test")
	defer cleanup()

	// A pre-existing events table holding types no constraint ever listed — the
	// state every long-lived deployment can be in.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE events (
			time       TIMESTAMPTZ NOT NULL,
			event_type TEXT        NOT NULL
		);
		INSERT INTO events (time, event_type) VALUES
			(now(), 'process'), (now(), 'wmi_activity'), (now(), 'named_pipe');`); err != nil {
		t.Fatalf("events テーブル準備失敗: %v", err)
	}

	blocks := constraintMigrationBlocks(t)
	if len(blocks) == 0 {
		t.Fatal("events_event_type_check を操作するマイグレーションが見つかりません")
	}
	for _, b := range blocks {
		if _, err := pool.Exec(ctx, b.sql); err != nil {
			t.Fatalf(`%s がレガシー行のある DB で失敗しました: %v

このエラーは本番では「API がマイグレーション失敗で起動できず再起動ループ」になり、
以降のマイグレーションが一切適用されなくなります。制約は防御であって、
起動を止める仕掛けであってはなりません。NOT VALID で張るか、既存の値を保持してください。`, b.name, err)
		}
	}

	// The constraint must still be a constraint: new writes are checked.
	if _, err := pool.Exec(ctx, `INSERT INTO events (time, event_type) VALUES (now(), 'definitely_not_an_event_type')`); err == nil {
		t.Error("未知の event_type が通ってしまいました（制約が防御として機能していません）")
	}
	// And a representative type from each constraint-widening migration must be
	// writable, so a NOT VALID rewrite that quietly narrows the list is caught.
	// Extend this when a migration adds a type. The entries below come from
	// 322 (host_integrity) / 417 (parent_pid_spoof) / 380 (ps_module) /
	// 373 (device_event) / 370 (wmi_activity)。417 / 418 / 421 は本ブランチが
	// 追加した event_type 拡張で、いずれも NOT VALID 付きで張っている。
	for _, ty := range []string{"process", "host_integrity", "parent_pid_spoof", "ps_module", "device_event", "wmi_activity", "tls_handshake"} {
		if _, err := pool.Exec(ctx, `INSERT INTO events (time, event_type) VALUES (now(), $1)`, ty); err != nil {
			t.Errorf("event_type=%q が拒否されました: %v", ty, err)
		}
	}
}

type migrationBlock struct {
	name string
	sql  string
}

var doBlockRe = regexp.MustCompile(`(?s)DO \$migration\$.*?\$migration\$;`)

// constraintMigrationBlocks returns, in migration order, the DO blocks of every
// migration that manipulates events_event_type_check. Only the DO blocks are taken:
// the surrounding files also insert rules, which need tables this test does not
// create and are not what is under test here.
func constraintMigrationBlocks(t *testing.T) []migrationBlock {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("マイグレーション列挙失敗: %v", err)
	}
	sort.Strings(paths)
	var out []migrationBlock
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s 読み込み失敗: %v", p, err)
		}
		if !strings.Contains(string(b), "events_event_type_check") {
			continue
		}
		for _, blk := range doBlockRe.FindAllString(string(b), -1) {
			out = append(out, migrationBlock{name: filepath.Base(p), sql: blk})
		}
	}
	return out
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
