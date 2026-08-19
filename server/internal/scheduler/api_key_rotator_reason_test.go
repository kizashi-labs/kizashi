package scheduler

import (
	"context"
	"os"
	"testing"

	"github.com/edr-platform/server/internal/apikeys"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The rotator retires API keys unused for 90 days, and used to leave no record
// of having done so.
//
// It probed for api_keys.disabled_reason and, finding it absent — no migration
// created it — ran a second copy of the same UPDATE without the reason. The key
// went off correctly and silently, indistinguishable afterwards from one an
// operator revoked deliberately. Migration 378 adds the column; the probe and
// the duplicate branch are gone.

func rotatorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedRotatorKey inserts an enabled key last used the given number of days ago.
func seedRotatorKey(t *testing.T, pool *pgxpool.Pool, prefix string, daysAgo int) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO api_keys (name, key_prefix, key_hash, role, scopes, enabled, last_used_at)
		VALUES ($1, $1, $1 || '-hash', 'analyst', '{}', true, NOW() - make_interval(days => $2))
		RETURNING id::text`, prefix, daysAgo).Scan(&id); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_keys WHERE id=$1::uuid`, id)
	})
	return id
}

func rotatorKeyState(t *testing.T, pool *pgxpool.Pool, id string) (bool, string) {
	t.Helper()
	var enabled bool
	var reason string
	if err := pool.QueryRow(context.Background(),
		`SELECT enabled, COALESCE(disabled_reason,'') FROM api_keys WHERE id=$1::uuid`,
		id).Scan(&enabled, &reason); err != nil {
		t.Fatalf("read: %v", err)
	}
	return enabled, reason
}

// A key retired for inactivity must say so, and must be distinguishable from a
// deliberate revocation.
func TestTheRotatorRecordsWhyItDisabledAKey(t *testing.T) {
	pool := rotatorPool(t)
	stale := seedRotatorKey(t, pool, "rot-stale", 120)

	NewAPIKeyRotator(pool, nil).disableInactiveKeys(context.Background())

	enabled, reason := rotatorKeyState(t, pool, stale)
	if enabled {
		t.Fatal("90日以上未使用のキーが無効化されていません")
	}
	if reason != apikeys.DisabledReasonInactive {
		t.Errorf("無効化理由が %q、期待は %q — "+
			"手動失効と区別がつきません", reason, apikeys.DisabledReasonInactive)
	}
	if reason == apikeys.DisabledReasonRevoked {
		t.Error("自動無効化が手動失効として記録されました")
	}
}

// A key still in use must be left alone, reason included.
func TestTheRotatorLeavesActiveKeysAlone(t *testing.T) {
	pool := rotatorPool(t)
	fresh := seedRotatorKey(t, pool, "rot-fresh", 3)

	NewAPIKeyRotator(pool, nil).disableInactiveKeys(context.Background())

	enabled, reason := rotatorKeyState(t, pool, fresh)
	if !enabled {
		t.Error("使用中のキーが無効化されました")
	}
	if reason != "" {
		t.Errorf("使用中のキーに無効化理由 %q が付きました", reason)
	}
}

// The 90-day boundary decides, not an approximation of it.
func TestTheRotatorBoundaryIsNinetyDays(t *testing.T) {
	pool := rotatorPool(t)
	just := seedRotatorKey(t, pool, "rot-89", 89)
	over := seedRotatorKey(t, pool, "rot-91", 91)

	NewAPIKeyRotator(pool, nil).disableInactiveKeys(context.Background())

	if enabled, _ := rotatorKeyState(t, pool, just); !enabled {
		t.Error("89日しか経っていないキーが無効化されました")
	}
	if enabled, _ := rotatorKeyState(t, pool, over); enabled {
		t.Error("91日経過したキーが無効化されていません")
	}
}
