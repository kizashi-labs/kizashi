package apikeys

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// An API key could be switched off two different ways and left no record of
// which.
//
// api_keys.disabled_reason is the column APIKeyRotator writes when it retires a
// key unused for 90 days. No migration created it, so the rotator's existence
// probe fell through to a second copy of the same UPDATE without the reason,
// and Manager.Revoke never wrote one at all. Keys were disabled correctly and
// silently.
//
// That silence costs at exactly the wrong moment. A key stops working, and
// whoever is paged has to decide between re-enabling it and going to look for a
// compromise — and `enabled = false` answers neither question. The two causes
// call for opposite responses.
//
// Migration 378 adds the column. These gates pin that both paths record which
// one happened and that the reason reaches the API.

func keysPool(t *testing.T) *pgxpool.Pool {
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

// seedKey inserts an enabled key last used the given number of days ago.
func seedKey(t *testing.T, pool *pgxpool.Pool, name string, lastUsedDaysAgo int) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO api_keys (name, key_prefix, key_hash, role, scopes, enabled, last_used_at)
		VALUES ($1, 'test1234', 'x', 'analyst', '{}', true,
		        NOW() - make_interval(days => $2))
		RETURNING id::text`, name, lastUsedDaysAgo).Scan(&id); err != nil {
		t.Fatalf("seed key %q: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_keys WHERE id=$1::uuid`, id)
	})
	return id
}

// keyState reads back whether a key is enabled and why it is not.
func keyState(t *testing.T, pool *pgxpool.Pool, id string) (enabled bool, reason string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT enabled, COALESCE(disabled_reason,'') FROM api_keys WHERE id=$1::uuid`,
		id).Scan(&enabled, &reason); err != nil {
		t.Fatalf("read key %s: %v", id, err)
	}
	return
}

// Revoking must say a person did it.
func TestRevokingRecordsThatItWasDeliberate(t *testing.T) {
	pool := keysPool(t)
	id := seedKey(t, pool, "revoke-reason", 1)

	if err := NewManager(pool).Revoke(context.Background(), id); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	enabled, reason := keyState(t, pool, id)
	if enabled {
		t.Error("失効させたキーが有効なままです")
	}
	if reason != DisabledReasonRevoked {
		t.Errorf("無効化理由が %q、期待は %q — "+
			"手動失効とローテーターによる自動無効化が区別できません", reason, DisabledReasonRevoked)
	}
}

// Revoking a key that is not there must still be reported as such.
func TestRevokingAnUnknownKeyIsAnError(t *testing.T) {
	pool := keysPool(t)

	err := NewManager(pool).Revoke(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("存在しないキーの失効がエラーになりませんでした")
	}
}

// An enabled key carries no reason: the field must not be filled in
// speculatively.
func TestAnEnabledKeyHasNoReason(t *testing.T) {
	pool := keysPool(t)
	id := seedKey(t, pool, "enabled-no-reason", 1)

	enabled, reason := keyState(t, pool, id)
	if !enabled {
		t.Fatal("seeded key is not enabled")
	}
	if reason != "" {
		t.Errorf("有効なキーに無効化理由 %q が入っています", reason)
	}
}

// The reason must reach the API, or recording it changes nothing an operator
// can see.
func TestTheReasonIsReturnedByTheAPI(t *testing.T) {
	pool := keysPool(t)
	ctx := context.Background()
	m := NewManager(pool)

	id := seedKey(t, pool, "listed-reason", 1)
	if err := m.Revoke(ctx, id); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	keys, err := m.ListAll(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *APIKey
	for _, k := range keys {
		if k.ID == id {
			found = k
			break
		}
	}
	if found == nil {
		t.Fatalf("失効したキーが一覧に現れません")
	}
	if found.DisabledReason != DisabledReasonRevoked {
		t.Errorf("APIが返した無効化理由が %q、期待は %q", found.DisabledReason, DisabledReasonRevoked)
	}
	if found.Enabled {
		t.Error("APIが失効済みのキーを有効として返しました")
	}
}

// The two reasons must stay distinct, since telling them apart is the point.
func TestTheTwoReasonsAreDistinct(t *testing.T) {
	if DisabledReasonRevoked == DisabledReasonInactive {
		t.Fatalf("2つの無効化理由が同じ値です: %q", DisabledReasonRevoked)
	}
	for _, r := range []string{DisabledReasonRevoked, DisabledReasonInactive} {
		if r == "" {
			t.Error("無効化理由が空文字です。有効なキーと区別がつきません")
		}
	}
}

// A key already disabled before the column existed reads as unknown rather
// than being credited with a reason nobody established.
func TestAKeyDisabledBeforeTheColumnHasNoReason(t *testing.T) {
	pool := keysPool(t)
	ctx := context.Background()

	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_prefix, key_hash, role, scopes, enabled, last_used_at)
		VALUES ('legacy-disabled', 'test5678', 'x', 'analyst', '{}', false, NOW())
		RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_keys WHERE id=$1::uuid`, id)
	})

	if _, reason := keyState(t, pool, id); reason != "" {
		t.Errorf("理由が記録されていないキーに %q が付きました", reason)
	}
}
