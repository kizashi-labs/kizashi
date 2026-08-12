package handlers_test

import (
	"context"
	"testing"
)

// TestUsers_Migration326_TenantDefault verifies migration 326's core mechanism:
// the users.tenant_id column DEFAULT derives the tenant from the connection's
// app.tenant_id (falling back to the default tenant), so INSERTs that omit
// tenant_id land in the caller's tenant — the property that lets RLS be enabled
// on users without rewriting every INSERT site. Also asserts the backfill left
// no NULL-tenant rows. Runs against the migrated CI database (TEST_DATABASE_URL).
func TestUsers_Migration326_TenantDefault(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	const tenantID = "aaaaaaaa-0000-0000-0000-0000000000ab"
	const email = "itest-tenant-default@example.com"

	cleanup := func() {
		_, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE email=$1", email)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenantID)
	}
	cleanup()
	t.Cleanup(cleanup)

	// A distinct tenant so we can tell the app.tenant_id branch of the DEFAULT
	// apart from the default-tenant fallback.
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name, slug, plan)
		 VALUES ($1, 'itest-td', 'itest-td', 'standard') ON CONFLICT (id) DO NOTHING`,
		tenantID,
	); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Pin a single connection so set_config and the INSERT share a session.
	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT set_config('app.tenant_id', $1, false)", tenantID); err != nil {
		conn.Release()
		t.Fatalf("set app.tenant_id: %v", err)
	}
	// INSERT without tenant_id → column DEFAULT should resolve to app.tenant_id.
	_, insErr := conn.Exec(ctx,
		`INSERT INTO users (email, password_hash, full_name, role)
		 VALUES ($1, 'x', 'Tenant Default', 'viewer')`, email)
	// Clear the setting before returning the connection to the pool.
	_, _ = conn.Exec(ctx, "SELECT set_config('app.tenant_id', '', false)")
	conn.Release()
	if insErr != nil {
		t.Fatalf("insert user under app.tenant_id: %v", insErr)
	}

	var got string
	if err := db.Pool().QueryRow(ctx,
		"SELECT tenant_id::text FROM users WHERE email=$1", email,
	).Scan(&got); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if got != tenantID {
		t.Errorf("expected user tenant_id=%s (derived from app.tenant_id), got %s", tenantID, got)
	}

	// Migration 326 backfilled all pre-existing NULL-tenant users.
	var nulls int
	if err := db.Pool().QueryRow(ctx,
		"SELECT count(*) FROM users WHERE tenant_id IS NULL",
	).Scan(&nulls); err != nil {
		t.Fatalf("count NULL-tenant users: %v", err)
	}
	if nulls != 0 {
		t.Errorf("expected 0 NULL-tenant users after migration 326, got %d", nulls)
	}
}
