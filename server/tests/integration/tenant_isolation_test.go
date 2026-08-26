//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// createTenant inserts a tenant row and returns its UUID string.
func createTenant(t *testing.T, ctx context.Context, name, slug string) string {
	t.Helper()
	db := requireDB(t)
	var id string
	err := db.Pool().QueryRow(ctx,
		`INSERT INTO tenants (name, slug, plan) VALUES ($1, $2, 'standard') RETURNING id`,
		name, slug,
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTenant(%q): %v", name, err)
	}
	t.Cleanup(func() {
		// Remove test tenant (cascades to tenant_roles; other FK-guarded rows
		// are cleaned up explicitly in each test before this runs).
		_, _ = db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// createAgent inserts a minimal agent for the given tenant and returns its UUID.
func createAgent(t *testing.T, ctx context.Context, hostname, tenantID string) string {
	t.Helper()
	db := requireDB(t)
	id := uuid.New().String()
	_, err := db.Pool().Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, status, tenant_id, last_seen)
		VALUES ($1, $2, 'linux', 'online', $3, NOW())`,
		id, hostname, tenantID,
	)
	if err != nil {
		t.Fatalf("createAgent(%q): %v", hostname, err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(),
			`DELETE FROM agents WHERE id = $1`, id)
	})
	return id
}

// createAlert inserts a minimal alert for the given agent/tenant and returns its UUID.
func createAlert(t *testing.T, ctx context.Context, title, agentID, tenantID string) string {
	t.Helper()
	db := requireDB(t)
	id := uuid.New().String()
	_, err := db.Pool().Exec(ctx, `
		INSERT INTO alerts (id, agent_id, severity, status, title, tenant_id)
		VALUES ($1, $2, 5, 'open', $3, $4)`,
		id, agentID, title, tenantID,
	)
	if err != nil {
		t.Fatalf("createAlert(%q): %v", title, err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(),
			`DELETE FROM alerts WHERE id = $1`, id)
	})
	return id
}

// createIncident inserts a minimal incident for the given tenant and returns its UUID.
func createIncident(t *testing.T, ctx context.Context, title, tenantID string) string {
	t.Helper()
	db := requireDB(t)
	id := uuid.New().String()
	_, err := db.Pool().Exec(ctx, `
		INSERT INTO incidents (id, title, severity, status, tenant_id)
		VALUES ($1, $2, 5, 'open', $3)`,
		id, title, tenantID,
	)
	if err != nil {
		t.Fatalf("createIncident(%q): %v", title, err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(),
			`DELETE FROM incidents WHERE id = $1`, id)
	})
	return id
}

// setTenantContext issues SET LOCAL for app.tenant_id inside a single-use
// connection acquired from the pool. It returns a cleanup func that must be
// deferred by the caller.
//
// Because pgxpool reuses connections, we use a dedicated *pgxpool.Conn so the
// session setting does not leak into other goroutines.
func withTenantContext(t *testing.T, ctx context.Context, tenantID string, fn func()) {
	t.Helper()
	db := requireDB(t)
	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantID)
	if err != nil {
		t.Fatalf("set_config tenant_id=%q: %v", tenantID, err)
	}

	fn()
}

// ─── TestTenantIsolation ──────────────────────────────────────────────────────

// TestTenantIsolation verifies that RLS prevents cross-tenant data access for
// the alerts, agents, and incidents tables.
func TestTenantIsolation(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	// ── Setup: two independent tenants ──────────────────────────────────────
	tenantAID := createTenant(t, ctx, "Isolation-Tenant-A", fmt.Sprintf("isolation-a-%s", uuid.New().String()[:8]))
	tenantBID := createTenant(t, ctx, "Isolation-Tenant-B", fmt.Sprintf("isolation-b-%s", uuid.New().String()[:8]))

	agentAID := createAgent(t, ctx, "host-tenant-a", tenantAID)
	agentBID := createAgent(t, ctx, "host-tenant-b", tenantBID)

	alertAID := createAlert(t, ctx, "Alert-A", agentAID, tenantAID)
	alertBID := createAlert(t, ctx, "Alert-B", agentBID, tenantBID)

	incidentAID := createIncident(t, ctx, "Incident-A", tenantAID)
	incidentBID := createIncident(t, ctx, "Incident-B", tenantBID)

	// Ensure the compiler does not complain about unused variables if a sub-test
	// is skipped; reference them via a no-op assertion.
	_ = alertAID
	_ = alertBID
	_ = agentAID
	_ = agentBID
	_ = incidentAID
	_ = incidentBID

	// ── Test 1: Tenant A cannot see Tenant B's alerts ────────────────────────
	t.Run("TenantA_cannot_see_TenantB_alerts", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantAID)
		if err != nil {
			t.Fatalf("set tenant context: %v", err)
		}

		rows, err := conn.Query(ctx, `SELECT id FROM alerts WHERE tenant_id = $1`, tenantBID)
		if err != nil {
			t.Fatalf("query alerts for tenant B under tenant A context: %v", err)
		}
		defer rows.Close()

		var ids []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}

		if len(ids) > 0 {
			t.Errorf("RLS violation: Tenant A context returned %d Tenant B alert(s): %v", len(ids), ids)
		} else {
			t.Logf("PASS: Tenant A context returned 0 Tenant B alerts (RLS enforced)")
		}
	})

	// ── Test 2: Tenant A cannot see Tenant B's agents ────────────────────────
	t.Run("TenantA_cannot_see_TenantB_agents", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantAID)
		if err != nil {
			t.Fatalf("set tenant context: %v", err)
		}

		rows, err := conn.Query(ctx, `SELECT id, hostname FROM agents WHERE tenant_id = $1`, tenantBID)
		if err != nil {
			t.Fatalf("query agents for tenant B under tenant A context: %v", err)
		}
		defer rows.Close()

		var hostnames []string
		for rows.Next() {
			var id, hostname string
			_ = rows.Scan(&id, &hostname)
			hostnames = append(hostnames, hostname)
		}

		if len(hostnames) > 0 {
			t.Errorf("RLS violation: Tenant A context returned %d Tenant B agent(s): %v", len(hostnames), hostnames)
		} else {
			t.Logf("PASS: Tenant A context returned 0 Tenant B agents (RLS enforced)")
		}
	})

	// ── Test 3: Tenant A cannot see Tenant B's incidents ────────────────────
	t.Run("TenantA_cannot_see_TenantB_incidents", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantAID)
		if err != nil {
			t.Fatalf("set tenant context: %v", err)
		}

		rows, err := conn.Query(ctx, `SELECT id FROM incidents WHERE tenant_id = $1`, tenantBID)
		if err != nil {
			t.Fatalf("query incidents for tenant B under tenant A context: %v", err)
		}
		defer rows.Close()

		var ids []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}

		if len(ids) > 0 {
			t.Errorf("RLS violation: Tenant A context returned %d Tenant B incident(s): %v", len(ids), ids)
		} else {
			t.Logf("PASS: Tenant A context returned 0 Tenant B incidents (RLS enforced)")
		}
	})

	// ── Test 4: No tenant context (admin/superuser) can see all data ─────────
	t.Run("Admin_sees_all_tenants_data", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		// Clear tenant context — empty string triggers the OR condition in the
		// RLS policy: current_setting('app.tenant_id', TRUE) = ''
		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', '', TRUE)`)
		if err != nil {
			t.Fatalf("clear tenant context: %v", err)
		}

		// Both test agents should be visible.
		rows, err := conn.Query(ctx,
			`SELECT id FROM agents WHERE id IN ($1, $2)`, agentAID, agentBID)
		if err != nil {
			t.Fatalf("query agents (no tenant context): %v", err)
		}
		defer rows.Close()

		var found []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			found = append(found, id)
		}

		if len(found) < 2 {
			t.Errorf("Admin context: expected ≥2 agents (one per tenant), got %d — possible RLS over-restriction", len(found))
		} else {
			t.Logf("PASS: Admin context returned %d agent(s) across both tenants", len(found))
		}

		// Both test alerts should be visible.
		alertRows, err := conn.Query(ctx,
			`SELECT id FROM alerts WHERE id IN ($1, $2)`, alertAID, alertBID)
		if err != nil {
			t.Fatalf("query alerts (no tenant context): %v", err)
		}
		defer alertRows.Close()

		var alertsFound []string
		for alertRows.Next() {
			var id string
			_ = alertRows.Scan(&id)
			alertsFound = append(alertsFound, id)
		}
		if len(alertsFound) < 2 {
			t.Errorf("Admin context: expected ≥2 alerts (one per tenant), got %d", len(alertsFound))
		} else {
			t.Logf("PASS: Admin context returned %d alert(s) across both tenants", len(alertsFound))
		}
	})
}

// ─── TestRLSSetConfig ─────────────────────────────────────────────────────────

// TestRLSSetConfig verifies that set_config properly scopes SELECT COUNT(*)
// queries to the active tenant.
func TestRLSSetConfig(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	// ── Setup ────────────────────────────────────────────────────────────────
	tenantAID := createTenant(t, ctx,
		"RLS-SetConfig-A", fmt.Sprintf("rls-cfg-a-%s", uuid.New().String()[:8]))
	tenantBID := createTenant(t, ctx,
		"RLS-SetConfig-B", fmt.Sprintf("rls-cfg-b-%s", uuid.New().String()[:8]))

	agentAID := createAgent(t, ctx, "rls-host-a", tenantAID)
	agentBID := createAgent(t, ctx, "rls-host-b", tenantBID)

	// Two alerts for tenant A, one for tenant B.
	_ = createAlert(t, ctx, "RLS-Alert-A1", agentAID, tenantAID)
	_ = createAlert(t, ctx, "RLS-Alert-A2", agentAID, tenantAID)
	_ = createAlert(t, ctx, "RLS-Alert-B1", agentBID, tenantBID)

	// ── Execute with Tenant A context ────────────────────────────────────────
	t.Run("set_config_tenantA_scopes_alerts", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantAID)
		if err != nil {
			t.Fatalf("set_config (tenant A): %v", err)
		}

		var count int
		err = conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts WHERE agent_id IN ($1, $2)`,
			agentAID, agentBID,
		).Scan(&count)
		if err != nil {
			t.Fatalf("COUNT alerts under tenant A context: %v", err)
		}

		// Under tenant A context the RLS policy hides tenant B's alert, so
		// only the 2 tenant A alerts should be returned.
		if count != 2 {
			t.Errorf("set_config tenant A: expected 2 alerts, got %d (RLS may not be filtering correctly)", count)
		} else {
			t.Logf("PASS: Tenant A context returned exactly 2 alerts")
		}
	})

	// ── Execute with Tenant B context ────────────────────────────────────────
	t.Run("set_config_tenantB_scopes_alerts", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantBID)
		if err != nil {
			t.Fatalf("set_config (tenant B): %v", err)
		}

		var count int
		err = conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts WHERE agent_id IN ($1, $2)`,
			agentAID, agentBID,
		).Scan(&count)
		if err != nil {
			t.Fatalf("COUNT alerts under tenant B context: %v", err)
		}

		// Under tenant B context only the single tenant B alert should be visible.
		if count != 1 {
			t.Errorf("set_config tenant B: expected 1 alert, got %d (RLS may not be filtering correctly)", count)
		} else {
			t.Logf("PASS: Tenant B context returned exactly 1 alert")
		}
	})

	// ── Switching context on the same connection ──────────────────────────────
	t.Run("set_config_switch_context_between_tenants", func(t *testing.T) {
		conn, err := db.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire connection: %v", err)
		}
		defer conn.Release()

		// Start with tenant A.
		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantAID)
		if err != nil {
			t.Fatalf("set_config (tenant A): %v", err)
		}

		var countA int
		err = conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts WHERE agent_id IN ($1, $2)`,
			agentAID, agentBID,
		).Scan(&countA)
		if err != nil {
			t.Fatalf("COUNT alerts (tenant A context): %v", err)
		}

		// Switch to tenant B on the same connection.
		_, err = conn.Exec(ctx, `SELECT set_config('app.tenant_id', $1, TRUE)`, tenantBID)
		if err != nil {
			t.Fatalf("set_config (tenant B): %v", err)
		}

		var countB int
		err = conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM alerts WHERE agent_id IN ($1, $2)`,
			agentAID, agentBID,
		).Scan(&countB)
		if err != nil {
			t.Fatalf("COUNT alerts (tenant B context): %v", err)
		}

		if countA == countB {
			t.Errorf("context switch did not change visible rows: both contexts returned %d alerts", countA)
		} else {
			t.Logf("PASS: context switch effective — tenant A saw %d, tenant B saw %d", countA, countB)
		}
	})
}
