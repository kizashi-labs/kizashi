//go:build integration

package store_test

import (
	"context"
	"testing"
)

// TestTenantRLS verifies that PostgreSQL Row-Level Security
// correctly isolates data between tenants.
func TestTenantRLS(t *testing.T) {
	ctx := context.Background()
	db := startDB(t)

	pool := db.Pool()

	// Create two tenants
	var tenant1ID, tenant2ID string
	err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug, plan) VALUES ('Tenant A', 'tenant-a', 'standard') RETURNING id`,
	).Scan(&tenant1ID)
	if err != nil {
		t.Fatalf("create tenant1: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug, plan) VALUES ('Tenant B', 'tenant-b', 'standard') RETURNING id`,
	).Scan(&tenant2ID)
	if err != nil {
		t.Fatalf("create tenant2: %v", err)
	}

	// Insert agents for each tenant
	var agent1ID, agent2ID string
	err = pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, tenant_id, status, last_seen)
		 VALUES ('host-a', $1, 'online', NOW()) RETURNING id`, tenant1ID,
	).Scan(&agent1ID)
	if err != nil {
		t.Fatalf("create agent1: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, tenant_id, status, last_seen)
		 VALUES ('host-b', $1, 'online', NOW()) RETURNING id`, tenant2ID,
	).Scan(&agent2ID)
	if err != nil {
		t.Fatalf("create agent2: %v", err)
	}

	// Test: With tenant1 context, should only see tenant1 agents
	_, err = pool.Exec(ctx, "SELECT set_config('app.tenant_id', $1, TRUE)", tenant1ID)
	if err != nil {
		t.Fatalf("set tenant context: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT id, hostname FROM agents`)
	if err != nil {
		t.Fatalf("query agents: %v", err)
	}
	defer rows.Close()

	var seen []string
	for rows.Next() {
		var id, hostname string
		rows.Scan(&id, &hostname)
		seen = append(seen, hostname)
	}

	for _, h := range seen {
		if h == "host-b" {
			t.Errorf("RLS violation: tenant1 context saw tenant2 agent 'host-b'")
		}
	}
	t.Logf("Tenant1 RLS: saw agents %v", seen)

	// Test: Clear tenant context, should see all agents (super-user behavior)
	_, err = pool.Exec(ctx, "SELECT set_config('app.tenant_id', '', TRUE)")
	if err != nil {
		t.Fatalf("clear tenant context: %v", err)
	}

	rows2, err := pool.Query(ctx, `SELECT COUNT(*) FROM agents`)
	if err != nil {
		t.Fatalf("count agents: %v", err)
	}
	defer rows2.Close()

	var total int
	if rows2.Next() {
		rows2.Scan(&total)
	}
	// With empty tenant_id, RLS policy allows all (based on OR condition in policy)
	t.Logf("No tenant context: total agents = %d", total)
}

// TestComplianceFrameworksSeeded verifies that compliance frameworks are seeded correctly.
func TestComplianceFrameworksSeeded(t *testing.T) {
	ctx := context.Background()
	db := startDB(t)

	pool := db.Pool()

	expectedFrameworks := []string{"soc2", "iso27001", "pcidss"}
	for _, fw := range expectedFrameworks {
		var count int
		err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM compliance_frameworks WHERE id=$1`, fw,
		).Scan(&count)
		if err != nil {
			t.Errorf("query framework %s: %v", fw, err)
			continue
		}
		if count != 1 {
			t.Errorf("framework %s: expected 1, got %d", fw, count)
		} else {
			t.Logf("framework %s seeded", fw)
		}
	}
}

// TestForensicsJobLifecycle tests the forensics_jobs table schema.
func TestForensicsJobLifecycle(t *testing.T) {
	ctx := context.Background()
	db := startDB(t)

	pool := db.Pool()

	jobID := "fj-test-001"
	_, err := pool.Exec(ctx,
		`INSERT INTO forensics_jobs (id, agent_id, type, status)
		 VALUES ($1, gen_random_uuid(), 'process_list', 'pending')`,
		jobID,
	)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}

	// Transition to running
	_, err = pool.Exec(ctx,
		`UPDATE forensics_jobs SET status='running' WHERE id=$1`, jobID)
	if err != nil {
		t.Fatalf("update to running: %v", err)
	}

	// Complete with artifact
	_, err = pool.Exec(ctx,
		`UPDATE forensics_jobs SET status='done', artifact_data=$1, completed_at=NOW() WHERE id=$2`,
		[]byte(`{"processes":[]}`), jobID,
	)
	if err != nil {
		t.Fatalf("complete job: %v", err)
	}

	var status string
	pool.QueryRow(ctx, `SELECT status FROM forensics_jobs WHERE id=$1`, jobID).Scan(&status)
	if status != "done" {
		t.Errorf("expected status 'done', got %q", status)
	}
	t.Logf("forensics job lifecycle: pending -> running -> done")
}
