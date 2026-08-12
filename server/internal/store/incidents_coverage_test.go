package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// Drives the IncidentStore link/note/read paths against the migrated schema.
// LinkAlert/UnlinkAlert touch incidents.alert_ids (added by migration 323).
func TestIncidentStore_LinkAndNotes(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	s := store.NewIncidentStore(db)

	userID := seedUserStore(t, db)
	agentID := seedAgentStore(t, db)

	var incID, alertID string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO incidents (title, description, severity, status)
		 VALUES ('cov-inc', 'd', 7, 'open') RETURNING id::text`).Scan(&incID); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM incidents WHERE id=$1", incID) })
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status, created_at)
		 VALUES ($1::uuid, 8, 'cov-inc-alert', 'd', 'open', NOW()) RETURNING id::text`, agentID).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })

	if err := s.LinkAlert(ctx, incID, alertID); err != nil {
		t.Fatalf("LinkAlert: %v", err)
	}
	if _, err := s.AddNote(ctx, incID, userID, "cov note"); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if _, err := s.ListNotes(ctx, incID); err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if _, err := s.Get(ctx, incID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, _, err := s.List(ctx, "open", 20, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.UnlinkAlert(ctx, incID, alertID); err != nil {
		t.Fatalf("UnlinkAlert: %v", err)
	}
}
