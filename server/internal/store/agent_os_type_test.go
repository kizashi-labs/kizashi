package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// TestUpdateLastSeen_OSTypeCorrection pins the fix for a Windows host that was
// auto-created from a heartbeat and then displayed as Linux forever: the
// hardcoded fallback belongs to the INSERT branch only, and a later heartbeat
// that does report its OS must be able to correct the stored value.
func TestUpdateLastSeen_OSTypeCorrection(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentStore(db)
	ctx := context.Background()
	id := uuidNewStr()

	osTypeOf := func() string {
		var got string
		if err := db.Pool().QueryRow(ctx, `SELECT os_type FROM agents WHERE id = $1::uuid`, id).Scan(&got); err != nil {
			t.Fatalf("read os_type: %v", err)
		}
		return got
	}

	// Auto-create with no OS reported — the fallback applies.
	if err := s.UpdateLastSeen(ctx, id, "cov-os-host", []string{"10.0.0.1"}, "0.1", "", ""); err != nil {
		t.Fatalf("UpdateLastSeen (insert): %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, id) })
	if got := osTypeOf(); got != "linux" {
		t.Fatalf("insert fallback os_type = %q, want linux", got)
	}

	// The agent now reports its real OS: the stored value must follow.
	if err := s.UpdateLastSeen(ctx, id, "cov-os-host", []string{"10.0.0.1"}, "0.1",
		"Windows Server 2022 (Build 20348)", "windows"); err != nil {
		t.Fatalf("UpdateLastSeen (correct): %v", err)
	}
	if got := osTypeOf(); got != "windows" {
		t.Fatalf("os_type after windows heartbeat = %q, want windows", got)
	}

	// A heartbeat that omits the OS must not drag it back to the fallback.
	if err := s.UpdateLastSeen(ctx, id, "cov-os-host", []string{"10.0.0.1"}, "0.1", "", ""); err != nil {
		t.Fatalf("UpdateLastSeen (unreported): %v", err)
	}
	if got := osTypeOf(); got != "windows" {
		t.Fatalf("os_type after unreported heartbeat = %q, want windows", got)
	}

	// An out-of-range value would violate the agents.os_type CHECK constraint;
	// it is treated as unreported rather than written through.
	if err := s.UpdateLastSeen(ctx, id, "cov-os-host", []string{"10.0.0.1"}, "0.1", "", "freebsd"); err != nil {
		t.Fatalf("UpdateLastSeen (invalid): %v", err)
	}
	if got := osTypeOf(); got != "windows" {
		t.Fatalf("os_type after invalid heartbeat = %q, want windows", got)
	}
}
