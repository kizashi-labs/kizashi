package agentconfig

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// covPool connects to TEST_DATABASE_URL (the migrated schema), skipping when
// unset so pure-logic runs stay green. Drives the config-profile CRUD lifecycle
// plus the default-profile / by-OS lookups against the real schema.
func covPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping agentconfig coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestStore_ProfileCRUD_DB(t *testing.T) {
	pool := covPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	p, err := s.CreateProfile(ctx, &Profile{
		Name: "cov-profile", Description: "d", OSType: "linux", IsDefault: false,
	})
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agent_config_profiles WHERE id=$1", p.ID) })

	if _, err := s.GetProfile(ctx, p.ID); err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if _, err := s.ListProfiles(ctx); err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if _, err := s.UpdateProfile(ctx, p.ID, &Profile{
		Name: "cov-profile-2", Description: "d2", OSType: "linux", IsDefault: false,
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	_, _ = s.GetDefaultProfile(ctx, "linux")

	// 戻り値を捨てず err を検証する。ここを `_, _ =` にしていたため、
	// ListAgentsByOSType が存在しない列 os を参照して 42703 を返し続けていても
	// このテストは green のままだった（PushProfileAll は常に 500 だった）。
	// 実スキーマに対して走るテストなので、列名の誤りはここで落ちる。
	if _, err := s.ListAgentsByOSType(ctx, "linux"); err != nil {
		t.Fatalf("ListAgentsByOSType: %v", err)
	}
	// 'all' は「全 OS を対象」を意味する特別値。分岐が違うので別途通す。
	if _, err := s.ListAgentsByOSType(ctx, "all"); err != nil {
		t.Fatalf("ListAgentsByOSType(all): %v", err)
	}
	if err := s.DeleteProfile(ctx, p.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
}
