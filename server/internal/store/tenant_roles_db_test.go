package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// HasRole が、切り出した判定を本当に通っていること。
//
// **切り出しただけでは何も保証されません。** `RoleAtLeast` を直しても、
// `HasRole` が別の比較を持ったままなら検査は緑で、権限判定は嘘のままです。
// このキャンペーンで `readVmRSS` と `scanPidMapsStats` のときに同じ穴を
// 開けかけました。
//
// `HasRole` には**製品側の呼び出し元がありません。** いま壊れている
// わけではなく、**誰かが使い始めた日に静かに間違う**形です。

// seedTenantRole creates the tenant, the user and the role row.
//
// **飛ばしません。** 外部キーが張られているので土台の行が要ります ——
// 用意せずに Skip すると、権限判定の検査が「走った」ことになりません。
func seedTenantRole(t *testing.T, db *store.DB, tenantID, userID, role string) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $2)
	      ON CONFLICT (id) DO NOTHING`, tenantID, "role-probe-tenant")
	exec(`INSERT INTO users (id, email, role) VALUES ($1::uuid, $2, 'analyst')
	      ON CONFLICT (id) DO NOTHING`, userID, "role-probe@example.test")
	exec(`INSERT INTO tenant_roles (tenant_id, user_id, role)
	      VALUES ($1::uuid, $2::uuid, $3)
	      ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		tenantID, userID, role)

	t.Cleanup(func() {
		_, _ = db.Pool().Exec(ctx,
			"DELETE FROM tenant_roles WHERE tenant_id=$1::uuid AND user_id=$2::uuid",
			tenantID, userID)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1::uuid", userID)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM tenants WHERE id=$1::uuid", tenantID)
	})
}

func TestHasRoleGoesThroughRoleAtLeast(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()

	const tenantID = "11111111-1111-1111-1111-111111111111"
	const userID = "22222222-2222-2222-2222-222222222222"
	seedTenantRole(t, db, tenantID, userID, "viewer")

	s := store.NewTenantRoleStore(db.Pool())

	ok, err := s.HasRole(ctx, tenantID, userID, "viewer")
	if err != nil {
		t.Fatalf("HasRole: %v", err)
	}
	if !ok {
		t.Error("viewer が viewer の要件を満たしていません")
	}

	ok, err = s.HasRole(ctx, tenantID, userID, "tenant_admin")
	if err != nil {
		t.Fatalf("HasRole: %v", err)
	}
	if ok {
		t.Error("**viewer が tenant_admin の要件を満たしています。** " +
			"権限判定が反転しているか、切り出した判定を通っていません")
	}

	// 知らないロールは error です（**true ではありません**）。
	if _, err := s.HasRole(ctx, tenantID, userID, "superadmin"); err == nil {
		t.Error("知らないロール名がエラーになっていません")
	}
}
