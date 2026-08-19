package store

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

// This platform had two answers to "which customer does this row belong to".
//
//	tenants        migration 027. 55 tables carry tenant_id REFERENCES
//	               tenants(id). RLS is enforced against it — the API middleware
//	               puts tenant_id in the request context and store.Connect's
//	               PrepareConn hook calls set_config('app.tenant_id') on every
//	               connection. Served by /tenants and /admin/tenants.
//
//	organizations  migration 183. Zero foreign keys pointed at it. Exactly one
//	               Go file read it — internal/tenant/store.go — behind
//	               /admin/organizations and the 組織管理 screen.
//
// Both were seeded with the same default UUID, which is the only reason a
// single-tenant deployment never noticed. What the split cost:
//
//   - tenant.GetStats counted agents, users and alerts WHERE org_id = $1 on
//     three tables with no org_id column, discarded all three errors and
//     returned (stats, nil). Every organization reported 0/0/0, always.
//   - An organization created through the API could never own anything: agents,
//     users and alerts are foreign keys into tenants.
//   - internal/middleware/tenant.go, which looked an org up for access control,
//     was never registered on a route.
//   - organizations.settings held allow_sso, retention_days, logo_url and
//     primary_color. Those four names appeared in their own struct definition
//     and nowhere else, and the UI's SSO toggle POSTed "sso_allowed", which did
//     not even match the "allow_sso" JSON tag.
//
// Migration 380 dropped the table; the package, handler and routes went with
// it. These gates keep the second answer from coming back — as a table, as a
// query, or as a route.

// orgReferenceRe finds SQL naming the dropped table. Word-bounded so that
// organization_id or organizational_units elsewhere would not trip it.
var orgReferenceRe = regexp.MustCompile(`(?i)\b(FROM|INTO|UPDATE|TABLE|JOIN)\s+"?organizations"?\b`)

// deadOrgRouteRe finds the routes that served it.
var deadOrgRouteRe = regexp.MustCompile(`"/admin/organizations"|"/org/current"|"/org/settings"|"/org"`)

// TestThereIsOnlyOneTenancyTable is the schema half.
func TestThereIsOnlyOneTenancyTable(t *testing.T) {
	schema := migrationSchema(t)

	if _, present := schema["organizations"]; present {
		t.Error("organizations テーブルが復活しています。テナント境界の答えは tenants 一つです " +
			"— 55テーブルの tenant_id が参照しているのは tenants で、RLS もそちらに対して効きます")
	}

	cols, ok := schema["tenants"]
	if !ok {
		t.Fatal("tenants がマイグレーションにありません。移行先が失われています")
	}
	// If these go, the gate above would be passing by having lost both models
	// rather than by having consolidated onto one.
	for _, want := range []string{"id", "name", "slug", "plan", "max_agents", "is_active"} {
		if _, present := cols[want]; !present {
			t.Errorf("tenants.%s がありません", want)
		}
	}
}

// TestNoCodeReadsTheOrganizationsTable is the source half. A query naming a
// dropped table fails at runtime with 42P01, but every failure this file was
// written about was a silent one, so the point is to fail early and legibly.
func TestNoCodeReadsTheOrganizationsTable(t *testing.T) {
	root := filepath.Join("..", "..")
	var problems []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range orgReferenceRe.FindAllString(stripGoComments(string(b)), -1) {
			problems = append(problems, rel+": "+strings.Join(strings.Fields(m), " "))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("organizations テーブルを参照しています。migration 380 で削除されました "+
			"— テナントは tenants を参照してください: %s", p)
	}
}

// TestTheOrganizationRoutesAreGone keeps the endpoints from being re-added
// against some other backing store. They reported 0 agents, 0 users and
// 0 alerts for every organization, and the UI rendered that as fact.
func TestTheOrganizationRoutesAreGone(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "api", "router.go"))
	if err != nil {
		t.Fatalf("read router: %v", err)
	}
	src := stripGoComments(string(b))

	for _, m := range deadOrgRouteRe.FindAllString(src, -1) {
		t.Errorf("削除されたルート %s が復活しています。"+
			"テナント管理は /admin/tenants です", m)
	}

	// And the surviving tenant handlers must still be wired, or this would pass
	// by having removed tenant management altogether. Matched on the handler
	// rather than the path: /admin/tenants is registered as a subgroup of an
	// /admin group, so the full path never appears as one literal.
	for _, want := range []string{
		"s.handlers.tenants.List",
		"s.handlers.MultiTenant.ListTenants",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("%s の登録が見つかりません。移行先が失われています", want)
		}
	}
}

// TestTenancyForeignKeysPointAtTenants is the check that makes the choice
// non-arbitrary: it is the database, not a preference, that says which table is
// authoritative. These three are the ones GetStats counted with the wrong
// column.
func TestTenancyForeignKeysPointAtTenants(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	for _, table := range []string{"agents", "users", "alerts"} {
		var refs string
		err := pool.QueryRow(ctx, `
			SELECT ccu.table_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
			  ON tc.constraint_name = kcu.constraint_name
			JOIN information_schema.constraint_column_usage ccu
			  ON tc.constraint_name = ccu.constraint_name
			WHERE tc.constraint_type = 'FOREIGN KEY'
			  AND tc.table_name = $1
			  AND kcu.column_name = 'tenant_id'`, table).Scan(&refs)
		if err != nil {
			t.Errorf("%s.tenant_id の外部キーが読めません: %v", table, err)
			continue
		}
		if refs != "tenants" {
			t.Errorf("%s.tenant_id が %q を参照しています。期待は tenants", table, refs)
		}
	}

	// The count that used to be structurally zero must now be answerable.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE tenant_id = $1`,
		"00000000-0000-0000-0000-000000000001").Scan(&n); err != nil {
		t.Errorf("テナント単位のエージェント数が数えられません: %v", err)
	}
}

// TestTheOrganizationScanWorks stops the source gate passing because the regex
// stopped matching.
func TestTheOrganizationScanWorks(t *testing.T) {
	for _, bad := range []string{
		"q := `SELECT id FROM organizations WHERE id = $1`",
		"q := `INSERT INTO organizations (name) VALUES ($1)`",
		"q := `UPDATE organizations SET name=$1`",
		"q := `SELECT o.id FROM tenants t JOIN organizations o ON o.id = t.id`",
	} {
		if !orgReferenceRe.MatchString(bad) {
			t.Errorf("organizations の参照を検出できませんでした: %q", bad)
		}
	}
	for _, ok := range []string{
		"q := `SELECT id FROM tenants WHERE id = $1`",
		"q := `SELECT organization_id FROM billing_customers`",
		"q := `SELECT id FROM organizational_units`",
	} {
		if orgReferenceRe.MatchString(ok) {
			t.Errorf("正常なコードを organizations 参照として検出しました: %q", ok)
		}
	}

	// A comment explaining the removal must not read as a use of it.
	commented := "// organizations was dropped by migration 380\n" +
		"q := `SELECT id FROM tenants`"
	if orgReferenceRe.MatchString(stripGoComments(commented)) {
		t.Error("コメント中のテーブル名が使用として検出されました")
	}

	// And the route scan.
	if !deadOrgRouteRe.MatchString(`protected.Group("/admin/organizations")`) {
		t.Error("削除されたルートを検出できませんでした")
	}
	if deadOrgRouteRe.MatchString(`protected.Group("/admin/tenants")`) {
		t.Error("生きているルートを削除済みとして検出しました")
	}
}
