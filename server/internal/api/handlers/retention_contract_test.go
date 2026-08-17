package handlers

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The data-retention endpoints build their statements from retentionSpecs — a
// table name and a time column per policy type, plus an optional extra
// predicate. That makes them invisible to the two schema gates in
// internal/store, which can only prepare statements whose text is fixed:
// store.knownUnresolvableStatements lists them and points here.
//
// They are checkable exactly, though, because the specs are a compile-time
// table and purgeWhere is the production builder. This test asks the same
// builder for the same clause and prepares what it produced, so a spec naming a
// column the table does not have fails here rather than on the first purge.
//
// That matters more for these than for a read: PurgeNow issues a DELETE. A
// wrong time column would either delete nothing (a retention policy that
// silently never runs, so the disk fills) or match the wrong rows.

func retentionPool(t *testing.T) *pgxpool.Pool {
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

// TestEveryRetentionStatementAgreesWithTheSchema is the gate.
func TestEveryRetentionStatementAgreesWithTheSchema(t *testing.T) {
	pool := retentionPool(t)
	ctx := context.Background()

	if len(retentionSpecs) < 3 {
		t.Fatalf("retentionSpecs holds %d entries — too few for this test to be "+
			"checking anything", len(retentionSpecs))
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	var types []string
	for k := range retentionSpecs {
		types = append(types, k)
	}
	sort.Strings(types)

	n := 0
	for _, typ := range types {
		sp := retentionSpecs[typ]
		// The three statements the handlers build, with the production
		// purgeWhere rather than a copy of it: a test that wrote its own clause
		// would pass whatever the handler does.
		stmts := []string{
			fmt.Sprintf(`SELECT COUNT(*) FROM %s`, sp.table),
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s`, sp.table, sp.purgeWhere()),
			fmt.Sprintf(`DELETE FROM %s WHERE %s`, sp.table, sp.purgeWhere()),
		}
		for _, stmt := range stmts {
			n++
			// Prepare only — Parse/Describe/Sync resolves the statement without
			// running it, so the DELETE deletes nothing.
			if _, err := conn.Conn().Prepare(ctx, fmt.Sprintf("retgate%d", n), stmt); err != nil {
				t.Errorf("保持ポリシー %q の文がスキーマと一致しません: %v\n      %s\n"+
					"retentionSpecs の table / timeCol / extra を確認してください。"+
					"PurgeNow は DELETE を発行するので、時刻列が違えば"+
					"「一件も消えない保持ポリシー」になり、ディスクだけが増えます",
					typ, err, stmt)
			}
		}
	}
	t.Logf("保持ポリシー %d 種類 × 3文 = %d 文を検査しました", len(types), n)
}

// The extra predicate must actually reach the clause. It is the only part of a
// spec that is optional, so it is the part a refactor drops without noticing —
// and dropping it on `alerts` would widen the purge from resolved alerts to
// every alert older than the cutoff.
func TestTheRetentionClauseCarriesTheExtraPredicate(t *testing.T) {
	withExtra := retentionSpec{table: "alerts", timeCol: "updated_at", extra: "status = 'resolved'"}
	plain := retentionSpec{table: "events", timeCol: "time"}

	gotExtra := withExtra.purgeWhere()
	gotPlain := plain.purgeWhere()

	if gotExtra == gotPlain {
		t.Fatalf("extra の有無で述語が変わりません (%q)", gotExtra)
	}
	for _, want := range []string{"updated_at < $1", "status = 'resolved'"} {
		if !strings.Contains(gotExtra, want) {
			t.Errorf("述語に %q がありません: %q", want, gotExtra)
		}
	}
	if strings.Contains(gotPlain, "AND") {
		t.Errorf("extra が無いのに AND が付いています: %q。"+
			"空の条件を AND で繋ぐと構文エラーになります", gotPlain)
	}

	// And the live specs must still carry theirs: alerts is the one that has it,
	// and losing it is a silent widening of what gets deleted.
	if sp, ok := retentionSpecs["alerts"]; !ok || sp.extra == "" {
		t.Error("alerts の保持ポリシーから extra が消えています。" +
			"未解決のアラートまで削除対象になります")
	}
}
