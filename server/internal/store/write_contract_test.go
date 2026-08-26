package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The sibling gate in select_contract_test.go proves every static SELECT
// resolves against the migrated schema. Nothing proved the same of the writes,
// and there are 829 of them.
//
// A write that disagrees with the schema is worse than a read that does. A
// broken read renders an empty screen — misleading, but the data is still
// there. A broken write is an operator pressing a button, getting a response,
// and having nothing happen: the state they believe they changed is unchanged,
// and there is no later moment at which anyone finds out.
//
// This gate found exactly one, which is the point of running it now rather than
// after the next hundred statements are written. handlers/cloudruntime_handler
// blocked a runtime threat with `UPDATE events … WHERE id = $1`, and events has
// no id column (it is event_id). Every "block this threat" answered 500.
//
// Method is the same as the SELECT gate's: pgx Prepare sends Parse/Describe/
// Sync, which makes Postgres resolve every table, column, function and operator
// in the statement without executing it. An INSERT/UPDATE/DELETE prepared this
// way writes nothing.

// writeLiteralRe captures a backtick string, as SQL in this tree is always a Go
// raw string.
var writeLiteralRe = regexp.MustCompile("(?s)`([^`]*)`")

// writeStartRe recognises a statement this gate can check.
//
// The leading \s* is not redundant with the caller's TrimSpace: SQL in this
// tree is written as an indented raw string, so an untrimmed literal starts
// with a newline and two tabs. Relying on the caller to trim makes the
// extractor silently miss every statement the day someone calls it directly.
var writeStartRe = regexp.MustCompile(`(?is)^\s*(INSERT\s+INTO|UPDATE\s|DELETE\s+FROM)`)

// knownBrokenWrites are the writes that disagree with the migrated schema, each
// with what the failure costs. The map ratchets: an entry the scan stops
// finding must be deleted, so the list can never drift into describing history.
//
// いまは空です。**空にできたことより、いつ空になったかの方が大事です。**
//
// ここには「遡及ルールハントの再開位置を保存できない（どのマイグレーションも
// retro_rule_state を作らない）」が入っていました。同じキャンペーンの
// マイグレーション 382 がそのテーブルを作ったあとも、項目は残り続けました ——
// **このゲートを、全マイグレーションを当てた DB に対して一度も走らせて
// いなかったからです。** TEST_DATABASE_URL が無ければ丸ごと飛びます。
// 走っていない検査と、通った検査は、同じ行を出します。
var knownBrokenWrites = map[string]string{}

// environmentDependentWrites resolve or not according to what is installed
// rather than to anything in this repository, so they are exempt and are NOT
// ratcheted.
var environmentDependentWrites = map[string]string{
	"internal/store/migrate.go: [42P01] relation \"schema_migrations\" does not exist": "" +
		"マイグレーションランナー自身が直前に CREATE します",
}

// writeSite is one static write literal found in the source.
type writeSite struct {
	file string
	sql  string
}

// staticWrites collects every complete, static INSERT/UPDATE/DELETE literal in
// non-test Go, and separately counts the fragments it cannot check.
func staticWrites(t *testing.T) (sites []writeSite, fragments int) {
	t.Helper()
	root := filepath.Join("..", "..")
	seen := map[string]bool{}

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
		src := string(b)
		for _, loc := range writeLiteralRe.FindAllStringSubmatchIndex(src, -1) {
			sql := strings.TrimSpace(src[loc[2]:loc[3]])
			if !writeStartRe.MatchString(sql) {
				continue
			}
			// A literal carrying a format verb is one piece of a query built at
			// runtime. It cannot be prepared, so it is counted and reported
			// rather than silently dropped.
			if interpolationRe.MatchString(sql) {
				fragments++
				continue
			}
			key := rel + "\x00" + sql
			if seen[key] {
				continue
			}
			seen[key] = true
			sites = append(sites, writeSite{file: rel, sql: sql})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source: %v", err)
	}
	return sites, fragments
}

// TestEveryWriteAgreesWithTheSchema is the gate.
func TestEveryWriteAgreesWithTheSchema(t *testing.T) {
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

	// The database must be a faithful replica of the migrations, or a "missing"
	// column would only mean this database is behind.
	assertSchemaMatchesMigrations(t, pool)

	sites, fragments := staticWrites(t)
	if len(sites) < 250 {
		t.Fatalf("only %d static writes found — the extractor is broken and this "+
			"test would pass nearly vacuously", len(sites))
	}
	t.Logf("static INSERT/UPDATE/DELETE literals checked: %d (%d runtime-assembled fragments skipped)",
		len(sites), fragments)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	found := map[string]bool{}
	var problems []string
	for i, s := range sites {
		// Prepare only: Parse/Describe/Sync resolves the statement without
		// running it, so nothing here writes to the database.
		_, err := conn.Conn().Prepare(ctx, fmt.Sprintf("writegate%d", i), s.sql)
		if err == nil {
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("%s: preparing returned a non-Postgres error: %v", s.file, err)
		}
		kind, isSchema := schemaFailure[pgErr.Code]
		if !isSchema {
			continue // syntax error from a runtime-assembled fragment
		}

		key := fmt.Sprintf("%s: [%s] %s", s.file, pgErr.Code, pgErr.Message)
		found[key] = true
		if _, exempt := environmentDependentWrites[key]; exempt {
			continue
		}
		if _, known := knownBrokenWrites[key]; known {
			continue
		}
		one := strings.Join(strings.Fields(s.sql), " ")
		if len(one) > 160 {
			one = one[:160] + "…"
		}
		problems = append(problems, fmt.Sprintf("%s (%s)\n      %s", key, kind, one))
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("書き込みが現在のスキーマと一致しません。"+
			"操作は成功したように見えて、状態は変わりません: %s", p)
	}

	// Ratchet: an entry the scan no longer finds must go.
	for key := range knownBrokenWrites {
		if !found[key] {
			t.Errorf("knownBrokenWrites still lists %q, but the scan no longer "+
				"finds it. Delete the entry.", key)
		}
	}
}

// The extractor has to actually recognise writes, and has to reject what it
// cannot check. Both halves matter: an extractor that finds nothing makes the
// gate vacuous, and one that treats a runtime-assembled fragment as a statement
// reports a syntax error as a schema defect.
func TestTheWriteExtractorWorks(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want bool
	}{
		{"insert", "INSERT INTO agents (id) VALUES ($1)", true},
		{"update", "UPDATE agents SET status = $1", true},
		{"delete", "DELETE FROM agents WHERE id = $1", true},
		{"lowercase", "insert into agents (id) values ($1)", true},
		{"leading newline", "\n\t\tUPDATE agents SET status = $1", true},
		{"select is not a write", "SELECT * FROM agents", false},
		{"cte is not a write", "WITH x AS (SELECT 1) SELECT * FROM x", false},
		{"updated_at is not an UPDATE", "updated_at = NOW()", false},
		{"a word starting with delete", "deleted_at IS NULL", false},
	} {
		if got := writeStartRe.MatchString(tc.sql); got != tc.want {
			t.Errorf("%s: recognised=%v, want %v (%q)", tc.name, got, tc.want, tc.sql)
		}
	}

	for _, tc := range []struct {
		name string
		sql  string
		want bool
	}{
		{"format verb", "UPDATE agents SET %s = $1", true},
		{"no verb", "UPDATE agents SET status = $1", false},
	} {
		if got := interpolationRe.MatchString(tc.sql); got != tc.want {
			t.Errorf("%s: fragment=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// The two allowlists must not overlap, or an entry could be exempt and
// ratcheted at once and the ratchet would never fire on it.
func TestTheWriteAllowlistsAreDisjoint(t *testing.T) {
	for key := range knownBrokenWrites {
		if _, both := environmentDependentWrites[key]; both {
			t.Errorf("%q is in both knownBrokenWrites and environmentDependentWrites", key)
		}
	}
}
