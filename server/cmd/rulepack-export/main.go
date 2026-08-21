// Command rulepack-export reads detection rules out of a database and writes
// them as a rule pack.
//
// It exists because the rules did not start life as content. 2,404 of them are
// embedded as INSERT statements across 96 migrations, in a dozen different
// column orders, with dollar-quoted YAML bodies and interleaved comments.
// Parsing that SQL back out is possible and would be wrong: the result would be
// a second implementation of Postgres's parser, maintained forever, whose bugs
// would silently drop rules.
//
// Applying the migrations and reading the table instead makes the database the
// authority on what the migrations meant, which it already is.
//
// Usage:
//
//	rulepack-export -db postgres://… -migrations ./migrations \
//	    -name core -version 2026.08 -out rulepacks/core.json
//
// The -migrations flag is optional. Given it, the tool applies migrations
// first, so the export can run against an empty throwaway database:
//
//	docker run -d --name pack-src -e POSTGRES_PASSWORD=x -p 15432:5432 timescale/timescaledb:latest-pg16
//	rulepack-export -db postgres://postgres:x@localhost:15432/postgres \
//	    -migrations server/migrations -name core -version 2026.08 -out rulepacks/core.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/edr-platform/server/internal/rulepack"
	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	var (
		dbURL       = flag.String("db", "", "postgres connection URL (required)")
		migrations  = flag.String("migrations", "", "apply migrations from this directory first (optional)")
		name        = flag.String("name", "core", "pack name; forms the first half of pack_key")
		version     = flag.String("version", "", "pack version, e.g. 2026.08 (required)")
		out         = flag.String("out", "", "output path (required)")
		ruleType    = flag.String("type", "", "export only this rule type (sigma|yara|behavioral); empty exports all")
		onlyEnabled = flag.Bool("only-enabled", false, "skip rules that are disabled in the source database")
	)
	flag.Parse()

	if *dbURL == "" || *version == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "-db, -version and -out are required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fail("connect: %v", err)
	}
	defer pool.Close()

	if *migrations != "" {
		if err := store.RunMigrations(ctx, pool, *migrations); err != nil {
			fail("apply migrations: %v", err)
		}
	}

	rules, err := readRules(ctx, pool, *ruleType, *onlyEnabled)
	if err != nil {
		fail("read rules: %v", err)
	}
	if len(rules) == 0 {
		// An empty pack is rejected by the loader, and silently writing one
		// here would turn "the export did not work" into "the pack is empty",
		// which only shows up later as detections that never fire.
		fail("no rules matched; refusing to write an empty pack")
	}

	pack := rulepack.Pack{
		Name:        *name,
		Version:     *version,
		Description: fmt.Sprintf("Exported from %d rules in the rules table", len(rules)),
		Rules:       rules,
	}
	// Validate before writing. A pack this tool cannot load is not worth
	// shipping, and finding out at the customer's next update is too late.
	if err := pack.Validate(); err != nil {
		fail("the exported pack does not validate: %v", err)
	}

	if err := writePack(*out, &pack); err != nil {
		fail("write: %v", err)
	}
	fmt.Printf("wrote %s: %d rules (pack %q version %q)\n", *out, len(rules), pack.Name, pack.Version)
}

// readRules pulls the content-bearing columns. Columns the platform owns —
// id, compiled, timestamps, tenant_id, curate_state, quarantine fields — are
// deliberately not exported: a pack that could set them would describe rows the
// server never intended to accept.
func readRules(ctx context.Context, pool *pgxpool.Pool, ruleType string, onlyEnabled bool) ([]rulepack.Rule, error) {
	q := `
		SELECT name, type, platform, severity, content,
		       COALESCE(description, ''), COALESCE(source, 'community'),
		       COALESCE(mitre_tags, '{}'), COALESCE(ref_links, '{}'), COALESCE(tags, '{}'),
		       COALESCE(enabled, true), COALESCE(auto_isolate, false),
		       COALESCE(auto_kill, false), COALESCE(auto_quarantine, false)
		FROM rules
		WHERE ($1 = '' OR type = $1)
		  AND (NOT $2::bool OR COALESCE(enabled, true))
		  AND pack_key IS NULL
		ORDER BY type, name`

	rows, err := pool.Query(ctx, q, ruleType, onlyEnabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []rulepack.Rule
	seen := map[string]bool{}
	for rows.Next() {
		var r rulepack.Rule
		var enabled bool
		if err := rows.Scan(&r.Name, &r.Type, &r.Platform, &r.Severity, &r.Content,
			&r.Description, &r.Source, &r.MitreTags, &r.RefLinks, &r.Tags,
			&enabled, &r.AutoIsolate, &r.AutoKill, &r.AutoQuarantine); err != nil {
			return nil, err
		}
		// The source table has no unique constraint on name, and does contain
		// duplicates. Two rules with one name would collapse onto a single
		// pack_key, so the pack would load fewer rules than it lists — exactly
		// the silent shortfall the loader's validation exists to prevent.
		if seen[r.Name] {
			return nil, fmt.Errorf("duplicate rule name %q in the source database; "+
				"resolve it there before exporting (the pack keys on name)", r.Name)
		}
		seen[r.Name] = true

		r.Enabled = &enabled
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Type != rules[j].Type {
			return rules[i].Type < rules[j].Type
		}
		return rules[i].Name < rules[j].Name
	})
	return rules, nil
}

// writePack emits indented JSON so the file diffs readably. A rule pack is
// reviewed like content, not like a binary artefact.
func writePack(path string, pack *rulepack.Pack) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
