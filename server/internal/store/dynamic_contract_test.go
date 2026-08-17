package store

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The two sibling gates prove every STATIC SELECT and every STATIC write agrees
// with the schema. Both skip the statements assembled at runtime, and both say
// so — 100 of them, which is where the remaining risk sits: a fragment is
// exactly the shape no gate had been able to look at.
//
// Most of them are not really dynamic. The overwhelming pattern is a fixed
// column list held in a package-level constant, interpolated into an otherwise
// fixed statement:
//
//	fmt.Sprintf(`SELECT %s FROM auto_response_rules ORDER BY created_at ASC`,
//	            autoResponseRuleSelectCols)
//
// The constant is knowable at compile time, so the statement is knowable too.
// This gate parses the tree, resolves each Sprintf argument that is a string
// constant or literal, fills the numeric verbs with a value that cannot change
// how the statement resolves, and prepares the result.
//
// What it cannot resolve it reports and ratchets, rather than quietly counting
// itself as coverage. That distinction is the whole point: a gate that appears
// to check 100 statements while actually checking 40 is worse than one that
// checks 40 and says so.

// dynStart recognises a format string this gate can check.
var dynStart = regexp.MustCompile(`(?is)^\s*(SELECT|WITH|INSERT\s+INTO|UPDATE\s|DELETE\s+FROM)`)

// verbRe finds the format verbs in a statement, in order.
var verbRe = regexp.MustCompile(`%[a-zA-Z]`)

// knownUnresolvableStatements are the runtime-assembled statements whose
// arguments cannot be resolved from the source, with what each one is.
//
// These are the genuinely dynamic ones: a WHERE clause built from the request,
// a UNION of per-source sub-selects, a table name chosen by the caller. A gate
// cannot prepare them without reconstructing the builder, and a test that
// reconstructs the builder passes whatever the builder does — the failure mode
// this campaign has hit four times.
//
// Where the builder was already extracted into a function, the statement it
// returns IS checked, by the test that calls it. buildExportQuery is the model:
// export_types_executable_test.go executes what the handler builds, for every
// type and column. Moving one of these out of its handler and testing it that
// way is how an entry leaves this list.
//
// The map ratchets: an entry the scan stops finding must be deleted.
var knownUnresolvableStatements = map[string]string{
	"cmd/seed/main.go: DELETE FROM %s WHERE %s > NOW() - INTERVAL '365 days'": "" +
		"シードの掃除。表と時刻列を呼び出し側が渡します",
	"internal/api/handlers/alerts_handler.go: SELECT tech, COUNT(DISTINCT id) AS cnt, MAX(severity) AS max_sev FROM ( SELECT id, severity, mitre_technique AS tech FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique != '' %s UNION ALL SELECT id, severity, unnest(ai_mitre_t…": "" +
		"MITRE 集計。UNION の両腕に同じ絞り込み句を差し込みます",
	"internal/api/handlers/audit_export_handler.go: SELECT COALESCE(id,''), COALESCE(user_id,''), COALESCE(action,''), '', COALESCE(resource_id,''), COALESCE(details::text,'{}'), timestamp, '', COALESCE(ip_address,'') FROM audit_logs %s ORDER BY timestamp DESC LIMIT $%d": "" +
		"監査ログのエクスポート。WHERE を要求のフィルタから組み立てます",
	"internal/api/handlers/data_retention_handler.go: DELETE FROM %s WHERE %s": "" +
		"保持ポリシー。表と述語は retentionSpecs から決まるため、handlers 側の TestEveryRetentionStatementAgreesWithTheSchema が実文を組み立てて検査しています",
	"internal/api/handlers/data_retention_handler.go: SELECT COUNT(*) FROM %s WHERE %s": "" +
		"保持ポリシー。表と述語は retentionSpecs から決まるため、handlers 側の TestEveryRetentionStatementAgreesWithTheSchema が実文を組み立てて検査しています",
	"internal/api/handlers/data_retention_handler.go: SELECT COUNT(*) FROM %s": "" +
		"保持ポリシー。表と述語は retentionSpecs から決まるため、handlers 側の TestEveryRetentionStatementAgreesWithTheSchema が実文を組み立てて検査しています",
	"internal/api/handlers/endpoint_groups_handler.go: SELECT a.id::text, a.hostname, a.os_type, COALESCE((SELECT host(ipx) FROM unnest(a.ip_addresses) ipx LIMIT 1), ''), a.last_seen FROM agents a WHERE %s ORDER BY a.hostname LIMIT 500": "" +
		"端末グループのメンバー判定。WHERE がグループ定義そのものです",
	"internal/api/handlers/events_handler.go: SELECT COUNT(*) FROM (SELECT 1 FROM events %s LIMIT %d) t": "" +
		"イベント一覧。WHERE を要求のフィルタから組み立てます",
	"internal/api/handlers/events_handler.go: SELECT event_id::text, time::text, event_type, COALESCE(raw_data->>'image_path', raw_data->>'process_name', raw_data->>'destination_ip', raw_data->>'path', raw_data->>'username', raw_data->>'query', 'Event') AS title, COALESCE(raw_data->>'c…": "" +
		"イベント一覧。WHERE を要求のフィルタから組み立てます",
	"internal/api/handlers/export_handler.go: SELECT %s FROM %s %s %s ORDER BY %s DESC LIMIT $%d": "" +
		"エクスポート。buildExportQuery が関数として切り出されており、export_types_executable_test.go が全型・全列で実文を実行しています",
	"internal/api/handlers/export_handler.go: SELECT COUNT(*) FROM %s": "" +
		"エクスポート。buildExportQuery が関数として切り出されており、export_types_executable_test.go が全型・全列で実文を実行しています",
	"internal/api/handlers/soc_metrics_handler.go: SELECT CASE WHEN lower(title) LIKE '%%ransomware%%' OR lower(title) LIKE '%%ランサム%%' THEN 'ランサムウェア' WHEN lower(title) LIKE '%%malware%%' OR lower(title) LIKE '%%マルウェア%%' THEN 'マルウェア検知' WHEN lower…": "" +
		"カテゴリ別集計。%% を含むため書式適用後と原文が一致しません",
	"internal/api/handlers/timeline_handler.go: SELECT COUNT(*) FROM (%s) AS combined %s": "" +
		"タイムラインは複数ソースの UNION。部分文の組み立てを再現すると「実装と同じものを書いたテスト」になります",
	"internal/api/handlers/timeline_handler.go: SELECT eid, etype, etitle, edetail, eseverity, eagent_id, ts FROM (%s) AS combined %s ORDER BY ts DESC LIMIT $%d OFFSET $%d": "" +
		"タイムラインは複数ソースの UNION。部分文の組み立てを再現すると「実装と同じものを書いたテスト」になります",
	"internal/audit/logger.go: SELECT COUNT(*) FROM audit_events WHERE %s": "" +
		"監査イベントの検索。WHERE を要求のフィルタから組み立てます",
	"internal/audit/logger.go: SELECT id, timestamp, user_id, username, action, resource, resource_id, org_id, ip_address, user_agent, success, details, risk_score FROM audit_events WHERE %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d": "" +
		"監査イベントの検索。WHERE を要求のフィルタから組み立てます",
	"internal/hunting/query_engine.go: SELECT e.event_id::text, e.agent_id::text, COALESCE(a.hostname, e.agent_id::text), e.event_type, e.time, COALESCE(e.severity, 0), e.raw_data FROM events e LEFT JOIN agents a ON a.id = e.agent_id WHERE %s ORDER BY e.time %s LIMIT %d": "" +
		"スレットハンティング。WHERE も並び順もユーザのクエリ由来です",
	"internal/scheduler/retro_ioc_hunter.go: SELECT event_id::text, agent_id::text, %s AS matched, time FROM events WHERE event_type = $1 AND time > NOW() - $2::interval AND %s = ANY($3::text[]) ORDER BY time DESC LIMIT $4": "" +
		"遡及 IOC ハント。照合する raw_data のキーを呼び出し側が選びます",
	"internal/store/alerts.go: UPDATE alerts SET %s WHERE id = $1": "" +
		"部分更新。変更されたフィールドだけを SET に並べます",
	"internal/store/audit.go: SELECT id, timestamp, COALESCE(user_id,''), COALESCE(user_email,''), action, COALESCE(resource_id,''), COALESCE(ip_address,''), status_code, COALESCE(details,'{}') FROM audit_logs %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d": "" +
		"監査ログの一覧。WHERE を要求のフィルタから組み立てます",
	"internal/store/auto_response_store.go: UPDATE auto_response_executions SET status = $2, result_msg = $3%s WHERE id = $1": "" +
		"部分更新。完了時刻を条件付きで SET に足します",
	"internal/store/device_events.go: SELECT id, agent_id, action, device_id, COALESCE(device_name,''), COALESCE(device_type,''), COALESCE(vendor_id,''), COALESCE(product_id,''), raw_data::text, created_at FROM device_events %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d": "" +
		"デバイスイベントの一覧。WHERE を要求のフィルタから組み立てます",
	"internal/store/fim_rules.go: SELECT %s FROM fim_rules %s ORDER BY created_at ASC LIMIT $%d OFFSET $%d": "" +
		"一覧の WHERE が要求由来です。列リスト定数そのものは同ファイルの `SELECT %s FROM fim_rules WHERE id = $1` が解決済みで検査されています",
	"internal/store/process_block_rules.go: SELECT %s FROM process_block_rules %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d": "" +
		"同上 (process_block_rules)",
	"internal/store/yara_rules.go: SELECT %s FROM yara_rules %s ORDER BY enabled DESC, updated_at DESC LIMIT $%d OFFSET $%d": "" +
		"同上 (yara_rules)",
}

// siteKey names a site for the allowlist. The format string is single-spaced
// and truncated, because some of these run to 600 characters and an allowlist
// nobody can read is an allowlist nobody maintains. Truncation is safe only if
// no two sites collide on the shortened form, which TestTheSiteKeysAreUnique
// checks — a collision would let one waived statement silently cover another.
func siteKey(s dynSite) string {
	one := strings.Join(strings.Fields(s.format), " ")
	if len(one) > siteKeyLen {
		one = one[:siteKeyLen] + "…"
	}
	return s.file + ": " + one
}

// siteKeyLen is the truncation point for an allowlist key.
//
// 240 rather than something shorter and tidier: at 110 two of the SOC-metrics
// statements collapsed onto the same key, and at 200 one pair still did. The
// number is what TestTheSiteKeysAreUnique demands, not a preference.
const siteKeyLen = 240

// dynSite is one runtime-assembled statement found in the source.
type dynSite struct {
	file   string
	format string
	args   []string // resolved argument values, nil entry = unresolved
}

// stringConsts collects package-level string constants and variables per
// directory, so an argument that names one can be resolved.
//
// Keyed by directory rather than by import path because a Sprintf argument is
// always resolved against its own package here — none of these statements
// interpolate a constant from another package, and assuming otherwise would
// silently resolve the wrong value.
func stringConsts(t *testing.T, root string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		dir := filepath.Dir(path)
		if out[dir] == nil {
			out[dir] = map[string]string{}
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if v, ok := constString(vs.Values[i]); ok {
						out[dir][name.Name] = v
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk for constants: %v", err)
	}
	return out
}

// constString evaluates a string expression made of literals and `+`.
func constString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := constString(x.X)
		if !ok {
			return "", false
		}
		r, ok := constString(x.Y)
		if !ok {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return constString(x.X)
	}
	return "", false
}

// dynamicSites finds every fmt.Sprintf whose format string is a statement.
func dynamicSites(t *testing.T, root string, consts map[string]map[string]string) []dynSite {
	t.Helper()
	var sites []dynSite
	seen := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		dir := filepath.Dir(path)

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Sprintf" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
				return true
			}
			format, ok := constString(call.Args[0])
			if !ok || !dynStart.MatchString(strings.TrimSpace(format)) {
				return true
			}
			format = strings.TrimSpace(format)

			args := make([]string, 0, len(call.Args)-1)
			for _, a := range call.Args[1:] {
				if v, ok := constString(a); ok {
					args = append(args, v)
					continue
				}
				if id, ok := a.(*ast.Ident); ok {
					if v, ok := consts[dir][id.Name]; ok {
						args = append(args, v)
						continue
					}
				}
				args = append(args, "")
			}
			key := rel + "\x00" + format
			if seen[key] {
				return true
			}
			seen[key] = true
			sites = append(sites, dynSite{file: rel, format: format, args: args})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk for Sprintf sites: %v", err)
	}
	return sites
}

// concrete fills a site's verbs. It reports false when a %s-family verb has no
// resolved argument, because substituting a placeholder there would produce a
// statement the code never issues and a gate that passes for the wrong reason.
func concrete(s dynSite) (string, bool) {
	verbs := verbRe.FindAllString(s.format, -1)
	out := s.format
	argi := 0
	for _, v := range verbs {
		var repl string
		switch v {
		case "%d":
			// Any integer resolves the same way; 7 keeps intervals sane.
			repl = "7"
		case "%t":
			repl = "true"
		default:
			if argi >= len(s.args) || s.args[argi] == "" {
				return "", false
			}
			repl = s.args[argi]
		}
		if v != "%d" && v != "%t" {
			argi++
		} else {
			argi++
		}
		out = strings.Replace(out, v, repl, 1)
	}
	return out, true
}

// TestEveryResolvableDynamicStatementAgreesWithTheSchema is the gate.
func TestEveryResolvableDynamicStatementAgreesWithTheSchema(t *testing.T) {
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
	assertSchemaMatchesMigrations(t, pool)

	root := filepath.Join("..", "..")
	consts := stringConsts(t, root)
	sites := dynamicSites(t, root, consts)
	if len(sites) < 60 {
		t.Fatalf("only %d runtime-assembled statements found — the extractor is "+
			"broken and this test would pass nearly vacuously", len(sites))
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	resolved, unresolved := 0, 0
	found := map[string]bool{}
	var problems []string

	for i, s := range sites {
		stmt, ok := concrete(s)
		if !ok {
			unresolved++
			key := siteKey(s)
			found[key] = true
			if _, known := knownUnresolvableStatements[key]; !known {
				problems = append(problems, fmt.Sprintf(
					"引数を解決できない実行時組み立てが増えました。"+
						"検査できないなら、そうと記録してください: %s", key))
			}
			continue
		}
		resolved++
		_, perr := conn.Conn().Prepare(ctx, fmt.Sprintf("dyngate%d", i), stmt)
		if perr == nil {
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(perr, &pgErr) {
			t.Fatalf("%s: preparing returned a non-Postgres error: %v", s.file, perr)
		}
		kind, isSchema := schemaFailure[pgErr.Code]
		if !isSchema {
			// A resolved statement that is still one arm of a larger query, or
			// otherwise not a complete statement, shows up as a syntax error.
			continue
		}
		one := strings.Join(strings.Fields(stmt), " ")
		if len(one) > 160 {
			one = one[:160] + "…"
		}
		problems = append(problems, fmt.Sprintf(
			"%s: [%s] %s (%s)\n      %s", s.file, pgErr.Code, pgErr.Message, kind, one))
	}

	t.Logf("実行時組み立ての文: %d件中 %d件を実文まで解決して検査、%d件は解決不能 (内訳は knownUnresolvableStatements)",
		len(sites), resolved, unresolved)

	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}

	// Ratchet: an entry the scan no longer finds must go.
	for key := range knownUnresolvableStatements {
		if !found[key] {
			t.Errorf("knownUnresolvableStatements still lists %q, but the scan no "+
				"longer finds it. Delete the entry.", key)
		}
	}
}

// The resolver has to actually resolve, and has to refuse what it cannot.
// Both halves matter: a resolver that silently substitutes a placeholder for an
// unknown argument turns "unchecked" into "passed".
func TestTheDynamicResolverRefusesWhatItCannotResolve(t *testing.T) {
	for _, tc := range []struct {
		name string
		site dynSite
		want string
		ok   bool
	}{
		{
			"resolved column list",
			dynSite{format: "SELECT %s FROM agents", args: []string{"id, hostname"}},
			"SELECT id, hostname FROM agents", true,
		},
		{
			"numeric verb needs no argument",
			dynSite{format: "SELECT * FROM alerts WHERE created_at > NOW() - INTERVAL '%d days'", args: nil},
			"SELECT * FROM alerts WHERE created_at > NOW() - INTERVAL '7 days'", true,
		},
		{
			"boolean verb",
			dynSite{format: "SELECT * FROM rules WHERE enabled = %t", args: nil},
			"SELECT * FROM rules WHERE enabled = true", true,
		},
		{
			"unresolved string argument is refused",
			dynSite{format: "SELECT COUNT(*) FROM %s", args: []string{""}},
			"", false,
		},
		{
			"missing argument is refused",
			dynSite{format: "SELECT COUNT(*) FROM %s", args: nil},
			"", false,
		},
		{
			"mixed verbs keep their order",
			dynSite{format: "SELECT %s FROM alerts WHERE created_at > NOW() - INTERVAL '%d days'",
				args: []string{"id"}},
			"SELECT id FROM alerts WHERE created_at > NOW() - INTERVAL '7 days'", true,
		},
	} {
		got, ok := concrete(tc.site)
		if ok != tc.ok {
			t.Errorf("%s: resolvable=%v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// And the constant evaluator must handle the form these column lists are
// actually written in — a raw string broken across lines with `+`.
func TestTheConstantEvaluatorHandlesConcatenatedLiterals(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go",
		"package p\nconst cols = `id, name, ` +\n\t`enabled`\nconst n = 42\n", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if v, ok := constString(vs.Values[0]); ok {
				got[vs.Names[0].Name] = v
			}
		}
	}
	if got["cols"] != "id, name, enabled" {
		t.Errorf("連結された定数を評価できていません: %q", got["cols"])
	}
	if _, isString := got["n"]; isString {
		t.Error("数値定数を文字列として拾っています")
	}
}

// Allowlist keys are truncated, so two different statements in the same file
// could share one. That would let a waived statement silently cover a second
// one nobody ever looked at — the exact failure this gate exists to prevent.
func TestTheSiteKeysAreUnique(t *testing.T) {
	root := filepath.Join("..", "..")
	sites := dynamicSites(t, root, stringConsts(t, root))
	if len(sites) < 60 {
		t.Fatalf("only %d sites found — the extractor is broken", len(sites))
	}
	seen := map[string]string{}
	for _, s := range sites {
		k := siteKey(s)
		if prev, dup := seen[k]; dup && prev != s.format {
			t.Errorf("2つの文が同じ許可リストキーに潰れています (%q)。"+
				"siteKeyLen を伸ばしてください:\n  %s\n  %s", k, prev, s.format)
		}
		seen[k] = s.format
	}
}

// The two allowlists this package holds must not overlap with each other's
// purpose either: an entry here is "cannot be checked", an entry in
// knownBrokenSelects is "checked and wrong". A statement in both would be
// claimed as waived twice and ratcheted by neither.
func TestTheDynamicAllowlistDoesNotOverlapTheStaticOnes(t *testing.T) {
	for k := range knownUnresolvableStatements {
		file := strings.SplitN(k, ": ", 2)[0]
		for other := range knownBrokenSelects {
			if strings.HasPrefix(other, file+": [") {
				t.Logf("参考: %s は静的側にも未修正の項目があります (%s)", file, other)
			}
		}
	}
}
