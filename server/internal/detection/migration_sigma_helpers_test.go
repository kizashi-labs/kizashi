package detection

// migration の SQL から Sigma ルール本文を取り出す道具。**検査は入っていません。**
//
// もとは migration_sigma_parse_test.go の中にありました。あちらは
// 「migration が積んだルールが 100 本以上あること」を前提に置いた検査で、
// **有償エディションの検知ルール migration を落とした配布では成り立たない**ため
// 同梱していません。ところが道具まで一緒に消えるので、道具だけを使っている
// 4 本（linux_builtins / scp_exfil / shutdown_reboot / windows_vm_discovery）が
// package ごとコンパイルできなくなり、**detection のテストが 1 本も走らない**
// 状態になっていました。
//
// 道具を describe の無いファイルへ出す、というのはフロントエンド側で
// 同じ理由から先にやってあります（tests/lib/route-scan.ts ほか）。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	ruleTitleRe = regexp.MustCompile(`(?m)^title:\s*(.*)$`)
	// Opening delimiter of a Postgres dollar-quoted string: $$ or $tag$.
	dollarOpenRe = regexp.MustCompile(`\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$`)
)

// dollarQuotedBodies returns the contents of every dollar-quoted string in sql.
//
// This started life as the regexp `\$\$(.*?)\$\$`, which silently saw only the
// untagged form. Postgres also allows a TAG between the dollars, and migration
// 014 uses $SIGMA$ — so its five Sigma rules, including the WMI lateral-movement
// rule, were never once handed to the parser this file exists to run them
// through. The gate reported green over a file it could not see: the same shape
// as the inert-rule bugs it was written to catch, in the checker itself.
//
// It cannot go back to being one regexp. Matching a tagged quote requires
// asserting that the closing delimiter equals the opening one, and RE2 has no
// backreferences. So the tag is captured and the closer is found by index.
func dollarQuotedBodies(sql string) []string {
	var out []string
	for i := 0; i < len(sql); {
		loc := dollarOpenRe.FindStringIndex(sql[i:])
		if loc == nil {
			break
		}
		start, end := i+loc[0], i+loc[1]
		delim := sql[start:end]
		rest := sql[end:]
		n := strings.Index(rest, delim)
		if n < 0 {
			// Unterminated: nothing sensible to extract, and skipping only this
			// delimiter would rescan the body as if it were SQL.
			break
		}
		out = append(out, rest[:n])
		i = end + n + len(delim)
	}
	return out
}

// sigmaBlock is one rule's content and the migration it last came from.
type sigmaBlock struct {
	file string
	body string
}

// migrationSigmaBlocks returns the Sigma rule content the database ends up with,
// keyed by rule title.
//
// Migrations are replayed in filename order and a later definition of the same
// title REPLACES an earlier one, because that is what the database does: 019
// inserts a rule, 371 UPDATEs it, and only 371's content survives. Keeping both
// would make this test report a defect that no longer exists in any running
// system — and a checker that reports fixed bugs gets disabled just as fast as
// one that misses real ones.
//
// Matching on `detection:` + `condition:` rather than on the surrounding SQL is
// intentional: rules arrive via INSERT in some migrations and UPDATE in others,
// and a checker that only understood INSERT would go quiet exactly when a rule
// is being rewritten.
func migrationSigmaBlocks(t *testing.T) map[string]sigmaBlock {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	out := map[string]sigmaBlock{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, body := range dollarQuotedBodies(string(b)) {
			if !strings.Contains(body, "detection:") || !strings.Contains(body, "condition:") {
				continue
			}
			title := "(untitled)"
			if tm := ruleTitleRe.FindStringSubmatch(body); tm != nil {
				title = strings.TrimSpace(tm[1])
			}
			out[title] = sigmaBlock{file: name, body: body}
		}
	}
	return out
}
