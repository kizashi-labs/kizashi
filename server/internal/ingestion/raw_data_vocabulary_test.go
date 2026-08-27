package ingestion

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─── source extraction ───────────────────────────────────────────────────────

var (
	sqlLiteralRe  = regexp.MustCompile("(?s)`([^`]*)`")
	rawDataKeyRe  = regexp.MustCompile(`raw_data\s*(?:->>|->|#>>?)\s*'([a-zA-Z_0-9]+)'`)
	eventsTableRe = regexp.MustCompile(`(?is)\b(?:FROM|JOIN)\s+(?:public\.)?events\b`)
	// An `event_type = 'x'` comparison, or an `event_type IN ('x','y','z')` list.
	// The IN form matches the whole parenthesised group so every literal in it is
	// seen — matching only the first is how a query reading BOTH container_event
	// and process came to be judged against container_event's (empty) vocabulary,
	// which parked a live process-event defect in the allowlist as though the
	// telemetry simply did not exist.
	eventTypeEqRe       = regexp.MustCompile(`(?is)event_type\s*=\s*'([a-z_]+)'`)
	eventTypeInRe       = regexp.MustCompile(`(?is)event_type\s+IN\s*\(([^)]*)\)`)
	quotedLiteral       = regexp.MustCompile(`'([a-z_]+)'`)
	constraintLiteralRe = regexp.MustCompile(`'([a-z_]+)'::text`)
	// coalesceRe finds a COALESCE group so a wrong key written beside a right one
	// is recognised as a tolerated fallback rather than a dead read.
	coalesceRe = regexp.MustCompile(`(?is)COALESCE\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)`)
)

type rawDataRead struct {
	file   string
	key    string
	evType string // "" when the statement does not pin one
	line   string
}

// walkServerSQL calls fn for every SQL literal in non-test Go under server/.
func walkServerSQL(t *testing.T, fn func(file, sql string)) {
	t.Helper()
	root := filepath.Join("..", "..")
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
		for _, m := range sqlLiteralRe.FindAllStringSubmatch(string(b), -1) {
			fn(rel, m[1])
		}
		return nil
	}); err != nil {
		t.Fatalf("walk source: %v", err)
	}
}

// selectedEventTypes maps each event_type literal a query selects on to the
// files that select on it.
func selectedEventTypes(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	seen := map[string]bool{}
	walkServerSQL(t, func(file, sql string) {
		if !eventsTableRe.MatchString(sql) {
			return
		}
		for _, evType := range eventTypeLiterals(sql) {
			k := evType + "\x00" + file
			if seen[k] {
				continue
			}
			seen[k] = true
			out[evType] = append(out[evType], file)
		}
	})
	return out
}

// singleEventType returns the event_type a statement filters on, or "" when it
// names none or more than one.
func singleEventType(sql string) string {
	types := eventTypeLiterals(sql)
	if len(types) != 1 {
		return ""
	}
	return types[0]
}

// eventTypeLiterals returns every distinct event_type literal a statement
// compares against, from both the `= 'x'` and `IN ('x','y')` forms.
func eventTypeLiterals(sql string) []string {
	seen := map[string]bool{}
	for _, m := range eventTypeEqRe.FindAllStringSubmatch(sql, -1) {
		seen[m[1]] = true
	}
	for _, g := range eventTypeInRe.FindAllStringSubmatch(sql, -1) {
		for _, m := range quotedLiteral.FindAllStringSubmatch(g[1], -1) {
			seen[m[1]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rawDataReads collects every raw_data key read from a statement that selects
// from events, skipping keys COALESCEd with a key ingestion does produce.
func rawDataReads(t *testing.T, produced map[string]map[string]bool) []rawDataRead {
	t.Helper()
	union := map[string]bool{}
	for _, keys := range produced {
		for k := range keys {
			union[k] = true
		}
	}

	var out []rawDataRead
	walkServerSQL(t, func(file, sql string) {
		if !eventsTableRe.MatchString(sql) {
			return
		}
		// Only attribute an event type when the statement pins exactly one.
		// A statement with several subqueries, each filtering a different type,
		// would otherwise have every key judged against whichever type appeared
		// first — which is how a legitimate process.image_path read inside a
		// subquery came to be reported as auth.image_path.
		evType := singleEventType(sql)
		groups := coalesceRe.FindAllString(sql, -1)

		for _, loc := range rawDataKeyRe.FindAllStringSubmatchIndex(sql, -1) {
			key := sql[loc[2]:loc[3]]

			// A fallback beside a produced key is not a dead read.
			covered := false
			for _, g := range groups {
				if !strings.Contains(g, "'"+key+"'") {
					continue
				}
				for _, other := range rawDataKeyRe.FindAllStringSubmatch(g, -1) {
					if other[1] != key && union[other[1]] {
						covered = true
					}
				}
			}
			if covered {
				continue
			}

			start := strings.LastIndex(sql[:loc[0]], "\n") + 1
			end := strings.Index(sql[loc[0]:], "\n")
			if end < 0 {
				end = len(sql) - loc[0]
			}
			out = append(out, rawDataRead{
				file: file, key: key, evType: evType,
				line: strings.TrimSpace(sql[start : loc[0]+end]),
			})
		}
	})
	return out
}

// ─── (3) read keys ↔ written keys ────────────────────────────────────────────

// knownDeadRawDataKeys are raw_data keys read from events that
// normalizeEventData never writes. The key is "<event_type>.<key>", or just
// "<key>" when the statement does not pin a type.
//
// Each entry records what the read is therefore unable to see. These are not
// renames — the value in the entry is that the agent does not collect the datum
// at all, so the query needs either new telemetry or deletion. Renames were
// fixed rather than listed.
//
// The list only shrinks. A new dead key fails the test, and an entry whose key
// has become live must be deleted. It is a worklist, not an amnesty.
var knownDeadRawDataKeys = map[string]string{
	// ── container runtime ─────────────────────────────────────────────────
	// Containment itself is collected now, from /proc on the endpoint:
	// container_id, privileged and host_network need no runtime API because
	// they are kernel state (cgroup path, CapEff, net namespace).
	//
	// These two are not kernel state. They are the runtime's own bookkeeping,
	// and reaching them means a client for whichever runtime is present —
	// Docker, containerd, CRI-O, Podman — each with its own API, socket path
	// and permissions, mounted into the agent. The cgroup path does encode
	// them, but only sometimes and differently per runtime, so deriving them
	// from it would be a guess that is right often enough to be trusted and
	// wrong often enough to mislead.
}

// The rest of this list has been worked off, and how each one went is worth
// keeping because the shapes recur.
//
// Two were plain key-name errors with the datum right there under another name:
// hashes is written as the separate sha256 / sha1 / md5 keys, and the FIM
// change type is `operation`, carrying the FileEvent.Action enum name. The FIM
// one was not a substitution — the values differ too (FILE_ACTION_DELETE vs
// "deleted"), and because the missing key fell through to COALESCE's default of
// 'modified', deriveRiskReasons could never award "System file deleted". A
// missing key that has a plausible default is worse than one that does not: it
// answers confidently.
//
// Three were a semantic mismatch rather than a naming one. is_suspicious is the
// agent's DGA/homograph verdict and exists on DnsEvent alone. The equivalent
// judgement on a network event is threat_intel_matched and on a file event
// yara_matched; both are now read, so CIS-3.1 and the alert investigation
// graph light up on the evidence they were meant to. A process event has no
// such verdict at all, so that read is gone rather than repointed — the graph's
// process nodes are context around the alert, and inventing a verdict for them
// would be worse than having none.
//
// process.elevated was the same shape: no boolean is collected, but Windows
// elevation is integrity_level (Sysmon's Untrusted|Low|Medium|High|System), and
// High/System is precisely what CIS-1.1 was asking for. The username checks it
// sat beside cannot see an elevated ordinary administrator, who is neither root
// nor SYSTEM.
//
// dns.src_ip had no counterpart in the payload because DnsEvent carries no
// source address — but the query came from the endpoint, so the address is
// agents.ip_addresses and was on the server all along. A multi-homed endpoint
// makes the choice of interface a guess, so the screen returns agent_id too.

// Every raw_data key read from events must be one normalizeEventData can write
// for the event type being selected.
func TestEveryRawDataReadMatchesWhatIngestionWrites(t *testing.T) {
	produced := producedKeys(t)

	union := map[string]bool{}
	for _, keys := range produced {
		for k := range keys {
			union[k] = true
		}
	}

	reads := rawDataReads(t, produced)
	if len(reads) < 50 {
		t.Fatalf("raw_data の読み出しが %d 箇所しか見つかりませんでした — "+
			"抽出が壊れており、このテストはほぼ無条件に通ってしまいます", len(reads))
	}
	t.Logf("events.raw_data の読み出し %d 箇所を検査しました", len(reads))

	writes := func(r rawDataRead) bool {
		if r.evType != "" {
			if keys, ok := produced[r.evType]; ok {
				return keys[r.key]
			}
			// An event type with no payload probe (a log-style finding, or an
			// impossible type) cannot be judged by key; the event-type gate
			// covers it.
			return union[r.key]
		}
		return union[r.key]
	}

	seen := map[string]bool{}
	byLabel := map[string][]string{}
	for _, r := range reads {
		if writes(r) {
			continue
		}
		label := r.key
		if r.evType != "" {
			label = r.evType + "." + r.key
		}
		seen[label] = true
		byLabel[label] = append(byLabel[label], r.file+": "+r.line)
	}

	for label, sites := range byLabel {
		if _, known := knownDeadRawDataKeys[label]; known {
			continue
		}
		sort.Strings(sites)
		if len(sites) > 4 {
			sites = append(sites[:4], "…")
		}
		t.Errorf("raw_data のキー %q を読んでいますが、ingestion は"+
			"このキーを書きません。値は常に NULL です。\n  %s",
			label, strings.Join(sites, "\n  "))
	}

	for label := range knownDeadRawDataKeys {
		if !seen[label] {
			t.Errorf("knownDeadRawDataKeys の %q はもう読まれていないか、"+
				"ingestion が書くようになりました。行を削除してください", label)
		}
	}
}
