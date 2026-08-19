package handlers_test

// 実在しないテーブル・列を参照して「静かに空を返す」箇所の再発防止。
//
// 一覧の静かな切り詰め（scan_truncation_guard_test.go）を掃除した後に残った、
// もう一つの静かな失敗の型がこれ。SQL が存在しない識別子を指しているので実 DB
// では必ずエラーになるが、呼び出し側が
//
//	_ = pool.QueryRow(...).Scan(&n)      // 件数は 0 のまま
//	if err == nil { ... }                // ブロックごと素通り
//	c.JSON(http.StatusOK, []T{})         // 空配列を 200 で返す
//
// と握り潰すため、画面には「該当なし」としか出ない。壊れていることを示す手掛かり
// が UI にもログにも残らない。2026-08-04 に実測した実害は次のとおり:
//
//   - insider-threat / ueba のリスクユーザ一覧が常に空（users.username が無い）
//   - SOC メトリクスの未解決インシデント一覧が常に空（users.display_name が無い）
//   - コンプライアンス/運用レポートの IOC 件数と有効プレイブック数が常に 0
//     （iocs テーブルが無い・playbooks.enabled が無い）
//   - IOC レトロハントが毎周期そのまま帰る（iocs テーブルが無い）
//   - ベンダーリスク一覧が常に空（vendor_assessments.created_at が無い）
//
// このテストは DB を必要としない。migrations/*.sql を読んで「存在しないこと」を
// 確かめたうえで、その識別子が Go のソースに再び現れていないことを見る。列名を
// 追加する正攻法で直した場合はマイグレーションが増えるので、このテストは自動的
// に黙る（存在するようになった識別子は禁止対象から外れる）。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// forbiddenIdentifier は「マイグレーションに無いのに SQL 文字列へ現れる」識別子。
type forbiddenIdentifier struct {
	// pattern は Go ソース中に現れてはならない SQL 断片。
	pattern string
	// table / column はスキーマ側の存在確認。column が空ならテーブル自体の
	// 存在を見る。実装された場合はその時点でこの禁止をスキップする。
	table  string
	column string
	// correct は正しい書き方（失敗メッセージ用）。
	correct string
	// symptom は放置した場合に利用者から見える症状。
	symptom string
}

var forbiddenIdentifiers = []forbiddenIdentifier{
	{
		pattern: "u.username",
		table:   "users", column: "username",
		correct: "users にあるのは email / full_name。OS ユーザ名の列は無いので結合キーにできない",
		symptom: "インサイダー脅威・UEBA のリスクユーザ一覧が常に空",
	},
	{
		pattern: "u.display_name",
		table:   "users", column: "display_name",
		correct: "users.full_name",
		symptom: "SOC メトリクスの未解決インシデント一覧が常に空",
	},
	{
		pattern: "FROM iocs",
		table:   "iocs",
		correct: "ioc_entries（列は ioc_type ではなく type、確度は severity 1-10）",
		symptom: "IOC 件数が常に 0、IOC レトロハントが毎周期空振り",
	},
	{
		pattern: "tablename='iocs'",
		table:   "iocs",
		correct: "tablename='ioc_entries'",
		symptom: "IOC レトロハントが存在チェックで必ず false になり毎周期帰る",
	},
	{
		pattern: "FILTER (WHERE enabled) FROM playbooks",
		table:   "playbooks", column: "enabled",
		correct: "playbooks.is_active",
		symptom: "コンプライアンススコアの有効プレイブック数が常に 0",
	},
	{
		pattern: "va.created_at",
		table:   "vendor_assessments", column: "created_at",
		correct: "vendor_assessments.assessed_at",
		symptom: "ベンダーリスク評価一覧が常に空",
	},
	// ── 2026-08-04 第2弾 (P1-7) ────────────────────────────────────────────
	{
		pattern: "FROM network_connections\n\t\t\t WHERE timestamp",
		table:   "network_connections", column: "timestamp",
		correct: "network_connections.time（002 の Timescale ハイパーテーブル）",
		symptom: "ネットワークマップのエッジが常に空",
	},
	{
		pattern: "FROM nta_detections WHERE created_at",
		table:   "nta_detections", column: "created_at",
		correct: "nta_detections.detected_at",
		symptom: "ネットワークトラフィックの suspicious_flows が常に 0",
	},
	{
		pattern: "FROM api_endpoints WHERE enabled",
		table:   "api_endpoints", column: "enabled",
		correct: "api_endpoints は 124 の定義が有効（risk_score INT）。168 の定義は " +
			"CREATE TABLE IF NOT EXISTS のため黙って捨てられている",
		symptom: "API セキュリティ統計のエンドポイント数と高リスク数が常に 0",
	},
	{
		pattern: "COALESCE(category, 'general'), COUNT(*) FROM rules",
		table:   "rules", column: "category",
		correct: "rules.type（'yara'|'sigma'|'behavioral'）",
		symptom: "コンプライアンススコアのルール内訳が常に空",
	},
	{
		pattern: "r.mitre_tactic",
		table:   "rules", column: "mitre_tactic",
		correct: "rules.mitre_tags TEXT[] を detection.TacticForTechnique で戦術へ写す",
		symptom: "MITRE カバレッジが常に空",
	},
	{
		pattern: "JOIN events e ON e.id",
		table:   "events", column: "id",
		correct: "events.event_id（時刻列も created_at ではなく time）",
		symptom: "MTTD が常に 0 分（もっともらしい値なので気付きにくい）",
	},
	{
		pattern: "THEN ' ' || resource ELSE",
		table:   "audit_logs", column: "resource",
		correct: "audit_logs.resource_id（resource を持つのは別テーブル audit_events）",
		symptom: "監査行だけでなくタイムライン全体が空（UNION 全体が落ちるため）",
	},
	{
		pattern: "FROM vuln_findings",
		table:   "vuln_findings",
		correct: "vulnerabilities（時刻列は found_at ではなく detected_at）",
		symptom: "コンプライアンスのパッチ状態が常に合格（未知を合格として採点する向きの誤り）",
	},
	{
		pattern: "FROM compliance_checks",
		table:   "compliance_checks",
		correct: "compliance_scores (042)。チェック単位の結果は details JSONB の checks 配列に " +
			"入るので LATERAL で展開する。POST /compliance/score が agent×framework で upsert する",
		symptom: "監査向けのコンプライアンスエクスポートが常に空（無い証拠を出すのと同じ）",
	},
	{
		pattern: "FROM endpoint_hardening\n",
		table:   "endpoint_hardening",
		correct: "ディスク暗号化は endpoint_encryption (362)、ファイアウォールは " +
			"hardening_assessments.findings の JSONB を LATERAL で展開して id='firewall' を引く",
		symptom: "コンプライアンスの暗号化・ファイアウォール判定が常に不合格（未計測と区別できない）",
	},
	{
		pattern: "FROM endpoint_hardening_assessments",
		table:   "endpoint_hardening_assessments",
		correct: "hardening_assessments (171)。364 でハードニングスキーマが統合され " +
			"363 の endpoint_hardening_* は DROP 済み。チェック単位の結果は findings JSONB",
		symptom: "コンプライアンスレポートの統制が常に空で、総合スコアだけ既定値 65.0 が出る",
	},
	{
		pattern: "rule_id = 'ioc-match'",
		table:   "alerts", column: "ioc_match_sentinel_never_exists",
		correct: "alerts.rule_id は uuid 型。IOC アラートは rule_id を空で作るので " +
			"title の '既知IOC検出: ' プレフィクスで数える",
		symptom: "IOC の7日間アラート数が常に 0",
	},
}

func TestNoReferencesToNonexistentSchemaIdentifiers(t *testing.T) {
	migrationSQL := readAllMigrations(t)

	for _, f := range forbiddenIdentifiers {
		f := f
		t.Run(f.pattern, func(t *testing.T) {
			cols, tableExists := schemaColumns(migrationSQL, f.table)
			if f.column == "" && tableExists {
				t.Skipf("テーブル %s が作られるようになったため、この禁止は不要になりました", f.table)
			}
			if f.column != "" && cols[f.column] {
				t.Skipf("%s.%s が追加されたため、この禁止は不要になりました", f.table, f.column)
			}
			hits := grepGoSources(t, f.pattern)
			if len(hits) > 0 {
				t.Errorf(`%q はスキーマに存在しません。%d 箇所が参照しています:

%s

正しくは: %s
放置した場合の症状: %s

実 DB ではクエリ全体がエラーになりますが、呼び出し側がエラーを握り潰して空配列や
0 件を返すため、画面上は「該当なし」としか見えません。`,
					f.pattern, len(hits), strings.Join(hits, "\n"), f.correct, f.symptom)
			}
		})
	}
}

// readAllMigrations concatenates every migration so the probes can ask "does the
// schema define this anywhere?" without needing a live database.
func readAllMigrations(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("migrations を読めません: %v", err)
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s を読めません: %v", e.Name(), err)
		}
		sb.Write(b)
		sb.WriteString("\n")
	}
	if sb.Len() == 0 {
		t.Fatal("migrations が空です（パスの解決に失敗している可能性があります）")
	}
	return sb.String()
}

// schemaColumns collects the columns migrations define for a table, from the
// CREATE TABLE body and later ALTER TABLE ... ADD COLUMN statements. The second
// return value reports whether the table is created at all.
//
// Scoping to one table matters: `username` and `display_name` both exist on other
// tables (ueba_anomalies, ad_users), so a probe that searched the whole migration
// text would conclude users had them.
//
// Only the FIRST CREATE TABLE counts, because that is what postgres does. Several
// tables here are created twice by different migrations with incompatible bodies —
// api_endpoints is defined by 124 (risk_score INT, is_public) and again by 168
// (risk_level TEXT, enabled BOOLEAN). `IF NOT EXISTS` makes the second a silent
// no-op, so 168's columns never exist. Merging every CREATE body would have this
// guard confirm columns the database does not have, which is how the api_endpoints
// breakage stayed invisible: the query referenced 168's schema, the table had
// 124's, and nothing objected.
//
// DROP TABLE is modelled, because a migration here does it: 364 consolidated the
// two rival hardening schemas and dropped 363's endpoint_hardening_* tables. A
// CREATE that a later migration drops must not count as "the table exists" — the
// compliance report kept querying endpoint_hardening_assessments long after 364
// removed it, and an earlier version of this helper would have reported the table
// present and skipped the probe.
func schemaColumns(sql, table string) (map[string]bool, bool) {
	cols := map[string]bool{}
	exists := false

	createRe := regexp.MustCompile(`(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?` +
		regexp.QuoteMeta(table) + `\s*\((.*?)\n\s*\)\s*;`)
	dropRe := regexp.MustCompile(`(?is)drop\s+table\s+(?:if\s+exists\s+)?(?:public\.)?` +
		regexp.QuoteMeta(table) + `\s*(?:cascade\s*)?;`)
	if loc := createRe.FindStringIndex(sql); loc != nil {
		// Migrations are concatenated in filename order, so a DROP appearing after
		// the last CREATE is the final word on whether the table exists.
		if d := dropRe.FindAllStringIndex(sql, -1); len(d) > 0 && d[len(d)-1][0] > loc[0] {
			return cols, false
		}
	}
	if m := createRe.FindStringSubmatch(sql); m != nil {
		exists = true
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			name := strings.ToLower(strings.Fields(line)[0])
			// Skip table-level constraints (PRIMARY KEY (...), UNIQUE(...), ...).
			switch name {
			case "primary", "unique", "foreign", "constraint", "check", "exclude":
				continue
			}
			cols[strings.Trim(name, "\"")] = true
		}
	}

	alterRe := regexp.MustCompile(`(?is)alter\s+table\s+(?:if\s+exists\s+)?(?:public\.)?` +
		regexp.QuoteMeta(table) + `\s+add\s+column\s+(?:if\s+not\s+exists\s+)?([a-z0-9_"]+)`)
	for _, m := range alterRe.FindAllStringSubmatch(sql, -1) {
		exists = true
		cols[strings.Trim(strings.ToLower(m[1]), "\"")] = true
	}

	return cols, exists
}

// grepGoSources returns "path:line" for every non-test Go source containing lit.
//
// Comment lines are skipped on purpose: the ban is on the SQL, not on prose that
// explains which identifier was wrong and why.
func grepGoSources(t *testing.T, lit string) []string {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(line, lit) {
				hits = append(hits, filepath.ToSlash(path)+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ソースの走査に失敗しました: %v", err)
	}
	return hits
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
