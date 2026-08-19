package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 姿勢管理が読む列が、本当に存在すること。
//
// `/api/v1/cloud/posture` は、表の名前だけを差し替えて同じ SQL を両方に
// 投げていました。実測 (2026-08-13):
//
//	cspm_findings            provider 列が無く、`finding` 列も無い
//	cloud_misconfigurations  resource_type も resource_id も `finding` も無い
//
// **どちらを選んでも 42703 で落ちます。**149 を当てた DB には cspm_findings が
// あるので先に選ばれ、この画面はデータを返したことが一度もありませんでした。
//
// この環境に PostgreSQL は無いので、実行では確かめられません。**移行ファイル
// が唯一の一次資料**なので、そこから列名を読んで突き合わせます。

var columnRef = regexp.MustCompile(`\b([a-z])\.([a-z_]+)\b|\b([a-z][a-z_]{2,})\b`)

// sqlKeywords は、列名として数えない語です。
var sqlKeywords = map[string]bool{
	"coalesce": true, "nullif": true, "join": true, "on": true, "and": true,
	"or": true, "not": true, "null": true, "case": true, "when": true,
	"then": true, "else": true, "end": true, "global": true, "unknown": true,
	"open": true, "critical": true, "high": true, "medium": true, "low": true,
	"aws": true, "azure": true, "gcp": true, "alibaba": true,
	// 表そのものの名前は列ではありません（FROM 句に出ます）。
	"cspm_findings": true, "cspm_accounts": true, "cloud_misconfigurations": true,
}

// migrationColumns は、その表を作る移行ファイルから列名を読みます。
func migrationColumns(t *testing.T, table string) map[string]bool {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("移行ファイルが読めません: %v", err)
	}
	head := regexp.MustCompile(`(?is)CREATE TABLE (?:IF NOT EXISTS )?` + table + `\s*\((.*?)\n\);`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s を読めません: %v", f, err)
		}
		m := head.FindSubmatch(b)
		if m == nil {
			continue
		}
		cols := map[string]bool{}
		for _, line := range strings.Split(string(m[1]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			name := strings.Fields(line)[0]
			name = strings.Trim(name, ",")
			if name == "" || strings.EqualFold(name, "PRIMARY") ||
				strings.EqualFold(name, "UNIQUE") || strings.EqualFold(name, "CHECK") ||
				strings.EqualFold(name, "FOREIGN") || strings.EqualFold(name, "CONSTRAINT") {
				continue
			}
			cols[name] = true
		}
		// ALTER TABLE で足された列も拾います。
		for _, g := range files {
			ab, err := os.ReadFile(g)
			if err != nil {
				continue
			}
			for _, mm := range regexp.MustCompile(
				`(?i)ALTER TABLE `+table+` ADD COLUMN (?:IF NOT EXISTS )?([a-z_]+)`).FindAllSubmatch(ab, -1) {
				cols[string(mm[1])] = true
			}
		}
		return cols
	}
	t.Fatalf("%s を作る移行ファイルがありません", table)
	return nil
}

func TestCloudPostureReadsColumnsThatExist(t *testing.T) {
	byAlias := map[string]string{
		"f": "cspm_findings",
		"a": "cspm_accounts",
	}
	cases := []struct {
		name     string
		exists   func(string) bool
		fallback string // 別名の付いていない列が属する表
	}{
		{"cspm_findings がある場合", func(s string) bool { return s == "cspm_findings" }, ""},
		{"cloud_misconfigurations だけの場合",
			func(s string) bool { return s == "cloud_misconfigurations" }, "cloud_misconfigurations"},
	}

	cols := map[string]map[string]bool{}
	get := func(table string) map[string]bool {
		if _, ok := cols[table]; !ok {
			cols[table] = migrationColumns(t, table)
		}
		return cols[table]
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := cloudPostureSource(tc.exists)
			if src.from == "" {
				t.Fatal("表が在るのに読み方が空です")
			}
			checked := 0
			for _, expr := range []string{
				src.from, src.provider, src.severity, src.status,
				src.resourceType, src.resourceID, src.finding, src.region,
			} {
				for _, m := range columnRef.FindAllStringSubmatch(expr, -1) {
					alias, col, bare := m[1], m[2], m[3]
					table := ""
					switch {
					case alias != "":
						table = byAlias[alias]
					case bare != "" && !sqlKeywords[bare]:
						table, col = tc.fallback, bare
					}
					if table == "" || col == "" {
						continue
					}
					if strings.EqualFold(col, "id") || strings.EqualFold(col, "account_id") {
						// 結合の両端。表の定義側で確かめます。
					}
					if !get(table)[col] {
						t.Errorf("%s.%s は移行ファイルにありません（%q）。"+
							"**42703 になり、この画面は 500 を返します**", table, col, expr)
					}
					checked++
				}
			}
			// **0 件を検査して緑を返すのがいちばん高くつきます。**
			if checked < 6 {
				t.Errorf("列を %d 個しか見ていません。読み方の取り出しが壊れています", checked)
			}
		})
	}
}

// 表が1つも無ければ、読み方は空です（呼び出し側が問い合わせを飛ばします）。
func TestCloudPostureSourceIsEmptyWithoutTables(t *testing.T) {
	if src := cloudPostureSource(func(string) bool { return false }); src.from != "" {
		t.Errorf("表が無いのに %q から読もうとしています", src.from)
	}
}
