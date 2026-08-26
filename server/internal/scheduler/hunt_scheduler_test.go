package scheduler

import (
	"strings"
	"testing"
)

// validateSelectOnly はハントクエリが読み取り専用 (SELECT / WITH) であることを
// 保証するセキュリティガードである。ここが緩むとハント経由で任意の DML/DDL を
// 実行される恐れがあるため、許可・拒否の両方を網羅的に検証する。

func TestValidateSelectOnly_Allowed(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"単純なSELECT", "SELECT * FROM process_events"},
		{"小文字select", "select id from alerts"},
		{"先頭に空白", "   \n\t SELECT 1"},
		{"WITH句(CTE)", "WITH recent AS (SELECT * FROM alerts) SELECT * FROM recent"},
		{"小文字with", "with x as (select 1) select * from x"},
		{"列名にupdatedを含むが単語ではない", "SELECT updated_at FROM alerts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSelectOnly(tc.query); err != nil {
				t.Errorf("validateSelectOnly(%q) = %v, want nil", tc.query, err)
			}
		})
	}
}

func TestValidateSelectOnly_RejectsNonSelectPrefix(t *testing.T) {
	cases := []string{
		"INSERT INTO alerts VALUES (1)",
		"DELETE FROM alerts",
		"  DROP TABLE alerts",
		"EXPLAIN SELECT * FROM alerts",
		"",
	}
	for _, q := range cases {
		if err := validateSelectOnly(q); err == nil {
			t.Errorf("validateSelectOnly(%q) = nil, want error (SELECT/WITH で始まっていない)", q)
		}
	}
}

func TestValidateSelectOnly_RejectsEmbeddedDML(t *testing.T) {
	// SELECT で始まっていても、DML/DDL キーワードが埋め込まれていれば拒否する。
	cases := []struct {
		query   string
		keyword string
	}{
		{"SELECT 1; DROP TABLE alerts", "DROP"},
		{"SELECT 1; DELETE FROM alerts", "DELETE"},
		{"WITH x AS (SELECT 1) INSERT INTO y SELECT * FROM x", "INSERT"},
		{"SELECT 1; update alerts set x=1", "UPDATE"},
		{"SELECT 1; TRUNCATE alerts", "TRUNCATE"},
		{"SELECT 1; ALTER TABLE alerts ADD c int", "ALTER"},
		{"SELECT 1; CREATE TABLE t (id int)", "CREATE"},
		{"SELECT 1; GRANT ALL ON alerts TO evil", "GRANT"},
		{"SELECT 1; REVOKE ALL ON alerts FROM app", "REVOKE"},
	}
	for _, tc := range cases {
		t.Run(tc.keyword, func(t *testing.T) {
			err := validateSelectOnly(tc.query)
			if err == nil {
				t.Fatalf("validateSelectOnly(%q) = nil, want error", tc.query)
			}
			if !strings.Contains(err.Error(), tc.keyword) {
				t.Errorf("error = %q, キーワード %q を含むべき", err.Error(), tc.keyword)
			}
		})
	}
}
