package handlers_test

// エクスポートの列定義が実スキーマと一致しているかを、全タイプについて確認する。
//
// ExportHandler は「テーブルが存在するか」だけを事前に確認し、列名は検証せずに
// SELECT を組み立てる。そのため列名を 1 つ間違えるだけで、そのタイプの
// エクスポートがまるごと 500 になる。テーブルは存在するので事前チェックは
// 通ってしまい、実際にエクスポートを実行するまで誰も気づけない。
//
// 実際 events / agents / audit_logs / network_connections の 4 タイプが
// 実スキーマと食い違っていた（events は timestamp・data・id、agents は os・
// version、audit_logs は resource、network_connections は id・timestamp・bytes）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

func postExport(t *testing.T, h *handlers.ExportHandler, body map[string]any) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/export", bytes.NewReader(data))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Export(c)
	return w.Code, w.Body.String()
}

// TestExportHandler_AllTypesRunAgainstRealSchema は全エクスポートタイプを
// 実 DB に対して実行する。列名が実スキーマとずれていれば 500 になる。
func TestExportHandler_AllTypesRunAgainstRealSchema(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewExportHandler(pool)

	// exportTypes のキーと同じ集合。非公開変数なのでここに明示的に並べ、
	// タイプが増えたときにこのテストも更新されるようにしておく。
	types := []string{"alerts", "events", "agents", "audit_logs", "network_connections", "processes"}

	for _, typ := range types {
		for _, format := range []string{"json", "csv", "ndjson"} {
			t.Run(typ+"/"+format, func(t *testing.T) {
				code, body := postExport(t, h, map[string]any{
					"type":   typ,
					"format": format,
					"limit":  10,
				})
				if code != http.StatusOK {
					t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 400))
				}
				// ndjson は 1 行 1 レコードなので、0 件なら空ボディが正しい。
				// json は必ず構造を、csv は必ずヘッダ行を返す。
				if format != "ndjson" && body == "" {
					t.Errorf("%s 形式で空のレスポンス", format)
				}
			})
		}
	}
}

// TestExportHandler_RejectsUnknownType は未知のタイプが 400 になることを見る。
func TestExportHandler_RejectsUnknownType(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewExportHandler(pool)

	code, body := postExport(t, h, map[string]any{"type": "no_such_type", "format": "json"})
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", code, truncate(body, 200))
	}
}

// TestExportHandler_RejectsUnknownFormat は未知の format が 400 になることを見る。
func TestExportHandler_RejectsUnknownFormat(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewExportHandler(pool)

	code, body := postExport(t, h, map[string]any{"type": "alerts", "format": "xlsx"})
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body: %s)", code, truncate(body, 200))
	}
}

// TestExportHandler_ColumnAllowlist は、許可されていない列名を要求しても
// SQL に混ざらないことを確認する。ここが漏れると列名経由のインジェクションになる。
func TestExportHandler_ColumnAllowlist(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewExportHandler(pool)

	code, body := postExport(t, h, map[string]any{
		"type":    "alerts",
		"format":  "json",
		"columns": []string{"id", "title", "(SELECT password_hash FROM users LIMIT 1)"},
		"limit":   1,
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 400))
	}
	if bytes.Contains([]byte(body), []byte("password")) {
		t.Errorf("許可外の列が応答に現れている: %s", truncate(body, 300))
	}
}

// TestExportHandler_GetExportStatus は各タイプの利用可否一覧を返す経路。
func TestExportHandler_GetExportStatus(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewExportHandler(pool)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/export/status", nil)
	h.GetExportStatus(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, truncate(w.Body.String(), 300))
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
