package handlers_test

// 残る未カバーの読み取り系エンドポイントのスモークテスト。
//
// 対象はいずれもテストが 1 本も無かったハンドラ。実 DB に対してクエリが通り、
// 期待した形の応答を返すことだけを確認する。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// callGET は GET ハンドラを 1 本叩き、ステータスと本文を返す。
func callGET(t *testing.T, target string, h gin.HandlerFunc) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	h(c)
	return w.Code, w.Body.String()
}

// ── 監査ログの署名付きエクスポート ───────────────────────────────

func TestAuditSignHandler_ExportSigned(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewAuditSignHandler(pool, "test-secret-for-signing")

	code, body := callGET(t, "/api/v1/audit/export-signed?limit=10", h.ExportSigned)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 400))
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (body: %s)", err, truncate(body, 200))
	}
	// 署名が無いと改竄検知の用をなさない。
	if _, ok := resp["signature"]; !ok {
		t.Errorf("署名が含まれていない (keys: %v)", mapKeys(resp))
	}
}

// TestAuditSignHandler_RejectsBadTimeRange は不正な時刻指定が 400 になることを見る。
func TestAuditSignHandler_RejectsBadTimeRange(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewAuditSignHandler(pool, "test-secret-for-signing")

	code, _ := callGET(t, "/api/v1/audit/export-signed?from=not-a-time", h.ExportSigned)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

// ── レポートエクスポート ─────────────────────────────────────────

func TestReportExportHandler_Endpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewReportExportHandler(pool)

	t.Run("ExportAlerts", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/reports/alerts.csv", h.ExportAlerts)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
	})

	t.Run("ExportCompliance", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/reports/compliance.csv", h.ExportCompliance)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
	})

	t.Run("不正な since は 400", func(t *testing.T) {
		code, _ := callGET(t, "/api/v1/reports/alerts.csv?since=nope", h.ExportAlerts)
		if code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", code)
		}
	})
}

// ── フォレンジクスジョブ ─────────────────────────────────────────

func TestForensicsHandler_ListJobs(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewForensicsHandler(pool, noopPublisher{})

	t.Run("フィルタなし", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/forensics/jobs", h.ListJobs)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
	})

	t.Run("agent_id 指定", func(t *testing.T) {
		code, body := callGET(t,
			"/api/v1/forensics/jobs?agent_id=d6d6d6d6-0000-4000-8000-000000000001", h.ListJobs)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
	})
}

// ── インストーラ配布 ─────────────────────────────────────────────

func TestInstallerHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewInstallerHandler("https://edr.example.test", t.TempDir(), pool)

	t.Run("ListTokens", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/installer/tokens", h.ListTokens)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
	})

	t.Run("LinuxInstaller", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/installer/linux.sh", h.LinuxInstaller)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
		// 生成物にサーバ URL が入っていないとインストーラとして機能しない。
		if !contains(body, "edr.example.test") {
			t.Errorf("生成スクリプトにサーバ URL が含まれていない: %s", truncate(body, 200))
		}
	})

	t.Run("WindowsInstaller", func(t *testing.T) {
		code, body := callGET(t, "/api/v1/installer/windows.ps1", h.WindowsInstaller)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", code, truncate(body, 300))
		}
		if !contains(body, "edr.example.test") {
			t.Errorf("生成スクリプトにサーバ URL が含まれていない: %s", truncate(body, 200))
		}
	})
}

// ── ユーザープロファイル ─────────────────────────────────────────

func TestUserProfileHandler_ReadOnlyEndpoints(t *testing.T) {
	db := testDB(t)
	h := handlers.NewUserProfileHandler(store.NewAuditStore(db), store.NewNotificationPrefStore(db))

	// いずれも認証済みユーザーを前提とするため user_id をコンテキストに積む。
	const userID = "d7d7d7d7-0000-4000-8000-000000000001"

	cases := []struct {
		name   string
		target string
		fn     gin.HandlerFunc
	}{
		{"LoginHistory", "/api/v1/me/login-history", h.LoginHistory},
		{"APIActivity", "/api/v1/me/api-activity", h.APIActivity},
		{"GetNotificationPrefs", "/api/v1/me/notification-prefs", h.GetNotificationPrefs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tc.target, nil)
			c.Set("user_id", userID)
			tc.fn(c)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, truncate(w.Body.String(), 300))
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
