package middleware

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// この middleware は長いあいだ**未配線のまま「直された」**経歴がある
// （NewAuditLogger の呼び出し元がゼロのまま、二世代カラム対応や Warn 格上げが
// 入っていた）。だからここでは (1) エントリの中身と (2) router への配線の両方を
// 通常の go test で押さえる。

func runAudit(t *testing.T, method, path, body string, setup func(*gin.Context)) (AuditEntry, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	var mu sync.Mutex
	var got AuditEntry
	captured := false
	done := make(chan struct{}, 1)

	a := &AuditLogger{logFn: func(_ context.Context, e AuditEntry) {
		mu.Lock()
		got = e
		captured = true
		mu.Unlock()
		done <- struct{}{}
	}}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		if setup != nil {
			setup(c)
		}
		c.Next()
	})
	r.Use(a.Middleware())
	handle := func(c *gin.Context) { c.Status(200) }
	r.POST("/*any", handle)
	r.GET("/*any", handle)

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 変異リクエストなら logFn が goroutine で呼ばれる
	if method != "GET" {
		<-done
	}
	mu.Lock()
	defer mu.Unlock()
	return got, captured
}

func TestAuditMiddleware_CapturesMutationWithUserRole(t *testing.T) {
	e, ok := runAudit(t, "POST", "/api/v1/agents/x/isolate", `{"reason":"test"}`, func(c *gin.Context) {
		// authMiddleware が置く鍵は "user_role"。"role" を読んでいた時期があり、
		// その鍵では user_role 列が永久に空になる。
		c.Set("user_id", "11111111-1111-1111-1111-111111111111")
		c.Set("user_role", "admin")
	})
	if !ok {
		t.Fatal("変異リクエストが監査に載っていない")
	}
	if e.Method != "POST" {
		t.Errorf("method: got %q", e.Method)
	}
	if e.UserID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("user_id: got %q", e.UserID)
	}
	if e.UserRole != "admin" {
		t.Errorf("user_role が拾えていない（鍵の名前を確認）: got %q", e.UserRole)
	}
	if !strings.Contains(e.RequestBody, "reason") {
		t.Errorf("通常経路の本文は保存される: got %q", e.RequestBody)
	}
}

func TestAuditMiddleware_SkipsReads(t *testing.T) {
	if _, ok := runAudit(t, "GET", "/api/v1/agents", "", nil); ok {
		t.Fatal("GET は監査に載せない")
	}
}

func TestAuditMiddleware_RedactsCredentialBodies(t *testing.T) {
	// /auth/login の本文は平文のパスワード。監査ログに写すと、
	// ログが資格情報の保管庫になる。
	e, ok := runAudit(t, "POST", "/api/v1/auth/login", `{"email":"a@example.com","password":"S3cret!pass"}`, nil)
	if !ok {
		t.Fatal("ログイン試行そのものは監査に載せる（総当たりの痕跡）")
	}
	if strings.Contains(e.RequestBody, "S3cret") {
		t.Fatalf("パスワードが監査ログに写っている: %q", e.RequestBody)
	}
	if e.RequestBody != "[redacted]" {
		t.Errorf("伏せ字の形: got %q", e.RequestBody)
	}

	e, _ = runAudit(t, "POST", "/api/v1/users/x/password", `{"new_password":"S3cret!pass"}`, nil)
	if strings.Contains(e.RequestBody, "S3cret") {
		t.Fatalf("パスワード変更の本文が写っている: %q", e.RequestBody)
	}
}

// 配線の契約: router が NewAuditLogger を実際に使っていること。
// この middleware は一度、未配線のまま数ヶ月「存在」していた —— その間、
// 生きていた別実装（router 内の簡易版）は書き込み失敗を握り潰していた。
func TestAuditLoggerIsWiredIntoRouter(t *testing.T) {
	b, err := os.ReadFile("../api/router.go")
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "NewAuditLogger(") {
		t.Fatal("router が NewAuditLogger を呼んでいない。監査 middleware がまた未配線に戻っている")
	}
	if strings.Contains(src, "func (s *Server) auditMiddleware()") {
		t.Fatal("router 内の旧 auditMiddleware が復活している。書き込み失敗を握り潰す実装なので戻さない")
	}
}
