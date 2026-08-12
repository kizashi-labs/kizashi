package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/compliance"
)

// ─── parseFramework ────────────────────────────────────────────────────────

// ginContextWithQuery constructs a minimal *gin.Context with the given query string.
func ginContextWithQuery(query string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/?"+query, nil)
	c.Request = req
	return c
}

func TestParseFramework_Default(t *testing.T) {
	c := ginContextWithQuery("")
	got := parseFramework(c)
	if got != compliance.FrameworkCIS {
		t.Errorf("クエリパラメータなし: CIS を期待しましたが %q が返りました", got)
	}
}

func TestParseFramework_CIS(t *testing.T) {
	c := ginContextWithQuery("framework=cis")
	got := parseFramework(c)
	if got != compliance.FrameworkCIS {
		t.Errorf("framework=cis: got %q, want %q", got, compliance.FrameworkCIS)
	}
}

func TestParseFramework_NIST(t *testing.T) {
	c := ginContextWithQuery("framework=nist")
	got := parseFramework(c)
	if got != compliance.FrameworkNIST {
		t.Errorf("framework=nist: got %q, want %q", got, compliance.FrameworkNIST)
	}
}

func TestParseFramework_SOC2(t *testing.T) {
	c := ginContextWithQuery("framework=soc2")
	got := parseFramework(c)
	if got != compliance.FrameworkSOC2 {
		t.Errorf("framework=soc2: got %q, want %q", got, compliance.FrameworkSOC2)
	}
}

func TestParseFramework_Unknown_FallsBackToCIS(t *testing.T) {
	for _, v := range []string{"iso27001", "pci", "", "NIST", "CIS"} {
		c := ginContextWithQuery("framework=" + v)
		got := parseFramework(c)
		if got != compliance.FrameworkCIS {
			t.Errorf("framework=%q: 不明な値はCISにフォールバックするべきです、got %q", v, got)
		}
	}
}
