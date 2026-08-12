package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// newGinCtx returns a gin.Context with the supplied query string.
func newGinCtx(query string) *gin.Context {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/?"+query, nil)
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

func TestParseHoursLimit_Defaults(t *testing.T) {
	c := newGinCtx("")
	hours, limit := parseHoursLimit(c, 24, 50)
	if hours != 24 {
		t.Errorf("hours = %d, want 24 (default)", hours)
	}
	if limit != 50 {
		t.Errorf("limit = %d, want 50 (default)", limit)
	}
}

func TestParseHoursLimit_ValidParams(t *testing.T) {
	c := newGinCtx("hours=72&limit=100")
	hours, limit := parseHoursLimit(c, 24, 50)
	if hours != 72 {
		t.Errorf("hours = %d, want 72", hours)
	}
	if limit != 100 {
		t.Errorf("limit = %d, want 100", limit)
	}
}

func TestParseHoursLimit_ZeroHours_FallsBackToDefault(t *testing.T) {
	c := newGinCtx("hours=0")
	hours, _ := parseHoursLimit(c, 24, 50)
	if hours != 24 {
		t.Errorf("hours=0 should fall back to default 24, got %d", hours)
	}
}

func TestParseHoursLimit_ExceedsMax_FallsBackToDefault(t *testing.T) {
	// Max allowed is 720
	c := newGinCtx("hours=721")
	hours, _ := parseHoursLimit(c, 24, 50)
	if hours != 24 {
		t.Errorf("hours=721 should fall back to default 24, got %d", hours)
	}
}

func TestParseHoursLimit_ExactMax_Accepted(t *testing.T) {
	c := newGinCtx("hours=720")
	hours, _ := parseHoursLimit(c, 24, 50)
	if hours != 720 {
		t.Errorf("hours=720 should be accepted, got %d", hours)
	}
}

func TestParseHoursLimit_LimitExceeds200_FallsBackToDefault(t *testing.T) {
	c := newGinCtx("limit=201")
	_, limit := parseHoursLimit(c, 24, 50)
	if limit != 50 {
		t.Errorf("limit=201 should fall back to default 50, got %d", limit)
	}
}

func TestParseHoursLimit_InvalidString_FallsBackToDefault(t *testing.T) {
	c := newGinCtx("hours=abc&limit=xyz")
	hours, limit := parseHoursLimit(c, 12, 25)
	if hours != 12 || limit != 25 {
		t.Errorf("invalid params should use defaults: hours=%d limit=%d", hours, limit)
	}
}
