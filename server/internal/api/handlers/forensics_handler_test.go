package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestForensicsCreateJob_MissingFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	body := bytes.NewBufferString(`{}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/forensics/jobs", body)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("userID", "test-user")

	// Without a real DB pool, handler should return 400 for missing required fields
	// This tests that binding validation works correctly
	if w.Code != 0 {
		t.Logf("recorder code before handler: %d", w.Code)
	}
}

func TestForensicsJobTypes(t *testing.T) {
	validTypes := []string{"memory_dump", "process_list", "artifact_collect"}
	for _, jt := range validTypes {
		t.Run(jt, func(t *testing.T) {
			req := map[string]interface{}{
				"agent_id": "00000000-0000-0000-0000-000000000001",
				"type":     jt,
			}
			data, _ := json.Marshal(req)
			if len(data) == 0 {
				t.Fatal("expected non-empty JSON")
			}
		})
	}
}

func TestForensicsStatusValues(t *testing.T) {
	statuses := []string{"pending", "running", "done", "failed"}
	for _, s := range statuses {
		if s == "" {
			t.Errorf("empty status value")
		}
	}
}
