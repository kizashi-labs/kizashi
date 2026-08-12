package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestDownloadHandler_GetBinaryAndChecksum verifies the agent download API
// serves the requested binary and returns its SHA-256 as JSON. This is the
// endpoint install.sh/update scripts and the updater rely on.
func TestDownloadHandler_GetBinaryAndChecksum(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	content := []byte("fake-agent-binary-content")
	if err := os.WriteFile(filepath.Join(dir, "edr-agent-linux-amd64"), content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	wantHex := hex.EncodeToString(sum[:])

	h := NewDownloadHandler(dir)

	// GetBinary serves the file bytes.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?platform=linux&arch=amd64&binary=agent", nil)
	h.GetBinary(c)
	if w.Code != http.StatusOK {
		t.Fatalf("GetBinary status = %d, want 200", w.Code)
	}
	if w.Body.String() != string(content) {
		t.Errorf("GetBinary body mismatch")
	}

	// GetChecksum returns the SHA-256 as JSON {"checksum":"<hex>"}.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/?platform=linux&arch=amd64&binary=agent", nil)
	h.GetChecksum(c2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GetChecksum status = %d, want 200", w2.Code)
	}
	var resp struct {
		Checksum string `json:"checksum"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("checksum response not JSON: %v", err)
	}
	if resp.Checksum != wantHex {
		t.Errorf("checksum = %q, want %q", resp.Checksum, wantHex)
	}

	// Missing binary → 404.
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request = httptest.NewRequest(http.MethodGet, "/?platform=windows&arch=amd64&binary=agent", nil)
	h.GetBinary(c3)
	if w3.Code != http.StatusNotFound {
		t.Errorf("missing binary status = %d, want 404", w3.Code)
	}
}
