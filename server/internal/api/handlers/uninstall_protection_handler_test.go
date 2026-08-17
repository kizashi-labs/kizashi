package handlers

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestUninstallKDFMatchesAgent is the test that matters most in this file.
//
// The server derives the digest and the agent verifies against it, in two
// different modules with no shared code. If the algorithm, key length or
// encoding drift apart, nothing fails at build time and nothing fails in CI —
// the symptom appears in the field as "the correct uninstall password is
// rejected on every endpoint", with the server perfectly happy.
//
// It works off a fixed known-answer vector rather than deriving both sides here
// (which would just compare a function to itself). The identical vector is
// asserted in agent/internal/uninstallguard's tests, so the two modules are
// pinned to the same value without sharing code — if either side changes its
// hash, key length or encoding, its own test goes red and names the reason.
//
// Vector: PBKDF2-HMAC-SHA256, password "correct horse battery staple",
// salt "0123456789abcdef", 1000 iterations, 32-byte key, standard base64.
const uninstallKDFKnownAnswer = "yqSq2SygY1sB4EcH9f2FG0JTMES+wqLsOT5YmiRBplI="

func TestUninstallKDFMatchesAgent(t *testing.T) {
	got, err := pbkdf2.Key(sha256.New, "correct horse battery staple",
		[]byte("0123456789abcdef"), 1000, uninstallKDFKeyLen)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if enc := base64.StdEncoding.EncodeToString(got); enc != uninstallKDFKnownAnswer {
		t.Fatalf("KDF known-answer mismatch:\n got  %s\n want %s\n"+
			"The agent verifies against digests derived here. A mismatch means every "+
			"endpoint rejects the correct uninstall password, with no error on either side.",
			enc, uninstallKDFKnownAnswer)
	}

	if uninstallKDFKeyLen != 32 {
		t.Errorf("uninstallKDFKeyLen = %d; the agent uses 32", uninstallKDFKeyLen)
	}
	if uninstallKDFAlgorithm != "pbkdf2-hmac-sha256" {
		t.Errorf("uninstallKDFAlgorithm = %q; the agent writes and expects pbkdf2-hmac-sha256",
			uninstallKDFAlgorithm)
	}
	if uninstallKDFIterations < 600_000 {
		t.Errorf("uninstallKDFIterations = %d; the digest sits on every protected endpoint "+
			"and must stay expensive to attack offline", uninstallKDFIterations)
	}
}

func TestTenantOfFallsBackToDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := tenantOf(c); got != DefaultTenantID {
		t.Errorf("tenantOf with no tenant = %q, want the default tenant %q", got, DefaultTenantID)
	}

	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Set("tenant_id", "11111111-2222-3333-4444-555555555555")
	if got := tenantOf(c2); got != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("tenantOf ignored the request's tenant: %q", got)
	}

	// An empty tenant_id must not become an empty tenant scope — that would
	// write rows with a NULL tenant and read nobody's.
	c3, _ := gin.CreateTestContext(httptest.NewRecorder())
	c3.Set("tenant_id", "")
	if got := tenantOf(c3); got != DefaultTenantID {
		t.Errorf("tenantOf with an empty tenant_id = %q, want the default tenant", got)
	}
}

// TestSetPasswordRejectsShortPasswords covers the length floor without needing
// a database: the check runs before any store call.
func TestSetPasswordRejectsShortPasswords(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &UninstallProtectionHandler{} // store is never reached on this path

	for _, pw := range []string{"", "short", "elevenchars", "   padded   "} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		body, _ := json.Marshal(setUninstallPasswordRequest{Password: pw})
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		c.Request.Header.Set("Content-Type", "application/json")

		h.SetPassword(c)

		if w.Code != http.StatusBadRequest {
			t.Errorf("SetPassword(%q) = %d, want 400 (a short password falls to offline brute force)",
				pw, w.Code)
		}
	}
}

// TestStatusResponseCarriesNoSecret pins that the console-facing status shape
// cannot grow a salt or digest field. Those are exactly what an offline attack
// needs, and the console has no use for them.
func TestStatusResponseCarriesNoSecret(t *testing.T) {
	raw, err := json.Marshal(uninstallStatusResponse{
		Configured: true,
		Algorithm:  uninstallKDFAlgorithm,
		Iterations: uninstallKDFIterations,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"salt", "digest", "password"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Errorf("the status response exposes %q: %s", forbidden, raw)
		}
	}
}
