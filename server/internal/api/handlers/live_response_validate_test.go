package handlers

import (
	"testing"
)

// emailerStub implements the duck-typed emailer interface used by extractEmail.
type emailerStub struct{ addr string }

func (e emailerStub) GetEmail() string { return e.addr }

func TestExtractEmail_NoUserKey_ReturnsEmpty(t *testing.T) {
	c := newGinCtx("")
	if got := extractEmail(c); got != "" {
		t.Errorf("extractEmail() = %q, want \"\"", got)
	}
}

func TestExtractEmail_MapWithEmail_ReturnsEmail(t *testing.T) {
	c := newGinCtx("")
	c.Set("user", map[string]interface{}{"email": "admin@example.com", "role": "admin"})
	if got := extractEmail(c); got != "admin@example.com" {
		t.Errorf("extractEmail() = %q, want \"admin@example.com\"", got)
	}
}

func TestExtractEmail_MapWithEmptyEmail_ReturnsEmpty(t *testing.T) {
	c := newGinCtx("")
	c.Set("user", map[string]interface{}{"email": ""})
	if got := extractEmail(c); got != "" {
		t.Errorf("extractEmail() = %q, want \"\" (empty email)", got)
	}
}

func TestExtractEmail_MapWithoutEmailKey_ReturnsEmpty(t *testing.T) {
	c := newGinCtx("")
	c.Set("user", map[string]interface{}{"sub": "user-uuid"})
	if got := extractEmail(c); got != "" {
		t.Errorf("extractEmail() = %q, want \"\" (no email key)", got)
	}
}

func TestExtractEmail_EmailerInterface_ReturnsEmail(t *testing.T) {
	c := newGinCtx("")
	c.Set("user", emailerStub{addr: "soc@example.com"})
	if got := extractEmail(c); got != "soc@example.com" {
		t.Errorf("extractEmail() = %q, want \"soc@example.com\"", got)
	}
}

func TestExtractEmail_UnknownType_ReturnsEmpty(t *testing.T) {
	c := newGinCtx("")
	c.Set("user", 42) // neither map nor emailer
	if got := extractEmail(c); got != "" {
		t.Errorf("extractEmail() = %q, want \"\" (unknown type)", got)
	}
}
