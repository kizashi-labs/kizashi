package handlers

import (
	"strings"
	"testing"
)

// ─── signPayload ─────────────────────────────────────────────────────────────

func TestSignPayload_HasSHA256Prefix(t *testing.T) {
	got := signPayload([]byte("secret"), []byte("payload"))
	if !strings.HasPrefix(got, "sha256=") {
		t.Errorf("signPayload: want sha256= prefix, got %q", got)
	}
}

func TestSignPayload_Deterministic(t *testing.T) {
	a := signPayload([]byte("key"), []byte("data"))
	b := signPayload([]byte("key"), []byte("data"))
	if a != b {
		t.Errorf("signPayload: same inputs should produce same output, got %q != %q", a, b)
	}
}

func TestSignPayload_DifferentSecrets_DifferentOutput(t *testing.T) {
	a := signPayload([]byte("secret1"), []byte("payload"))
	b := signPayload([]byte("secret2"), []byte("payload"))
	if a == b {
		t.Error("signPayload: different secrets should produce different signatures")
	}
}

func TestSignPayload_DifferentPayloads_DifferentOutput(t *testing.T) {
	a := signPayload([]byte("secret"), []byte("payload1"))
	b := signPayload([]byte("secret"), []byte("payload2"))
	if a == b {
		t.Error("signPayload: different payloads should produce different signatures")
	}
}

func TestSignPayload_EmptyPayload(t *testing.T) {
	got := signPayload([]byte("secret"), []byte(""))
	if !strings.HasPrefix(got, "sha256=") {
		t.Errorf("signPayload(empty): want sha256= prefix, got %q", got)
	}
}

// ─── VerifyWebhookSignature ───────────────────────────────────────────────────

func TestVerifyWebhookSignature_ValidSignature(t *testing.T) {
	secret := "mysecret"
	payload := []byte("test-payload")
	sig := signPayload([]byte(secret), payload)
	if !VerifyWebhookSignature(secret, payload, sig) {
		t.Error("VerifyWebhookSignature: valid signature should return true")
	}
}

func TestVerifyWebhookSignature_InvalidSignature(t *testing.T) {
	if VerifyWebhookSignature("secret", []byte("data"), "sha256=badhex") {
		t.Error("VerifyWebhookSignature: invalid signature should return false")
	}
}

func TestVerifyWebhookSignature_WrongSecret(t *testing.T) {
	payload := []byte("data")
	sig := signPayload([]byte("secret1"), payload)
	if VerifyWebhookSignature("secret2", payload, sig) {
		t.Error("VerifyWebhookSignature: wrong secret should return false")
	}
}
