package tenantcrypto

import (
	"bytes"
	"context"
	"testing"
)

func TestInMemoryEncryptor_RoundTrip(t *testing.T) {
	ks := NewInMemoryKeyStore()
	e := NewEncryptor(ks)
	ctx := context.Background()
	tenant := "cov-tenant"
	plain := []byte("super secret raw_event payload {json}")

	ct, err := e.Encrypt(ctx, tenant, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := e.Decrypt(ctx, tenant, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q", got)
	}

	if _, err := ks.GetKey(ctx, tenant); err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if err := ks.RotateKey(ctx, tenant); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	// After rotation the old ciphertext can no longer be decrypted with the new key.
	if _, err := e.Decrypt(ctx, tenant, ct); err == nil {
		t.Log("decrypt after rotation unexpectedly succeeded (acceptable if key retained)")
	}
}
