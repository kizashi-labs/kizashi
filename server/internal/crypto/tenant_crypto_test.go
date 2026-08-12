package tenantcrypto_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
)

// newTestEncryptor is a helper that wires an InMemoryKeyStore into an Encryptor.
func newTestEncryptor(t *testing.T) (*tenantcrypto.Encryptor, *tenantcrypto.InMemoryKeyStore) {
	t.Helper()
	ks := tenantcrypto.NewInMemoryKeyStore()
	enc := tenantcrypto.NewEncryptor(ks)
	return enc, ks
}

// TestEncryptDecryptRoundtrip verifies that data encrypted for a tenant can be
// correctly decrypted back to the original plaintext.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	enc, _ := newTestEncryptor(t)

	cases := []struct {
		name      string
		tenantID  string
		plaintext []byte
	}{
		{
			name:      "non-empty plaintext",
			tenantID:  "tenant-alpha",
			plaintext: []byte("sensitive EDR event data"),
		},
		{
			name:      "empty plaintext",
			tenantID:  "tenant-alpha",
			plaintext: []byte{},
		},
		{
			name:      "binary plaintext",
			tenantID:  "tenant-alpha",
			plaintext: []byte{0x00, 0x01, 0xFF, 0xFE, 0x80},
		},
		{
			name:      "large plaintext",
			tenantID:  "tenant-beta",
			plaintext: bytes.Repeat([]byte("abcdefgh"), 1024),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(ctx, tc.tenantID, tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: unexpected error: %v", err)
			}

			// Ciphertext must differ from plaintext (even for empty input the
			// header alone makes the lengths differ).
			if len(tc.plaintext) > 0 && bytes.Equal(ciphertext, tc.plaintext) {
				t.Fatal("Encrypt: ciphertext equals plaintext")
			}

			got, err := enc.Decrypt(ctx, tc.tenantID, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: unexpected error: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("roundtrip mismatch: got %q, want %q", got, tc.plaintext)
			}
		})
	}
}

// TestEncryptProducesUniqueNonces verifies that two calls to Encrypt for the
// same plaintext and tenant produce different ciphertexts (nonce is random).
func TestEncryptProducesUniqueNonces(t *testing.T) {
	ctx := context.Background()
	enc, _ := newTestEncryptor(t)

	plaintext := []byte("same plaintext every time")
	tenantID := "tenant-nonce-test"

	ct1, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}
	ct2, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two Encrypt calls produced identical ciphertexts (nonce not random)")
	}

	// Both should still decrypt correctly.
	got1, err := enc.Decrypt(ctx, tenantID, ct1)
	if err != nil {
		t.Fatalf("Decrypt ct1: %v", err)
	}
	got2, err := enc.Decrypt(ctx, tenantID, ct2)
	if err != nil {
		t.Fatalf("Decrypt ct2: %v", err)
	}
	if !bytes.Equal(got1, plaintext) || !bytes.Equal(got2, plaintext) {
		t.Fatal("one or both decryptions did not return original plaintext")
	}
}

// TestDifferentTenantsCantDecrypt confirms that a ciphertext produced for
// tenant A cannot be decrypted using tenant B's key.
func TestDifferentTenantsCantDecrypt(t *testing.T) {
	ctx := context.Background()
	enc, _ := newTestEncryptor(t)

	tenantA := "tenant-a"
	tenantB := "tenant-b"
	plaintext := []byte("private data for tenant A")

	ciphertext, err := enc.Encrypt(ctx, tenantA, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Attempting to decrypt with tenant B's key must fail.
	_, err = enc.Decrypt(ctx, tenantB, ciphertext)
	if err == nil {
		t.Fatal("expected Decrypt to fail when using a different tenant's key, but it succeeded")
	}

	// The error should not be a programming mistake — just an authentication failure.
	t.Logf("expected decryption failure (tenant isolation confirmed): %v", err)
}

// TestKeyRotation verifies that after rotating a tenant's key:
//  1. New data is encrypted with the new key (different from old key material).
//  2. Data encrypted before the rotation cannot be decrypted with the new key
//     (since InMemoryKeyStore discards the old key), which confirms the keys
//     are truly different.
func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	enc, ks := newTestEncryptor(t)

	tenantID := "tenant-rotation"
	plaintext := []byte("pre-rotation secret")

	// Encrypt before rotation.
	ctBefore, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt before rotation: %v", err)
	}

	// Confirm pre-rotation decrypt works.
	got, err := enc.Decrypt(ctx, tenantID, ctBefore)
	if err != nil {
		t.Fatalf("Decrypt before rotation: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("pre-rotation roundtrip failed: got %q", got)
	}

	// Capture the key before rotation.
	keyBefore, err := ks.GetKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetKey before rotation: %v", err)
	}

	// Rotate.
	if err = ks.RotateKey(ctx, tenantID); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Capture the key after rotation.
	keyAfter, err := ks.GetKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetKey after rotation: %v", err)
	}

	// The keys must differ.
	if bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("key after rotation is identical to key before rotation")
	}

	// New data encrypted with the rotated key must decrypt successfully.
	ctAfter, err := enc.Encrypt(ctx, tenantID, []byte("post-rotation secret"))
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	gotAfter, err := enc.Decrypt(ctx, tenantID, ctAfter)
	if err != nil {
		t.Fatalf("Decrypt post-rotation ciphertext: %v", err)
	}
	if !bytes.Equal(gotAfter, []byte("post-rotation secret")) {
		t.Fatalf("post-rotation roundtrip failed: got %q", gotAfter)
	}

	// Pre-rotation ciphertext must no longer decrypt (InMemoryKeyStore has
	// replaced the old key — this verifies keys are truly different).
	_, err = enc.Decrypt(ctx, tenantID, ctBefore)
	if err == nil {
		t.Fatal("expected Decrypt of pre-rotation ciphertext to fail after key rotation, but it succeeded")
	}
	t.Logf("pre-rotation ciphertext correctly rejected after rotation: %v", err)
}

// TestDecryptRejectsTruncatedCiphertext ensures Decrypt returns an error for
// obviously malformed input.
func TestDecryptRejectsTruncatedCiphertext(t *testing.T) {
	ctx := context.Background()
	enc, _ := newTestEncryptor(t)

	tenantID := "tenant-truncate"

	truncated := []byte{0x00, 0x00, 0x00, 0x01} // only version, no nonce or body

	_, err := enc.Decrypt(ctx, tenantID, truncated)
	if err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

// TestDecryptRejectsWrongVersion ensures Decrypt returns an error for an
// unsupported version field.
func TestDecryptRejectsWrongVersion(t *testing.T) {
	ctx := context.Background()
	enc, _ := newTestEncryptor(t)

	tenantID := "tenant-version"

	// Build a 32-byte buffer with version = 99.
	blob := make([]byte, 4+12+16) // version + nonce + minimum GCM overhead
	blob[0] = 0x00
	blob[1] = 0x00
	blob[2] = 0x00
	blob[3] = 0x63 // version 99

	_, err := enc.Decrypt(ctx, tenantID, blob)
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !containsString(err.Error(), "unsupported ciphertext version") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestInMemoryKeyStoreGetKeyIsIdempotent verifies that GetKey returns the same
// key on repeated calls for the same tenant.
func TestInMemoryKeyStoreGetKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ks := tenantcrypto.NewInMemoryKeyStore()

	tenantID := "tenant-idempotent"

	k1, err := ks.GetKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("first GetKey: %v", err)
	}
	k2, err := ks.GetKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("second GetKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("GetKey returned different keys for the same tenant on repeated calls")
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(k1))
	}
}

// TestInMemoryKeyStoreDifferentTenantsGetDifferentKeys confirms isolation
// between tenants at the key store level.
func TestInMemoryKeyStoreDifferentTenantsGetDifferentKeys(t *testing.T) {
	ctx := context.Background()
	ks := tenantcrypto.NewInMemoryKeyStore()

	kA, err := ks.GetKey(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetKey alpha: %v", err)
	}
	kB, err := ks.GetKey(ctx, "beta")
	if err != nil {
		t.Fatalf("GetKey beta: %v", err)
	}
	if bytes.Equal(kA, kB) {
		t.Fatal("two different tenants received identical keys")
	}
}

// containsString is a small helper so the test file has no extra dependencies.
func containsString(s, substr string) bool {
	return errors.New(s) != nil && len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}()
}
