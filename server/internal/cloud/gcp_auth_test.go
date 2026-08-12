package cloud

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pkcs1PEM(key *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	got, err := parseRSAPrivateKey(pkcs8PEM(t, key))
	if err != nil {
		t.Fatalf("PKCS#8 parse failed: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("parsed key does not match original (PKCS#8)")
	}
}

func TestParseRSAPrivateKey_PKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	got, err := parseRSAPrivateKey(pkcs1PEM(key))
	if err != nil {
		t.Fatalf("PKCS#1 parse failed: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("parsed key does not match original (PKCS#1)")
	}
}

// TestParseRSAPrivateKey_LiteralNewlines covers GCP service-account JSON where the
// PEM is stored on one line with literal "\n" escape sequences.
func TestParseRSAPrivateKey_LiteralNewlines(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	literal := strings.ReplaceAll(pkcs8PEM(t, key), "\n", `\n`)
	if !strings.Contains(literal, `\n`) {
		t.Fatal("test setup: expected literal backslash-n in the PEM")
	}
	if _, err := parseRSAPrivateKey(literal); err != nil {
		t.Errorf("should parse PEM with literal \\n sequences: %v", err)
	}
}

func TestParseRSAPrivateKey_Errors(t *testing.T) {
	// Not PEM at all.
	if _, err := parseRSAPrivateKey("not a pem"); err == nil {
		t.Error("expected error on non-PEM input")
	}
	// Unknown block type.
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
	if _, err := parseRSAPrivateKey(cert); err == nil {
		t.Error("expected error on unknown block type")
	}
	// PKCS#8 block holding a non-RSA (ECDSA) key.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))
	if _, err := parseRSAPrivateKey(ecPEM); err == nil {
		t.Error("expected error when PKCS#8 key is not RSA")
	}
}

// TestSignJWT_Verifiable signs a JWT and verifies the RS256 signature with the
// corresponding public key — proving the signature is cryptographically valid.
func TestSignJWT_Verifiable(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"svc@example.iam.gserviceaccount.com"}`))

	jwt, err := signJWT(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT must have 3 dot-separated parts, got %d", len(parts))
	}
	if parts[0] != header || parts[1] != payload {
		t.Error("signing input (header/payload) altered in output")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("RS256 signature does not verify against the public key: %v", err)
	}
}

// TestSignJWT_RoundTripWithParsedKey exercises parse → sign → verify end to end.
func TestSignJWT_RoundTripWithParsedKey(t *testing.T) {
	orig, _ := rsa.GenerateKey(rand.Reader, 2048)
	parsed, err := parseRSAPrivateKey(pkcs8PEM(t, orig))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	jwt, err := signJWT("aGRy", "cGxk", parsed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte("aGRy.cGxk"))
	if err := rsa.VerifyPKCS1v15(&orig.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("round-trip signature failed to verify: %v", err)
	}
}
