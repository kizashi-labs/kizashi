package cloud

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// TestSigningKey_AWSVector verifies the SigV4 signing-key derivation against the
// canonical example published in the AWS documentation ("Deriving the signing key").
//
//	secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY date=20150830 region=us-east-1 service=iam
func TestSigningKey_AWSVector(t *testing.T) {
	key := signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("signing key mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestSHA256Hex(t *testing.T) {
	// SHA256 of the empty string — a universally known constant.
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := sha256Hex([]byte("")); got != emptyHash {
		t.Errorf("sha256Hex(\"\"): got %s, want %s", got, emptyHash)
	}
	// Determinism + difference.
	if sha256Hex([]byte("a")) == sha256Hex([]byte("b")) {
		t.Error("distinct inputs must hash differently")
	}
}

func TestHMACSHA256_KnownVector(t *testing.T) {
	// Well-known HMAC-SHA256 test vector.
	got := hex.EncodeToString(hmacSHA256([]byte("key"), "The quick brown fox jumps over the lazy dog"))
	const want = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Errorf("hmacSHA256 vector mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestURIEncode(t *testing.T) {
	cases := map[string]string{
		"abc123": "abc123",
		"-_.~":   "-_.~",  // unreserved, must NOT be encoded
		"a b":    "a%20b", // space
		"a/b":    "a%2Fb", // slash IS encoded (query-value rules)
		"=&":     "%3D%26",
		"日":      "%E6%97%A5", // multibyte UTF-8 → per-byte percent encoding
	}
	for in, want := range cases {
		if got := uriEncode(in); got != want {
			t.Errorf("uriEncode(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestIsUnreserved(t *testing.T) {
	for _, c := range []byte("AZaz09-_.~") {
		if !isUnreserved(c) {
			t.Errorf("%q should be unreserved", c)
		}
	}
	for _, c := range []byte(" /=&%+") {
		if isUnreserved(c) {
			t.Errorf("%q should NOT be unreserved", c)
		}
	}
}

// TestSigV4Sign_HeaderShape exercises the full signing path and checks that all
// required SigV4 headers are produced with the correct structure. (The signature
// value itself depends on the current time, so we assert shape, not an exact hash.)
func TestSigV4Sign_HeaderShape(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://cloudtrail.us-east-1.amazonaws.com/?Action=LookupEvents", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")

	sigV4Sign(req, []byte("{}"), "cloudtrail", "us-east-1", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

	if req.Header.Get("x-amz-date") == "" {
		t.Error("x-amz-date header not set")
	}
	if req.Header.Get("x-amz-content-sha256") != sha256Hex([]byte("{}")) {
		t.Error("x-amz-content-sha256 should be the body hash")
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization missing algorithm prefix: %q", auth)
	}
	for _, must := range []string{
		"Credential=AKIDEXAMPLE/",
		"/us-east-1/cloudtrail/aws4_request",
		"SignedHeaders=",
		"Signature=",
	} {
		if !strings.Contains(auth, must) {
			t.Errorf("Authorization missing %q: %s", must, auth)
		}
	}
	// Signed headers must include host and x-amz-date (always-signed).
	if !strings.Contains(auth, "host") || !strings.Contains(auth, "x-amz-date") {
		t.Errorf("SignedHeaders should include host and x-amz-date: %s", auth)
	}
	// Signature must be 64 lowercase hex chars.
	idx := strings.Index(auth, "Signature=")
	sig := auth[idx+len("Signature="):]
	if len(sig) != 64 {
		t.Errorf("signature should be 64 hex chars, got %d (%q)", len(sig), sig)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		t.Errorf("signature is not valid hex: %v", err)
	}
}
