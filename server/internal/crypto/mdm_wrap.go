package tenantcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// MDM global credential wrapper.
//
// MDM integration credentials (APNs .p12, ABM .p7m, AE service-account JSON,
// SCEP shared secrets) are workspace-wide rather than per-tenant. They are
// wrapped with a single AES-256 master key sourced from the environment
// variable MDM_MASTER_KEY (base64, 32 bytes of raw key material before
// encoding). If the variable is absent, wrapping is disabled and callers
// receive a sentinel error so they can fall back to plaintext storage in
// local/dev environments.
//
// On-disk layout mirrors Encryptor.Encrypt:
//   [4 bytes big-endian version=1] [12-byte nonce] [ciphertext+tag]
// The version byte makes future algorithm agility cheap.

const (
	mdmCipherVersion uint32 = 1
	mdmNonceSize     int    = 12
	mdmKeySize       int    = 32
)

// ErrMDMKeyMissing indicates MDM_MASTER_KEY is not configured.
// Callers should surface this clearly in operator-visible responses and
// decide whether to allow plaintext storage (dev) or refuse (prod).
var ErrMDMKeyMissing = errors.New("mdm: MDM_MASTER_KEY not set")

var (
	mdmKeyOnce sync.Once
	mdmKey     []byte
	mdmKeyErr  error
)

func loadMDMKey() ([]byte, error) {
	mdmKeyOnce.Do(func() {
		raw := os.Getenv("MDM_MASTER_KEY")
		if raw == "" {
			mdmKeyErr = ErrMDMKeyMissing
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			mdmKeyErr = fmt.Errorf("mdm: MDM_MASTER_KEY is not valid base64: %w", err)
			return
		}
		if len(decoded) != mdmKeySize {
			mdmKeyErr = fmt.Errorf("mdm: MDM_MASTER_KEY must be %d bytes after base64 decode, got %d", mdmKeySize, len(decoded))
			return
		}
		mdmKey = decoded
	})
	return mdmKey, mdmKeyErr
}

// MDMWrapCredential encrypts plaintext with the MDM master key.
// Returns ErrMDMKeyMissing when the env var is absent so callers can degrade
// to plaintext in dev without surprising behaviour.
func MDMWrapCredential(plaintext []byte) ([]byte, error) {
	key, err := loadMDMKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mdm: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mdm: gcm: %w", err)
	}
	nonce := make([]byte, mdmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("mdm: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 4+mdmNonceSize+len(ct))
	binary.BigEndian.PutUint32(out[0:4], mdmCipherVersion)
	copy(out[4:4+mdmNonceSize], nonce)
	copy(out[4+mdmNonceSize:], ct)
	return out, nil
}

// MDMUnwrapCredential decrypts ciphertext produced by MDMWrapCredential.
// A missing key returns ErrMDMKeyMissing; mismatched versions, short blobs
// and GCM auth failures all return descriptive errors.
func MDMUnwrapCredential(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4+mdmNonceSize+16 {
		return nil, errors.New("mdm: ciphertext too short")
	}
	ver := binary.BigEndian.Uint32(ciphertext[0:4])
	if ver != mdmCipherVersion {
		return nil, fmt.Errorf("mdm: unsupported ciphertext version %d", ver)
	}
	key, err := loadMDMKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mdm: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mdm: gcm: %w", err)
	}
	nonce := ciphertext[4 : 4+mdmNonceSize]
	ct := ciphertext[4+mdmNonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// MDMCiphertextEnvelope reports whether a blob starts with the v1 envelope
// header. Used to distinguish legacy plaintext rows from wrapped rows during
// unwrap so existing data keeps working until it is re-uploaded.
func MDMCiphertextEnvelope(data []byte) bool {
	if len(data) < 4+mdmNonceSize {
		return false
	}
	return binary.BigEndian.Uint32(data[0:4]) == mdmCipherVersion
}
