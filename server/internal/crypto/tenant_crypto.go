// Package tenantcrypto provides per-tenant AES-256-GCM encryption for sensitive data.
// It manages tenant-specific encryption keys stored in PostgreSQL, wrapped by a
// master key so raw tenant keys are never persisted in plaintext.
//
// Required PostgreSQL migration:
//
//	CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
//	  tenant_id   TEXT PRIMARY KEY,
//	  encrypted_key BYTEA NOT NULL,
//	  key_version INT NOT NULL DEFAULT 1,
//	  created_at  TIMESTAMPTZ DEFAULT NOW(),
//	  rotated_at  TIMESTAMPTZ
//	);
package tenantcrypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ciphertextVersion is the only version this implementation writes.
const ciphertextVersion uint32 = 1

// nonceSize is the standard GCM nonce length (96 bits).
const nonceSize = 12

// keySize is the AES-256 key size in bytes.
const keySize = 32

// headerSize is the number of bytes prepended to every ciphertext:
// 4 bytes (version) + 12 bytes (nonce).
const headerSize = 4 + nonceSize

// -----------------------------------------------------------------------------
// KeyStore interface
// -----------------------------------------------------------------------------

// KeyStore abstracts the source of per-tenant AES-256 encryption keys.
type KeyStore interface {
	// GetKey returns the 32-byte AES-256 key for the given tenant.
	// Implementations must return a non-nil, exactly 32-byte slice on success.
	GetKey(ctx context.Context, tenantID string) ([]byte, error)

	// RotateKey replaces the tenant's current key with a freshly generated one.
	// Data encrypted with the previous key remains readable only if the caller
	// has stored the old key elsewhere; this implementation does not retain
	// previous key material after rotation.
	RotateKey(ctx context.Context, tenantID string) error
}

// -----------------------------------------------------------------------------
// InMemoryKeyStore — for testing and development only
// -----------------------------------------------------------------------------

// InMemoryKeyStore is a thread-safe, in-process KeyStore backed by a plain map.
// Keys are generated randomly on first access and replaced on rotation.
// Do NOT use this in production; keys are lost when the process exits.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewInMemoryKeyStore returns an empty InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{keys: make(map[string][]byte)}
}

// GetKey returns the stored key for tenantID, creating a random one if absent.
func (s *InMemoryKeyStore) GetKey(_ context.Context, tenantID string) ([]byte, error) {
	s.mu.RLock()
	k, ok := s.keys[tenantID]
	s.mu.RUnlock()
	if ok {
		out := make([]byte, keySize)
		copy(out, k)
		return out, nil
	}

	// Key does not exist yet — generate and store it.
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock.
	if k, ok = s.keys[tenantID]; ok {
		out := make([]byte, keySize)
		copy(out, k)
		return out, nil
	}
	newKey, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: generate key for tenant %q: %w", tenantID, err)
	}
	s.keys[tenantID] = newKey
	out := make([]byte, keySize)
	copy(out, newKey)
	return out, nil
}

// RotateKey replaces the tenant's key with a new random one.
func (s *InMemoryKeyStore) RotateKey(_ context.Context, tenantID string) error {
	newKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("tenantcrypto: rotate key for tenant %q: %w", tenantID, err)
	}
	s.mu.Lock()
	s.keys[tenantID] = newKey
	s.mu.Unlock()
	return nil
}

// -----------------------------------------------------------------------------
// DBKeyStore — production KeyStore backed by PostgreSQL
// -----------------------------------------------------------------------------

// DBKeyStore stores AES-256 tenant keys in PostgreSQL, each encrypted (wrapped)
// by a single master key using AES-256-GCM.  The master key must be 32 bytes
// and should be sourced from a secrets manager (e.g. AWS Secrets Manager,
// HashiCorp Vault) rather than a config file.
//
// Required table (run once per database):
//
//	CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
//	  tenant_id   TEXT PRIMARY KEY,
//	  encrypted_key BYTEA NOT NULL,
//	  key_version INT NOT NULL DEFAULT 1,
//	  created_at  TIMESTAMPTZ DEFAULT NOW(),
//	  rotated_at  TIMESTAMPTZ
//	);
type DBKeyStore struct {
	db        *pgxpool.Pool
	masterKey []byte
}

// NewDBKeyStore constructs a DBKeyStore.
// masterKey must be exactly 32 bytes.
func NewDBKeyStore(db *pgxpool.Pool, masterKey []byte) (*DBKeyStore, error) {
	if len(masterKey) != keySize {
		return nil, fmt.Errorf("tenantcrypto: master key must be %d bytes, got %d", keySize, len(masterKey))
	}
	mk := make([]byte, keySize)
	copy(mk, masterKey)
	return &DBKeyStore{db: db, masterKey: mk}, nil
}

// GetKey loads and unwraps the tenant key from the database.
// If no row exists for the tenant a new key is generated, wrapped, and stored.
func (s *DBKeyStore) GetKey(ctx context.Context, tenantID string) ([]byte, error) {
	const query = `
		SELECT encrypted_key FROM tenant_encryption_keys WHERE tenant_id = $1
	`
	var encryptedKey []byte
	err := s.db.QueryRow(ctx, query, tenantID).Scan(&encryptedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		// 本当に行が無い = 新しいテナント。作って保存します。
		return s.createAndStoreKey(ctx, tenantID)
	}
	if err != nil {
		// 以前はここも createAndStoreKey に落ちていました。コメントには
		// 「No row」と書いてありますが、条件は「どんな失敗でも」です。
		// 接続が一瞬切れただけで新しい鍵を作り、その鍵で暗号化します。
		// INSERT は ON CONFLICT DO NOTHING なので保存済みの鍵は残り、
		// 呼び出し側が受け取るのは DB に無い鍵です。この鍵で書いたものは
		// 二度と復号できません。
		return nil, fmt.Errorf("tenantcrypto: load key for tenant %q: %w", tenantID, err)
	}

	// Unwrap the stored key using the master key.
	tenantKey, err := gcmDecrypt(s.masterKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: unwrap key for tenant %q: %w", tenantID, err)
	}
	if len(tenantKey) != keySize {
		return nil, fmt.Errorf("tenantcrypto: unwrapped key for tenant %q has unexpected length %d", tenantID, len(tenantKey))
	}
	return tenantKey, nil
}

// RotateKey generates a new tenant key, wraps it with the master key, and
// replaces the existing row in the database.
func (s *DBKeyStore) RotateKey(ctx context.Context, tenantID string) error {
	newKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("tenantcrypto: generate rotation key for tenant %q: %w", tenantID, err)
	}
	wrappedKey, err := gcmEncrypt(s.masterKey, newKey)
	if err != nil {
		return fmt.Errorf("tenantcrypto: wrap rotation key for tenant %q: %w", tenantID, err)
	}

	const upsert = `
		INSERT INTO tenant_encryption_keys (tenant_id, encrypted_key, key_version, rotated_at)
		VALUES ($1, $2, 1, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		  SET encrypted_key = EXCLUDED.encrypted_key,
		      key_version    = tenant_encryption_keys.key_version + 1,
		      rotated_at     = NOW()
	`
	_, err = s.db.Exec(ctx, upsert, tenantID, wrappedKey)
	if err != nil {
		return fmt.Errorf("tenantcrypto: persist rotated key for tenant %q: %w", tenantID, err)
	}
	return nil
}

// createAndStoreKey generates a new tenant key and inserts it into the database.
// It returns the raw (unwrapped) tenant key on success.
func (s *DBKeyStore) createAndStoreKey(ctx context.Context, tenantID string) ([]byte, error) {
	tenantKey, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: generate key for tenant %q: %w", tenantID, err)
	}
	wrappedKey, err := gcmEncrypt(s.masterKey, tenantKey)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: wrap new key for tenant %q: %w", tenantID, err)
	}

	const insert = `
		INSERT INTO tenant_encryption_keys (tenant_id, encrypted_key, key_version)
		VALUES ($1, $2, 1)
		ON CONFLICT (tenant_id) DO NOTHING
	`
	_, err = s.db.Exec(ctx, insert, tenantID, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: store new key for tenant %q: %w", tenantID, err)
	}

	// ON CONFLICT DO NOTHING なので、同時に2つの呼び出しが来たときは
	// どちらか一方の鍵しか入りません。生成したほうをそのまま返すと、
	// 負けた側は DB に無い鍵で暗号化します。入っている鍵を読み直します。
	var stored []byte
	if err := s.db.QueryRow(ctx,
		`SELECT encrypted_key FROM tenant_encryption_keys WHERE tenant_id = $1`, tenantID,
	).Scan(&stored); err != nil {
		return nil, fmt.Errorf("tenantcrypto: re-read key for tenant %q: %w", tenantID, err)
	}
	out, err := gcmDecrypt(s.masterKey, stored)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: unwrap stored key for tenant %q: %w", tenantID, err)
	}
	if len(out) != keySize {
		return nil, fmt.Errorf("tenantcrypto: stored key for tenant %q has unexpected length %d", tenantID, len(out))
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Encryptor
// -----------------------------------------------------------------------------

// Encryptor encrypts and decrypts arbitrary byte slices using per-tenant keys
// sourced from a KeyStore.
//
// Ciphertext wire format:
//
//	[4 bytes: version (big-endian uint32)] [12 bytes: GCM nonce] [ciphertext + 16-byte GCM tag]
//
// The version field is currently always 1 and is reserved for future algorithm
// agility.
type Encryptor struct {
	ks KeyStore
}

// NewEncryptor constructs an Encryptor backed by the given KeyStore.
func NewEncryptor(ks KeyStore) *Encryptor {
	return &Encryptor{ks: ks}
}

// Encrypt encrypts plaintext for tenantID and returns the versioned ciphertext.
func (e *Encryptor) Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	key, err := e.ks.GetKey(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: get key for tenant %q: %w", tenantID, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("tenantcrypto: generate nonce: %w", err)
	}

	// Pre-allocate the full output buffer.
	// Layout: version(4) | nonce(12) | ciphertext+tag
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, headerSize+len(ciphertext))
	binary.BigEndian.PutUint32(out[0:4], ciphertextVersion)
	copy(out[4:headerSize], nonce)
	copy(out[headerSize:], ciphertext)
	return out, nil
}

// Decrypt parses the versioned ciphertext produced by Encrypt and returns the
// original plaintext.
func (e *Encryptor) Decrypt(ctx context.Context, tenantID string, data []byte) ([]byte, error) {
	if len(data) < headerSize+aes.BlockSize {
		return nil, errors.New("tenantcrypto: ciphertext too short")
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != ciphertextVersion {
		return nil, fmt.Errorf("tenantcrypto: unsupported ciphertext version %d", version)
	}

	nonce := data[4:headerSize]
	ciphertext := data[headerSize:]

	key, err := e.ks.GetKey(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: get key for tenant %q: %w", tenantID, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: decrypt for tenant %q: %w", tenantID, err)
	}
	return plaintext, nil
}

// -----------------------------------------------------------------------------
// Low-level AES-256-GCM helpers (used internally for key wrapping)
// -----------------------------------------------------------------------------

// gcmEncrypt encrypts plaintext with key using AES-256-GCM.
// The output is: [12-byte nonce][ciphertext+tag] — no version header, as this
// is an internal format used only for key wrapping within DBKeyStore.
func gcmEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, nonceSize+len(ct))
	copy(out, nonce)
	copy(out[nonceSize:], ct)
	return out, nil
}

// gcmDecrypt is the inverse of gcmEncrypt.
func gcmDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < nonceSize {
		return nil, errors.New("tenantcrypto: wrapped key blob too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := data[:nonceSize]
	ct := data[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// generateKey returns a cryptographically random 32-byte AES-256 key.
func generateKey() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}
