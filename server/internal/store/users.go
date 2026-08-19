package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// UserStore handles user database operations.
type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(db *DB) *UserStore {
	return &UserStore{pool: db.Pool()}
}

// UserRow mirrors the users table.
type UserRow struct {
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	FullName           string     `json:"full_name"`
	Role               string     `json:"role"`
	TenantID           string     `json:"tenant_id"`
	MFAEnabled         bool       `json:"mfa_enabled"`
	LastLogin          *time.Time `json:"last_login,omitempty"`
	IsActive           bool       `json:"is_active"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
}

const (
	maxFailedLogins   = 5
	loginLockDuration = 15 * time.Minute
)

// Authenticate validates email+password and returns the user if valid.
// Failed attempts are recorded in DB; after maxFailedLogins the account
// is locked for loginLockDuration. This survives API restarts and works
// across multiple API instances without requiring Redis.
func (s *UserStore) Authenticate(ctx context.Context, email, password string) (*UserRow, error) {
	var u UserRow
	var passwordHash string
	var failedCount int
	var lockedUntil *time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT id, email, COALESCE(full_name,''), role,
		       COALESCE(tenant_id::text, ''),
		       mfa_enabled, last_login, is_active, must_change_password, created_at,
		       COALESCE(password_hash,''),
		       COALESCE(failed_login_count, 0),
		       locked_until
		FROM users
		WHERE email = $1 AND is_active = true`,
		email,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Role,
		&u.TenantID,
		&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
		&passwordHash,
		&failedCount,
		&lockedUntil,
	)
	if err != nil {
		return nil, fmt.Errorf("ユーザーが見つかりません")
	}

	// Check DB-level lockout (persists across restarts)
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return nil, fmt.Errorf("アカウントがロックされています。%s まで再試行できません", lockedUntil.Format("15:04"))
	}

	if passwordHash == "" {
		return nil, fmt.Errorf("パスワードが設定されていません")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		// Increment failure count; lock if threshold reached.
		//
		// **この加算が落ちると、総当たりに対するロックアウトが黙って
		// 効かなくなります。** 呼び出し側はもう応答を返しているので
		// （goroutine です）、報告先は部品ごとの件数です。
		go func() {
			newCount := failedCount + 1
			var err error
			if newCount >= maxFailedLogins {
				lockUntil := time.Now().Add(loginLockDuration)
				_, err = s.pool.Exec(context.Background(),
					`UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,
					newCount, lockUntil, u.ID)
			} else {
				_, err = s.pool.Exec(context.Background(),
					`UPDATE users SET failed_login_count = $1 WHERE id = $2`,
					newCount, u.ID)
			}
			if err != nil {
				metrics.BackgroundFailed("login_lockout", err,
					"ログイン失敗回数を記録できませんでした。ロックアウトが効きません",
					"user_id", u.ID, "count", newCount)
			}
		}()
		return nil, fmt.Errorf("パスワードが正しくありません")
	}

	// Success — reset failure count and last_login.
	//
	// **落ちると、失敗回数が積み上がったまま残ります** —— 正しい
	// パスワードで入り続けている利用者が、いずれロックされます。
	// `last_login` は休眠アカウントの棚卸しにも使われます。
	go func() {
		if _, err := s.pool.Exec(context.Background(),
			`UPDATE users SET last_login = NOW(), failed_login_count = 0, locked_until = NULL WHERE id = $1`,
			u.ID); err != nil {
			metrics.BackgroundFailed("login_lockout", err,
				"ログイン成功を記録できませんでした。失敗回数が残ったままです",
				"user_id", u.ID)
		}
	}()

	return &u, nil
}

// GetByID retrieves a user by ID.
func (s *UserStore) GetByID(ctx context.Context, id string) (*UserRow, error) {
	var u UserRow
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, COALESCE(full_name,''), role,
		       COALESCE(tenant_id::text, ''),
		       mfa_enabled, last_login, is_active, must_change_password, created_at
		FROM users WHERE id = $1`,
		id,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Role,
		&u.TenantID,
		&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// List returns all users (admin only).
func (s *UserStore) List(ctx context.Context) ([]*UserRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, COALESCE(full_name,''), role,
		       mfa_enabled, last_login, is_active, must_change_password, created_at
		FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(
			&u.ID, &u.Email, &u.FullName, &u.Role,
			&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
		); err != nil {
			continue
		}
		users = append(users, &u)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// Create creates a new user with a bcrypt-hashed password.
func (s *UserStore) Create(ctx context.Context, email, password, fullName, role string) (*UserRow, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("パスワードのハッシュ化に失敗しました: %w", err)
	}

	var u UserRow
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, role, must_change_password)
		VALUES ($1, $2, $3, $4, TRUE)
		RETURNING id, email, COALESCE(full_name,''), role,
		          mfa_enabled, last_login, is_active, must_change_password, created_at`,
		email, string(hash), fullName, role,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Role,
		&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ユーザーの作成に失敗しました: %w", err)
	}
	return &u, nil
}

// CreateFromInvitation creates a user account from an accepted invitation.
// Sets must_change_password = false since the user sets their password during invitation acceptance.
func (s *UserStore) CreateFromInvitation(ctx context.Context, email, password, fullName, role, tenantID string) (*UserRow, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("パスワードのハッシュ化に失敗しました: %w", err)
	}

	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	var tenantParam interface{} = tenantID

	var u UserRow
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, role, tenant_id, must_change_password)
		VALUES ($1, $2, $3, $4, $5, FALSE)
		RETURNING id, email, COALESCE(full_name,''), role,
		          mfa_enabled, last_login, is_active, must_change_password, created_at`,
		email, string(hash), fullName, role, tenantParam,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Role,
		&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ユーザーの作成に失敗しました: %w", err)
	}
	return &u, nil
}

// ClearMustChangePassword clears the must_change_password flag after a successful password change.
func (s *UserStore) ClearMustChangePassword(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET must_change_password = FALSE, updated_at = NOW() WHERE id = $1",
		id,
	)
	return err
}

// VerifyCurrentPassword checks that the given plaintext password matches the stored hash.
// Returns nil if valid, or an error if the password is wrong or the user is not found.
func (s *UserStore) VerifyCurrentPassword(ctx context.Context, id, password string) error {
	var hash string
	err := s.pool.QueryRow(ctx,
		"SELECT COALESCE(password_hash,'') FROM users WHERE id = $1", id,
	).Scan(&hash)
	if err != nil {
		return fmt.Errorf("ユーザーが見つかりません")
	}
	if hash == "" {
		return fmt.Errorf("パスワードが設定されていません")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return fmt.Errorf("現在のパスワードが正しくありません")
	}
	return nil
}

// UpdatePassword updates a user's password.
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		"UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1",
		id, string(hash),
	)
	return err
}

// GetByEmail retrieves an active user by email address.
// Returns nil if not found.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*UserRow, error) {
	var u UserRow
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, COALESCE(full_name,''), role,
		       COALESCE(tenant_id::text, ''),
		       mfa_enabled, last_login, is_active, must_change_password, created_at
		FROM users WHERE email = $1 AND is_active = true`,
		email,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Role,
		&u.TenantID,
		&u.MFAEnabled, &u.LastLogin, &u.IsActive, &u.MustChangePassword, &u.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetMFASecret returns the TOTP secret for a user (empty string if not set).
func (s *UserStore) GetMFASecret(ctx context.Context, userID string) (secret string, enabled bool, err error) {
	err = s.pool.QueryRow(ctx,
		"SELECT COALESCE(mfa_secret,''), mfa_enabled FROM users WHERE id = $1",
		userID,
	).Scan(&secret, &enabled)
	return
}

// SetMFASecret stores the TOTP secret and enables MFA for the user.
func (s *UserStore) SetMFASecret(ctx context.Context, userID, secret string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET mfa_secret = $2, mfa_enabled = TRUE, updated_at = NOW() WHERE id = $1",
		userID, secret,
	)
	return err
}

// StoreMFASecret stores the TOTP secret without enabling MFA (pending /mfa/confirm).
func (s *UserStore) StoreMFASecret(ctx context.Context, userID, secret string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET mfa_secret = $2, updated_at = NOW() WHERE id = $1",
		userID, secret,
	)
	return err
}

// EnableMFA marks MFA as enabled for the user (called after successful /mfa/confirm).
func (s *UserStore) EnableMFA(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET mfa_enabled = TRUE, updated_at = NOW() WHERE id = $1",
		userID,
	)
	return err
}

// DisableMFA clears the TOTP secret and disables MFA.
func (s *UserStore) DisableMFA(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET mfa_secret = NULL, mfa_enabled = FALSE, updated_at = NOW() WHERE id = $1",
		userID,
	)
	return err
}

// SaveBackupCodes stores hashed backup codes, replacing any existing ones.
func (s *UserStore) SaveBackupCodes(ctx context.Context, userID string, codes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Delete old codes
	if _, err := tx.Exec(ctx, "DELETE FROM mfa_backup_codes WHERE user_id = $1", userID); err != nil {
		return err
	}

	// Insert new hashed codes
	for _, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)",
			userID, string(hash),
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// UseBackupCode verifies and consumes a backup code. Returns false if invalid/already used.
func (s *UserStore) UseBackupCode(ctx context.Context, userID, code string) (bool, error) {
	// **候補を読み切ってから接続を返します。**
	//
	// 以前は `rows` を開いたまま、その中で `s.pool.Exec` を呼んでいました
	// —— 1つ目の接続を握ったまま2つ目を要求する形です。**同時に来た要求が
	// プールの本数を超えると、全員が互いの接続を待って進まなくなります**
	// （pgxpool の既定は 4 本。この形は検査を書いたときに詰まって
	// 見つかりました）。あいだに bcrypt の比較が入るので、握っている
	// 時間も短くありません。
	rows, err := s.pool.Query(ctx,
		"SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = $1 AND used = FALSE",
		userID,
	)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	type candidate struct{ id, hash string }
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			// pgx はここで結果セットを終えるので、下の rows.Err() が
			// 本当の報告です。
			continue
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	// **ここまでで pgx は接続を返しています**（`Next()` が false を
	// 返した時点）。下の UPDATE は2本目を要求しません。

	for _, c := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(code)) != nil {
			continue
		}
		// **使用済みの印を書けなければ、このコードは使えていません。**
		//
		// ここは `_, _ =` でした。書けなくても `true` を返すので、
		// **一度だけ使えるはずの復旧コードが、何度でも使えます** ——
		// MFA の最後の手段が、使い捨てでなくなります。
		//
		// `used = FALSE` を条件に入れてあるのは、読んでから書くまでの
		// あいだに同じコードが使われる場合のためです。**同時に2回
		// 出されたコードは、1回だけ通ります。**
		tag, uerr := s.pool.Exec(ctx,
			"UPDATE mfa_backup_codes SET used = TRUE, used_at = NOW() WHERE id = $1 AND used = FALSE", c.id)
		if uerr != nil {
			return false, fmt.Errorf("復旧コードを使用済みにできませんでした: %w", uerr)
		}
		if tag.RowsAffected() == 0 {
			// 先に誰か（別の要求）が同じコードを使いました。
			return false, nil
		}
		return true, nil
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// BackupCodeStatus describes one stored backup code without revealing it
// (codes are bcrypt-hashed and can never be shown again after generation).
type BackupCodeStatus struct {
	Used      bool
	CreatedAt time.Time
	UsedAt    *time.Time
}

// ListBackupCodeStatus returns the status of the user's backup codes.
func (s *UserStore) ListBackupCodeStatus(ctx context.Context, userID string) ([]BackupCodeStatus, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT used, created_at, used_at FROM mfa_backup_codes WHERE user_id = $1 ORDER BY created_at, id",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []BackupCodeStatus
	for rows.Next() {
		var st BackupCodeStatus
		if err := rows.Scan(&st.Used, &st.CreatedAt, &st.UsedAt); err != nil {
			continue
		}
		list = append(list, st)
	}
	return list, rows.Err()
}

// GenerateBackupCodes generates n random 8-character hex backup codes.
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, n)
	buf := make([]byte, 4)
	for i := range codes {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(buf)
	}
	return codes, nil
}

// SetMFAType は users.mfa_type を更新する ('totp' | 'email' | 'none')。
func (s *UserStore) SetMFAType(ctx context.Context, userID, mfaType string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET mfa_type = $2, updated_at = NOW() WHERE id = $1",
		userID, mfaType,
	)
	return err
}

// GetMFAType は users.mfa_type を返す。カラムが存在しない場合は 'totp' を返す。
func (s *UserStore) GetMFAType(ctx context.Context, userID string) (string, error) {
	var mfaType string
	err := s.pool.QueryRow(ctx,
		"SELECT COALESCE(mfa_type, 'totp') FROM users WHERE id = $1",
		userID,
	).Scan(&mfaType)
	if err != nil {
		return "totp", err
	}
	return mfaType, nil
}

// SetActive activates or deactivates a user.
func (s *UserStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET is_active = $2, updated_at = NOW() WHERE id = $1",
		id, active,
	)
	return err
}

// UpdateFullName updates the display name of a user.
func (s *UserStore) UpdateFullName(ctx context.Context, id, fullName string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET full_name = $2, updated_at = NOW() WHERE id = $1",
		id, fullName,
	)
	return err
}

// UpdateRole changes the role of a user.
func (s *UserStore) UpdateRole(ctx context.Context, id, role string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1",
		id, role,
	)
	return err
}

// SeedAdminUser creates admin@example.com if no users exist yet.
// Called once at startup; safe to call on every boot (no-op if user exists).
func SeedAdminUser(ctx context.Context, pool *pgxpool.Pool, password string) error {
	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("ユーザー数の取得に失敗しました: %w", err)
	}
	if count > 0 {
		return nil // already seeded
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("パスワードのハッシュ化に失敗しました: %w", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO users (email, password_hash, full_name, role, must_change_password, is_active)
		VALUES ('admin@example.com', $1, 'Administrator', 'admin', FALSE, TRUE)
		ON CONFLICT (email) DO NOTHING`,
		string(hash),
	)
	if err != nil {
		return fmt.Errorf("管理者ユーザーの作成に失敗しました: %w", err)
	}
	return nil
}

// SeedTestMFAUser creates an MFA(TOTP)-enabled user for E2E tests so the MFA
// login flow can be exercised. Intended ONLY for test/CI environments — gate the
// call behind an env flag and never enable it in production. The TOTP secret is a
// fixed valid base32 value; the E2E tests only assert that the MFA prompt appears
// and that an invalid code is rejected, so no valid code generation is required.
func SeedTestMFAUser(ctx context.Context, pool *pgxpool.Pool, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("MFAテストユーザーのパスワードハッシュ化に失敗しました: %w", err)
	}

	const totpSecret = "JBSWY3DPEHPK3PXP" // valid base32, fixed for tests
	_, err = pool.Exec(ctx, `
		INSERT INTO users (email, password_hash, full_name, role, must_change_password, is_active, mfa_enabled, mfa_secret, mfa_type)
		VALUES ($1, $2, 'MFA Test User', 'analyst', FALSE, TRUE, TRUE, $3, 'totp')
		ON CONFLICT (email) DO UPDATE
		   SET mfa_enabled = TRUE, mfa_secret = EXCLUDED.mfa_secret, mfa_type = 'totp', is_active = TRUE`,
		email, string(hash), totpSecret,
	)
	if err != nil {
		return fmt.Errorf("MFAテストユーザーの作成に失敗しました: %w", err)
	}
	return nil
}
