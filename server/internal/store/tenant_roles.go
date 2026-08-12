package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantRole はテナントスコープのロールエントリを表します。
type TenantRole struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	GrantedBy string `json:"granted_by,omitempty"`
	CreatedAt string `json:"created_at"`
}

// roleWeight はロールの優先度を数値で表します（高いほど強い権限）。
var roleWeight = map[string]int{
	"tenant_admin": 3,
	"analyst":      2,
	"viewer":       1,
}

// TenantRoleStore はテナントロールのデータベース操作を提供します。
type TenantRoleStore struct {
	pool *pgxpool.Pool
}

// NewTenantRoleStore は TenantRoleStore を生成します。
func NewTenantRoleStore(pool *pgxpool.Pool) *TenantRoleStore {
	return &TenantRoleStore{pool: pool}
}

// List は指定テナントの全ロールエントリを返します。
func (s *TenantRoleStore) List(ctx context.Context, tenantID string) ([]TenantRole, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, role::text,
		       COALESCE(granted_by::text, ''),
		       created_at::text
		FROM tenant_roles
		WHERE tenant_id = $1
		ORDER BY created_at`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("tenant_roles の一覧取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var result []TenantRole
	for rows.Next() {
		var r TenantRole
		if err := rows.Scan(&r.ID, &r.TenantID, &r.UserID, &r.Role, &r.GrantedBy, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("tenant_roles のスキャンに失敗しました: %w", err)
		}
		result = append(result, r)
	}
	if result == nil {
		result = []TenantRole{}
	}
	return result, nil
}

// Get は特定ユーザーのテナントロールを返します。
func (s *TenantRoleStore) Get(ctx context.Context, tenantID, userID string) (*TenantRole, error) {
	var r TenantRole
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, role::text,
		       COALESCE(granted_by::text, ''),
		       created_at::text
		FROM tenant_roles
		WHERE tenant_id = $1 AND user_id = $2`,
		tenantID, userID,
	).Scan(&r.ID, &r.TenantID, &r.UserID, &r.Role, &r.GrantedBy, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("tenant_role の取得に失敗しました: %w", err)
	}
	return &r, nil
}

// Upsert はロールを追加または更新します。
func (s *TenantRoleStore) Upsert(ctx context.Context, tenantID, userID, role, grantedBy string) (*TenantRole, error) {
	var r TenantRole

	// grantedBy が空文字列の場合は NULL として扱う
	var grantedByParam interface{}
	if grantedBy != "" {
		grantedByParam = grantedBy
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant_roles (tenant_id, user_id, role, granted_by)
		VALUES ($1, $2, $3::tenant_role, $4)
		ON CONFLICT (tenant_id, user_id)
		DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by
		RETURNING id, tenant_id, user_id, role::text,
		          COALESCE(granted_by::text, ''),
		          created_at::text`,
		tenantID, userID, role, grantedByParam,
	).Scan(&r.ID, &r.TenantID, &r.UserID, &r.Role, &r.GrantedBy, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("tenant_role の upsert に失敗しました: %w", err)
	}
	return &r, nil
}

// Delete はロールエントリを削除します。
func (s *TenantRoleStore) Delete(ctx context.Context, tenantID, userID string) error {
	result, err := s.pool.Exec(ctx, `
		DELETE FROM tenant_roles
		WHERE tenant_id = $1 AND user_id = $2`,
		tenantID, userID,
	)
	if err != nil {
		return fmt.Errorf("tenant_role の削除に失敗しました: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("対象のロールエントリが見つかりません")
	}
	return nil
}

// HasRole は指定ユーザーが指定テナントで requiredRole 以上のロールを持つか確認します。
// ロール順序: tenant_admin > analyst > viewer
func (s *TenantRoleStore) HasRole(ctx context.Context, tenantID, userID, requiredRole string) (bool, error) {
	requiredWeight, ok := roleWeight[requiredRole]
	if !ok {
		return false, fmt.Errorf("不明なロール: %s", requiredRole)
	}

	var currentRole string
	err := s.pool.QueryRow(ctx, `
		SELECT role::text
		FROM tenant_roles
		WHERE tenant_id = $1 AND user_id = $2`,
		tenantID, userID,
	).Scan(&currentRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("ロールの確認に失敗しました: %w", err)
	}

	currentWeight, ok := roleWeight[currentRole]
	if !ok {
		return false, fmt.Errorf("データベースに不明なロールが格納されています: %s", currentRole)
	}

	return currentWeight >= requiredWeight, nil
}
