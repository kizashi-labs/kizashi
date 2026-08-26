package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SSOConfig represents a stored SSO/SAML or OIDC provider configuration.
type SSOConfig struct {
	ID               string          `json:"id"`
	Provider         string          `json:"provider" binding:"required"` // "saml" or "oidc"
	Name             string          `json:"name" binding:"required"`     // e.g. "Okta", "Azure AD"
	IDPEntityID      string          `json:"idp_entity_id"`               // SAML: IdP Entity ID
	IDPSSOUrl        string          `json:"idp_sso_url"`                 // SAML: IdP Single Sign-On URL
	IDPCertificate   string          `json:"idp_certificate"`             // SAML: PEM-encoded X.509 certificate
	SPEntityID       string          `json:"sp_entity_id"`                // SAML: SP Entity ID (our ACS URL)
	ClientID         string          `json:"client_id"`                   // OIDC: client_id
	ClientSecret     string          `json:"client_secret,omitempty"`     // OIDC: client_secret (omitted in list responses)
	DiscoveryURL     string          `json:"discovery_url"`               // OIDC: .well-known/openid-configuration URL
	Enabled          bool            `json:"enabled"`
	AttributeMapping json.RawMessage `json:"attribute_mapping"` // JSON: {"email": "...", "name": "...", "role": "..."}
	DefaultRole      string          `json:"default_role"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// SSOPublicProvider is the limited view exposed to unauthenticated clients
// (used for the login page provider list).
type SSOPublicProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SSOConfigStore handles CRUD for sso_configs.
type SSOConfigStore struct {
	pool *pgxpool.Pool
}

// NewSSOConfigStore creates a new SSOConfigStore.
func NewSSOConfigStore(pool *pgxpool.Pool) *SSOConfigStore {
	return &SSOConfigStore{pool: pool}
}

// List returns all SSO configs (admin view, includes secrets).
func (s *SSOConfigStore) List(ctx context.Context) ([]SSOConfig, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, name,
		       COALESCE(idp_entity_id, ''), COALESCE(idp_sso_url, ''),
		       COALESCE(idp_certificate, ''), COALESCE(sp_entity_id, ''),
		       COALESCE(client_id, ''), COALESCE(client_secret, ''),
		       COALESCE(discovery_url, ''),
		       enabled, attribute_mapping, default_role,
		       created_at, updated_at
		FROM sso_configs
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("SSO設定一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var configs []SSOConfig
	for rows.Next() {
		var c SSOConfig
		if err := rows.Scan(
			&c.ID, &c.Provider, &c.Name,
			&c.IDPEntityID, &c.IDPSSOUrl, &c.IDPCertificate, &c.SPEntityID,
			&c.ClientID, &c.ClientSecret, &c.DiscoveryURL,
			&c.Enabled, &c.AttributeMapping, &c.DefaultRole,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("SSO設定行のスキャンに失敗しました: %w", err)
		}
		configs = append(configs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SSO設定行の読み取りに失敗しました: %w", err)
	}
	if configs == nil {
		configs = []SSOConfig{}
	}
	return configs, nil
}

// Get returns a single SSO config by ID.
func (s *SSOConfigStore) Get(ctx context.Context, id string) (*SSOConfig, error) {
	var c SSOConfig
	err := s.pool.QueryRow(ctx, `
		SELECT id, provider, name,
		       COALESCE(idp_entity_id, ''), COALESCE(idp_sso_url, ''),
		       COALESCE(idp_certificate, ''), COALESCE(sp_entity_id, ''),
		       COALESCE(client_id, ''), COALESCE(client_secret, ''),
		       COALESCE(discovery_url, ''),
		       enabled, attribute_mapping, default_role,
		       created_at, updated_at
		FROM sso_configs WHERE id = $1`, id,
	).Scan(
		&c.ID, &c.Provider, &c.Name,
		&c.IDPEntityID, &c.IDPSSOUrl, &c.IDPCertificate, &c.SPEntityID,
		&c.ClientID, &c.ClientSecret, &c.DiscoveryURL,
		&c.Enabled, &c.AttributeMapping, &c.DefaultRole,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("SSO設定の取得に失敗しました: %w", err)
	}
	return &c, nil
}

// Create inserts a new SSO config and returns it.
func (s *SSOConfigStore) Create(ctx context.Context, c SSOConfig) (*SSOConfig, error) {
	attrMapping := c.AttributeMapping
	if len(attrMapping) == 0 {
		attrMapping = json.RawMessage(`{"email": "email", "name": "name", "role": "role"}`)
	}

	var created SSOConfig
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sso_configs (
			provider, name,
			idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id,
			client_id, client_secret, discovery_url,
			enabled, attribute_mapping, default_role
		) VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''),
		          NULLIF($7,''), NULLIF($8,''), NULLIF($9,''),
		          $10, $11, $12)
		RETURNING id, provider, name,
		          COALESCE(idp_entity_id, ''), COALESCE(idp_sso_url, ''),
		          COALESCE(idp_certificate, ''), COALESCE(sp_entity_id, ''),
		          COALESCE(client_id, ''), COALESCE(client_secret, ''),
		          COALESCE(discovery_url, ''),
		          enabled, attribute_mapping, default_role,
		          created_at, updated_at`,
		c.Provider, c.Name,
		c.IDPEntityID, c.IDPSSOUrl, c.IDPCertificate, c.SPEntityID,
		c.ClientID, c.ClientSecret, c.DiscoveryURL,
		c.Enabled, attrMapping, c.DefaultRole,
	).Scan(
		&created.ID, &created.Provider, &created.Name,
		&created.IDPEntityID, &created.IDPSSOUrl, &created.IDPCertificate, &created.SPEntityID,
		&created.ClientID, &created.ClientSecret, &created.DiscoveryURL,
		&created.Enabled, &created.AttributeMapping, &created.DefaultRole,
		&created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("SSO設定の作成に失敗しました: %w", err)
	}
	return &created, nil
}

// Update replaces all fields of an SSO config.
func (s *SSOConfigStore) Update(ctx context.Context, id string, c SSOConfig) (*SSOConfig, error) {
	attrMapping := c.AttributeMapping
	if len(attrMapping) == 0 {
		attrMapping = json.RawMessage(`{"email": "email", "name": "name", "role": "role"}`)
	}

	var updated SSOConfig
	err := s.pool.QueryRow(ctx, `
		UPDATE sso_configs SET
			provider = $2, name = $3,
			idp_entity_id = NULLIF($4,''), idp_sso_url = NULLIF($5,''),
			idp_certificate = NULLIF($6,''), sp_entity_id = NULLIF($7,''),
			client_id = NULLIF($8,''), client_secret = NULLIF($9,''),
			discovery_url = NULLIF($10,''),
			enabled = $11, attribute_mapping = $12, default_role = $13,
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, provider, name,
		          COALESCE(idp_entity_id, ''), COALESCE(idp_sso_url, ''),
		          COALESCE(idp_certificate, ''), COALESCE(sp_entity_id, ''),
		          COALESCE(client_id, ''), COALESCE(client_secret, ''),
		          COALESCE(discovery_url, ''),
		          enabled, attribute_mapping, default_role,
		          created_at, updated_at`,
		id, c.Provider, c.Name,
		c.IDPEntityID, c.IDPSSOUrl, c.IDPCertificate, c.SPEntityID,
		c.ClientID, c.ClientSecret, c.DiscoveryURL,
		c.Enabled, attrMapping, c.DefaultRole,
	).Scan(
		&updated.ID, &updated.Provider, &updated.Name,
		&updated.IDPEntityID, &updated.IDPSSOUrl, &updated.IDPCertificate, &updated.SPEntityID,
		&updated.ClientID, &updated.ClientSecret, &updated.DiscoveryURL,
		&updated.Enabled, &updated.AttributeMapping, &updated.DefaultRole,
		&updated.CreatedAt, &updated.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("SSO設定の更新に失敗しました: %w", err)
	}
	return &updated, nil
}

// Delete removes an SSO config by ID.
func (s *SSOConfigStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sso_configs WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("SSO設定の削除に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("SSO設定が見つかりません")
	}
	return nil
}

// ListEnabledFull returns full SSOConfig records for all enabled providers.
// Used internally by callback handlers to retrieve credentials for token exchange.
func (s *SSOConfigStore) ListEnabledFull(ctx context.Context) ([]SSOConfig, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, name,
		       COALESCE(idp_entity_id, ''), COALESCE(idp_sso_url, ''),
		       COALESCE(idp_certificate, ''), COALESCE(sp_entity_id, ''),
		       COALESCE(client_id, ''), COALESCE(client_secret, ''),
		       COALESCE(discovery_url, ''),
		       enabled, attribute_mapping, default_role,
		       created_at, updated_at
		FROM sso_configs WHERE enabled = true ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("有効なSSO設定一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var configs []SSOConfig
	for rows.Next() {
		var c SSOConfig
		if err := rows.Scan(
			&c.ID, &c.Provider, &c.Name,
			&c.IDPEntityID, &c.IDPSSOUrl, &c.IDPCertificate, &c.SPEntityID,
			&c.ClientID, &c.ClientSecret, &c.DiscoveryURL,
			&c.Enabled, &c.AttributeMapping, &c.DefaultRole,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("SSO設定行のスキャンに失敗しました: %w", err)
		}
		configs = append(configs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SSO設定行の読み取りに失敗しました: %w", err)
	}
	if configs == nil {
		configs = []SSOConfig{}
	}
	return configs, nil
}

// ListEnabled returns the public name/id list of all enabled SSO providers.
// This is called by the login page to determine whether to show the SSO button.
func (s *SSOConfigStore) ListEnabled(ctx context.Context) ([]SSOPublicProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name FROM sso_configs WHERE enabled = true ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("有効なSSO設定一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var providers []SSOPublicProvider
	for rows.Next() {
		var p SSOPublicProvider
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, fmt.Errorf("SSO設定行のスキャンに失敗しました: %w", err)
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SSO設定行の読み取りに失敗しました: %w", err)
	}
	if providers == nil {
		providers = []SSOPublicProvider{}
	}
	return providers, nil
}
