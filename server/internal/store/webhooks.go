package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookTarget represents a registered webhook endpoint.
type WebhookTarget struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Secret          string     `json:"secret,omitempty"`
	Events          []string   `json:"events"`
	Enabled         bool       `json:"enabled"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	LastStatus      *int       `json:"last_status,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// WebhookStore handles CRUD for webhook_targets.
type WebhookStore struct {
	pool *pgxpool.Pool
}

// NewWebhookStore creates a new WebhookStore.
func NewWebhookStore(pool *pgxpool.Pool) *WebhookStore {
	return &WebhookStore{pool: pool}
}

// Pool returns the underlying connection pool for advanced queries.
func (s *WebhookStore) Pool() *pgxpool.Pool {
	return s.pool
}

// List returns all webhook targets.
func (s *WebhookStore) List(ctx context.Context) ([]WebhookTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, url, COALESCE(secret, ''), events, enabled,
		       last_triggered_at, last_status, created_at, updated_at
		FROM webhook_targets
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("webhookターゲット一覧の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var targets []WebhookTarget
	for rows.Next() {
		var t WebhookTarget
		if err := rows.Scan(
			&t.ID, &t.Name, &t.URL, &t.Secret, &t.Events, &t.Enabled,
			&t.LastTriggeredAt, &t.LastStatus, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("webhookターゲット行のスキャンに失敗しました: %w", err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webhookターゲット行の読み取りに失敗しました: %w", err)
	}
	if targets == nil {
		targets = []WebhookTarget{}
	}
	return targets, nil
}

// Get returns a single webhook target by ID.
func (s *WebhookStore) Get(ctx context.Context, id string) (*WebhookTarget, error) {
	var t WebhookTarget
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, url, COALESCE(secret, ''), events, enabled,
		       last_triggered_at, last_status, created_at, updated_at
		FROM webhook_targets
		WHERE id = $1`, id,
	).Scan(
		&t.ID, &t.Name, &t.URL, &t.Secret, &t.Events, &t.Enabled,
		&t.LastTriggeredAt, &t.LastStatus, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("webhookターゲットの取得に失敗しました: %w", err)
	}
	return &t, nil
}

// Create inserts a new webhook target and returns it.
func (s *WebhookStore) Create(ctx context.Context, t WebhookTarget) (*WebhookTarget, error) {
	var created WebhookTarget
	err := s.pool.QueryRow(ctx, `
		INSERT INTO webhook_targets (name, url, secret, events, enabled)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		RETURNING id, name, url, COALESCE(secret, ''), events, enabled,
		          last_triggered_at, last_status, created_at, updated_at`,
		t.Name, t.URL, t.Secret, t.Events, t.Enabled,
	).Scan(
		&created.ID, &created.Name, &created.URL, &created.Secret, &created.Events,
		&created.Enabled, &created.LastTriggeredAt, &created.LastStatus,
		&created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("webhookターゲットの作成に失敗しました: %w", err)
	}
	return &created, nil
}

// Update replaces name, url, secret, events, enabled for a webhook target.
func (s *WebhookStore) Update(ctx context.Context, id string, t WebhookTarget) (*WebhookTarget, error) {
	var updated WebhookTarget
	err := s.pool.QueryRow(ctx, `
		UPDATE webhook_targets
		SET name = $2, url = $3, secret = NULLIF($4, ''), events = $5, enabled = $6,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, url, COALESCE(secret, ''), events, enabled,
		          last_triggered_at, last_status, created_at, updated_at`,
		id, t.Name, t.URL, t.Secret, t.Events, t.Enabled,
	).Scan(
		&updated.ID, &updated.Name, &updated.URL, &updated.Secret, &updated.Events,
		&updated.Enabled, &updated.LastTriggeredAt, &updated.LastStatus,
		&updated.CreatedAt, &updated.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("webhookターゲットの更新に失敗しました: %w", err)
	}
	return &updated, nil
}

// Delete removes a webhook target by ID.
func (s *WebhookStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook_targets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("webhookターゲットの削除に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhookターゲットが見つかりません")
	}
	return nil
}

// SetEnabled updates the enabled flag for a webhook target.
func (s *WebhookStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webhook_targets SET enabled = $2, updated_at = NOW() WHERE id = $1`,
		id, enabled,
	)
	if err != nil {
		return fmt.Errorf("webhookターゲットの有効/無効切り替えに失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhookターゲットが見つかりません")
	}
	return nil
}

// UpdateDeliveryStatus records the last delivery timestamp and HTTP status code.
func (s *WebhookStore) UpdateDeliveryStatus(ctx context.Context, id string, status int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE webhook_targets
		 SET last_triggered_at = NOW(), last_status = $2, updated_at = NOW()
		 WHERE id = $1`,
		id, status,
	)
	if err != nil {
		return fmt.Errorf("webhook配信ステータスの更新に失敗しました: %w", err)
	}
	return nil
}

// ListEnabledForEvent returns all enabled webhook targets that subscribe to the given event type.
func (s *WebhookStore) ListEnabledForEvent(ctx context.Context, event string) ([]WebhookTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, url, COALESCE(secret, ''), events, enabled,
		       last_triggered_at, last_status, created_at, updated_at
		FROM webhook_targets
		WHERE enabled = true
		  AND ($1 = ANY(events) OR 'alert.any' = ANY(events))
		ORDER BY created_at`,
		event,
	)
	if err != nil {
		return nil, fmt.Errorf("イベント対象webhookターゲットの取得に失敗しました: %w", err)
	}
	defer rows.Close()

	var targets []WebhookTarget
	for rows.Next() {
		var t WebhookTarget
		if err := rows.Scan(
			&t.ID, &t.Name, &t.URL, &t.Secret, &t.Events, &t.Enabled,
			&t.LastTriggeredAt, &t.LastStatus, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("webhook行のスキャンに失敗しました: %w", err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webhook行の読み取りに失敗しました: %w", err)
	}
	if targets == nil {
		targets = []WebhookTarget{}
	}
	return targets, nil
}
