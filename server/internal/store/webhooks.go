package store

import (
	"context"
	"errors"
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
	// RetryPolicy governs how internal/notification delivers to this target.
	// It is part of the target rather than a separate lookup because the
	// notifier already has the target in hand when it delivers.
	RetryPolicy WebhookRetryPolicy `json:"retry_policy"`
}

// WebhookRetryPolicy is how hard to try before a notification is dropped.
//
// Before these columns existed the notifier made exactly one attempt with a
// hardcoded 10 second timeout: a single 502 from the customer's SIEM lost the
// alert with nothing but a Warn line to show for it, and the endpoint that was
// supposed to configure this stored nothing. Bounds are enforced here and by a
// CHECK constraint in migration 375.
type WebhookRetryPolicy struct {
	// MaxRetries is the number of retries AFTER the first attempt. 0 means one
	// attempt and no retry.
	MaxRetries int `json:"max_retries"`
	// RetryDelaySeconds is the base delay; the notifier backs off linearly from
	// it so a struggling endpoint is not hit at a fixed rate.
	RetryDelaySeconds int `json:"retry_delay_seconds"`
	// TimeoutSeconds bounds each individual attempt.
	TimeoutSeconds int `json:"timeout_seconds"`
}

// Retry policy bounds. They are duplicated in the CHECK constraint of
// migration 375 so a write from any other code path is refused too.
const (
	MaxRetriesLimit        = 10
	RetryDelaySecondsLimit = 300
	TimeoutSecondsLimit    = 120
)

// Valid reports whether p is within the bounds the database will accept.
func (p WebhookRetryPolicy) Valid() bool {
	return p.MaxRetries >= 0 && p.MaxRetries <= MaxRetriesLimit &&
		p.RetryDelaySeconds >= 0 && p.RetryDelaySeconds <= RetryDelaySecondsLimit &&
		p.TimeoutSeconds >= 1 && p.TimeoutSeconds <= TimeoutSecondsLimit
}

// webhookColumns is the column list every read of webhook_targets uses. It is
// shared so a new column cannot be added to one query and forgotten in another
// — the notifier reads through ListEnabledForEvent, and a policy missing only
// there would be invisible until a delivery failed.
const webhookColumns = `id, name, url, COALESCE(secret, ''), events, enabled,
		       last_triggered_at, last_status, created_at, updated_at,
		       max_retries, retry_delay_seconds, timeout_seconds`

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
		SELECT `+webhookColumns+`
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
			&t.RetryPolicy.MaxRetries, &t.RetryPolicy.RetryDelaySeconds,
			&t.RetryPolicy.TimeoutSeconds,
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
		SELECT `+webhookColumns+`
		FROM webhook_targets
		WHERE id = $1`, id,
	).Scan(
		&t.ID, &t.Name, &t.URL, &t.Secret, &t.Events, &t.Enabled,
		&t.LastTriggeredAt, &t.LastStatus, &t.CreatedAt, &t.UpdatedAt,
		&t.RetryPolicy.MaxRetries, &t.RetryPolicy.RetryDelaySeconds,
		&t.RetryPolicy.TimeoutSeconds,
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
		RETURNING `+webhookColumns,
		t.Name, t.URL, t.Secret, t.Events, t.Enabled,
	).Scan(
		&created.ID, &created.Name, &created.URL, &created.Secret, &created.Events,
		&created.Enabled, &created.LastTriggeredAt, &created.LastStatus,
		&created.CreatedAt, &created.UpdatedAt,
		&created.RetryPolicy.MaxRetries, &created.RetryPolicy.RetryDelaySeconds,
		&created.RetryPolicy.TimeoutSeconds,
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
		RETURNING `+webhookColumns,
		id, t.Name, t.URL, t.Secret, t.Events, t.Enabled,
	).Scan(
		&updated.ID, &updated.Name, &updated.URL, &updated.Secret, &updated.Events,
		&updated.Enabled, &updated.LastTriggeredAt, &updated.LastStatus,
		&updated.CreatedAt, &updated.UpdatedAt,
		&updated.RetryPolicy.MaxRetries, &updated.RetryPolicy.RetryDelaySeconds,
		&updated.RetryPolicy.TimeoutSeconds,
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
		SELECT `+webhookColumns+`
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
			&t.RetryPolicy.MaxRetries, &t.RetryPolicy.RetryDelaySeconds,
			&t.RetryPolicy.TimeoutSeconds,
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

// ErrWebhookNotFound is returned when an operation names a webhook target that
// is not there. It is a distinct error so a handler can answer 404 rather than
// reporting success for a webhook nobody has.
var ErrWebhookNotFound = errors.New("webhookターゲットが見つかりません")

// UpdateRetryPolicy stores the retry policy for one webhook target.
func (s *WebhookStore) UpdateRetryPolicy(ctx context.Context, id string, p WebhookRetryPolicy) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webhook_targets
		SET max_retries = $2, retry_delay_seconds = $3, timeout_seconds = $4,
		    updated_at = NOW()
		WHERE id = $1`,
		id, p.MaxRetries, p.RetryDelaySeconds, p.TimeoutSeconds)
	if err != nil {
		return fmt.Errorf("リトライポリシーの更新に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrWebhookNotFound
	}
	return nil
}

// UpdateEvents replaces the event subscriptions of one webhook target.
func (s *WebhookStore) UpdateEvents(ctx context.Context, id string, events []string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webhook_targets SET events = $2, updated_at = NOW() WHERE id = $1`,
		id, events)
	if err != nil {
		return fmt.Errorf("イベントタイプの更新に失敗しました: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrWebhookNotFound
	}
	return nil
}

// WebhookDelivery is one HTTP attempt made against a webhook target.
//
// A delivery that succeeded on its third attempt leaves three rows: two with
// Delivered false and one true. That sequence is the point — with only the
// final status stamped on the target there was no way to tell an endpoint that
// answered immediately from one that needed every retry in its policy.
type WebhookDelivery struct {
	ID          string    `json:"id"`
	WebhookID   string    `json:"webhook_id"`
	Event       string    `json:"event"`
	Attempt     int       `json:"attempt"`
	StatusCode  int       `json:"status_code"`
	Error       string    `json:"error,omitempty"`
	DurationMs  int64     `json:"duration_ms"`
	Delivered   bool      `json:"delivered"`
	AttemptedAt time.Time `json:"attempted_at"`
}

// DeliveryHistoryLimit is how many attempts are read back for one webhook.
const DeliveryHistoryLimit = 100

// DeliveryRetainPerWebhook is how many attempts are kept per webhook. The read
// exposes DeliveryHistoryLimit, so this leaves headroom while keeping a busy
// webhook on a noisy tenant from growing the table without bound — there is no
// scheduled prune in this codebase to fall back on.
const DeliveryRetainPerWebhook = 500

// RecordDelivery appends one attempt to a target's history and prunes that
// target's oldest rows beyond DeliveryRetainPerWebhook.
//
// The prune runs in the same statement as the insert: a separate periodic job
// would be another moving part, and bounding at write time means the table
// cannot grow past retain × targets no matter which path delivers.
func (s *WebhookStore) RecordDelivery(ctx context.Context, d WebhookDelivery) error {
	// The OFFSET is retain-1, not retain. Every part of a statement containing
	// data-modifying CTEs sees the same snapshot, so the DELETE's subquery reads
	// the table as it was BEFORE this INSERT and cannot count the row being
	// added. Offsetting by retain would therefore settle at retain+1 rows.
	_, err := s.pool.Exec(ctx, `
		WITH inserted AS (
		    INSERT INTO webhook_target_deliveries
		        (webhook_id, event, attempt, status_code, error, duration_ms, delivered)
		    VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		)
		DELETE FROM webhook_target_deliveries
		WHERE webhook_id = $1::uuid
		  AND id IN (
		      SELECT id FROM webhook_target_deliveries
		      WHERE webhook_id = $1::uuid
		      ORDER BY attempted_at DESC, id
		      OFFSET GREATEST($8::int - 1, 0)
		  )`,
		d.WebhookID, d.Event, d.Attempt, d.StatusCode, d.Error, d.DurationMs, d.Delivered,
		DeliveryRetainPerWebhook)
	if err != nil {
		return fmt.Errorf("webhook配信履歴の記録に失敗しました: %w", err)
	}
	return nil
}

// ListDeliveries returns the most recent attempts for one webhook target,
// newest first. It returns ErrWebhookNotFound if the target does not exist, so
// that an unknown id is distinguishable from a target that has never fired.
func (s *WebhookStore) ListDeliveries(ctx context.Context, id string, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 || limit > DeliveryHistoryLimit {
		limit = DeliveryHistoryLimit
	}

	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM webhook_targets WHERE id = $1::uuid)`, id,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("webhookターゲットの確認に失敗しました: %w", err)
	}
	if !exists {
		return nil, ErrWebhookNotFound
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id::text, webhook_id::text, event, attempt, status_code,
		       error, duration_ms, delivered, attempted_at
		FROM webhook_target_deliveries
		WHERE webhook_id = $1::uuid
		ORDER BY attempted_at DESC, id
		LIMIT $2`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("webhook配信履歴の取得に失敗しました: %w", err)
	}
	defer rows.Close()

	deliveries := []WebhookDelivery{}
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.Event, &d.Attempt, &d.StatusCode,
			&d.Error, &d.DurationMs, &d.Delivered, &d.AttemptedAt); err != nil {
			return nil, fmt.Errorf("webhook配信履歴のスキャンに失敗しました: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webhook配信履歴の読み取りに失敗しました: %w", err)
	}
	return deliveries, nil
}
