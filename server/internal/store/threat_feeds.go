package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrThreatFeedNotFound is returned by Update/Delete when no row matches the id.
var ErrThreatFeedNotFound = errors.New("threat feed not found")

// ThreatFeed defines an external IOC feed source.
type ThreatFeed struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	URL               string            `json:"url"`
	FeedType          string            `json:"feed_type"`               // txt|csv|misp|otx
	IOCType           string            `json:"ioc_type"`                // ip|domain|hash|url
	SourceFormat      string            `json:"source_format,omitempty"` // otx_reputation|urlhaus_csv|malwarebazaar_csv|feodo_csv|misp_json
	APIKey            string            `json:"api_key,omitempty"`       // optional API key for authenticated feeds
	Description       string            `json:"description,omitempty"`
	IsActive          bool              `json:"is_active"`
	LastSyncAt        *time.Time        `json:"last_sync_at,omitempty"`
	LastCount         int               `json:"last_count"`
	SyncIntervalHours int               `json:"sync_interval_hours"`
	Headers           map[string]string `json:"headers,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// ThreatFeedStore manages threat feed persistence.
type ThreatFeedStore struct {
	pool *pgxpool.Pool
}

func NewThreatFeedStore(db *DB) *ThreatFeedStore {
	return &ThreatFeedStore{pool: db.Pool()}
}

func (s *ThreatFeedStore) List(ctx context.Context) ([]*ThreatFeed, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, url, feed_type, ioc_type, COALESCE(description,''),
		       is_active, last_sync_at, COALESCE(last_count,0), sync_interval_hours,
		       COALESCE(headers,'{}')::jsonb, created_at, updated_at,
		       COALESCE(source_format,''), COALESCE(api_key,'')
		FROM threat_feeds
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []*ThreatFeed
	for rows.Next() {
		f := &ThreatFeed{}
		if err := rows.Scan(
			&f.ID, &f.Name, &f.URL, &f.FeedType, &f.IOCType, &f.Description,
			&f.IsActive, &f.LastSyncAt, &f.LastCount, &f.SyncIntervalHours,
			&f.Headers, &f.CreatedAt, &f.UpdatedAt,
			&f.SourceFormat, &f.APIKey,
		); err != nil {
			continue
		}
		feeds = append(feeds, f)
	}
	if feeds == nil {
		feeds = []*ThreatFeed{}
	}
	return feeds, nil
}

func (s *ThreatFeedStore) Insert(ctx context.Context, f *ThreatFeed) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO threat_feeds
		  (name, url, feed_type, ioc_type, description, is_active, sync_interval_hours, headers, source_format, api_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		f.Name, f.URL, f.FeedType, f.IOCType, f.Description,
		f.IsActive, f.SyncIntervalHours, headersJSON(f.Headers),
		f.SourceFormat, f.APIKey,
	).Scan(&id)
	return id, err
}

func (s *ThreatFeedStore) Update(ctx context.Context, f *ThreatFeed) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE threat_feeds
		SET name=$2, url=$3, feed_type=$4, ioc_type=$5, description=$6,
		    is_active=$7, sync_interval_hours=$8, headers=$9, updated_at=NOW(),
		    source_format=$10, api_key=$11
		WHERE id=$1`,
		f.ID, f.Name, f.URL, f.FeedType, f.IOCType, f.Description,
		f.IsActive, f.SyncIntervalHours, headersJSON(f.Headers),
		f.SourceFormat, f.APIKey,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrThreatFeedNotFound
	}
	return nil
}

func (s *ThreatFeedStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM threat_feeds WHERE id=$1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrThreatFeedNotFound
	}
	return nil
}

func (s *ThreatFeedStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE threat_feeds SET is_active=$2, updated_at=NOW() WHERE id=$1",
		id, active)
	return err
}

// MarkSynced updates last_sync_at and last_count after a successful sync.
func (s *ThreatFeedStore) MarkSynced(ctx context.Context, id string, count int) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE threat_feeds SET last_sync_at=NOW(), last_count=$2, updated_at=NOW() WHERE id=$1",
		id, count)
	return err
}

// GetDueForSync returns active feeds whose next sync time has passed.
func (s *ThreatFeedStore) GetDueForSync(ctx context.Context) ([]*ThreatFeed, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, url, feed_type, ioc_type, COALESCE(description,''),
		       is_active, last_sync_at, COALESCE(last_count,0), sync_interval_hours,
		       COALESCE(headers,'{}')::jsonb, created_at, updated_at,
		       COALESCE(source_format,''), COALESCE(api_key,'')
		FROM threat_feeds
		WHERE is_active = TRUE
		  AND (last_sync_at IS NULL
		    OR last_sync_at + (sync_interval_hours * interval '1 hour') <= NOW())`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []*ThreatFeed
	for rows.Next() {
		f := &ThreatFeed{}
		if err := rows.Scan(
			&f.ID, &f.Name, &f.URL, &f.FeedType, &f.IOCType, &f.Description,
			&f.IsActive, &f.LastSyncAt, &f.LastCount, &f.SyncIntervalHours,
			&f.Headers, &f.CreatedAt, &f.UpdatedAt,
			&f.SourceFormat, &f.APIKey,
		); err != nil {
			continue
		}
		feeds = append(feeds, f)
	}
	return feeds, nil
}

func headersJSON(h map[string]string) interface{} {
	if len(h) == 0 {
		return "{}"
	}
	return h
}
