package watchlist

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WatchlistEntry represents a single watchlisted entity.
type WatchlistEntry struct {
	ID          string     `json:"id"`
	EntityType  string     `json:"entity_type"` // ip/domain/hash/hostname/username/process
	EntityValue string     `json:"entity_value"`
	Label       string     `json:"label"`
	Reason      string     `json:"reason"`
	Priority    int        `json:"priority"` // 1-5
	AddedBy     string     `json:"added_by"`
	Tags        []string   `json:"tags"`
	HitCount    int64      `json:"hit_count"`
	LastHit     *time.Time `json:"last_hit"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WatchlistStats holds aggregate statistics about the watchlist.
type WatchlistStats struct {
	Total     int            `json:"total"`
	ByType    map[string]int `json:"by_type"`
	HitsToday int64          `json:"hits_today"`
}

// cacheKey is the compound lookup key used in the in-memory cache.
type cacheKey struct {
	entityType  string
	entityValue string
}

// Store manages watchlist entries with a PostgreSQL backend and in-memory cache.
type Store struct {
	pool  *pgxpool.Pool
	cache sync.Map // map[cacheKey]*WatchlistEntry
}

// NewStore creates a new Store backed by the given connection pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Add inserts a new entry into the DB and populates the cache.
func (s *Store) Add(ctx context.Context, entry *WatchlistEntry) (*WatchlistEntry, error) {
	if entry.Priority == 0 {
		entry.Priority = 3
	}
	if entry.Tags == nil {
		entry.Tags = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO watchlist
			(entity_type, entity_value, label, reason, priority, added_by, tags, enabled, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (entity_type, entity_value) DO UPDATE SET
			label      = EXCLUDED.label,
			reason     = EXCLUDED.reason,
			priority   = EXCLUDED.priority,
			added_by   = EXCLUDED.added_by,
			tags       = EXCLUDED.tags,
			enabled    = EXCLUDED.enabled,
			expires_at = EXCLUDED.expires_at
		RETURNING id, entity_type, entity_value, label, reason, priority, added_by,
		          tags, hit_count, last_hit, enabled, expires_at, created_at`,
		entry.EntityType, entry.EntityValue, entry.Label, entry.Reason,
		entry.Priority, entry.AddedBy, entry.Tags, entry.Enabled, entry.ExpiresAt,
	)

	out := &WatchlistEntry{}
	err := row.Scan(
		&out.ID, &out.EntityType, &out.EntityValue, &out.Label, &out.Reason,
		&out.Priority, &out.AddedBy, &out.Tags, &out.HitCount, &out.LastHit,
		&out.Enabled, &out.ExpiresAt, &out.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if out.Enabled {
		s.cache.Store(cacheKey{out.EntityType, out.EntityValue}, out)
	}
	return out, nil
}

// Remove deletes an entry by ID and purges it from the cache.
func (s *Store) Remove(ctx context.Context, id string) error {
	// Retrieve the entry first so we can remove the cache key.
	var entityType, entityValue string
	_ = s.pool.QueryRow(ctx,
		`SELECT entity_type, entity_value FROM watchlist WHERE id=$1`, id,
	).Scan(&entityType, &entityValue)

	_, err := s.pool.Exec(ctx, `DELETE FROM watchlist WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if entityType != "" {
		s.cache.Delete(cacheKey{entityType, entityValue})
	}
	return nil
}

// List returns paginated entries, optionally filtered by entity type.
func (s *Store) List(ctx context.Context, entityType string) ([]*WatchlistEntry, int, error) {
	var (
		rows interface{ Next() bool }
		err  error
	)

	query := `SELECT id, entity_type, entity_value, label, reason, priority, added_by,
	                 tags, hit_count, last_hit, enabled, expires_at, created_at
	          FROM watchlist`
	args := []interface{}{}

	if entityType != "" {
		query += ` WHERE entity_type=$1 ORDER BY priority DESC, created_at DESC`
		args = append(args, entityType)
	} else {
		query += ` ORDER BY priority DESC, created_at DESC`
	}

	pgRows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer pgRows.Close()
	rows = pgRows

	var entries []*WatchlistEntry
	for rows.Next() {
		e := &WatchlistEntry{}
		if scanErr := pgRows.Scan(
			&e.ID, &e.EntityType, &e.EntityValue, &e.Label, &e.Reason,
			&e.Priority, &e.AddedBy, &e.Tags, &e.HitCount, &e.LastHit,
			&e.Enabled, &e.ExpiresAt, &e.CreatedAt,
		); scanErr != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, len(entries), nil
}

// Check performs a fast in-memory lookup. Returns the entry and true when found
// and enabled (and not expired).
func (s *Store) Check(entityType, value string) (*WatchlistEntry, bool) {
	v, ok := s.cache.Load(cacheKey{entityType, value})
	if !ok {
		return nil, false
	}
	entry, _ := v.(*WatchlistEntry)
	if entry == nil || !entry.Enabled {
		return nil, false
	}
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		s.cache.Delete(cacheKey{entityType, value})
		return nil, false
	}
	return entry, true
}

// RecordHit increments the hit counter and updates last_hit asynchronously.
func (s *Store) RecordHit(ctx context.Context, id string) {
	// Update the cache entry's hit_count immediately (best-effort).
	s.cache.Range(func(k, v interface{}) bool {
		e, ok := v.(*WatchlistEntry)
		if ok && e.ID == id {
			atomic.AddInt64(&e.HitCount, 1)
			now := time.Now()
			e.LastHit = &now
		}
		return true
	})

	// Persist asynchronously so the hot path is not blocked.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := s.pool.Exec(bgCtx,
			`UPDATE watchlist SET hit_count=hit_count+1, last_hit=NOW() WHERE id=$1`, id,
		)
		if err != nil {
			slog.Warn("watchlist: hit count update failed", "id", id, "error", err)
		}
	}()
}

// LoadCache fetches all enabled (non-expired) entries from the DB into memory.
func (s *Store) LoadCache(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, entity_type, entity_value, label, reason, priority, added_by,
		       tags, hit_count, last_hit, enabled, expires_at, created_at
		FROM watchlist
		WHERE enabled = true
		  AND (expires_at IS NULL OR expires_at > NOW())`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		e := &WatchlistEntry{}
		if err := rows.Scan(
			&e.ID, &e.EntityType, &e.EntityValue, &e.Label, &e.Reason,
			&e.Priority, &e.AddedBy, &e.Tags, &e.HitCount, &e.LastHit,
			&e.Enabled, &e.ExpiresAt, &e.CreatedAt,
		); err != nil {
			continue
		}
		s.cache.Store(cacheKey{e.EntityType, e.EntityValue}, e)
		count++
	}
	slog.Info("watchlist: cache loaded", "entries", count)
	return nil
}

// GetStats returns aggregate statistics about the watchlist.
func (s *Store) GetStats(ctx context.Context) WatchlistStats {
	stats := WatchlistStats{ByType: make(map[string]int)}

	rows, err := s.pool.Query(ctx, `
		SELECT entity_type, COUNT(*) AS cnt FROM watchlist GROUP BY entity_type`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var cnt int
			if rows.Scan(&t, &cnt) == nil {
				stats.ByType[t] = cnt
				stats.Total += cnt
			}
		}
	}

	var hitsToday int64
	_ = s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(hit_count),0) FROM watchlist
		WHERE last_hit >= NOW() - INTERVAL '24 hours'`,
	).Scan(&hitsToday)
	stats.HitsToday = hitsToday

	return stats
}

// Update applies field changes to an existing entry.
func (s *Store) Update(ctx context.Context, id string, entry *WatchlistEntry) (*WatchlistEntry, error) {
	if entry.Tags == nil {
		entry.Tags = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE watchlist SET
			label      = $1,
			reason     = $2,
			priority   = $3,
			tags       = $4,
			enabled    = $5,
			expires_at = $6
		WHERE id=$7
		RETURNING id, entity_type, entity_value, label, reason, priority, added_by,
		          tags, hit_count, last_hit, enabled, expires_at, created_at`,
		entry.Label, entry.Reason, entry.Priority, entry.Tags,
		entry.Enabled, entry.ExpiresAt, id,
	)
	out := &WatchlistEntry{}
	err := row.Scan(
		&out.ID, &out.EntityType, &out.EntityValue, &out.Label, &out.Reason,
		&out.Priority, &out.AddedBy, &out.Tags, &out.HitCount, &out.LastHit,
		&out.Enabled, &out.ExpiresAt, &out.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if out.Enabled {
		s.cache.Store(cacheKey{out.EntityType, out.EntityValue}, out)
	} else {
		s.cache.Delete(cacheKey{out.EntityType, out.EntityValue})
	}
	return out, nil
}
