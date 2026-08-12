package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCEntry represents a single indicator of compromise.
type IOCEntry struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Description string    `json:"description,omitempty"`
	Severity    int       `json:"severity"`
	IsActive    bool      `json:"is_active"`
	AddedBy     *string   `json:"added_by,omitempty"`
	AddedByName string    `json:"added_by_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// IOCStore handles persistence of IOC entries.
type IOCStore struct {
	pool *pgxpool.Pool
}

func NewIOCStore(db *DB) *IOCStore {
	return &IOCStore{pool: db.Pool()}
}

// List returns paginated IOC entries with optional type filter and search.
func (s *IOCStore) List(ctx context.Context, iocType, search string, activeOnly bool, limit, offset int) ([]*IOCEntry, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if iocType != "" {
		where += fmt.Sprintf(" AND i.type = $%d", argIdx)
		args = append(args, iocType)
		argIdx++
	}
	if activeOnly {
		where += " AND i.is_active = TRUE"
	}
	if search != "" {
		where += fmt.Sprintf(" AND i.value ILIKE $%d", argIdx)
		args = append(args, "%"+search+"%")
		argIdx++
	}

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM ioc_entries i "+where, countArgs...,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.type, i.value, COALESCE(i.description,''),
		       i.severity, i.is_active, i.added_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       i.created_at, i.updated_at
		FROM ioc_entries i
		LEFT JOIN users u ON u.id = i.added_by
		`+where+fmt.Sprintf(" ORDER BY i.created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*IOCEntry
	for rows.Next() {
		e := &IOCEntry{}
		var addedBy *string
		if err := rows.Scan(
			&e.ID, &e.Type, &e.Value, &e.Description,
			&e.Severity, &e.IsActive, &addedBy, &e.AddedByName,
			&e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			continue
		}
		e.AddedBy = addedBy
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []*IOCEntry{}
	}
	return entries, total, nil
}

// Insert adds a new IOC entry. Returns ErrDuplicate if the type+value already exists.
func (s *IOCStore) Insert(ctx context.Context, e *IOCEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ioc_entries (type, value, description, severity, is_active, added_by)
		VALUES ($1, $2, $3, $4, $5, $6::uuid)`,
		e.Type, e.Value, e.Description, e.Severity, e.IsActive, nilIfEmpty(e.AddedBy),
	)
	return err
}

// Delete removes an IOC entry by ID.
func (s *IOCStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM ioc_entries WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// SetActive toggles the is_active flag.
func (s *IOCStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE ioc_entries SET is_active = $2, updated_at = NOW() WHERE id = $1",
		id, active,
	)
	return err
}

// Check looks up a value across all active IOC entries of the given type.
// Returns nil if not found.
func (s *IOCStore) Check(ctx context.Context, iocType, value string) (*IOCEntry, error) {
	e := &IOCEntry{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, type, value, COALESCE(description,''), severity, is_active, created_at
		FROM ioc_entries
		WHERE is_active = TRUE AND type = $1 AND value = $2`,
		iocType, value,
	).Scan(&e.ID, &e.Type, &e.Value, &e.Description, &e.Severity, &e.IsActive, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// IOCStats holds aggregate counts for the IOC dashboard widget.
type IOCStats struct {
	Total    int            `json:"total"`
	Active   int            `json:"active"`
	ByType   map[string]int `json:"by_type"`
	Alerts7d int            `json:"alerts_7d"`
}

// Stats returns aggregate IOC counts including alert hits over the last 7 days.
func (s *IOCStore) Stats(ctx context.Context) (*IOCStats, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT type, COUNT(*) AS total, COUNT(*) FILTER (WHERE is_active) AS active
		FROM ioc_entries
		GROUP BY type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &IOCStats{ByType: make(map[string]int)}
	for rows.Next() {
		var iocType string
		var total, active int
		if err := rows.Scan(&iocType, &total, &active); err != nil {
			continue
		}
		stats.ByType[iocType] = total
		stats.Total += total
		stats.Active += active
	}

	// Count IOC-triggered alerts in last 7 days
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE rule_id = 'ioc-match' AND created_at > NOW() - INTERVAL '7 days'`,
	).Scan(&stats.Alerts7d)

	return stats, nil
}

// BulkInsert inserts multiple IOC entries, skipping duplicates (ON CONFLICT DO NOTHING).
// Returns the number of newly inserted rows.
func (s *IOCStore) BulkInsert(ctx context.Context, entries []*IOCEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	inserted := 0
	for _, e := range entries {
		ct, err := tx.Exec(ctx, `
			INSERT INTO ioc_entries (type, value, description, severity, is_active, added_by)
			VALUES ($1, $2, $3, $4, TRUE, $5::uuid)
			ON CONFLICT (type, value) DO NOTHING`,
			e.Type, e.Value, e.Description, e.Severity, nilIfEmpty(e.AddedBy),
		)
		if err != nil {
			return inserted, fmt.Errorf("insert %s %s: %w", e.Type, e.Value, err)
		}
		inserted += int(ct.RowsAffected())
	}
	return inserted, tx.Commit(ctx)
}

func nilIfEmpty(s *string) interface{} {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

// IOCTopHit holds an IOC value and how many alerts it matched.
type IOCTopHit struct {
	Value    string    `json:"value"`
	Type     string    `json:"type"`
	HitCount int       `json:"hit_count"`
	LastSeen time.Time `json:"last_seen"`
}

// TopHits returns the IOC entries that matched the most alerts in the last 30 days.
func (s *IOCStore) TopHits(ctx context.Context, limit int) ([]IOCTopHit, error) {
	if limit <= 0 {
		limit = 10
	}
	// IOC とアラートの結び付け方について。
	//
	// 以前は alerts.src_ip / dst_ip / file_hash / domain を突き合わせていたが、
	// alerts にその 4 列はいずれも存在せず、このクエリは毎回
	// `column a.src_ip does not exist` で失敗していた。
	//
	// 実際には IOC マッチのアラートは detection.AlertPipeline.createAlertFromIOC が
	// 作っており、そこで確実に残る手掛かりは title だけ:
	//
	//     title = "Known IOC detected: " || <IOC の値>
	//
	// rule_id は IOC 経路では設定されず、値は raw_event にも別列にも入らない。
	// そのため title の完全一致で突き合わせる。プレフィックスは
	// createAlertFromIOC 側の書式と対で維持すること (片方だけ変えると、
	// エラーにはならず件数が黙って 0 になる)。
	rows, err := s.pool.Query(ctx, `
		SELECT i.value, i.type, COUNT(DISTINCT a.id) AS hit_count, MAX(a.created_at) AS last_seen
		FROM ioc_entries i
		JOIN alerts a ON a.title = 'Known IOC detected: ' || i.value
		WHERE i.is_active = true
		  AND a.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY i.value, i.type
		ORDER BY hit_count DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hits []IOCTopHit
	for rows.Next() {
		var h IOCTopHit
		if err := rows.Scan(&h.Value, &h.Type, &h.HitCount, &h.LastSeen); err != nil {
			continue
		}
		hits = append(hits, h)
	}
	if hits == nil {
		hits = []IOCTopHit{}
	}
	return hits, rows.Err()
}
