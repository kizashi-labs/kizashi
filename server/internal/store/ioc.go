package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IOC alerts carry no structured back-reference to the indicator that produced
// them: alerts has no ioc_id, rule_id is uuid-typed and is left NULL on the IOC
// path, and the value is written to neither raw_event nor a column of its own.
// The only durable link is the alert title, which both producers build as a
// fixed prefix followed by the matched value.
//
// There are two producers and they do not use the same prefix:
//
//	detection.AlertPipeline.createAlertFromIOC  (server-api)     "Known IOC detected: "
//	detection.Engine  (server-detect)                            "既知IOC検出: "
//
// Whichever service processes an event writes its own wording, so every reader
// that knows only one prefix silently halves its counts. IOCStore.TopHits knew
// only the first, and undercounted by exactly the share of traffic handled by
// the detection engine.
//
// These constants are the single definition. Both producers build their titles
// from them and both readers match on them, so the two can no longer drift.
// Changing one of these strings does not raise an error anywhere — it makes IOC
// statistics quietly go to zero — so they are pinned by a test.
const (
	// IOCAlertTitlePrefixEN is the title prefix written by server-api.
	IOCAlertTitlePrefixEN = "Known IOC detected: "
	// IOCAlertTitlePrefixJA is the title prefix written by server-detect.
	IOCAlertTitlePrefixJA = "既知IOC検出: "
)

// iocAlertTitleMatch matches an alert produced by either IOC path. The alias a
// must be bound to alerts.
const iocAlertTitleMatch = `(a.title LIKE '` + IOCAlertTitlePrefixEN + `%' OR a.title LIKE '` + IOCAlertTitlePrefixJA + `%')`

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
// iocListWhere builds the WHERE clause and arguments for List.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 公開はしません —— `List` からしか使わないので、公開すると
// `TestStoreSymbolsAreReachable` の数が1つ増えます。
// 検査ファイルには `buildIOCWhere` という同じ組み立ての写しが置いて
// ありました。写しを試しても、こちらは無傷のまま壊せます。
func iocListWhere(iocType, search string, activeOnly bool) (string, []interface{}) {
	where := "WHERE 1=1"
	args := []interface{}{}

	if iocType != "" {
		where += fmt.Sprintf(" AND i.type = $%d", len(args)+1)
		args = append(args, iocType)
	}
	if activeOnly {
		// **値を取らない条件です。** ここで番号を進めると、次の条件の
		// プレースホルダが引数とずれます。
		where += " AND i.is_active = TRUE"
	}
	if search != "" {
		where += fmt.Sprintf(" AND i.value ILIKE $%d", len(args)+1)
		args = append(args, "%"+search+"%")
	}
	return where, args
}

func (s *IOCStore) List(ctx context.Context, iocType, search string, activeOnly bool, limit, offset int) ([]*IOCEntry, int, error) {
	where, args := iocListWhere(iocType, search, activeOnly)
	argIdx := len(args) + 1

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
	if err := rows.Err(); err != nil {
		return nil, 0, err
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
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Count IOC-triggered alerts in last 7 days.
	//
	// **プレフィクスは 2 つある。** server-api は "Known IOC detected: "、
	// server-detect は "既知IOC検出: " を書くので、片方だけで数えると
	// もう片方が処理した分がまるごと落ちる。定数で両方を突き合わせる。
	//
	// This matched `rule_id = 'ioc-match'`. alerts.rule_id is uuid, so the
	// comparison failed with 22P02 on every call, and the row was scanned with
	// `_ =` — Alerts7d has always been 0. The sentinel it looked for was removed
	// from the producer some time ago precisely because it made the INSERT fail;
	// the reader was never updated, and nothing said so.
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts a
		WHERE `+iocAlertTitleMatch+`
		  AND a.created_at > NOW() - INTERVAL '7 days'`,
	).Scan(&stats.Alerts7d); err != nil {
		return nil, fmt.Errorf("iocstore: count IOC alerts (7d): %w", err)
	}

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
	// `column a.src_ip does not exist` で失敗していた。そのため title で
	// 突き合わせる方式に変えた。
	//
	// ただしその時点では突き合わせ先が createAlertFromIOC (server-api) の
	// 英語プレフィックスだけで、server-detect 側の Engine が書く
	// 「既知IOC検出: 」を見ていなかった。両者は同じ IOC に対して同じ alerts
	// テーブルに書くので、どちらのサービスがそのイベントを処理したかで件数が
	// 変わる — 実測で、片方だけを見ると 2 件のうち 1 件しか数えられない。
	//
	// プレフィックスは IOCAlertTitlePrefixEN / JA に一本化した。生成側も
	// この定数から title を組み立てるので、もう片方だけが変わることはない。
	rows, err := s.pool.Query(ctx, `
		SELECT i.value, i.type, COUNT(DISTINCT a.id) AS hit_count, MAX(a.created_at) AS last_seen
		FROM ioc_entries i
		JOIN alerts a
		  ON a.title = ANY (ARRAY[$2 || i.value, $3 || i.value])
		WHERE i.is_active = true
		  AND a.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY i.value, i.type
		ORDER BY hit_count DESC
		LIMIT $1`, limit, IOCAlertTitlePrefixEN, IOCAlertTitlePrefixJA)
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
