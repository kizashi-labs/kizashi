package threatintel

// Feed types: MISP, OpenCTI, TAXII, CSV, custom HTTP JSON
// Supports: IP IOCs, domain IOCs, hash IOCs, URL IOCs

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
)

// IOC represents an Indicator of Compromise.
type IOC struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"` // ip/domain/hash/url
	Value      string     `json:"value"`
	Confidence int        `json:"confidence"` // 0-100
	Severity   int        `json:"severity"`   // 1-10
	Source     string     `json:"source"`
	Tags       []string   `json:"tags"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Feed represents a threat intelligence feed source.
type Feed struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"` // MISP, OpenCTI, TAXII, CSV, JSON
	URL              string    `json:"url"`
	APIKey           string    `json:"api_key,omitempty"`
	Enabled          bool      `json:"enabled"`
	LastFetch        time.Time `json:"last_fetch"`
	FetchIntervalMin int       `json:"fetch_interval_min"`
	IOCCount         int       `json:"ioc_count"`
}

// FeedStats holds aggregate statistics about the feed manager.
type FeedStats struct {
	TotalIOCs   int            `json:"total_iocs"`
	FeedsCount  int            `json:"feeds_count"`
	LastUpdated time.Time      `json:"last_updated"`
	IOCsByType  map[string]int `json:"iocs_by_type"`
}

// FeedManager manages threat intelligence feeds and IOC lookups.
type FeedManager struct {
	mu          sync.RWMutex
	feeds       map[string]*Feed
	iocs        sync.Map // key: "type:value" -> *IOC
	pool        *pgxpool.Pool
	lastUpdated time.Time
	totalIOCs   atomic.Int64
}

// NewFeedManager creates a new FeedManager with the given database pool.
func NewFeedManager(pool *pgxpool.Pool) *FeedManager {
	return &FeedManager{
		feeds: make(map[string]*Feed),
		pool:  pool,
	}
}

// AddFeed registers a new feed with the manager.
func (m *FeedManager) AddFeed(feed *Feed) error {
	if feed == nil {
		return fmt.Errorf("feed cannot be nil")
	}
	if feed.ID == "" {
		feed.ID = uuid.New().String()
	}
	if feed.FetchIntervalMin <= 0 {
		feed.FetchIntervalMin = 60
	}
	m.mu.Lock()
	m.feeds[feed.ID] = feed
	m.mu.Unlock()

	// Persist to DB if pool available
	if m.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := m.pool.Exec(ctx, `
			INSERT INTO threat_intel_feeds (id, name, feed_type, url, api_key, enabled, fetch_interval_min)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				feed_type = EXCLUDED.feed_type,
				url = EXCLUDED.url,
				api_key = EXCLUDED.api_key,
				enabled = EXCLUDED.enabled,
				fetch_interval_min = EXCLUDED.fetch_interval_min,
				updated_at = NOW()
		`, feed.ID, feed.Name, feed.Type, feed.URL, feed.APIKey, feed.Enabled, feed.FetchIntervalMin)
		if err != nil {
			slog.Warn("threatintel: failed to persist feed", "feed_id", feed.ID, "error", err)
		}
	}
	return nil
}

// FetchFeed fetches IOCs from the given feed via HTTP GET with API key header.
func (m *FeedManager) FetchFeed(ctx context.Context, feedID string) (int, error) {
	m.mu.RLock()
	feed, ok := m.feeds[feedID]
	m.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("feed %s not found", feedID)
	}
	if feed.URL == "" {
		return 0, fmt.Errorf("feed %s has no URL configured", feedID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}
	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
		req.Header.Set("X-API-Key", feed.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB limit
	if err != nil {
		return 0, fmt.Errorf("reading response: %w", err)
	}

	imported, err := m.parseAndStoreIOCs(ctx, body, feed)
	if err != nil {
		return 0, fmt.Errorf("parsing IOCs: %w", err)
	}

	// Update feed metadata
	m.mu.Lock()
	feed.LastFetch = time.Now().UTC()
	feed.IOCCount += imported
	m.mu.Unlock()

	// Update in DB.
	//
	// **記憶の側は上で進めてあります。** ここが書けないと、画面の
	// 「最終取得」は止まったまま、IOC だけが増えていきます —— 外からは
	// 「取り込みが止まっている」と同じ姿です。
	//
	// 報告先は `tick.Fail` です。周期の同期（`threatintel_periodic_sync`）
	// から来たときはその回に落ち、**画面からの手動取得で呼ばれたときは
	// ログだけ**になります（`ctx` に回が無いため）。
	if m.pool != nil {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := m.pool.Exec(updateCtx, `
			UPDATE threat_intel_feeds
			SET last_fetch = NOW(), ioc_count = ioc_count + $2, updated_at = NOW()
			WHERE id = $1
		`, feedID, imported); err != nil {
			tick.Fail(ctx, err, "threatintel: 取得結果を記録できませんでした。画面の最終取得が止まって見えます",
				"feed", feed.Name, "imported", imported)
		}
	}

	slog.Info("threatintel: feed fetch complete", "feed", feed.Name, "imported", imported)
	return imported, nil
}

// parseAndStoreIOCs parses a JSON array of IOC objects and stores them.
// Expected format: [{"type":"ip","value":"1.2.3.4","confidence":80,"severity":7,...}]
func (m *FeedManager) parseAndStoreIOCs(ctx context.Context, body []byte, feed *Feed) (int, error) {
	var rawIOCs []map[string]interface{}
	if err := json.Unmarshal(body, &rawIOCs); err != nil {
		// Try wrapped format: {"iocs": [...]}
		var wrapped struct {
			IOCs []map[string]interface{} `json:"iocs"`
		}
		if err2 := json.Unmarshal(body, &wrapped); err2 != nil {
			return 0, fmt.Errorf("parsing JSON: %w", err)
		}
		rawIOCs = wrapped.IOCs
	}

	count := 0
	for _, raw := range rawIOCs {
		ioc := &IOC{
			ID:        uuid.New().String(),
			Source:    feed.Name,
			CreatedAt: time.Now().UTC(),
		}

		if t, ok := raw["type"].(string); ok {
			ioc.Type = t
		}
		if v, ok := raw["value"].(string); ok {
			ioc.Value = v
		}
		if c, ok := raw["confidence"].(float64); ok {
			ioc.Confidence = int(c)
		} else {
			ioc.Confidence = 50
		}
		if s, ok := raw["severity"].(float64); ok {
			ioc.Severity = int(s)
		} else {
			ioc.Severity = 5
		}
		if tags, ok := raw["tags"].([]interface{}); ok {
			for _, tag := range tags {
				if ts, ok := tag.(string); ok {
					ioc.Tags = append(ioc.Tags, ts)
				}
			}
		}

		if ioc.Type == "" || ioc.Value == "" {
			continue
		}

		key := ioc.Type + ":" + ioc.Value
		m.iocs.Store(key, ioc)
		m.totalIOCs.Add(1)
		m.lastUpdated = time.Now().UTC()

		// Persist to DB
		if m.pool != nil {
			_, err := m.pool.Exec(ctx, `
				INSERT INTO threat_intel_iocs (id, ioc_type, value, confidence, severity, source, tags, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (ioc_type, value) DO UPDATE SET
					confidence = EXCLUDED.confidence,
					severity = EXCLUDED.severity,
					source = EXCLUDED.source,
					tags = EXCLUDED.tags,
					expires_at = EXCLUDED.expires_at
			`, ioc.ID, ioc.Type, ioc.Value, ioc.Confidence, ioc.Severity, ioc.Source, ioc.Tags, ioc.ExpiresAt)
			if err != nil {
				tick.Fail(ctx, err, "threatintel: failed to persist IOC", "value", ioc.Value)
			}
		}
		count++
	}
	return count, nil
}

// storeBuiltinIOC stores an IOC directly into the in-memory cache (used by LoadBuiltinIOCs).
func (m *FeedManager) storeBuiltinIOC(ioc *IOC) {
	key := ioc.Type + ":" + ioc.Value
	m.iocs.Store(key, ioc)
	m.totalIOCs.Add(1)
	m.lastUpdated = time.Now().UTC()

	if m.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := m.pool.Exec(ctx, `
			INSERT INTO threat_intel_iocs (id, ioc_type, value, confidence, severity, source, tags)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (ioc_type, value) DO NOTHING
		`, ioc.ID, ioc.Type, ioc.Value, ioc.Confidence, ioc.Severity, ioc.Source, ioc.Tags)
		if err != nil {
			slog.Debug("threatintel: builtin IOC already exists or failed", "value", ioc.Value)
		}
	}
}

// LookupIP returns the IOC for the given IP address, or nil if not found.
func (m *FeedManager) LookupIP(ip string) *IOC {
	val, ok := m.iocs.Load("ip:" + ip)
	if !ok {
		return nil
	}
	ioc, _ := val.(*IOC)
	return ioc
}

// LookupDomain returns the IOC for the given domain, or nil if not found.
func (m *FeedManager) LookupDomain(domain string) *IOC {
	val, ok := m.iocs.Load("domain:" + domain)
	if !ok {
		return nil
	}
	ioc, _ := val.(*IOC)
	return ioc
}

// LookupHash returns the IOC for the given hash, or nil if not found.
func (m *FeedManager) LookupHash(hash string) *IOC {
	val, ok := m.iocs.Load("hash:" + hash)
	if !ok {
		return nil
	}
	ioc, _ := val.(*IOC)
	return ioc
}

// LookupURL returns the IOC for the given URL, or nil if not found.
func (m *FeedManager) LookupURL(u string) *IOC {
	val, ok := m.iocs.Load("url:" + u)
	if !ok {
		return nil
	}
	ioc, _ := val.(*IOC)
	return ioc
}

// GetStats returns aggregate statistics about the feed manager.
func (m *FeedManager) GetStats() FeedStats {
	byType := map[string]int{}
	m.iocs.Range(func(key, value interface{}) bool {
		if ioc, ok := value.(*IOC); ok {
			byType[ioc.Type]++
		}
		return true
	})

	m.mu.RLock()
	feedsCount := len(m.feeds)
	m.mu.RUnlock()

	return FeedStats{
		TotalIOCs:   int(m.totalIOCs.Load()),
		FeedsCount:  feedsCount,
		LastUpdated: m.lastUpdated,
		IOCsByType:  byType,
	}
}

// GetAllFeeds returns all registered feeds.
func (m *FeedManager) GetAllFeeds() []*Feed {
	m.mu.RLock()
	defer m.mu.RUnlock()
	feeds := make([]*Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		feeds = append(feeds, f)
	}
	return feeds
}

// GetFeed returns a single feed by ID.
func (m *FeedManager) GetFeed(id string) (*Feed, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.feeds[id]
	return f, ok
}

// UpdateFeed updates a feed's mutable fields.
func (m *FeedManager) UpdateFeed(id string, updates *Feed) (*Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.feeds[id]
	if !ok {
		return nil, fmt.Errorf("feed %s not found", id)
	}
	// **新しい値をまず作って、DB に書けてから記憶に当てます。**
	//
	// `existing` は map の中のポインタなので、先に書き換えると、DB への
	// UPDATE が失敗しても記憶だけ新しい値になります —— **画面は変わった
	// ように見えて、次の再起動で戻ります。**
	name, url, apiKey := existing.Name, existing.URL, existing.APIKey
	interval := existing.FetchIntervalMin
	if updates.Name != "" {
		name = updates.Name
	}
	if updates.URL != "" {
		url = updates.URL
	}
	if updates.APIKey != "" {
		apiKey = updates.APIKey
	}
	if updates.FetchIntervalMin > 0 {
		interval = updates.FetchIntervalMin
	}

	if m.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := m.pool.Exec(ctx, `
			UPDATE threat_intel_feeds
			SET name=$2, url=$3, api_key=$4, enabled=$5, fetch_interval_min=$6, updated_at=NOW()
			WHERE id=$1
		`, id, name, url, apiKey, updates.Enabled, interval); err != nil {
			return nil, fmt.Errorf("フィードを更新できませんでした（再起動で戻ります）: %w", err)
		}
	}

	existing.Name, existing.URL, existing.APIKey = name, url, apiKey
	existing.Enabled = updates.Enabled
	existing.FetchIntervalMin = interval
	return existing, nil
}

// RemoveFeed removes a feed by ID.
func (m *FeedManager) RemoveFeed(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.feeds[id]; !ok {
		return fmt.Errorf("feed %s not found", id)
	}

	// **DB を先に消します。** 記憶から先に消して DELETE を捨てると、
	// **消したはずのフィードが次の再起動で戻ります。**
	if m.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := m.pool.Exec(ctx, `DELETE FROM threat_intel_feeds WHERE id=$1`, id); err != nil {
			return fmt.Errorf("フィードを削除できませんでした（再起動で戻ります）: %w", err)
		}
	}
	delete(m.feeds, id)
	return nil
}

// RunPeriodicSync runs a background goroutine that syncs enabled feeds on schedule.
func (m *FeedManager) RunPeriodicSync(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "threatintel_periodic_sync", m.syncDueFeeds)
		}
	}
}

// syncDueFeeds fetches every enabled feed whose interval has elapsed.
//
// **回ごとの仕事として切り出してあります。** `tick.Run` に渡せる形
// （`func(context.Context)`）にしないと、回ったことも、途中で諦めたことも
// 記録できません。
func (m *FeedManager) syncDueFeeds(ctx context.Context) {
	m.mu.RLock()
	now := time.Now()
	toSync := make([]*Feed, 0)
	for _, f := range m.feeds {
		if !f.Enabled {
			continue
		}
		if f.LastFetch.IsZero() || now.Sub(f.LastFetch) >= time.Duration(f.FetchIntervalMin)*time.Minute {
			toSync = append(toSync, f)
		}
	}
	m.mu.RUnlock()

	for _, feed := range toSync {
		go func(f *Feed) {
			syncCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			count, err := m.FetchFeed(syncCtx, f.ID)
			if err != nil {
				// **回の失敗として数えます。** 取り込めなかったフィードは、
				// 指標が0件のフィードと同じ姿になります。
				tick.Fail(syncCtx, err, "threatintel: periodic sync failed", "feed", f.Name)
				return
			}
			slog.Info("threatintel: periodic sync complete", "feed", f.Name, "imported", count)
		}(feed)
	}
}

// GetAllIOCs returns a paginated list of all IOCs and total count.
func (m *FeedManager) GetAllIOCs(limit, offset int) ([]*IOC, int) {
	all := make([]*IOC, 0)
	m.iocs.Range(func(_, value interface{}) bool {
		if ioc, ok := value.(*IOC); ok {
			all = append(all, ioc)
		}
		return true
	})

	total := len(all)
	if offset >= total {
		return []*IOC{}, total
	}
	end := offset + limit
	if end > total || limit <= 0 {
		end = total
	}
	return all[offset:end], total
}

// GetIOCsByType returns IOCs filtered by type with pagination.
func (m *FeedManager) GetIOCsByType(iocType string, limit, offset int) ([]*IOC, int) {
	all := make([]*IOC, 0)
	m.iocs.Range(func(_, value interface{}) bool {
		if ioc, ok := value.(*IOC); ok && ioc.Type == iocType {
			all = append(all, ioc)
		}
		return true
	})

	total := len(all)
	if offset >= total {
		return []*IOC{}, total
	}
	end := offset + limit
	if end > total || limit <= 0 {
		end = total
	}
	return all[offset:end], total
}

// LoadFromDB loads feeds and IOCs from the database at startup.
func (m *FeedManager) LoadFromDB(ctx context.Context) {
	if m.pool == nil {
		return
	}

	// Load feeds
	rows, err := m.pool.Query(ctx, `
		SELECT id, name, feed_type, COALESCE(url,''), COALESCE(api_key,''),
		       enabled, COALESCE(last_fetch, '1970-01-01'::timestamptz),
		       fetch_interval_min, ioc_count
		FROM threat_intel_feeds
		ORDER BY created_at
	`)
	if err != nil {
		metrics.BackgroundFailed("threatintel_feed_load", err, "threatintel: failed to load feeds from DB")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var f Feed
		var lastFetch time.Time
		if err := rows.Scan(&f.ID, &f.Name, &f.Type, &f.URL, &f.APIKey,
			&f.Enabled, &lastFetch, &f.FetchIntervalMin, &f.IOCCount); err == nil {
			f.LastFetch = lastFetch
			m.mu.Lock()
			m.feeds[f.ID] = &f
			m.mu.Unlock()
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("脅威フィード一覧の読み込みが途中で終わりました。メモリ上のフィード集合は不完全です", "error", err)
	}

	// Load IOCs
	iocRows, err := m.pool.Query(ctx, `
		SELECT id, ioc_type, value, confidence, severity, COALESCE(source,''),
		       COALESCE(tags, '{}'), expires_at, created_at
		FROM threat_intel_iocs
		LIMIT 100000
	`)
	if err != nil {
		metrics.BackgroundFailed("threatintel_feed_load", err, "threatintel: failed to load IOCs from DB")
		return
	}
	defer iocRows.Close()
	for iocRows.Next() {
		var ioc IOC
		if err := iocRows.Scan(&ioc.ID, &ioc.Type, &ioc.Value,
			&ioc.Confidence, &ioc.Severity, &ioc.Source,
			&ioc.Tags, &ioc.ExpiresAt, &ioc.CreatedAt); err == nil {
			key := ioc.Type + ":" + ioc.Value
			iocCopy := ioc
			m.iocs.Store(key, &iocCopy)
			m.totalIOCs.Add(1)
		}
	}
	if err := iocRows.Err(); err != nil {
		slog.Error("IOCの読み込みが途中で終わりました。メモリ上のIOC集合は不完全で、読めなかったIOCは照合されません", "error", err)
	}
	slog.Info("threatintel: loaded from DB", "feeds", len(m.feeds), "iocs", m.totalIOCs.Load())
}

// AddIOC adds a single IOC to the in-memory store and persists it to the database.
// It is safe to call from multiple goroutines and duplicates (by type+value) are silently skipped.
func (m *FeedManager) AddIOC(ioc *IOC) {
	if ioc == nil {
		return
	}
	if ioc.ID == "" {
		ioc.ID = uuid.New().String()
	}
	key := ioc.Type + ":" + ioc.Value
	// Load-or-store: skip if already present
	if _, loaded := m.iocs.LoadOrStore(key, ioc); loaded {
		return
	}
	m.totalIOCs.Add(1)
	m.lastUpdated = time.Now().UTC()

	if m.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := m.pool.Exec(ctx, `
			INSERT INTO threat_intel_iocs (id, ioc_type, value, confidence, severity, source, tags)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (ioc_type, value) DO NOTHING
		`, ioc.ID, ioc.Type, ioc.Value, ioc.Confidence, ioc.Severity, ioc.Source, ioc.Tags)
		if err != nil {
			slog.Debug("threatintel: AddIOC persist skipped", "value", ioc.Value, "error", err)
		}
	}
}
