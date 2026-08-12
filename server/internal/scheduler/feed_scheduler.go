package scheduler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/intel"
	"github.com/edr-platform/server/internal/store"
)

// FeedScheduler periodically fetches threat intelligence feeds and updates IOC data.
// It complements the inline goroutine in main.go by using the structured store layer
// and providing configurable interval control.
type FeedScheduler struct {
	pool      *pgxpool.Pool
	feedStore *store.ThreatFeedStore
	client    *http.Client
	interval  time.Duration
	importer  *intel.FeedImporter // format-aware parser for abuse.ch / OTX / MISP feeds
	taxii     *intel.TAXIIClient  // TAXII 2.1 collection poller for source_format="taxii21"
}

// NewFeedScheduler creates a FeedScheduler that polls for due feeds on the given interval.
// If interval is <= 0 it defaults to 6 hours.
func NewFeedScheduler(pool *pgxpool.Pool, feedStore *store.ThreatFeedStore, interval time.Duration) *FeedScheduler {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &FeedScheduler{
		pool:      pool,
		feedStore: feedStore,
		client:    &http.Client{Timeout: 30 * time.Second},
		interval:  interval,
		importer:  intel.NewFeedImporter(),
		taxii:     intel.NewTAXIIClient(),
	}
}

// Run starts the feed scheduler loop. Designed to be called as a goroutine.
func (s *FeedScheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	slog.Info("脅威フィードスケジューラー起動", "interval", s.interval)
	// Run once on startup to handle feeds that became due while the server was offline.
	s.processFeeds(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processFeeds(ctx)
		}
	}
}

func (s *FeedScheduler) processFeeds(ctx context.Context) {
	feeds, err := s.feedStore.GetDueForSync(ctx)
	if err != nil {
		slog.Debug("脅威フィードの取得をスキップ", "error", err)
		return
	}

	for _, feed := range feeds {
		feed := feed // capture
		var (
			count int
			err   error
		)
		if feed.SourceFormat == "taxii21" {
			count, err = s.fetchTAXIIFeed(ctx, feed)
		} else {
			count, err = s.fetchFeed(ctx, feed.ID, feed.URL, feed.SourceFormat, feed.IOCType, feed.APIKey)
		}
		if err != nil {
			slog.Error("フィードの取得に失敗しました", "name", feed.Name, "error", err)
			// MarkSynced with 0 to advance last_sync_at and avoid a tight retry loop.
			_ = s.feedStore.MarkSynced(ctx, feed.ID, 0)
		} else {
			slog.Info("フィード更新完了", "name", feed.Name, "iocs_added", count)
			_ = s.feedStore.MarkSynced(ctx, feed.ID, count)
		}
	}
}

// fetchTAXIIFeed polls a TAXII 2.1 collection for the given feed. It syncs
// incrementally by passing the feed's last successful sync time as added_after,
// so each run only pulls indicators added since. The feed URL is the collection
// endpoint; api_key/headers carry auth (Basic when api_key is "user:pass").
func (s *FeedScheduler) fetchTAXIIFeed(ctx context.Context, feed *store.ThreatFeed) (int, error) {
	cfg := intel.TAXIIPollConfig{
		CollectionURL: feed.URL,
		APIKey:        feed.APIKey,
		Headers:       feed.Headers,
		AddedAfter:    feed.LastSyncAt,
	}
	entries, err := s.taxii.PollCollection(ctx, cfg)
	// PollCollection returns the indicators pulled before any mid-poll failure,
	// so persist whatever arrived even on error.
	added := s.upsertEntries(ctx, entries, "taxii")
	if err != nil {
		return 0, err
	}
	return added, nil
}

func (s *FeedScheduler) fetchFeed(ctx context.Context, feedID, url, sourceFormat, iocType, apiKey string) (int, error) {
	// Format-aware feeds (abuse.ch URLhaus/MalwareBazaar/Feodo, AlienVault OTX):
	// each ships a real CSV/reputation schema (header rows, "#" comments, multiple
	// columns) that the generic line parser would mangle. Delegate fetch+parse to
	// the intel importer, which knows each source's layout, then upsert.
	switch sourceFormat {
	case "otx_reputation", "urlhaus_csv", "malwarebazaar_csv", "feodo_csv", "threatfox_csv":
		entries, err := s.importer.Import(ctx, url, sourceFormat, apiKey)
		if err != nil {
			return 0, err
		}
		return s.upsertEntries(ctx, entries, sourceFormat), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "EDR-Platform-FeedScheduler/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB max
	if err != nil {
		return 0, err
	}

	src := sourceFormat
	if src == "" {
		src = "text-feed"
	}
	switch sourceFormat {
	case "misp_json":
		return s.importMISPJSON(ctx, iocType, src, string(body))
	case "json":
		return s.importJSONFeed(ctx, src, string(body))
	default:
		// Plain text list: ip, domain, hash, url
		return s.importTextFeed(ctx, iocType, src, string(body))
	}
}

// importTextFeed parses a newline-delimited plain-text IOC list and upserts
// entries into the ioc_entries table.
// upsertIOC inserts/updates one IOC with multi-source reputation.
//   - Sets BOTH type and ioc_type. The latter was left NULL by every feed INSERT,
//     blinding the DB-polling matcher (scheduler/ioc_matcher.go reads ioc_type) to
//     all feed IOCs (実測 23,379件 全件 NULL). Fixed here + migration 277.
//   - A NEW source for an existing IOC raises confidence and source_count
//     (multi-source agreement = higher trust); a re-import from the SAME source
//     only refreshes last_seen, so confidence does not inflate on every sync.
func (s *FeedScheduler) upsertIOC(ctx context.Context, iocType, value, desc, source string) error {
	value = strings.TrimSpace(value)
	if iocType == "" || value == "" {
		return nil
	}
	if source == "" {
		source = "feed"
	}
	// Rolling TTL: each time a feed re-lists an IOC, expires_at is pushed 30 days
	// out. An IOC that drops off its feed(s) stops being refreshed and, once the
	// window lapses, the IOC expiry sweeper (scheduler/ioc_expiry_sweeper.go)
	// deactivates it — keeping the (now large) feed IOC set fresh and stopping
	// stale attacker IPs from accumulating into false positives forever.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ioc_entries
		    (type, ioc_type, value, description, severity, is_active,
		     source_feed, confidence, source_count, sources, first_seen, last_seen, expires_at)
		VALUES ($1, $1, $2, $3, 2, TRUE, $4, 50, 1, ARRAY[$4]::text[], NOW(), NOW(), NOW() + INTERVAL '30 days')
		ON CONFLICT (type, value) DO UPDATE SET
		    updated_at   = NOW(),
		    last_seen    = NOW(),
		    expires_at   = NOW() + INTERVAL '30 days',
		    -- Resurrect an IOC the sweeper had expired if a feed lists it again,
		    -- but never override an analyst who disabled a still-fresh IOC.
		    is_active    = CASE WHEN ioc_entries.expires_at IS NOT NULL AND ioc_entries.expires_at < NOW()
		                        THEN TRUE ELSE ioc_entries.is_active END,
		    ioc_type     = EXCLUDED.ioc_type,
		    source_count = CASE WHEN $4 = ANY(ioc_entries.sources)
		                        THEN ioc_entries.source_count
		                        ELSE ioc_entries.source_count + 1 END,
		    confidence   = CASE WHEN $4 = ANY(ioc_entries.sources)
		                        THEN ioc_entries.confidence
		                        ELSE LEAST(100, ioc_entries.confidence + 15) END,
		    sources      = CASE WHEN $4 = ANY(ioc_entries.sources)
		                        THEN ioc_entries.sources
		                        ELSE array_append(ioc_entries.sources, $4) END`,
		iocType, value, desc, source,
	)
	return err
}

func (s *FeedScheduler) importTextFeed(ctx context.Context, iocType, source, body string) (int, error) {
	normalized := normaliseIOCType(iocType)
	count := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") ||
			strings.HasPrefix(line, ";") {
			continue
		}
		// Take the first whitespace-separated token as the indicator: many public
		// IP lists carry a trailing column (ipsum "IP\tscore") or comment
		// ("IP ; note"). A plain IP/domain/URL has no whitespace, so this is a
		// no-op for the simple case.
		if f := strings.Fields(line); len(f) > 0 {
			line = f[0]
		}
		if err := s.upsertIOC(ctx, normalized, line, "feed-auto-import", source); err == nil {
			count++
		}
	}
	return count, nil
}

// upsertEntries inserts IOC entries parsed by the format-aware intel importer.
// The entry's Threat (e.g. "malware_distribution", "c2") becomes the description,
// preserving each feed's threat context.
func (s *FeedScheduler) upsertEntries(ctx context.Context, entries []intel.FeedEntry, source string) int {
	count := 0
	for _, e := range entries {
		t := normaliseIOCType(e.Type)
		desc := "feed-auto-import"
		if e.Threat != "" {
			desc = e.Threat
		}
		// Per-entry source overrides the feed source when the parser supplies one
		// (e.g. ThreatFox rows carry their own malware tag), else the feed format.
		src := source
		if e.Source != "" {
			src = e.Source
		}
		if err := s.upsertIOC(ctx, t, e.Value, desc, src); err == nil {
			count++
		}
	}
	return count
}

// importJSONFeed parses a JSON array of {"type":"...","value":"..."} objects.
func (s *FeedScheduler) importJSONFeed(ctx context.Context, source, body string) (int, error) {
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		return 0, err
	}
	count := 0
	for _, item := range items {
		iocType, _ := item["type"].(string)
		value, _ := item["value"].(string)
		if err := s.upsertIOC(ctx, normaliseIOCType(iocType), value, "feed-auto-import", source); err == nil && iocType != "" && value != "" {
			count++
		}
	}
	return count, nil
}

// importMISPJSON parses a MISP event JSON payload. The IOC type is derived
// per-attribute (mispTypeToIOCType), so the feed's default type is unused here.
func (s *FeedScheduler) importMISPJSON(ctx context.Context, _ /*defaultType*/, source, body string) (int, error) {
	var result struct {
		Event struct {
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"Attribute"`
		} `json:"Event"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return 0, err
	}
	count := 0
	for _, attr := range result.Event.Attribute {
		entryType := mispTypeToIOCType(attr.Type)
		if entryType == "" {
			continue
		}
		val := attr.Value
		if strings.Contains(val, "|") {
			val = strings.Split(val, "|")[0]
		}
		if err := s.upsertIOC(ctx, entryType, val, "misp-feed-import", source); err == nil {
			count++
		}
	}
	return count, nil
}

// normaliseIOCType maps feed-specific type strings to the canonical values
// stored in ioc_entries.type.
func normaliseIOCType(t string) string {
	switch strings.ToLower(t) {
	case "ip", "ip_address":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "url":
		return "url"
	case "hash", "hash_sha256", "sha256", "md5", "sha1":
		return "hash"
	default:
		return "ip" // safe default for plain IP feeds
	}
}

func mispTypeToIOCType(t string) string {
	switch t {
	case "ip-dst", "ip-src", "ip-dst|port":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "url":
		return "url"
	case "sha256", "md5", "sha1":
		return "hash"
	default:
		return ""
	}
}
