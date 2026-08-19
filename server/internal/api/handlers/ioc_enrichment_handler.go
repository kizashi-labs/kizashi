package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/threatintel"
)

// IOCEnrichmentHandler handles IOC enrichment and search endpoints.
type IOCEnrichmentHandler struct {
	pool *pgxpool.Pool
	live *threatintel.LiveEnricher
}

// NewIOCEnrichmentHandler creates a new IOCEnrichmentHandler. It also constructs a
// live multi-source enricher (VirusTotal/OTX/AbuseIPDB); with no API keys set the
// enricher is inert and enrichment answers from the local DB only (air-gap safe).
func NewIOCEnrichmentHandler(pool *pgxpool.Pool) *IOCEnrichmentHandler {
	return &IOCEnrichmentHandler{pool: pool, live: threatintel.NewLiveEnricher()}
}

// EnrichmentResult holds the result of an IOC enrichment lookup.
type EnrichmentResult struct {
	Value       string   `json:"value"`
	Type        string   `json:"ioc_type"`
	Found       bool     `json:"found"`
	ThreatLevel int      `json:"threat_level"`
	Sources     []string `json:"sources"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	// Pointers so an unrecorded timestamp is absent from the response.
	// omitempty does nothing for a time.Time — it is a struct — so these used
	// to serialise as 0001-01-01T00:00:00Z, a year-1 date shown to an analyst
	// as though it were when the indicator was first seen.
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	Confidence int        `json:"confidence"` // 0-100
}

// tableExists checks whether ioc_entries exists in the current schema.
func (h *IOCEnrichmentHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "ioc_entries")
}

// Enrich looks up a single IOC value and returns enrichment data.
// POST /api/v1/threat-intel/enrich
func (h *IOCEnrichmentHandler) Enrich(c *gin.Context) {
	var req struct {
		Value string `json:"value" binding:"required"`
		Type  string `json:"type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value is required"})
		return
	}

	empty := EnrichmentResult{
		Value:   req.Value,
		Type:    req.Type,
		Found:   false,
		Sources: []string{},
		Tags:    []string{},
	}

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, empty)
		return
	}

	var (
		iocType     string
		threatLevel int
		tags        []string
		description string
		firstSeen   *time.Time
		lastSeen    *time.Time
		sourceFeed  string
	)

	// Reads type / severity / is_active — the columns live matching reads, and
	// the ones every writer sets. This used to read ioc_type / threat_level /
	// enabled: ioc_type is NULL for anything added by hand or imported over
	// TAXII or STIX, and a NULL fails the Scan below, which this treats as
	// "not found". So enriching an indicator the team had entered themselves
	// answered that the platform had never seen it. Measured, for a manually
	// added domain with severity 9 and a description:
	//
	//	{"found":false,"ioc_type":"","threat_level":0,...}
	//
	// first_seen and last_seen are nullable too, and none of those writers set
	// them, so they are scanned through pointers rather than into a time.Time
	// that a NULL cannot fill.
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT type, severity, tags, COALESCE(description,''),
		        COALESCE(first_seen, created_at), COALESCE(last_seen, created_at),
		        COALESCE(source_feed,'')
		   FROM ioc_entries
		  WHERE value = $1 AND is_active = true
		  LIMIT 1`,
		req.Value,
	).Scan(&iocType, &threatLevel, &tags, &description, &firstSeen, &lastSeen, &sourceFeed)

	// A row that is not there is not found; a row that is there but cannot be
	// read is a bug, and must not be reported as the same thing.
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("IOC enrichment: 既存エントリの読み取りに失敗しました",
			"value", req.Value, "error", err)
	}

	result := empty
	if err == nil {
		if tags == nil {
			tags = []string{}
		}
		sources := []string{}
		if sourceFeed != "" {
			sources = append(sources, sourceFeed)
		}
		result = EnrichmentResult{
			Value:       req.Value,
			Type:        iocType,
			Found:       true,
			ThreatLevel: threatLevel,
			Sources:     sources,
			Tags:        tags,
			Description: description,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			Confidence:  80,
		}
	}

	// Live multi-source enrichment: query external reputation providers when
	// configured (no API keys ⇒ inert, local-only). Augments the result and caches
	// external verdicts back into ioc_entries for future lookups / retro-hunting.
	if h.live != nil && h.live.Configured() {
		h.mergeLive(c.Request.Context(), &result, req.Value, req.Type)
	}

	c.JSON(http.StatusOK, result)
}

// mergeLive queries external providers and folds their reputation into result,
// then upserts a cache row when an external verdict is found.
func (h *IOCEnrichmentHandler) mergeLive(ctx context.Context, result *EnrichmentResult, value, iocType string) {
	t := iocType
	if t == "" {
		t = result.Type
	}
	live := h.live.Enrich(ctx, value, t)
	if !live.Found {
		return
	}
	result.Value = value
	if result.Type == "" {
		result.Type = t
	}
	result.Found = true
	// Merge sources and tags (dedup).
	seen := map[string]struct{}{}
	for _, s := range result.Sources {
		seen[s] = struct{}{}
	}
	for _, s := range live.Sources {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result.Sources = append(result.Sources, s)
		}
	}
	tagSeen := map[string]struct{}{}
	for _, tg := range result.Tags {
		tagSeen[tg] = struct{}{}
	}
	for _, tg := range live.Tags {
		if _, ok := tagSeen[tg]; !ok {
			tagSeen[tg] = struct{}{}
			result.Tags = append(result.Tags, tg)
		}
	}
	// Reputation score (0-100) maps to threat_level (0-10); take the stronger.
	lvl := live.Score / 10
	if lvl > result.ThreatLevel {
		result.ThreatLevel = lvl
	}
	if live.Score > result.Confidence {
		result.Confidence = live.Score
	}
	if result.Description == "" && live.Verdict != "unknown" {
		result.Description = "外部評価: " + live.Verdict
	}
	h.cacheLive(ctx, value, result.Type, result.ThreatLevel, result.Tags, live)
}

// cacheLive upserts an externally-enriched IOC into ioc_entries so subsequent
// lookups and the retro-IOC hunter see it. Best-effort: failures are logged only.
func (h *IOCEnrichmentHandler) cacheLive(ctx context.Context, value, iocType string, threatLevel int, tags []string, live threatintel.LiveResult) {
	if h.pool == nil || live.Score < 25 {
		return // only cache meaningful (suspicious+) verdicts
	}
	src := "live:" + strings.Join(live.Sources, ",")
	desc := "外部評価(" + live.Verdict + "), 検知数=" + strconv.Itoa(live.Malicious)
	_, err := h.pool.Exec(ctx,
		// severity, not threat_level: this was the one writer keeping the
		// duplicated column alive, and the value it computes (live.Score/10) is
		// on the same 1-10 scale severity uses. Clamped because the CHECK
		// requires at least 1 and a low score divides to 0.
		`INSERT INTO ioc_entries (type, value, severity, tags, description, source_feed, is_active, first_seen, last_seen)
		 VALUES ($1,$2,GREATEST(LEAST($3,10),1),$4,$5,$6,true,NOW(),NOW())
		 ON CONFLICT (type, value) DO UPDATE
		   SET severity    = GREATEST(ioc_entries.severity, EXCLUDED.severity),
		       tags        = EXCLUDED.tags,
		       description = EXCLUDED.description,
		       source_feed = EXCLUDED.source_feed,
		       last_seen   = NOW()`,
		iocType, value, threatLevel, tags, desc, src,
	)
	if err != nil {
		slog.Warn("ioc live-enrichment cache upsert failed", "value", value, "error", err)
	}
}

// BulkEnrich enriches up to 100 IOC values in a single request.
// POST /api/v1/threat-intel/enrich/bulk
func (h *IOCEnrichmentHandler) BulkEnrich(c *gin.Context) {
	var req struct {
		Items []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"items"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if len(req.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must not be empty"})
		return
	}
	if len(req.Items) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 100 items per bulk request"})
		return
	}

	tableOK := h.tableExists(c)

	results := make([]EnrichmentResult, 0, len(req.Items))

	for _, item := range req.Items {
		empty := EnrichmentResult{
			Value:   item.Value,
			Type:    item.Type,
			Found:   false,
			Sources: []string{},
			Tags:    []string{},
		}
		if !tableOK || strings.TrimSpace(item.Value) == "" {
			results = append(results, empty)
			continue
		}

		var (
			iocType     string
			threatLevel int
			tags        []string
			description string
			firstSeen   *time.Time
			lastSeen    *time.Time
			sourceFeed  string
		)

		// This half already read the right columns. It still reported "not
		// found" for most indicators, because first_seen and last_seen are
		// nullable and the writers that add them by hand or over TAXII/STIX
		// leave both NULL — which fails the Scan.
		err := h.pool.QueryRow(c.Request.Context(),
			`SELECT type, severity, tags, COALESCE(description,''),
			        COALESCE(first_seen, created_at), COALESCE(last_seen, created_at),
			        COALESCE(source_feed,'')
			   FROM ioc_entries
			  WHERE value = $1 AND is_active = true
			  LIMIT 1`,
			item.Value,
		).Scan(&iocType, &threatLevel, &tags, &description, &firstSeen, &lastSeen, &sourceFeed)

		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				slog.Warn("IOC enrichment: 一括照会で行の読み取りに失敗しました",
					"value", item.Value, "error", err)
			}
			results = append(results, empty)
			continue
		}

		if tags == nil {
			tags = []string{}
		}
		sources := []string{}
		if sourceFeed != "" {
			sources = append(sources, sourceFeed)
		}

		results = append(results, EnrichmentResult{
			Value:       item.Value,
			Type:        iocType,
			Found:       true,
			ThreatLevel: threatLevel,
			Sources:     sources,
			Tags:        tags,
			Description: description,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			Confidence:  80,
		})
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// Search performs an ILIKE search across ioc_entries.value, returning up to 20 matches.
// GET /api/v1/threat-intel/search?q=...
func (h *IOCEnrichmentHandler) Search(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q parameter is required"})
		return
	}

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"results": []interface{}{}})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT value, type, severity, tags, COALESCE(description,''),
		        COALESCE(first_seen, created_at), COALESCE(last_seen, created_at),
		        COALESCE(source_feed,'')
		   FROM ioc_entries
		  WHERE value ILIKE $1 AND is_active = true
		  ORDER BY severity DESC, last_seen DESC NULLS LAST
		  LIMIT 20`,
		"%"+q+"%",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}
	defer rows.Close()

	type SearchHit struct {
		Value       string     `json:"value"`
		Type        string     `json:"ioc_type"`
		ThreatLevel int        `json:"threat_level"`
		Tags        []string   `json:"tags"`
		Description string     `json:"description"`
		FirstSeen   *time.Time `json:"first_seen,omitempty"`
		LastSeen    *time.Time `json:"last_seen,omitempty"`
		SourceFeed  string     `json:"source_feed"`
	}

	hits := make([]SearchHit, 0)
	for rows.Next() {
		var h SearchHit
		var tags []string
		// Nullable timestamps go through pointers: a NULL here used to fail the
		// Scan, and pgx ends iteration on a scan error, so one indicator with no
		// first_seen truncated the rest of the results.
		var firstSeen, lastSeen *time.Time
		if err := rows.Scan(&h.Value, &h.Type, &h.ThreatLevel, &tags, &h.Description,
			&firstSeen, &lastSeen, &h.SourceFeed); err != nil {
			slog.Warn("IOC search: 行の読み取りに失敗しました。以降の結果は返りません", "error", err)
			break
		}
		h.FirstSeen = firstSeen
		h.LastSeen = lastSeen
		if tags == nil {
			tags = []string{}
		}
		h.Tags = tags
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": hits, "query": q, "count": len(hits)})
}
