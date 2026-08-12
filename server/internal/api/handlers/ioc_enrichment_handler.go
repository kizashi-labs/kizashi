package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	Value       string    `json:"value"`
	Type        string    `json:"ioc_type"`
	Found       bool      `json:"found"`
	ThreatLevel int       `json:"threat_level"`
	Sources     []string  `json:"sources"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Confidence  int       `json:"confidence"` // 0-100
}

// tableExists checks whether ioc_entries exists in the current schema.
func (h *IOCEnrichmentHandler) tableExists(c *gin.Context) bool {
	var exists bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'ioc_entries'
		)`).Scan(&exists)
	return err == nil && exists
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
		firstSeen   time.Time
		lastSeen    time.Time
		sourceFeed  string
	)

	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT ioc_type, threat_level, tags, description, first_seen, last_seen, source_feed
		   FROM ioc_entries
		  WHERE value = $1 AND enabled = true
		  LIMIT 1`,
		req.Value,
	).Scan(&iocType, &threatLevel, &tags, &description, &firstSeen, &lastSeen, &sourceFeed)

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
		`INSERT INTO ioc_entries (type, value, ioc_type, threat_level, tags, description, source_feed, enabled, first_seen, last_seen)
		 VALUES ($1,$2,$1,$3,$4,$5,$6,true,NOW(),NOW())
		 ON CONFLICT (type, value) DO UPDATE
		   SET threat_level = GREATEST(ioc_entries.threat_level, EXCLUDED.threat_level),
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
			firstSeen   time.Time
			lastSeen    time.Time
			sourceFeed  string
		)

		err := h.pool.QueryRow(c.Request.Context(),
			`SELECT type, severity, tags, description, first_seen, last_seen, source_feed
			   FROM ioc_entries
			  WHERE value = $1 AND is_active = true
			  LIMIT 1`,
			item.Value,
		).Scan(&iocType, &threatLevel, &tags, &description, &firstSeen, &lastSeen, &sourceFeed)

		if err != nil {
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
		`SELECT value, ioc_type, threat_level, tags, description, first_seen, last_seen, source_feed
		   FROM ioc_entries
		  WHERE value ILIKE $1 AND enabled = true
		  ORDER BY threat_level DESC, last_seen DESC
		  LIMIT 20`,
		"%"+q+"%",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}
	defer rows.Close()

	type SearchHit struct {
		Value       string    `json:"value"`
		Type        string    `json:"ioc_type"`
		ThreatLevel int       `json:"threat_level"`
		Tags        []string  `json:"tags"`
		Description string    `json:"description"`
		FirstSeen   time.Time `json:"first_seen,omitempty"`
		LastSeen    time.Time `json:"last_seen,omitempty"`
		SourceFeed  string    `json:"source_feed"`
	}

	hits := make([]SearchHit, 0)
	for rows.Next() {
		var h SearchHit
		var tags []string
		if err := rows.Scan(&h.Value, &h.Type, &h.ThreatLevel, &tags, &h.Description, &h.FirstSeen, &h.LastSeen, &h.SourceFeed); err != nil {
			continue
		}
		if tags == nil {
			tags = []string{}
		}
		h.Tags = tags
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"results": hits, "query": q, "count": len(hits)})
}
