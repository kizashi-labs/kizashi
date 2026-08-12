package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ThreatFusionHandler serves the TI-fusion views (intel sources + fusion stats)
// from real data, replacing the former empty-array / zero-count stubs. Sources
// are the configured threat feeds; stats aggregate the fused IOC store.
type ThreatFusionHandler struct {
	pool *pgxpool.Pool
}

// NewThreatFusionHandler creates a ThreatFusionHandler.
func NewThreatFusionHandler(pool *pgxpool.Pool) *ThreatFusionHandler {
	return &ThreatFusionHandler{pool: pool}
}

// fusionSource matches the shape the TI-fusion UI renders. Fields the store does
// not track yet are filled with safe, non-nil defaults (notably
// top_indicator_types, which the UI .map()s over) so real data renders without
// crashing the page that was previously fed an empty array.
type fusionSource struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Type              string  `json:"type"`
	Enabled           bool    `json:"enabled"`
	Reliability       string  `json:"reliability"`
	ReliabilityScore  int     `json:"reliability_score"`
	FreshnessScore    int     `json:"freshness_score"`
	IOCCount          int     `json:"ioc_count"`
	LastUpdated       string  `json:"last_updated"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	HitRate           float64 `json:"hit_rate"`
	TopIndicatorTypes []any   `json:"top_indicator_types"`
}

// Sources handles GET /threat-intel/fusion/sources — the configured threat
// feeds presented as fusion sources. Returns a bare array (stub-compatible).
func (h *ThreatFusionHandler) Sources(c *gin.Context) {
	if !tableExists(c, h.pool, "threat_feeds") {
		c.JSON(http.StatusOK, []fusionSource{})
		return
	}
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(NULLIF(source_format,''), feed_type),
		       is_active, COALESCE(last_count,0), last_sync_at
		FROM threat_feeds ORDER BY is_active DESC, last_count DESC NULLS LAST`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	sources := []fusionSource{}
	for rows.Next() {
		var (
			id, name, ftype string
			active          bool
			count           int
			lastSync        *time.Time
		)
		if rows.Scan(&id, &name, &ftype, &active, &count, &lastSync) != nil {
			continue
		}
		s := fusionSource{
			ID:                id,
			Name:              name,
			Type:              ftype,
			Enabled:           active,
			IOCCount:          count,
			Reliability:       reliabilityLabel(count),
			ReliabilityScore:  clampInt(count/50, 10, 100),
			FreshnessScore:    freshnessScore(lastSync),
			FalsePositiveRate: 0,
			HitRate:           0,
			TopIndicatorTypes: []any{},
		}
		if lastSync != nil {
			s.LastUpdated = lastSync.UTC().Format(time.RFC3339)
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, sources)
}

// Stats handles GET /threat-intel/fusion/stats.
func (h *ThreatFusionHandler) Stats(c *gin.Context) {
	resp := gin.H{"total": 0, "enriched_today": 0, "sources": 0, "active_sources": 0}
	if !tableExists(c, h.pool, "ioc_entries") {
		c.JSON(http.StatusOK, resp)
		return
	}
	var total, enrichedToday int
	_ = h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM ioc_entries`).Scan(&total)
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ioc_entries WHERE updated_at::date = NOW()::date`).Scan(&enrichedToday)
	resp["total"] = total
	resp["enriched_today"] = enrichedToday

	if tableExists(c, h.pool, "threat_feeds") {
		var sources, active int
		_ = h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM threat_feeds`).Scan(&sources)
		_ = h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM threat_feeds WHERE is_active`).Scan(&active)
		resp["sources"] = sources
		resp["active_sources"] = active
	}
	c.JSON(http.StatusOK, resp)
}

func reliabilityLabel(iocCount int) string {
	switch {
	case iocCount >= 1000:
		return "high"
	case iocCount >= 100:
		return "medium"
	default:
		return "low"
	}
}

// freshnessScore maps sync recency to 0-100 (100 = synced within a day).
func freshnessScore(lastSync *time.Time) int {
	if lastSync == nil {
		return 0
	}
	age := time.Since(*lastSync)
	switch {
	case age <= 24*time.Hour:
		return 100
	case age <= 7*24*time.Hour:
		return 70
	case age <= 30*24*time.Hour:
		return 40
	default:
		return 10
	}
}
