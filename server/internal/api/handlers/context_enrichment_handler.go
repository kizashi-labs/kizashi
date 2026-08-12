package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/virustotal"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextEnrichmentHandler handles threat context enrichment endpoints.
type ContextEnrichmentHandler struct {
	pool *pgxpool.Pool
}

// NewContextEnrichmentHandler creates a new ContextEnrichmentHandler.
func NewContextEnrichmentHandler(pool *pgxpool.Pool) *ContextEnrichmentHandler {
	return &ContextEnrichmentHandler{pool: pool}
}

func (h *ContextEnrichmentHandler) checkSourcesTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='enrichment_sources')`).Scan(&exists)
	return err == nil && exists
}

func (h *ContextEnrichmentHandler) checkCacheTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='enrichment_cache')`).Scan(&exists)
	return err == nil && exists
}

// ListSources returns all enrichment sources.
// GET /api/v1/admin/enrichment/sources
func (h *ContextEnrichmentHandler) ListSources(c *gin.Context) {
	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusOK, gin.H{"sources": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, source_type, api_key_masked, is_active,
		        requests_today, daily_limit, avg_latency_ms, created_at
		 FROM enrichment_sources ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type Source struct {
		ID            string    `json:"id"`
		Name          string    `json:"name"`
		SourceType    string    `json:"source_type"`
		APIKeyMasked  *string   `json:"api_key_masked"`
		IsActive      bool      `json:"is_active"`
		RequestsToday int       `json:"requests_today"`
		DailyLimit    int       `json:"daily_limit"`
		AvgLatencyMS  int       `json:"avg_latency_ms"`
		CreatedAt     time.Time `json:"created_at"`
	}
	var sources []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Name, &s.SourceType, &s.APIKeyMasked, &s.IsActive,
			&s.RequestsToday, &s.DailyLimit, &s.AvgLatencyMS, &s.CreatedAt); err != nil {
			continue
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if sources == nil {
		sources = []Source{}
	}
	c.JSON(http.StatusOK, gin.H{"sources": sources, "total": len(sources)})
}

// CreateSource creates a new enrichment source.
// POST /api/v1/admin/enrichment/sources
func (h *ContextEnrichmentHandler) CreateSource(c *gin.Context) {
	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrichment_sources table not ready"})
		return
	}
	var in struct {
		Name         string  `json:"name" binding:"required"`
		SourceType   string  `json:"source_type" binding:"required"`
		APIKeyMasked *string `json:"api_key_masked"`
		DailyLimit   int     `json:"daily_limit"`
		AvgLatencyMS int     `json:"avg_latency_ms"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.DailyLimit <= 0 {
		in.DailyLimit = 1000
	}
	if in.AvgLatencyMS <= 0 {
		in.AvgLatencyMS = 200
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO enrichment_sources (name, source_type, api_key_masked, daily_limit, avg_latency_ms)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		in.Name, in.SourceType, in.APIKeyMasked, in.DailyLimit, in.AvgLatencyMS,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "source created"})
}

// UpdateSource updates an existing enrichment source.
// PUT /api/v1/admin/enrichment/sources/:id
func (h *ContextEnrichmentHandler) UpdateSource(c *gin.Context) {
	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrichment_sources table not ready"})
		return
	}
	id := c.Param("id")
	var in struct {
		Name         *string `json:"name"`
		SourceType   *string `json:"source_type"`
		APIKeyMasked *string `json:"api_key_masked"`
		DailyLimit   *int    `json:"daily_limit"`
		AvgLatencyMS *int    `json:"avg_latency_ms"`
		IsActive     *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE enrichment_sources SET
		   name = COALESCE($2, name),
		   source_type = COALESCE($3, source_type),
		   api_key_masked = COALESCE($4, api_key_masked),
		   daily_limit = COALESCE($5, daily_limit),
		   avg_latency_ms = COALESCE($6, avg_latency_ms),
		   is_active = COALESCE($7, is_active)
		 WHERE id = $1`,
		id, in.Name, in.SourceType, in.APIKeyMasked, in.DailyLimit, in.AvgLatencyMS, in.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// DeleteSource removes an enrichment source.
// DELETE /api/v1/admin/enrichment/sources/:id
func (h *ContextEnrichmentHandler) DeleteSource(c *gin.Context) {
	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrichment_sources table not ready"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM enrichment_sources WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// ToggleSource toggles the is_active state of an enrichment source.
// POST /api/v1/admin/enrichment/sources/:id/toggle
func (h *ContextEnrichmentHandler) ToggleSource(c *gin.Context) {
	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`UPDATE enrichment_sources SET is_active = NOT is_active WHERE id=$1 RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "is_active": isActive})
}

// EnrichIndicator enriches an indicator, checking cache first.
// POST /api/v1/admin/enrichment/enrich
func (h *ContextEnrichmentHandler) EnrichIndicator(c *gin.Context) {
	var in struct {
		IndicatorType  string `json:"indicator_type" binding:"required"`
		IndicatorValue string `json:"indicator_value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	source := "internal"

	// Check cache first (if table exists).
	if h.checkCacheTable(c) {
		var cachedResult json.RawMessage
		err := h.pool.QueryRow(ctx,
			`SELECT result FROM enrichment_cache
			 WHERE indicator_value=$1 AND source=$2 AND expires_at > NOW()`,
			in.IndicatorValue, source,
		).Scan(&cachedResult)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"indicator_type":  in.IndicatorType,
				"indicator_value": in.IndicatorValue,
				"source":          source,
				"result":          cachedResult,
				"cached":          true,
			})
			return
		}
	}

	// Cache miss — perform real enrichment.
	result, enrichSource := enrichIndicator(ctx, in.IndicatorType, in.IndicatorValue)
	resultJSON, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		slog.Warn("context_enrichment: エンリッチ結果のシリアライズに失敗しました", "error", marshalErr)
		resultJSON = []byte("{}")
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	if h.checkCacheTable(c) {
		_, _ = h.pool.Exec(ctx,
			`INSERT INTO enrichment_cache (indicator_type, indicator_value, source, result, expires_at)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (indicator_value, source) DO UPDATE SET result=$4, expires_at=$5`,
			in.IndicatorType, in.IndicatorValue, enrichSource, resultJSON, expiresAt,
		)
		_, _ = h.pool.Exec(ctx,
			`UPDATE enrichment_sources SET requests_today = requests_today + 1
			 WHERE source_type = $1 AND is_active = true`, enrichSource)
	}

	c.JSON(http.StatusOK, gin.H{
		"indicator_type":  in.IndicatorType,
		"indicator_value": in.IndicatorValue,
		"source":          enrichSource,
		"result":          json.RawMessage(resultJSON),
		"cached":          false,
	})
}

// GetCachedResults returns paginated enrichment cache entries.
// GET /api/v1/admin/enrichment/cache
func (h *ContextEnrichmentHandler) GetCachedResults(c *gin.Context) {
	if !h.checkCacheTable(c) {
		c.JSON(http.StatusOK, gin.H{"results": []interface{}{}, "total": 0})
		return
	}
	indicatorType := c.Query("indicator_type")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(offsetStr)
	ctx := c.Request.Context()
	query := `SELECT id, indicator_type, indicator_value, source, result, expires_at, created_at
	          FROM enrichment_cache WHERE expires_at > NOW()`
	args := []interface{}{}
	i := 1
	if indicatorType != "" {
		query += " AND indicator_type = $" + strconv.Itoa(i)
		args = append(args, indicatorType)
		i++
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(i) + " OFFSET $" + strconv.Itoa(i+1)
	args = append(args, limit, offset)
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()
	type CacheEntry struct {
		ID             string          `json:"id"`
		IndicatorType  string          `json:"indicator_type"`
		IndicatorValue string          `json:"indicator_value"`
		Source         string          `json:"source"`
		Result         json.RawMessage `json:"result"`
		ExpiresAt      time.Time       `json:"expires_at"`
		CreatedAt      time.Time       `json:"created_at"`
	}
	var results []CacheEntry
	for rows.Next() {
		var e CacheEntry
		if err := rows.Scan(&e.ID, &e.IndicatorType, &e.IndicatorValue, &e.Source,
			&e.Result, &e.ExpiresAt, &e.CreatedAt); err != nil {
			continue
		}
		results = append(results, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if results == nil {
		results = []CacheEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "total": len(results)})
}

// GetStats returns enrichment statistics.
// GET /api/v1/admin/enrichment/stats
func (h *ContextEnrichmentHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	// Cache hit rate
	var totalEntries, expiredEntries int
	if h.checkCacheTable(c) {
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM enrichment_cache`).Scan(&totalEntries)
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM enrichment_cache WHERE expires_at <= NOW()`).Scan(&expiredEntries)
	}
	activeEntries := totalEntries - expiredEntries
	var cacheHitRate float64
	if totalEntries > 0 {
		cacheHitRate = float64(activeEntries) / float64(totalEntries) * 100.0
	}
	// Requests per source today + avg latency
	type SourceStat struct {
		Name          string `json:"name"`
		SourceType    string `json:"source_type"`
		RequestsToday int    `json:"requests_today"`
		DailyLimit    int    `json:"daily_limit"`
		AvgLatencyMS  int    `json:"avg_latency_ms"`
		IsActive      bool   `json:"is_active"`
	}
	var sources []SourceStat
	if h.checkSourcesTable(c) {
		srows, err := h.pool.Query(ctx,
			`SELECT name, source_type, requests_today, daily_limit, avg_latency_ms, is_active
			 FROM enrichment_sources ORDER BY requests_today DESC`)
		if err == nil {
			defer srows.Close()
			for srows.Next() {
				var s SourceStat
				if scanErr := srows.Scan(&s.Name, &s.SourceType, &s.RequestsToday, &s.DailyLimit, &s.AvgLatencyMS, &s.IsActive); scanErr == nil {
					sources = append(sources, s)
				}
			}
			if err := srows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}
	if sources == nil {
		sources = []SourceStat{}
	}
	c.JSON(http.StatusOK, gin.H{
		"cache_hit_rate": cacheHitRate,
		"total_cached":   totalEntries,
		"active_cached":  activeEntries,
		"sources":        sources,
	})
}

// HealthCheck tests the connection to a specific enrichment source.
// POST /api/v1/admin/enrichment/sources/:id/health
func (h *ContextEnrichmentHandler) HealthCheck(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	if !h.checkSourcesTable(c) {
		c.JSON(http.StatusOK, gin.H{"id": id, "status": "unknown", "latency_ms": 0})
		return
	}

	var sourceType string
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`SELECT source_type, is_active FROM enrichment_sources WHERE id=$1`, id,
	).Scan(&sourceType, &isActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}

	start := time.Now()
	status := "ok"
	message := sourceType + " connection successful"

	// Simple reachability check per source type.
	switch strings.ToLower(sourceType) {
	case "virustotal":
		if virustotal.New() == nil {
			status = "error"
			message = "VIRUSTOTAL_API_KEY が設定されていません"
		}
	case "geoip", "ip-api":
		_, lookupErr := enrichIP(ctx, "8.8.8.8")["status"]
		if !lookupErr {
			status = "error"
			message = "GeoIP lookup failed"
		}
	}

	latencyMS := int(time.Since(start).Milliseconds())
	_, _ = h.pool.Exec(ctx,
		`UPDATE enrichment_sources SET avg_latency_ms=$2 WHERE id=$1`, id, latencyMS)

	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"status":     status,
		"message":    message,
		"latency_ms": latencyMS,
		"is_active":  isActive,
	})
}

// ClearCache deletes expired (or all) cache entries.
// DELETE /api/v1/admin/enrichment/cache
func (h *ContextEnrichmentHandler) ClearCache(c *gin.Context) {
	if !h.checkCacheTable(c) {
		c.JSON(http.StatusOK, gin.H{"message": "cache cleared", "deleted": 0})
		return
	}
	ctx := c.Request.Context()
	// ?expired=true (default) clears only expired; ?expired=false clears everything.
	expiredOnly := c.DefaultQuery("expired", "true") != "false"

	var tag interface{ RowsAffected() int64 }
	var execErr error
	if expiredOnly {
		tag, execErr = h.pool.Exec(ctx, `DELETE FROM enrichment_cache WHERE expires_at <= NOW()`)
	} else {
		tag, execErr = h.pool.Exec(ctx, `DELETE FROM enrichment_cache`)
	}
	if execErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(execErr)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "cache cleared", "deleted": tag.RowsAffected()})
}

// ── Real enrichment logic ──────────────────────────────────────────────────────

// enrichIndicator performs real lookups based on indicator type.
// Returns the result map and the source name used.
func enrichIndicator(ctx context.Context, indicatorType, value string) (map[string]interface{}, string) {
	switch strings.ToLower(indicatorType) {
	case "ip", "ip_address":
		return enrichIP(ctx, value), "geoip"
	case "hash", "md5", "sha1", "sha256", "file_hash":
		return enrichHash(ctx, value), "virustotal"
	case "domain", "hostname":
		return enrichDomain(ctx, value), "dns"
	case "url":
		if u, err := url.Parse(value); err == nil && u.Host != "" {
			return enrichDomain(ctx, u.Host), "dns"
		}
		return map[string]interface{}{"status": "unknown", "error": "invalid url"}, "internal"
	default:
		return map[string]interface{}{"status": "unknown", "indicator_type": indicatorType}, "internal"
	}
}

// enrichIP looks up geolocation and proxy/Tor status via ip-api.com.
func enrichIP(ctx context.Context, ipStr string) map[string]interface{} {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return map[string]interface{}{"status": "invalid", "error": "not a valid IP address"}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return map[string]interface{}{"status": "private", "is_private": true}
	}

	geo := lookupGeoIP(ctx, ipStr)
	if geo == nil {
		return map[string]interface{}{"status": "unknown", "ip": ipStr}
	}

	verdict := "clean"
	if geo.IsProxy || geo.IsTor {
		verdict = "suspicious"
	}
	return map[string]interface{}{
		"status":       verdict,
		"ip":           ipStr,
		"country":      geo.Country,
		"country_code": geo.CountryCode,
		"city":         geo.City,
		"isp":          geo.ISP,
		"is_proxy":     geo.IsProxy,
		"is_tor":       geo.IsTor,
		"latitude":     geo.Lat,
		"longitude":    geo.Lon,
	}
}

// enrichHash looks up a file hash via VirusTotal (if API key is set).
func enrichHash(ctx context.Context, hash string) map[string]interface{} {
	vtClient := virustotal.New()
	if vtClient == nil {
		return map[string]interface{}{
			"status": "unavailable",
			"error":  "VIRUSTOTAL_API_KEY が設定されていません",
			"hash":   hash,
		}
	}

	report, err := vtClient.LookupHash(ctx, hash)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error(), "hash": hash}
	}
	if report == nil {
		return map[string]interface{}{"status": "unknown", "hash": hash}
	}

	return map[string]interface{}{
		"status":          report.Verdict,
		"hash":            hash,
		"score":           report.Score,
		"detection_count": report.DetectionCount,
		"total_engines":   report.TotalEngines,
		"signatures":      report.Signatures,
		"meaningful_name": report.MeaningfulName,
	}
}

// enrichDomain performs a DNS A/AAAA lookup and returns basic resolution info.
func enrichDomain(ctx context.Context, domain string) map[string]interface{} {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return map[string]interface{}{
			"status": "unresolved",
			"domain": domain,
			"error":  err.Error(),
		}
	}
	return map[string]interface{}{
		"status":     "resolved",
		"domain":     domain,
		"addresses":  addrs,
		"addr_count": len(addrs),
	}
}
