// Package enrichment provides background threat intelligence enrichment for alerts.
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// vtRateLimit is the number of requests allowed per minute on the VT free tier.
const vtRateLimit = 4

// VTEnricher subscribes to NATS "alert.created" events and enriches them with VirusTotal data.
type VTEnricher struct {
	nc     *nats.Conn
	pool   *pgxpool.Pool
	apiKey string
	tokens chan struct{} // channel-based token bucket for rate limiting
}

// NewVTEnricher creates a new VTEnricher with a 4 req/min rate limiter.
func NewVTEnricher(nc *nats.Conn, pool *pgxpool.Pool, apiKey string) *VTEnricher {
	e := &VTEnricher{
		nc:     nc,
		pool:   pool,
		apiKey: apiKey,
		tokens: make(chan struct{}, vtRateLimit),
	}
	// Pre-fill token bucket.
	for i := 0; i < vtRateLimit; i++ {
		e.tokens <- struct{}{}
	}
	return e
}

// Run subscribes to NATS and processes incoming alerts.
// Also polls for un-enriched alerts every 5 minutes as a fallback.
func (e *VTEnricher) Run(ctx context.Context) {
	// Refill token bucket at 4 tokens per minute.
	go func() {
		ticker := time.NewTicker(time.Minute / vtRateLimit)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case e.tokens <- struct{}{}:
				default:
					// Bucket is full; discard extra token.
				}
			}
		}
	}()

	// Subscribe to NATS alert.created events.
	var sub *nats.Subscription
	if e.nc != nil {
		var err error
		sub, err = e.nc.Subscribe("alert.created", func(msg *nats.Msg) {
			var payload struct {
				ID string `json:"id"`
			}
			if jsonErr := json.Unmarshal(msg.Data, &payload); jsonErr != nil || payload.ID == "" {
				return
			}
			// Enrich in a goroutine to not block the NATS callback.
			go e.enrichAlert(ctx, payload.ID)
		})
		if err != nil {
			slog.Warn("alert.createdのNATSサブスクリプションに失敗しました", "error", err)
		} else {
			defer sub.Unsubscribe()
			slog.Info("VTエンリッチャー: alert.createdをサブスクライブしました")
		}
	}

	// Fallback: poll for new un-enriched alerts every 5 minutes.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.pollUnenriched(ctx)
		}
	}
}

// pollUnenriched queries for recent alerts without enrichment data and enriches them.
func (e *VTEnricher) pollUnenriched(ctx context.Context) {
	rows, err := e.pool.Query(ctx,
		`SELECT id FROM alerts WHERE enrichment IS NULL AND created_at > NOW() - INTERVAL '24 hours' ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		slog.Warn("未エンリッチアラートのポーリングに失敗しました", "error", err)
		return
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	for _, id := range ids {
		e.enrichAlert(ctx, id)
	}
}

// enrichAlert queries VT for file hashes and IP addresses found in the alert's raw_event.
// Updates the alerts table with enrichment JSONB column.
func (e *VTEnricher) enrichAlert(ctx context.Context, alertID string) {
	// Fetch alert description and any raw_data.
	var description, title string
	err := e.pool.QueryRow(ctx,
		`SELECT COALESCE(description,''), COALESCE(title,'') FROM alerts WHERE id = $1`, alertID).
		Scan(&description, &title)
	if err != nil {
		slog.Debug("エンリッチメント用アラートの取得に失敗しました", "id", alertID, "error", err)
		return
	}

	text := title + " " + description

	// Extract IOCs from text.
	hash := extractHash(text)
	ip := extractIP(text)

	if hash == "" && ip == "" {
		// Nothing to enrich; mark as checked with empty object so we don't re-query.
		_, _ = e.pool.Exec(ctx,
			`UPDATE alerts SET enrichment = '{}' WHERE id = $1 AND enrichment IS NULL`, alertID)
		return
	}

	enrichmentData := map[string]interface{}{}

	if hash != "" {
		result, vtErr := e.vtLookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", strings.ToLower(hash)))
		if vtErr != nil {
			slog.Warn("VTファイルハッシュ照会に失敗しました", "hash", hash, "error", vtErr)
		} else if result != nil {
			enrichmentData["file"] = result
			enrichmentData["hash"] = hash
		}
	}

	if ip != "" {
		result, vtErr := e.vtLookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip))
		if vtErr != nil {
			slog.Warn("VT IP照会に失敗しました", "ip", ip, "error", vtErr)
		} else if result != nil {
			enrichmentData["ip"] = result
			enrichmentData["ip_address"] = ip
		}
	}

	enrichmentData["enriched_at"] = time.Now().UTC().Format(time.RFC3339)

	enrichJSON, err := json.Marshal(enrichmentData)
	if err != nil {
		slog.Warn("エンリッチメントデータのシリアライズに失敗しました", "error", err)
		return
	}

	_, err = e.pool.Exec(ctx,
		`UPDATE alerts SET enrichment = $1 WHERE id = $2`, enrichJSON, alertID)
	if err != nil {
		slog.Warn("エンリッチメントデータの保存に失敗しました", "id", alertID, "error", err)
		return
	}

	slog.Info("アラートをエンリッチしました", "alert_id", alertID, "hash", hash, "ip", ip)
}

// vtLookup performs a rate-limited VirusTotal API call.
func (e *VTEnricher) vtLookup(ctx context.Context, url string) (map[string]interface{}, error) {
	// Acquire token (blocks until one is available or ctx is cancelled).
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.tokens:
		// Token acquired; proceed.
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", e.apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VTリクエストに失敗しました: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return map[string]interface{}{"found": false}, nil
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("VirusTotal APIレート制限に達しました")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("VirusTotal returned HTTP %d", resp.StatusCode)
	}

	var raw struct {
		Data struct {
			Attributes map[string]interface{} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("VTレスポンスのデコードに失敗しました: %w", err)
	}

	attrs := raw.Data.Attributes
	result := map[string]interface{}{
		"found":      true,
		"attributes": attrs,
	}

	// Extract key metrics for easy querying.
	if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
		result["malicious"] = stats["malicious"]
		result["suspicious"] = stats["suspicious"]
		result["total_engines"] = sumStats(stats)
	}
	if rep, ok := attrs["reputation"]; ok {
		result["reputation"] = rep
	}

	return result, nil
}

// sumStats totals all engine counts.
func sumStats(stats map[string]interface{}) float64 {
	keys := []string{"malicious", "suspicious", "harmless", "undetected", "failure", "type-unsupported"}
	var total float64
	for _, k := range keys {
		if v, ok := stats[k].(float64); ok {
			total += v
		}
	}
	return total
}

var (
	// hashRe matches MD5 (32), SHA1 (40), SHA256 (64) hex strings.
	hashRe = regexp.MustCompile(`\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b`)
	// ipRe matches IPv4 addresses.
	ipRe = regexp.MustCompile(`\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b`)
	// privateIPRe matches private/loopback ranges we want to skip.
	privateIPRe = regexp.MustCompile(`^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)`)
)

// extractHash extracts the first file hash (SHA256 > SHA1 > MD5) from text.
func extractHash(text string) string {
	matches := hashRe.FindAllString(text, -1)
	// Prefer longer hashes (SHA256 first, then SHA1, then MD5).
	for _, length := range []int{64, 40, 32} {
		for _, m := range matches {
			if len(m) == length {
				return strings.ToLower(m)
			}
		}
	}
	return ""
}

// extractIP extracts the first public IPv4 address from text.
func extractIP(text string) string {
	matches := ipRe.FindAllString(text, -1)
	for _, ip := range matches {
		if !privateIPRe.MatchString(ip) {
			return ip
		}
	}
	return ""
}
