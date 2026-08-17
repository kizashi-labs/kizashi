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

	"github.com/edr-platform/server/internal/tick"
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
			tick.Run(ctx, "virustotal_enrichment", e.pollUnenriched)
		}
	}
}

// vtSectionKey is this enricher's section of the shared alerts.enrichment
// column. Writing under a key rather than replacing the object is what lets the
// alert-enrichment pipeline and this enricher coexist; the previous
// `SET enrichment = $1` erased whatever the other had written.
const vtSectionKey = "virustotal"

// storeSection merges this enricher's findings into alerts.enrichment.
func (e *VTEnricher) storeSection(ctx context.Context, alertID string, section map[string]interface{}) {
	payload, err := json.Marshal(map[string]interface{}{vtSectionKey: section})
	if err != nil {
		tick.FailComponent(ctx, "virustotal_enrichment", err, "エンリッチメントデータのシリアライズに失敗しました")
		return
	}
	if _, err := e.pool.Exec(ctx,
		`UPDATE alerts SET enrichment = COALESCE(enrichment, '{}'::jsonb) || $1::jsonb WHERE id = $2`,
		payload, alertID); err != nil {
		tick.Fail(ctx, err, "エンリッチメントデータの保存に失敗しました", "id", alertID)
	}
}

// vtCandidateWhere selects the alerts this enricher still has work to do on:
// "not yet looked at by VirusTotal", not "enrichment is empty". alerts.
// enrichment is shared — AlertActionHandler.Enrich writes {"status":"pending"}
// when an operator asks for enrichment, and the alert-enrichment pipeline
// writes its own section. Selecting on `enrichment IS NULL` meant that the
// moment either of them touched an alert, this enricher was excluded from it
// for ever, so pressing "enrich" in the console guaranteed the alert would
// never be enriched by VirusTotal.
//
// It is a constant rather than inline SQL so a test can apply the real
// predicate to a single row instead of restating it and drifting from it.
// $1 is the section key.
const vtCandidateWhere = `WHERE NOT (COALESCE(enrichment, '{}'::jsonb) ? $1)
		   AND created_at > NOW() - INTERVAL '24 hours'`

// pollUnenriched queries for recent alerts without enrichment data and enriches them.
func (e *VTEnricher) pollUnenriched(ctx context.Context) {
	rows, err := e.pool.Query(ctx,
		`SELECT id FROM alerts `+vtCandidateWhere+`
		 ORDER BY created_at DESC LIMIT 20`, vtSectionKey)
	if err != nil {
		tick.FailComponent(ctx, "virustotal_enrichment", err, "未エンリッチアラートのポーリングに失敗しました")
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
	if err := rows.Err(); err != nil {
		tick.Fail(ctx, err, "未エンリッチのハッシュ一覧の走査が途中で終わりました。今回のポーリングで照会しないハッシュがあります")
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
		tick.FailComponent(ctx, "virustotal_enrichment", err, "エンリッチメント用アラートの取得に失敗しました", "id", alertID)
		return
	}

	text := title + " " + description

	// Extract IOCs from text.
	hash := extractHash(text)
	ip := extractIP(text)

	if hash == "" && ip == "" {
		// Nothing to look up. Record an empty section so this alert is not
		// re-examined on every tick, without disturbing anything else in the
		// column.
		e.storeSection(ctx, alertID, map[string]interface{}{"checked_at": time.Now().UTC().Format(time.RFC3339)})
		return
	}

	enrichmentData := map[string]interface{}{}

	if hash != "" {
		result, vtErr := e.vtLookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", strings.ToLower(hash)))
		if vtErr != nil {
			tick.Fail(ctx, vtErr, "VTファイルハッシュ照会に失敗しました", "hash", hash)
		} else if result != nil {
			enrichmentData["file"] = result
			enrichmentData["hash"] = hash
		}
	}

	if ip != "" {
		result, vtErr := e.vtLookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip))
		if vtErr != nil {
			tick.Fail(ctx, vtErr, "VT IP照会に失敗しました", "ip", ip)
		} else if result != nil {
			enrichmentData["ip"] = result
			enrichmentData["ip_address"] = ip
		}
	}

	enrichmentData["enriched_at"] = time.Now().UTC().Format(time.RFC3339)
	e.storeSection(ctx, alertID, enrichmentData)

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

// SweepLockKey serialises test packages that write alerts.enrichment.
//
// `go test ./...` runs packages concurrently against one database, and the
// producers that share this column sweep it globally: AlertEnrichmentPipeline
// selects the 20 newest alerts that are unenriched or flagged pending, with no
// tenant or fixture scoping, and this enricher's poller does the same for its
// own section. A fixture seeded by one package is therefore fair game for the
// other package's sweep — measured directly: internal/api/handlers running its
// pipeline test rewrote this package's fixtures mid-assertion, turning
// {"status":"pending"} into {"status":"done"} and replacing the context section.
//
// Any test that runs one of those sweeps, or seeds a row one of them could
// select, must hold pg_advisory_lock(SweepLockKey) on a dedicated connection
// for its duration. The value is arbitrary; it only has to be unique among the
// advisory locks this codebase takes.
const SweepLockKey int64 = 0x656e72696368 // "enrich" in ASCII
