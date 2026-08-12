package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertEnrichmentPipeline enriches newly created alerts with GeoIP, reverse DNS,
// and IOC match data by polling for unenriched alerts every 30 seconds.
type AlertEnrichmentPipeline struct {
	pool *pgxpool.Pool
}

func NewAlertEnrichmentPipeline(pool *pgxpool.Pool) *AlertEnrichmentPipeline {
	return &AlertEnrichmentPipeline{pool: pool}
}

func (p *AlertEnrichmentPipeline) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.enrich(ctx)
		}
	}
}

// iocKeywords are hardcoded keywords that trigger threat tags when found in alert titles.
var iocKeywords = []string{
	"ransomware",
	"mimikatz",
	"cobalt",
	"beacon",
	"lateral",
}

// enrichmentData is the JSON structure stored in alerts.enrichment_data.
type enrichmentData struct {
	ReverseDNS string     `json:"reverse_dns,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
	EnrichedAt time.Time  `json:"enriched_at"`
	GeoIP      *geoIPInfo `json:"geoip,omitempty"`
}

// geoIPInfo holds IP geolocation data from ip-api.com.
type geoIPInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	IsProxy     bool    `json:"is_proxy,omitempty"`
	IsTor       bool    `json:"is_tor,omitempty"`
}

// ipAPIResponse is the JSON structure returned by ip-api.com/json/{ip}
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Query       string  `json:"query"`
}

// geoIPClient is shared across all lookups (rate-limited: free tier 45 req/min).
var geoIPClient = &http.Client{Timeout: 5 * time.Second}

// lookupGeoIP queries ip-api.com for geolocation data about an IP address.
// Returns nil gracefully if the lookup fails or the IP is private/loopback.
// ip-api.com: free for non-commercial use, 45 req/min limit.
// For commercial use, set GEOIP_API_KEY for the paid API endpoint.
func lookupGeoIP(ctx context.Context, ipStr string) *geoIPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	// プライベート・ループバックIPはスキップ
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := "http://ip-api.com/json/" + ipStr + "?fields=status,country,countryCode,regionName,city,isp,org,lat,lon,timezone,proxy,hosting,query"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := geoIPClient.Do(req)
	if err != nil {
		slog.Debug("geoip: lookup failed", "ip", ipStr, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var raw ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil
	}
	if raw.Status != "success" {
		return nil
	}

	return &geoIPInfo{
		IP:          raw.Query,
		Country:     raw.Country,
		CountryCode: raw.CountryCode,
		Region:      raw.Region,
		City:        raw.City,
		ISP:         raw.ISP,
		Org:         raw.Org,
		Lat:         raw.Lat,
		Lon:         raw.Lon,
		Timezone:    raw.Timezone,
		IsProxy:     raw.Proxy,
		IsTor:       raw.Hosting, // hosting/TorExitNode proxy として使用
	}
}

func (p *AlertEnrichmentPipeline) enrich(ctx context.Context) {
	// 1. Check if alerts table exists.
	var tableExists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='alerts')`).
		Scan(&tableExists)
	if err != nil || !tableExists {
		return
	}

	// 1b. Check if enrichment_status column exists — if not, skip silently.
	var colExists bool
	err = p.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='alerts' AND column_name='enrichment_status'
		)`).Scan(&colExists)
	if err != nil || !colExists {
		return
	}

	// 2. Query unenriched alerts.
	rows, err := p.pool.Query(ctx,
		`SELECT id, title, agent_id
		 FROM alerts
		 WHERE enrichment_status IS NULL OR enrichment_status = 'pending'
		 ORDER BY created_at DESC
		 LIMIT 20`)
	if err != nil {
		slog.Warn("アラートエンリッチメント: クエリ失敗", "error", err)
		return
	}
	defer rows.Close()

	type alertRow struct {
		ID      string
		Title   string
		AgentID *string
	}

	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.ID, &a.Title, &a.AgentID); err == nil {
			alerts = append(alerts, a)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	rows.Close()

	if len(alerts) == 0 {
		return
	}

	// Check if enrichment_data column exists before attempting updates.
	var dataColExists bool
	_ = p.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='alerts' AND column_name='enrichment_data'
		)`).Scan(&dataColExists)

	// 3. Enrich each alert.
	enriched := 0
	for _, a := range alerts {
		data := p.enrichAlert(ctx, a.ID, a.Title, a.AgentID)

		if !dataColExists {
			// Mark enrichment_status only (enrichment_data column doesn't exist yet)
			_, _ = p.pool.Exec(ctx,
				`UPDATE alerts SET enrichment_status='done' WHERE id=$1`,
				a.ID)
			enriched++
			continue
		}

		payload, err := json.Marshal(data)
		if err != nil {
			slog.Warn("アラートエンリッチメント: JSONシリアライズ失敗", "alert_id", a.ID, "error", err)
			continue
		}

		_, err = p.pool.Exec(ctx,
			`UPDATE alerts SET enrichment_data=$1, enrichment_status='done' WHERE id=$2`,
			payload, a.ID)
		if err != nil {
			slog.Warn("アラートエンリッチメント: UPDATE失敗", "alert_id", a.ID, "error", err)
			continue
		}
		enriched++
	}

	if enriched > 0 {
		slog.Info("アラートエンリッチメント完了", "count", enriched)
	}
}

func (p *AlertEnrichmentPipeline) enrichAlert(
	ctx context.Context,
	_ string, // alertID (reserved for future use)
	title string,
	agentID *string,
) enrichmentData {
	data := enrichmentData{
		EnrichedAt: time.Now().UTC(),
	}

	// Lookup agent IP and perform reverse DNS + GeoIP enrichment.
	if agentID != nil && *agentID != "" {
		var ipStr *string
		err := p.pool.QueryRow(ctx,
			`SELECT ip_addresses[1] FROM agents WHERE id=$1`,
			*agentID).Scan(&ipStr)
		if err == nil && ipStr != nil && *ipStr != "" {
			ip := *ipStr
			if net.ParseIP(ip) != nil {
				// 逆引きDNS (2秒タイムアウト)
				dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				resolver := &net.Resolver{}
				names, err := resolver.LookupAddr(dnsCtx, ip)
				if err == nil && len(names) > 0 {
					data.ReverseDNS = strings.TrimSuffix(names[0], ".")
				}

				// GeoIP ルックアップ (プライベートIPはスキップ)
				data.GeoIP = lookupGeoIP(ctx, ip)
			}
		}
	}

	// Check title against IOC keywords and build tags.
	titleLower := strings.ToLower(title)
	var tags []string
	for _, kw := range iocKeywords {
		if strings.Contains(titleLower, kw) {
			tags = append(tags, kw)
		}
	}
	if len(tags) > 0 {
		data.Tags = tags
	}

	return data
}

// http.StatusOK は lookupGeoIP 内で使用済み。
