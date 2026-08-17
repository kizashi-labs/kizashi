package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
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
			tick.Run(ctx, "alert_enrichment", p.enrich)
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

// alerts.enrichment is one JSONB column with three writers, and until this
// change they did not agree on what it holds:
//
//	internal/enrichment (VirusTotal)   selected `enrichment IS NULL` and
//	                                   REPLACED the whole object
//	AlertActionHandler.Enrich          jsonb_set(..., '{status}', '"pending"')
//	this pipeline                      enrichment_status / enrichment_data,
//	                                   neither of which any migration creates
//
// The third never ran: enrich() returned at a column-existence check on every
// tick since it was written. The second made things worse — writing
// {"status":"pending"} makes enrichment non-NULL, which permanently excludes
// the alert from the VirusTotal enricher's `enrichment IS NULL`. Verified end
// to end: pressing enrich answered 202, left {"status": "pending"}, and the
// pipeline then left the row untouched.
//
// The shape is now: a top-level "status", and one namespaced section per
// producer, merged rather than replaced so two enrichers cannot erase each
// other.
const (
	// enrichmentStatusPending is what AlertActionHandler.Enrich writes when an
	// operator asks for an alert to be enriched.
	enrichmentStatusPending = "pending"
	// enrichmentStatusDone marks an alert this pipeline has processed.
	enrichmentStatusDone = "done"
	// enrichmentContextKey is this pipeline's section of the column.
	enrichmentContextKey = "context"
)

// enrichmentData is the JSON structure stored under alerts.enrichment->'context'.
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
// ip-api.com: free for non-commercial use, 45 req/min limit.
// For commercial use, set GEOIP_API_KEY for the paid API endpoint.
//
// (nil, nil) は「この IP に位置情報は無い」、(nil, err) は「引けなかった」
// です。以前はどちらも nil でした。呼び出し側はアラートに status=done を
// 書くので、外部APIが5秒詰まっただけのアラートは、以後ずっと「位置情報の
// 無いアラート」として残ります。次の周回で取り直す機会がありません。
func lookupGeoIP(ctx context.Context, ipStr string) (*geoIPInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil // IPとして読めない = 引く対象が無い
	}
	// プライベート・ループバックIPはスキップ
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil, nil // 位置情報を持たないアドレス
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := "http://ip-api.com/json/" + ipStr + "?fields=status,country,countryCode,regionName,city,isp,org,lat,lon,timezone,proxy,hosting,query"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := geoIPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("geoip: %s を引けませんでした: %w", ipStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geoip: %s の応答が HTTP %d でした", ipStr, resp.StatusCode)
	}

	var raw ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("geoip: %s の応答を解釈できませんでした: %w", ipStr, err)
	}
	if raw.Status != "success" {
		// API が「この IP は引けない」と答えた場合。失敗ではありません。
		return nil, nil
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
	}, nil
}

func (p *AlertEnrichmentPipeline) enrich(ctx context.Context) {
	// 1. Check if alerts table exists.
	var tableExists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='alerts')`).
		Scan(&tableExists)
	if err != nil {
		// 「テーブルが無い」と「確認できなかった」を分けます。前者はこの
		// 配備でエンリッチメントを使っていないだけ、後者は障害です。
		// **`tick.Run` で回している仕事です。** ログだけだと、この回は
		// 成功として刻まれます。
		tick.Fail(ctx, err, "アラートエンリッチメント: alerts テーブルの有無を確認できませんでした")
		return
	}
	if !tableExists {
		return
	}

	// 2. Query alerts this pipeline has not finished with: never touched, or
	// flagged pending by an operator pressing enrich.
	rows, err := p.pool.Query(ctx,
		`SELECT id, title, agent_id
		 FROM alerts
		 WHERE enrichment IS NULL
		    OR COALESCE(enrichment->>'status','') = $1
		 ORDER BY created_at DESC
		 LIMIT 20`, enrichmentStatusPending)
	if err != nil {
		tick.Fail(ctx, err, "アラートエンリッチメント: クエリ失敗")
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
		tick.Fail(ctx, err, "アラートエンリッチメント: クエリ失敗")
		return
	}
	rows.Close()

	if len(alerts) == 0 {
		return
	}

	// 3. Enrich each alert.
	enriched := 0
	for _, a := range alerts {
		data, complete := p.enrichAlert(ctx, a.ID, a.Title, a.AgentID)

		status := enrichmentStatusDone
		if !complete {
			status = enrichmentStatusPending
		}
		payload, err := json.Marshal(map[string]interface{}{
			enrichmentContextKey: data,
			"status":             status,
		})
		if err != nil {
			tick.FailComponent(ctx, "alert_enrichment", err, "アラートエンリッチメント: JSONシリアライズ失敗", "alert_id", a.ID)
			continue
		}

		// Merge, never replace: the VirusTotal enricher writes its own section of
		// this column and must not be erased by a pipeline pass.
		_, err = p.pool.Exec(ctx,
			`UPDATE alerts SET enrichment = COALESCE(enrichment, '{}'::jsonb) || $1::jsonb
			 WHERE id=$2`,
			payload, a.ID)
		if err != nil {
			tick.FailComponent(ctx, "alert_enrichment", err, "アラートエンリッチメント: UPDATE失敗", "alert_id", a.ID)
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
) (enrichmentData, bool) {
	data := enrichmentData{
		EnrichedAt: time.Now().UTC(),
	}
	// complete が false のときは、この周回で埋められなかった項目があります。
	// done を書くと二度と取り直されないので、pending のまま残します。
	complete := true

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
				geo, geoErr := lookupGeoIP(ctx, ip)
				if geoErr != nil {
					slog.Warn("アラートエンリッチメント: 位置情報を引けませんでした。次の周回で取り直します",
						"ip", ip, "error", geoErr)
					complete = false
				}
				data.GeoIP = geo
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

	return data, complete
}

// http.StatusOK は lookupGeoIP 内で使用済み。
