// Package geoip provides IP geolocation via ip-api.com.
package geoip

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Location holds geo-location data for a single IP.
type Location struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	IsThreat    bool    `json:"is_threat"`
}

// ThreatMapEntry aggregates connection data per country.
type ThreatMapEntry struct {
	CountryCode     string  `json:"country_code"`
	Country         string  `json:"country"`
	Lat             float64 `json:"lat"`
	Lon             float64 `json:"lon"`
	ConnectionCount int     `json:"connection_count"`
	ThreatCount     int     `json:"threat_count"`
}

// ThreatEntry is a single threat IP with geo data.
type ThreatEntry struct {
	IP       string   `json:"ip"`
	Location Location `json:"location"`
	Count    int      `json:"count"`
}

var geoHTTPClient = &http.Client{Timeout: 5 * time.Second}

// ipAPIResponse mirrors the ip-api.com JSON response.
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Proxy       bool    `json:"proxy"`
	Query       string  `json:"query"`
}

// Locator performs IP-to-location lookups via ip-api.com.
type Locator struct{}

// NewLocator creates a new Locator.
func NewLocator() *Locator { return &Locator{} }

// Lookup returns geo-location for the given IP string.
// Uses ip-api.com (free tier: 45 req/min). Private/loopback IPs return "Internal".
func (l *Locator) Lookup(ip string) *Location {
	return l.LookupCtx(context.Background(), ip)
}

// LookupCtx is context-aware version of Lookup.
func (l *Locator) LookupCtx(ctx context.Context, ip string) *Location {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return &Location{IP: ip, Country: "Unknown", CountryCode: "XX"}
	}

	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return &Location{
			IP: ip, Country: "Internal", CountryCode: "INT",
			City: "Private Network", ISP: "Internal",
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,regionName,city,isp,lat,lon,proxy,query"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return &Location{IP: ip, Country: "Unknown", CountryCode: "XX"}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := geoHTTPClient.Do(req)
	if err != nil {
		slog.Debug("geoip: lookup failed", "ip", ip, "error", err)
		return &Location{IP: ip, Country: "Unknown", CountryCode: "XX"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &Location{IP: ip, Country: "Unknown", CountryCode: "XX"}
	}

	var raw ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil || raw.Status != "success" {
		return &Location{IP: ip, Country: "Unknown", CountryCode: "XX"}
	}

	return &Location{
		IP:          raw.Query,
		Country:     raw.Country,
		CountryCode: raw.CountryCode,
		City:        raw.City,
		Latitude:    raw.Lat,
		Longitude:   raw.Lon,
		ISP:         raw.ISP,
		IsThreat:    raw.Proxy,
	}
}

// GetThreatMapData queries network events and returns aggregated country data.
func (l *Locator) GetThreatMapData(ctx context.Context, pool *pgxpool.Pool, hours int) ([]ThreatMapEntry, error) {
	// events の時刻列は `time` (migration 002 の hypertable パーティションキー)。
	// `created_at` は存在せず、このクエリは毎回
	// `column "created_at" does not exist` で失敗していた。エラーは下で
	// 空スライスに変換されるため、脅威マップは常に「データ無し」に見えていた。
	rows, err := pool.Query(ctx,
		`SELECT raw_data->>'dst_ip' as dst_ip, COUNT(*) as cnt
		 FROM events
		 WHERE time > NOW() - ($1 || ' hours')::INTERVAL
		   AND raw_data->>'dst_ip' IS NOT NULL
		 GROUP BY dst_ip
		 LIMIT 500`,
		strconv.Itoa(hours),
	)
	if err != nil {
		slog.Warn("geoip: threat map query failed", "err", err)
		return []ThreatMapEntry{}, nil
	}
	defer rows.Close()

	type agg struct {
		entry ThreatMapEntry
	}
	byCountry := make(map[string]*agg)

	for rows.Next() {
		var dstIP string
		var cnt int
		if err := rows.Scan(&dstIP, &cnt); err != nil {
			continue
		}
		loc := l.LookupCtx(ctx, dstIP)
		if loc.CountryCode == "INT" || loc.CountryCode == "XX" {
			continue
		}
		a, ok := byCountry[loc.CountryCode]
		if !ok {
			a = &agg{entry: ThreatMapEntry{
				CountryCode: loc.CountryCode,
				Country:     loc.Country,
				Lat:         loc.Latitude,
				Lon:         loc.Longitude,
			}}
			byCountry[loc.CountryCode] = a
		}
		a.entry.ConnectionCount += cnt
		if loc.IsThreat {
			a.entry.ThreatCount += cnt
		}
	}

	result := make([]ThreatMapEntry, 0, len(byCountry))
	for _, a := range byCountry {
		result = append(result, a.entry)
	}
	return result, nil
}

// GetTopThreats returns the top 10 threat source IPs with location data.
func (l *Locator) GetTopThreats(ctx context.Context, pool *pgxpool.Pool) ([]ThreatEntry, error) {
	rows, err := pool.Query(ctx,
		// GetThreatMapData と同じく、events の時刻列は `time`。
		`SELECT raw_data->>'src_ip' as src_ip, COUNT(*) as cnt
		 FROM events
		 WHERE time > NOW() - INTERVAL '24 hours'
		   AND raw_data->>'src_ip' IS NOT NULL
		 GROUP BY src_ip
		 ORDER BY cnt DESC
		 LIMIT 10`,
	)
	if err != nil {
		slog.Warn("geoip: top threats query failed", "err", err)
		return []ThreatEntry{}, nil
	}
	defer rows.Close()

	var entries []ThreatEntry
	for rows.Next() {
		var srcIP string
		var cnt int
		if err := rows.Scan(&srcIP, &cnt); err != nil {
			continue
		}
		if !isPublicish(srcIP) {
			continue
		}
		loc := l.LookupCtx(ctx, srcIP)
		entries = append(entries, ThreatEntry{IP: srcIP, Location: *loc, Count: cnt})
	}
	if entries == nil {
		return []ThreatEntry{}, nil
	}
	return entries, nil
}

// isPrivate returns true if the IPv4 address is in a private range.
func isPrivate(v4 net.IP) bool {
	if v4[0] == 10 {
		return true
	}
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return true
	}
	if v4[0] == 192 && v4[1] == 168 {
		return true
	}
	if v4[0] == 127 {
		return true
	}
	return false
}

func isPublicish(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return true
	}
	return !isPrivate(v4)
}

// lookupFromRawData extracts dst_ip from a JSONB raw_data column value.
func lookupFromRawData(rawData []byte) string {
	var m map[string]interface{}
	if err := json.Unmarshal(rawData, &m); err != nil {
		return ""
	}
	if v, ok := m["dst_ip"].(string); ok {
		return v
	}
	return ""
}

// splitFirst returns the first octet of a dotted-decimal IP string.
func splitFirst(ip string) int {
	parts := strings.SplitN(ip, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(parts[0])
	return n
}

// ensure these are used to avoid compiler errors
var _ = lookupFromRawData
var _ = splitFirst
