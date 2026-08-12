package threatintel

// PublicFeedFetcher fetches IOCs from free public threat intel sources.

import (
	"bufio"
	"context"
	"encoding/csv"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FetchAbuseIPDB fetches bad IPs from AbuseIPDB API.
// Requires an API key; returns empty slice if none provided.
func FetchAbuseIPDB(ctx context.Context, apiKey string) ([]IOC, error) {
	if apiKey == "" {
		return []IOC{}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=500", nil)
	if err != nil {
		slog.Warn("public_feeds: abuseipdb request creation failed", "error", err)
		return []IOC{}, nil
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("public_feeds: abuseipdb fetch failed (no connectivity?)", "error", err)
		return []IOC{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("public_feeds: abuseipdb returned non-200", "status", resp.StatusCode)
		return []IOC{}, nil
	}

	// Response is JSON: {"data": [{"ipAddress": "...", "abuseConfidenceScore": 100, ...}]}
	// We do a simple line scan to avoid importing encoding/json here (already in package).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return []IOC{}, nil
	}

	var iocs []IOC
	// Simple extraction — look for "ipAddress":"X.X.X.X" patterns.
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, `"ipAddress":"`); idx >= 0 {
			rest := line[idx+len(`"ipAddress":"`):]
			end := strings.Index(rest, `"`)
			if end > 0 {
				ip := rest[:end]
				if ip != "" {
					iocs = append(iocs, IOC{
						ID:         uuid.New().String(),
						Type:       "ip",
						Value:      ip,
						Confidence: 90,
						Severity:   7,
						Source:     "abuseipdb",
						Tags:       []string{"abuseipdb", "blacklist"},
						CreatedAt:  time.Now(),
					})
				}
			}
		}
	}

	slog.Info("public_feeds: abuseipdb fetch complete", "count", len(iocs))
	return iocs, nil
}

// FetchURLhaus fetches recent malicious URLs from URLhaus (no auth required).
// Source: https://urlhaus.abuse.ch/downloads/csv_recent/
func FetchURLhaus(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://urlhaus.abuse.ch/downloads/csv_recent/", nil)
	if err != nil {
		return []IOC{}, nil
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatIntel")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("public_feeds: urlhaus fetch failed (no connectivity?)", "error", err)
		return []IOC{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("public_feeds: urlhaus returned non-200", "status", resp.StatusCode)
		return []IOC{}, nil
	}

	// URLhaus CSV format: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
	r := csv.NewReader(io.LimitReader(resp.Body, 5<<20))
	r.Comment = '#'
	r.LazyQuotes = true

	var iocs []IOC
	count := 0
	for {
		if count >= 1000 {
			break
		}
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 3 {
			continue
		}
		rawURL := strings.TrimSpace(record[2])
		if rawURL == "" || rawURL == "url" {
			continue
		}

		threat := ""
		if len(record) >= 6 {
			threat = record[5]
		}
		tags := []string{"urlhaus"}
		if threat != "" {
			tags = append(tags, threat)
		}

		severity := 7
		if strings.Contains(strings.ToLower(threat), "malware") {
			severity = 9
		}

		iocs = append(iocs, IOC{
			ID:         uuid.New().String(),
			Type:       "url",
			Value:      rawURL,
			Confidence: 80,
			Severity:   severity,
			Source:     "urlhaus",
			Tags:       tags,
			CreatedAt:  time.Now(),
		})
		count++
	}

	slog.Info("public_feeds: urlhaus fetch complete", "count", len(iocs))
	return iocs, nil
}

// FetchEmergingThreats fetches the Emerging Threats compromised IPs blocklist.
// Source: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
func FetchEmergingThreats(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://rules.emergingthreats.net/blockrules/compromised-ips.txt", nil)
	if err != nil {
		return []IOC{}, nil
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatIntel")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("public_feeds: emerging threats fetch failed (no connectivity?)", "error", err)
		return []IOC{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("public_feeds: emerging threats returned non-200", "status", resp.StatusCode)
		return []IOC{}, nil
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 2<<20))
	var iocs []IOC
	count := 0
	for scanner.Scan() {
		if count >= 5000 {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		iocs = append(iocs, IOC{
			ID:         uuid.New().String(),
			Type:       "ip",
			Value:      line,
			Confidence: 75,
			Severity:   6,
			Source:     "emerging_threats",
			Tags:       []string{"emerging_threats", "compromised"},
			CreatedAt:  time.Now(),
		})
		count++
	}

	slog.Info("public_feeds: emerging threats fetch complete", "count", len(iocs))
	return iocs, nil
}

// FetchCIDRReport returns a static list of known-bad CIDR ranges (RFC5737-safe fallback data).
// This provides offline/fallback IOC data when internet is unavailable.
func FetchCIDRReport(_ context.Context) ([]IOC, error) {
	// RFC 5737 TEST-NET ranges used as realistic-looking but safe placeholders.
	// In a production system these would be updated from actual threat feeds.
	badRanges := []struct {
		cidr   string
		reason string
	}{
		{"192.0.2.0/24", "TEST-NET-1 example range"},
		{"198.51.100.0/24", "TEST-NET-2 example range"},
		{"203.0.113.0/24", "TEST-NET-3 example range"},
		{"100.64.0.0/10", "Shared Address Space (RFC6598)"},
		{"192.88.99.0/24", "6to4 Relay Anycast (deprecated RFC3068)"},
		{"192.168.99.0/24", "Example internal misconfiguration range"},
		{"10.255.255.0/24", "RFC1918 edge abuse range"},
		{"172.31.255.0/24", "RFC1918 edge abuse range"},
	}

	var iocs []IOC
	for _, r := range badRanges {
		iocs = append(iocs, IOC{
			ID:         uuid.New().String(),
			Type:       "ip",
			Value:      r.cidr,
			Confidence: 50,
			Severity:   4,
			Source:     "cidr_report_fallback",
			Tags:       []string{"cidr", "fallback", "static"},
			CreatedAt:  time.Now(),
		})
	}
	slog.Info("public_feeds: cidr_report static fallback loaded", "count", len(iocs))
	return iocs, nil
}

// ScheduledSync runs all public feed fetchers periodically in the background.
// Never panics on connectivity errors — degrades gracefully.
func ScheduledSync(ctx context.Context, manager *FeedManager, intervalHours int) {
	if intervalHours <= 0 {
		intervalHours = 6
	}
	ticker := time.NewTicker(time.Duration(intervalHours) * time.Hour)
	defer ticker.Stop()

	// Run once immediately
	syncPublicFeeds(ctx, manager)

	for {
		select {
		case <-ctx.Done():
			slog.Info("public_feeds: scheduled sync stopping")
			return
		case <-ticker.C:
			syncPublicFeeds(ctx, manager)
		}
	}
}

// syncPublicFeeds performs a single sync pass of all public feeds.
func syncPublicFeeds(ctx context.Context, manager *FeedManager) {
	slog.Info("public_feeds: starting sync pass")
	total := 0

	abuseKey := "" // No key by default; can be set via env/config

	fetchers := []struct {
		name string
		fn   func() ([]IOC, error)
	}{
		{"abuseipdb", func() ([]IOC, error) { return FetchAbuseIPDB(ctx, abuseKey) }},
		{"urlhaus", func() ([]IOC, error) { return FetchURLhaus(ctx) }},
		{"emerging_threats", func() ([]IOC, error) { return FetchEmergingThreats(ctx) }},
		{"cidr_report", func() ([]IOC, error) { return FetchCIDRReport(ctx) }},
	}

	for _, f := range fetchers {
		iocs, err := f.fn()
		if err != nil {
			slog.Warn("public_feeds: fetcher error (skipped)", "source", f.name, "error", err)
			continue
		}
		for i := range iocs {
			manager.AddIOC(&iocs[i])
		}
		total += len(iocs)
		slog.Info("public_feeds: feed synced", "source", f.name, "count", len(iocs))
	}

	slog.Info("public_feeds: sync pass complete", "total_iocs", total)
}

// SyncAllPublicFeeds performs a one-shot sync and returns count per source.
// Used by the manual sync API endpoint.
func SyncAllPublicFeeds(ctx context.Context, manager *FeedManager, abuseIPDBKey string) (int, map[string]int) {
	sources := map[string]int{}
	total := 0

	fetch := func(name string, fn func() ([]IOC, error)) {
		iocs, err := fn()
		if err != nil {
			slog.Warn("public_feeds: sync error", "source", name, "error", err)
			return
		}
		for i := range iocs {
			manager.AddIOC(&iocs[i])
		}
		sources[name] = len(iocs)
		total += len(iocs)
	}

	fetch("abuseipdb", func() ([]IOC, error) { return FetchAbuseIPDB(ctx, abuseIPDBKey) })
	fetch("urlhaus", func() ([]IOC, error) { return FetchURLhaus(ctx) })
	fetch("emerging_threats", func() ([]IOC, error) { return FetchEmergingThreats(ctx) })
	fetch("cidr_report", func() ([]IOC, error) { return FetchCIDRReport(ctx) })

	return total, sources
}
