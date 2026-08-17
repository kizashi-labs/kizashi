package threatintel

// PublicFeedFetcher fetches IOCs from free public threat intel sources.

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/tick"
)

// fetchFeedBody fetches a feed and refuses to call a failure an empty feed.
//
// 3つのフィードが同じ形を書いていて、どれも失敗したときに []IOC{}, nil を
// 返していました。取り込み側は0件を正常として記録するので、フィードが
// 落ちていることは誰にも伝わりません。ここに集めて、失敗は失敗として返します。
func fetchFeedBody(ctx context.Context, url, feed string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: リクエストを作れませんでした: %w", feed, err)
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatIntel")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: 取得できませんでした: %w", feed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", feed, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: 応答を読めませんでした: %w", feed, err)
	}
	return b, nil
}

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
		return nil, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("public_feeds: abuseipdb fetch failed (no connectivity?)", "error", err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// 「このフィードには指標がありませんでした」と返していました。
		// 取り込み側は件数0を正常として記録するので、フィードが何日
		// 落ちていても気づけません。
		slog.Warn("public_feeds: abuseipdb returned non-200", "status", resp.StatusCode)
		return nil, fmt.Errorf("abuseipdb: HTTP %d", resp.StatusCode)
	}

	// Response is JSON: {"data": [{"ipAddress": "...", "abuseConfidenceScore": 100, ...}]}
	// We do a simple line scan to avoid importing encoding/json here (already in package).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: 応答を読めませんでした: %w", err)
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
		return nil, err
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatIntel")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: 取得できませんでした: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus: HTTP %d", resp.StatusCode)
	}

	// URLhaus CSV format: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
	r := csv.NewReader(io.LimitReader(resp.Body, 5<<20))
	r.Comment = '#'
	r.LazyQuotes = true

	var iocs []IOC
	count, skipped := 0, 0
	for {
		if count >= 1000 {
			break
		}
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 読めない行を黙って飛ばすと、書式が変わって全行落ちても
			// 「0件のフィード」と同じ形になります。取り込み側は0件を
			// 正常として記録します。
			skipped++
			continue
		}
		if len(record) < 3 {
			skipped++
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
	if skipped > 0 {
		slog.Warn("public_feeds: 読めない行を飛ばしました", "source", "urlhaus", "skipped", skipped)
		// **`tick.Run` で回している取り込みから呼ばれます。** 部品の件数
		// だけ数えると、飛ばした行があってもその回は成功として刻まれます。
		tick.FailComponent(ctx, "urlhaus_csv", fmt.Errorf("読めない行が %d 行ありました", skipped),
			"読めない行がありました", "skipped", skipped)
	}
	return iocs, nil
}

// FetchEmergingThreats fetches the Emerging Threats compromised IPs blocklist.
// Source: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
func FetchEmergingThreats(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://rules.emergingthreats.net/blockrules/compromised-ips.txt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatIntel")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emerging-threats: 取得できませんでした: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emerging-threats: HTTP %d", resp.StatusCode)
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
	tick.Run(ctx, "public_feeds_sync", func(ctx context.Context) { syncPublicFeeds(ctx, manager) })

	for {
		select {
		case <-ctx.Done():
			slog.Info("public_feeds: scheduled sync stopping")
			return
		case <-ticker.C:
			tick.Run(ctx, "public_feeds_sync", func(ctx context.Context) { syncPublicFeeds(ctx, manager) })
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
			// **その回は「取り込めなかったフィードがある」で終わりです。**
			tick.FailComponent(ctx, "public_feeds", err, "public_feeds: fetcher error (skipped)", "source", f.name)
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
