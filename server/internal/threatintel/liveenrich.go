// Package threatintel — liveenrich.go: on-demand multi-source IOC reputation.
//
// The IOC enrichment endpoint previously answered only from the local ioc_entries
// table (populated by scheduled feeds). This adds LIVE lookups against external
// reputation providers (VirusTotal, AlienVault OTX, AbuseIPDB) when the local DB
// is thin, aggregating a reputation verdict. It degrades gracefully: a provider
// with no API key is skipped, so an air-gapped deployment keeps working (local
// only). Each provider has a short timeout and they run concurrently.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// LiveResult is the aggregated reputation from all reachable providers.
type LiveResult struct {
	Found     bool     `json:"found"`
	Score     int      `json:"score"`   // 0-100 (max across providers)
	Verdict   string   `json:"verdict"` // malicious | suspicious | clean | unknown
	Malicious int      `json:"malicious_detections"`
	Sources   []string `json:"sources"`
	Tags      []string `json:"tags"`

	// Unreachable は「聞いたが答えなかった」提供元です。
	//
	// これが無いあいだ、外部の評判サービスが全部落ちていても Found=false /
	// Verdict="unknown" / Score=0 が返り、全部が答えて「何も知られていない」
	// と言った場合と同じ形でした。IP の評判が0だったのか、誰にも聞けなかった
	// のかを、受け取る側が区別できません。
	Unreachable []string `json:"unreachable,omitempty"`
}

// LiveEnricher queries external reputation providers. Zero value is not usable;
// use NewLiveEnricher.
type LiveEnricher struct {
	client                  *http.Client
	vtKey, otxKey, abuseKey string
	// Base URLs are overridable for tests; default to the real endpoints.
	vtBase, otxBase, abuseBase string
	timeout                    time.Duration
}

// NewLiveEnricher reads provider API keys from the environment. Providers without
// a key are skipped (Configured() reflects whether any provider is available).
func NewLiveEnricher() *LiveEnricher {
	return &LiveEnricher{
		client:    &http.Client{Timeout: 8 * time.Second},
		vtKey:     os.Getenv("VIRUSTOTAL_API_KEY"),
		otxKey:    os.Getenv("OTX_API_KEY"),
		abuseKey:  os.Getenv("ABUSEIPDB_API_KEY"),
		vtBase:    "https://www.virustotal.com",
		otxBase:   "https://otx.alienvault.com",
		abuseBase: "https://api.abuseipdb.com",
		timeout:   6 * time.Second,
	}
}

// Configured reports whether at least one external provider has an API key.
func (e *LiveEnricher) Configured() bool {
	return e.vtKey != "" || e.otxKey != "" || e.abuseKey != ""
}

// providerResult is one provider's contribution.
type providerResult struct {
	source    string
	score     int // 0-100
	malicious int
	tags      []string
	ok        bool
	// failed は「答えなかった」。ok=false かつ failed=false は
	// 「答えたが、この指標を知らなかった」です。
	failed bool
	err    error
}

// Enrich queries the applicable providers for value (of iocType: hash|ip|domain|url)
// concurrently and aggregates. Returns Found=false when no provider had data.
func (e *LiveEnricher) Enrich(ctx context.Context, value, iocType string) LiveResult {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var tasks []func(context.Context) providerResult
	switch strings.ToLower(iocType) {
	case "hash", "sha256", "md5", "sha1":
		if e.vtKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.vtFile(c, value) })
		}
		if e.otxKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.otx(c, "file", value) })
		}
	case "ip":
		if e.abuseKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.abuseIPDB(c, value) })
		}
		if e.otxKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.otx(c, "IPv4", value) })
		}
	case "domain":
		if e.otxKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.otx(c, "domain", value) })
		}
	case "url":
		if e.otxKey != "" {
			tasks = append(tasks, func(c context.Context) providerResult { return e.otx(c, "url", value) })
		}
	}

	results := make([]providerResult, len(tasks))
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		go func(i int, t func(context.Context) providerResult) {
			defer wg.Done()
			results[i] = t(ctx)
		}(i, t)
	}
	wg.Wait()

	agg := LiveResult{Verdict: "unknown", Sources: []string{}, Tags: []string{}}
	tagSet := map[string]struct{}{}
	for _, r := range results {
		if r.failed {
			slog.Warn("threatintel: 評判の問い合わせに失敗しました",
				"provider", r.source, "value", value, "error", r.err)
			agg.Unreachable = append(agg.Unreachable, r.source)
			continue
		}
		if !r.ok {
			continue
		}
		agg.Found = true
		agg.Sources = append(agg.Sources, r.source)
		if r.score > agg.Score {
			agg.Score = r.score
		}
		agg.Malicious += r.malicious
		for _, t := range r.tags {
			if t == "" {
				continue
			}
			if _, seen := tagSet[t]; !seen {
				tagSet[t] = struct{}{}
				agg.Tags = append(agg.Tags, t)
			}
		}
	}
	agg.Verdict = verdictForScore(agg.Score)
	return agg
}

func verdictForScore(score int) string {
	switch {
	case score >= 60:
		return "malicious"
	case score >= 25:
		return "suspicious"
	case score > 0:
		return "clean"
	default:
		return "unknown"
	}
}

// ─── Providers ───────────────────────────────────────────────

// vtFile queries VirusTotal v3 for a file hash and scores by malicious detections.
func (e *LiveEnricher) vtFile(ctx context.Context, hash string) providerResult {
	url := fmt.Sprintf("%s/api/v3/files/%s", e.vtBase, hash)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("x-apikey", e.vtKey)
	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Tags []string `json:"tags"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := e.getJSON(req, &body); err != nil {
		return providerResult{source: "VirusTotal", failed: true, err: err}
	}
	st := body.Data.Attributes.LastAnalysisStats
	total := st.Malicious + st.Suspicious + st.Harmless
	score := 0
	if total > 0 {
		score = (st.Malicious*100 + st.Suspicious*50) / total
	}
	return providerResult{source: "VirusTotal", score: score, malicious: st.Malicious, tags: body.Data.Attributes.Tags, ok: true}
}

// otx queries AlienVault OTX general indicator info; scores by pulse count.
func (e *LiveEnricher) otx(ctx context.Context, section, value string) providerResult {
	url := fmt.Sprintf("%s/api/v1/indicators/%s/%s/general", e.otxBase, section, value)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("X-OTX-API-KEY", e.otxKey)
	var body struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := e.getJSON(req, &body); err != nil {
		return providerResult{source: "AlienVault OTX", failed: true, err: err}
	}
	// Score by how many threat pulses reference the indicator (capped).
	score := body.PulseInfo.Count * 20
	if score > 100 {
		score = 100
	}
	var tags []string
	for _, p := range body.PulseInfo.Pulses {
		tags = append(tags, p.Tags...)
	}
	return providerResult{source: "AlienVault OTX", score: score, malicious: body.PulseInfo.Count, tags: tags, ok: true}
}

// abuseIPDB queries AbuseIPDB for an IP's abuse confidence.
func (e *LiveEnricher) abuseIPDB(ctx context.Context, ip string) providerResult {
	url := fmt.Sprintf("%s/api/v2/check?ipAddress=%s&maxAgeInDays=90", e.abuseBase, ip)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Key", e.abuseKey)
	req.Header.Set("Accept", "application/json")
	var body struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
		} `json:"data"`
	}
	if err := e.getJSON(req, &body); err != nil {
		return providerResult{source: "AbuseIPDB", failed: true, err: err}
	}
	var tags []string
	if body.Data.UsageType != "" {
		tags = append(tags, body.Data.UsageType)
	}
	return providerResult{source: "AbuseIPDB", score: body.Data.AbuseConfidenceScore, malicious: body.Data.TotalReports, tags: tags, ok: true}
}

// getJSON performs the request and decodes JSON on HTTP 200.
//
// 以前は bool を返していて、呼び出し側はそれを「この提供元は指標を
// 知らなかった」として集計から外していました。落ちている提供元と、
// 答えたうえで「知らない」と言った提供元が同じ扱いです。
func (e *LiveEnricher) getJSON(req *http.Request, out interface{}) error {
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
