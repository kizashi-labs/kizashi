package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VTResult is the normalized result from VirusTotal.
type VTResult struct {
	Found         bool                   `json:"found"`
	Malicious     int                    `json:"malicious"`
	Suspicious    int                    `json:"suspicious"`
	Undetected    int                    `json:"undetected"`
	TotalEngines  int                    `json:"total_engines"`
	Reputation    int                    `json:"reputation"` // VT reputation score (-100 to +100)
	Tags          []string               `json:"tags"`
	FirstSeen     *time.Time             `json:"first_seen,omitempty"`
	LastAnalysis  *time.Time             `json:"last_analysis,omitempty"`
	CommonName    string                 `json:"common_name,omitempty"` // most common detection name
	Type          string                 `json:"type"`                  // file|ip|domain|url
	RawAttributes map[string]interface{} `json:"raw_attributes,omitempty"`
}

// VirusTotalClient calls the VirusTotal API.
type VirusTotalClient struct {
	apiKey string
	client *http.Client
}

// NewVirusTotalClient creates a new VirusTotalClient.
func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// IsConfigured returns true if an API key is set.
func (c *VirusTotalClient) IsConfigured() bool {
	return c.apiKey != ""
}

// LookupHash queries VirusTotal for a file hash (MD5/SHA1/SHA256).
func (c *VirusTotalClient) LookupHash(ctx context.Context, hash string) (*VTResult, error) {
	return c.lookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", strings.ToLower(hash)), "file")
}

// LookupIP queries VirusTotal for an IP address.
func (c *VirusTotalClient) LookupIP(ctx context.Context, ip string) (*VTResult, error) {
	return c.lookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip), "ip")
}

// LookupDomain queries VirusTotal for a domain name.
func (c *VirusTotalClient) LookupDomain(ctx context.Context, domain string) (*VTResult, error) {
	return c.lookup(ctx, fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain), "domain")
}

func (c *VirusTotalClient) lookup(ctx context.Context, url, iocType string) (*VTResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return &VTResult{Found: false, Type: iocType}, nil
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("VirusTotal API rate limit exceeded")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("VirusTotal returned %d", resp.StatusCode)
	}

	var raw struct {
		Data struct {
			Attributes map[string]interface{} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("VT decode failed: %w", err)
	}

	return parseVTAttributes(raw.Data.Attributes, iocType), nil
}

func parseVTAttributes(attrs map[string]interface{}, iocType string) *VTResult {
	result := &VTResult{Found: true, Type: iocType, RawAttributes: attrs}

	// Parse last_analysis_stats (present for files, IPs, domains)
	if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
		result.Malicious = int(toFloat64(stats["malicious"]))
		result.Suspicious = int(toFloat64(stats["suspicious"]))
		result.Undetected = int(toFloat64(stats["undetected"]))
		result.TotalEngines = result.Malicious + result.Suspicious + result.Undetected +
			int(toFloat64(stats["harmless"])) + int(toFloat64(stats["failure"]))
	}

	// Reputation
	if rep, ok := attrs["reputation"]; ok {
		result.Reputation = int(toFloat64(rep))
	}

	// Tags
	if tags, ok := attrs["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				result.Tags = append(result.Tags, s)
			}
		}
	}

	// First seen (files)
	if fs, ok := attrs["first_submission_date"]; ok {
		if epoch, ok := fs.(float64); ok {
			t := time.Unix(int64(epoch), 0)
			result.FirstSeen = &t
		}
	}

	// Last analysis date
	if la, ok := attrs["last_analysis_date"]; ok {
		if epoch, ok := la.(float64); ok {
			t := time.Unix(int64(epoch), 0)
			result.LastAnalysis = &t
		}
	}

	// Most common detection name (files)
	if names, ok := attrs["popular_threat_name"].(string); ok && names != "" {
		result.CommonName = names
	} else if res, ok := attrs["last_analysis_results"].(map[string]interface{}); ok {
		counts := make(map[string]int)
		for _, v := range res {
			if engine, ok := v.(map[string]interface{}); ok {
				if name, ok := engine["result"].(string); ok && name != "" {
					counts[name]++
				}
			}
		}
		maxCount := 0
		for name, count := range counts {
			if count > maxCount {
				maxCount = count
				result.CommonName = name
			}
		}
	}

	return result
}

func toFloat64(v interface{}) float64 {
	if v == nil {
		return 0
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
