// Package virustotal provides a VirusTotal API v3 client for file hash lookups.
//
// 設定:
//
//	VIRUSTOTAL_API_KEY 環境変数に VirusTotal API キーを設定してください。
//	未設定の場合、サンドボックス機能は "pending" 状態を返します。
package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const baseURL = "https://www.virustotal.com/api/v3"

// Client is a VirusTotal API v3 client.
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// New creates a Client using the VIRUSTOTAL_API_KEY environment variable.
// Returns nil if the key is not set — callers should handle nil gracefully.
func New() *Client {
	key := os.Getenv("VIRUSTOTAL_API_KEY")
	if key == "" {
		return nil
	}
	return &Client{
		apiKey:     key,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// FileReport represents the analysis result for a file hash.
type FileReport struct {
	Hash              string             `json:"hash"`
	Verdict           string             `json:"verdict"`         // malicious | suspicious | undetected | unknown
	Score             int                `json:"score"`           // 0–100
	DetectionCount    int                `json:"detection_count"` // 検出したエンジン数
	TotalEngines      int                `json:"total_engines"`   // スキャンしたエンジン数
	Signatures        []string           `json:"signatures"`      // 検出名のリスト
	NetworkIndicators []NetworkIndicator `json:"network_indicators"`
	Behaviors         []Behavior         `json:"behaviors"`
	FirstSeen         *time.Time         `json:"first_seen,omitempty"`
	LastAnalysis      *time.Time         `json:"last_analysis,omitempty"`
	MeaningfulName    string             `json:"meaningful_name,omitempty"`
	TypeDescription   string             `json:"type_description,omitempty"`
}

// NetworkIndicator is an IP/domain observed in sandbox behavior.
type NetworkIndicator struct {
	Type  string `json:"type"` // ip | domain | url
	Value string `json:"value"`
}

// Behavior is a sandbox behavioral observation.
type Behavior struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// vtFilesResponse is the raw JSON from /files/{hash}.
type vtFilesResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				EngineName string `json:"engine_name"`
			} `json:"last_analysis_results"`
			NetworkInfrastructure []struct {
				URL string `json:"url"`
				IP  string `json:"ip"`
			} `json:"network_infrastructure"`
			MeaningfulName   string   `json:"meaningful_name"`
			TypeDescription  string   `json:"type_description"`
			FirstSeenITW     int64    `json:"first_seen_itw_date"`
			LastAnalysisDate int64    `json:"last_analysis_date"`
			Names            []string `json:"names"`
		} `json:"attributes"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// LookupHash queries VirusTotal for a file hash (MD5, SHA1, or SHA256).
func (c *Client) LookupHash(ctx context.Context, hash string) (*FileReport, error) {
	if c == nil {
		return nil, fmt.Errorf("VirusTotal APIキーが設定されていません (VIRUSTOTAL_API_KEY)")
	}

	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return nil, fmt.Errorf("ハッシュが空です")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/files/%s", baseURL, hash), nil)
	if err != nil {
		return nil, fmt.Errorf("リクエスト作成失敗: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal API リクエスト失敗: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	if resp.StatusCode == http.StatusNotFound {
		return &FileReport{
			Hash:    hash,
			Verdict: "unknown",
			Score:   0,
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		slog.Warn("virustotal: API returned non-200", "status", resp.StatusCode, "hash", hash)
		return nil, fmt.Errorf("VirusTotal API エラー: HTTP %d", resp.StatusCode)
	}

	var raw vtFilesResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("レスポンスの解析失敗: %w", err)
	}
	if raw.Error != nil {
		return nil, fmt.Errorf("VirusTotal エラー: %s — %s", raw.Error.Code, raw.Error.Message)
	}

	attrs := raw.Data.Attributes
	stats := attrs.LastAnalysisStats
	totalEngines := stats.Malicious + stats.Suspicious + stats.Undetected +
		stats.Harmless + stats.Timeout
	detections := stats.Malicious + stats.Suspicious

	// 判定
	verdict := "undetected"
	if stats.Malicious > 0 {
		verdict = "malicious"
	} else if stats.Suspicious > 0 {
		verdict = "suspicious"
	}

	// スコアを0–100に正規化
	score := 0
	if totalEngines > 0 {
		score = int(float64(detections) / float64(totalEngines) * 100)
	}

	// 検出名を収集
	var signatures []string
	seen := make(map[string]bool)
	for _, result := range attrs.LastAnalysisResults {
		if result.Category == "malicious" || result.Category == "suspicious" {
			if result.Result != "" && !seen[result.Result] {
				signatures = append(signatures, result.Result)
				seen[result.Result] = true
			}
		}
	}
	if len(signatures) > 10 {
		signatures = signatures[:10]
	}

	// ネットワーク指標
	var netIndicators []NetworkIndicator
	for _, ni := range attrs.NetworkInfrastructure {
		if ni.IP != "" {
			netIndicators = append(netIndicators, NetworkIndicator{Type: "ip", Value: ni.IP})
		}
		if ni.URL != "" {
			netIndicators = append(netIndicators, NetworkIndicator{Type: "url", Value: ni.URL})
		}
	}
	if len(netIndicators) > 20 {
		netIndicators = netIndicators[:20]
	}

	// タイムスタンプ
	var firstSeen, lastAnalysis *time.Time
	if attrs.FirstSeenITW > 0 {
		t := time.Unix(attrs.FirstSeenITW, 0)
		firstSeen = &t
	}
	if attrs.LastAnalysisDate > 0 {
		t := time.Unix(attrs.LastAnalysisDate, 0)
		lastAnalysis = &t
	}

	return &FileReport{
		Hash:              hash,
		Verdict:           verdict,
		Score:             score,
		DetectionCount:    detections,
		TotalEngines:      totalEngines,
		Signatures:        signatures,
		NetworkIndicators: netIndicators,
		FirstSeen:         firstSeen,
		LastAnalysis:      lastAnalysis,
		MeaningfulName:    attrs.MeaningfulName,
		TypeDescription:   attrs.TypeDescription,
	}, nil
}
