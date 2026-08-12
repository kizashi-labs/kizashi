package shipper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ElasticsearchShipper forwards events/alerts to an Elasticsearch cluster.
// Production implementation: use github.com/elastic/go-elasticsearch/v8
type ElasticsearchShipper struct {
	url      string
	username string
	password string
	index    string
	client   *http.Client
	enabled  bool
	buffer   []map[string]interface{}
	maxBuf   int
}

func NewElasticsearchShipper(url, username, password, index string) *ElasticsearchShipper {
	enabled := url != ""
	if index == "" {
		index = "edr-events"
	}
	return &ElasticsearchShipper{
		url:      strings.TrimRight(url, "/"),
		username: username,
		password: password,
		index:    index,
		client:   &http.Client{Timeout: 10 * time.Second},
		enabled:  enabled,
		buffer:   make([]map[string]interface{}, 0, 100),
		maxBuf:   100,
	}
}

// Ship adds a document to the buffer. Flushes when buffer is full.
func (s *ElasticsearchShipper) Ship(ctx context.Context, docType string, doc map[string]interface{}) {
	if !s.enabled {
		return
	}
	doc["@timestamp"] = time.Now().Format(time.RFC3339)
	doc["doc_type"] = docType
	s.buffer = append(s.buffer, doc)
	if len(s.buffer) >= s.maxBuf {
		s.Flush(ctx)
	}
}

// Flush sends buffered documents via the Bulk API.
func (s *ElasticsearchShipper) Flush(ctx context.Context) {
	if !s.enabled || len(s.buffer) == 0 {
		return
	}
	docs := s.buffer
	s.buffer = make([]map[string]interface{}, 0, s.maxBuf)

	var body bytes.Buffer
	for _, doc := range docs {
		meta := map[string]interface{}{"index": map[string]interface{}{"_index": s.index}}
		metaLine, _ := json.Marshal(meta)
		docLine, _ := json.Marshal(doc)
		body.Write(metaLine)
		body.WriteByte('\n')
		body.Write(docLine)
		body.WriteByte('\n')
	}

	url := s.url + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		slog.Error("ES bulk リクエスト作成失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Error("ES bulk 送信失敗", "error", err, "docs", len(docs))
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		slog.Error("ES bulk エラーレスポンス", "status", resp.StatusCode, "body", string(respBody[:minInt(200, len(respBody))]))
	} else {
		slog.Info("ES bulk 送信完了", "docs", len(docs), "status", resp.StatusCode)
	}
}

// Run starts a periodic flush loop.
func (s *ElasticsearchShipper) Run(ctx context.Context) {
	if !s.enabled {
		slog.Info("Elasticsearchシッパー無効 (ES_URL未設定)")
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	slog.Info("Elasticsearchシッパー起動", "url", s.url, "index", s.index)
	for {
		select {
		case <-ctx.Done():
			s.Flush(context.Background())
			return
		case <-ticker.C:
			s.Flush(ctx)
		}
	}
}

// Test checks connectivity to the Elasticsearch cluster.
func (s *ElasticsearchShipper) Test(ctx context.Context) (string, error) {
	if !s.enabled {
		return "", fmt.Errorf("ES_URL未設定")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_cluster/health", nil)
	if err != nil {
		return "", err
	}
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("ES返答エラー: %d", resp.StatusCode)
	}
	var health map[string]interface{}
	_ = json.Unmarshal(body, &health)
	status, _ := health["status"].(string)
	return status, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
