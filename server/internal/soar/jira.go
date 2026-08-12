package soar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// JiraClient はJira REST API v3 クライアントです
type JiraClient struct {
	baseURL  string // https://your-domain.atlassian.net
	email    string
	apiToken string
	project  string // プロジェクトキー (例: "EDR")
	client   *http.Client
}

// jiraIssuePriority はJiraの優先度名を返します
func jiraIssuePriority(priority string) string {
	switch priority {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	default:
		return "Low"
	}
}

// basicAuth はBasic認証ヘッダー値を生成します
func (j *JiraClient) basicAuth() string {
	creds := j.email + ":" + j.apiToken
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// doRequest はHTTPリクエストを実行してレスポンスボディを返します
func (j *JiraClient) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	url := strings.TrimRight(j.baseURL, "/") + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("リクエストのシリアライズに失敗: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("リクエスト作成に失敗: %w", err)
	}
	req.Header.Set("Authorization", j.basicAuth())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTPリクエストに失敗: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("レスポンス読み取りに失敗: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

// CreateTicket は Jira Issue を作成します
// POST /rest/api/3/issue
func (j *JiraClient) CreateTicket(ctx context.Context, req TicketRequest) (*TicketResponse, error) {
	// Atlassian Document Format (ADF) で description を組み立てる
	adfContent := []map[string]interface{}{
		{
			"type": "paragraph",
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": req.Description,
				},
			},
		},
	}

	labels := req.Labels
	if labels == nil {
		labels = []string{"edr", "security"}
	}

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":   map[string]string{"key": j.project},
			"summary":   req.Title,
			"issuetype": map[string]string{"name": "Bug"},
			"priority":  map[string]string{"name": jiraIssuePriority(req.Priority)},
			"labels":    labels,
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": adfContent,
			},
		},
	}

	respBody, statusCode, err := j.doRequest(ctx, http.MethodPost, "/rest/api/3/issue", payload)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusCreated {
		return nil, fmt.Errorf("jira APIエラー (status %d): %s", statusCode, string(respBody))
	}

	var result struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("jiraレスポンスのパースに失敗: %w", err)
	}

	// チケットURLを組み立てる
	ticketURL := strings.TrimRight(j.baseURL, "/") + "/browse/" + result.Key

	return &TicketResponse{
		TicketID:  result.Key,
		TicketURL: ticketURL,
		System:    "jira",
	}, nil
}

// TestConnection は GET /rest/api/3/myself でAPI疎通確認します
func (j *JiraClient) TestConnection(ctx context.Context) error {
	_, statusCode, err := j.doRequest(ctx, http.MethodGet, "/rest/api/3/myself", nil)
	if err != nil {
		return fmt.Errorf("jira接続テスト失敗: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("jira接続テスト失敗 (status %d): 認証情報を確認してください", statusCode)
	}
	return nil
}
