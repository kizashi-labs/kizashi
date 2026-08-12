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

// ServiceNowClient は ServiceNow Table API クライアントです
type ServiceNowClient struct {
	instanceURL string // https://instance.service-now.com
	username    string
	password    string
	table       string // デフォルト: "incident"
	client      *http.Client
}

// snUrgency はServiceNowの urgency 値を返します
// 1=Critical, 2=High, 3=Medium/Low
func snUrgency(priority string) string {
	switch priority {
	case "critical":
		return "1"
	case "high":
		return "2"
	default:
		return "3"
	}
}

// basicAuth はBasic認証ヘッダー値を生成します
func (s *ServiceNowClient) basicAuth() string {
	creds := s.username + ":" + s.password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// doRequest はHTTPリクエストを実行してレスポンスボディを返します
func (s *ServiceNowClient) doRequest(ctx context.Context, method, path string, body interface{}, queryParams map[string]string) ([]byte, int, error) {
	url := strings.TrimRight(s.instanceURL, "/") + path
	if len(queryParams) > 0 {
		params := make([]string, 0, len(queryParams))
		for k, v := range queryParams {
			params = append(params, k+"="+v)
		}
		url += "?" + strings.Join(params, "&")
	}

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
	req.Header.Set("Authorization", s.basicAuth())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
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

// CreateTicket は ServiceNow Incident を作成します
// POST /api/now/table/{table}
func (s *ServiceNowClient) CreateTicket(ctx context.Context, req TicketRequest) (*TicketResponse, error) {
	table := s.table
	if table == "" {
		table = "incident"
	}

	payload := map[string]interface{}{
		"short_description": req.Title,
		"description":       req.Description,
		"urgency":           snUrgency(req.Priority),
		"category":          "security",
		"u_edr_incident_id": req.IncidentID,
	}

	path := "/api/now/table/" + table
	respBody, statusCode, err := s.doRequest(ctx, http.MethodPost, path, payload, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return nil, fmt.Errorf("ServiceNow APIエラー (status %d): %s", statusCode, string(respBody))
	}

	var result struct {
		Result struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("ServiceNowレスポンスのパースに失敗: %w", err)
	}

	// レコードURLを組み立てる
	ticketURL := strings.TrimRight(s.instanceURL, "/") +
		"/nav_to.do?uri=" + table + ".do?sys_id=" + result.Result.SysID

	ticketID := result.Result.Number
	if ticketID == "" {
		ticketID = result.Result.SysID
	}

	return &TicketResponse{
		TicketID:  ticketID,
		TicketURL: ticketURL,
		System:    "servicenow",
	}, nil
}

// TestConnection は GET /api/now/table/incident?sysparm_limit=1 で疎通確認します
func (s *ServiceNowClient) TestConnection(ctx context.Context) error {
	table := s.table
	if table == "" {
		table = "incident"
	}
	path := "/api/now/table/" + table
	_, statusCode, err := s.doRequest(ctx, http.MethodGet, path, nil, map[string]string{
		"sysparm_limit": "1",
	})
	if err != nil {
		return fmt.Errorf("ServiceNow接続テスト失敗: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("ServiceNow接続テスト失敗 (status %d): 認証情報を確認してください", statusCode)
	}
	return nil
}
