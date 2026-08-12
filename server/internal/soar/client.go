package soar

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// TicketRequest はチケット作成リクエストの共通フォーマットです
type TicketRequest struct {
	Title       string
	Description string
	Priority    string // "critical", "high", "medium", "low"
	Labels      []string
	IncidentID  string
}

// TicketResponse はチケット作成結果です
type TicketResponse struct {
	TicketID  string
	TicketURL string
	System    string
}

// Client はSOARシステムへのチケット作成インターフェースです
type Client interface {
	CreateTicket(ctx context.Context, req TicketRequest) (*TicketResponse, error)
	TestConnection(ctx context.Context) error
}

// NewClient はSOARタイプに応じたクライアントを返します
func NewClient(systemType string, config map[string]interface{}) (Client, error) {
	httpClient := &http.Client{Timeout: 15 * time.Second}

	switch systemType {
	case "jira":
		baseURL, _ := config["url"].(string)
		email, _ := config["email"].(string)
		apiToken, _ := config["api_token"].(string)
		project, _ := config["project"].(string)
		if baseURL == "" || email == "" || apiToken == "" || project == "" {
			return nil, fmt.Errorf("jira設定に必須フィールドが不足しています (url, email, api_token, project)")
		}
		return &JiraClient{
			baseURL:  baseURL,
			email:    email,
			apiToken: apiToken,
			project:  project,
			client:   httpClient,
		}, nil

	case "servicenow":
		instanceURL, _ := config["url"].(string)
		username, _ := config["username"].(string)
		password, _ := config["password"].(string)
		table, _ := config["table"].(string)
		if instanceURL == "" || username == "" || password == "" {
			return nil, fmt.Errorf("servicenow設定に必須フィールドが不足しています (url, username, password)")
		}
		if table == "" {
			table = "incident"
		}
		return &ServiceNowClient{
			instanceURL: instanceURL,
			username:    username,
			password:    password,
			table:       table,
			client:      httpClient,
		}, nil

	default:
		return nil, fmt.Errorf("未対応のSOARタイプ: %s", systemType)
	}
}
