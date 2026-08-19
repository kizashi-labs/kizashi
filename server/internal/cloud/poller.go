package cloud

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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
)

// Integration represents a cloud monitoring integration from the DB.
type Integration struct {
	ID       string
	Name     string
	Provider string
	Region   string
	Config   map[string]interface{}
	Enabled  bool
}

// NATSPublisher is a minimal interface for publishing messages to NATS.
type NATSPublisher interface {
	Publish(subject string, data []byte) error
}

// Poller polls cloud provider APIs for new events on a schedule.
type Poller struct {
	pool     *pgxpool.Pool
	nc       NATSPublisher
	client   *http.Client
	interval time.Duration
}

func NewPoller(pool *pgxpool.Pool) *Poller {
	return &Poller{
		pool:     pool,
		client:   &http.Client{Timeout: 30 * time.Second},
		interval: 5 * time.Minute,
	}
}

// NewPollerWithNATS creates a Poller that publishes cloud events to NATS for detection processing.
func NewPollerWithNATS(pool *pgxpool.Pool, nc NATSPublisher) *Poller {
	p := NewPoller(pool)
	p.nc = nc
	return p
}

// CloudEventMsg is the NATS message format published to cloud.events.{provider}.
type CloudEventMsg struct {
	ID            string                 `json:"id"`
	IntegrationID string                 `json:"integration_id"`
	Provider      string                 `json:"provider"`
	EventType     string                 `json:"event_type"`
	EventTime     time.Time              `json:"event_time"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	UserIdentity  map[string]interface{} `json:"user_identity,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Region        string                 `json:"region,omitempty"`
	AgentID       string                 `json:"agent_id,omitempty"` // empty for cloud events
	Hostname      string                 `json:"hostname,omitempty"`
}

// publishCloudEvent formats a cloud event as a NATS message and publishes it
// to cloud.events.{provider} for the detection engine to process.
// It also persists the event in the database.
func (p *Poller) publishCloudEvent(ctx context.Context, intg Integration, eventType, sourceIP, resource string, identity map[string]interface{}) {
	if p.nc == nil {
		return
	}

	eventID := fmt.Sprintf("cloud-%s-%d", intg.ID[:8], time.Now().UnixNano())
	msg := CloudEventMsg{
		ID:            eventID,
		IntegrationID: intg.ID,
		Provider:      intg.Provider,
		EventType:     eventType,
		EventTime:     time.Now(),
		SourceIP:      sourceIP,
		UserIdentity:  identity,
		Resource:      resource,
		Region:        intg.Region,
		Hostname:      fmt.Sprintf("cloud-%s-%s", intg.Provider, intg.Region),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		tick.Fail(ctx, err, "クラウドイベントを組み立てられず、検知に送りませんでした",
			"provider", intg.Provider, "event", eventType)
		return
	}

	// Publish to cloud.events.{provider} subject
	subject := fmt.Sprintf("cloud.events.%s", intg.Provider)
	if err := p.nc.Publish(subject, data); err != nil {
		// **送れなかったイベントは検知に届きません。**
		tick.Fail(ctx, err, "クラウドイベントのNATS送信に失敗")
	}

	// Also store in DB.
	//
	// **検知に送るのと、画面に残すのは別の行き先です。** NATS に送れて
	// ここが書けなければ、アラートは立つのに、その元になったイベントを
	// クラウドイベントの一覧で探しても出てきません。上の2つと同じ回の
	// 中なので、同じところへ出します。
	if _, err := p.pool.Exec(ctx,
		`INSERT INTO cloud_events (id, integration_id, provider, event_type, event_time, source_ip, user_identity, resource, region, raw_event)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO NOTHING`,
		eventID, intg.ID, intg.Provider, eventType, msg.EventTime,
		sourceIP, identity, resource, intg.Region,
		map[string]interface{}{"event_type": eventType, "source_ip": sourceIP},
	); err != nil {
		tick.Fail(ctx, err, "クラウドイベントを保存できませんでした。検知には送れていますが一覧には出ません",
			"provider", intg.Provider, "event", eventType)
	}
}

// Run starts the polling loop. Call in a goroutine.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	slog.Info("クラウドポーリング開始", "interval", p.interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "cloud_poller", p.poll)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, provider, region, config FROM cloud_integrations WHERE enabled=TRUE`)
	if err != nil {
		tick.FailComponent(ctx, "cloud_poller", err, "クラウド統合の取得に失敗")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var intg Integration
		var configJSON []byte
		if err := rows.Scan(&intg.ID, &intg.Name, &intg.Provider, &intg.Region, &configJSON); err != nil {
			tick.FailComponent(ctx, "cloud_poller", err, "クラウド統合の行を読めませんでした")
			return
		}
		if err := json.Unmarshal(configJSON, &intg.Config); err != nil {
			// 設定が読めない統合は、画面上は「設定済み」のまま一度も
			// 収集されません。黙って飛ばすと、いつまでも気づきません。
			tick.Fail(ctx, err, "クラウド統合の設定を読めませんでした。この統合は収集されません",
				"integration", intg.Name, "provider", intg.Provider)
			continue
		}

		go func(i Integration) {
			var count int
			var pollErr error
			switch i.Provider {
			case "aws":
				count, pollErr = p.pollAWS(ctx, i)
			case "azure":
				count, pollErr = p.pollAzure(ctx, i)
			case "gcp":
				count, pollErr = p.pollGCP(ctx, i)
			default:
				return
			}

			// 同期状態の書き戻しが失敗すると、画面の「最終同期日時」や
			// エラー表示が古いまま止まる。捨てずにログへ出す。
			if pollErr != nil {
				tick.Fail(ctx, pollErr, "クラウドポーリングエラー", "integration", i.Name)
				if _, err := p.pool.Exec(ctx,
					`UPDATE cloud_integrations SET error_message=$1 WHERE id=$2`,
					pollErr.Error(), i.ID); err != nil {
					tick.Fail(ctx, err, "クラウド連携のエラー状態の保存に失敗しました",
						"integration", i.Name)
				}
				return
			}

			if _, err := p.pool.Exec(ctx,
				`UPDATE cloud_integrations SET last_synced_at=NOW(), error_message=NULL WHERE id=$1`,
				i.ID); err != nil {
				tick.Fail(ctx, err, "クラウド連携の同期状態の保存に失敗しました",
					"integration", i.Name)
			}
			if count > 0 {
				slog.Info("クラウドイベント取り込み", "integration", i.Name, "count", count)
			}
		}(intg)
	}
	if err := rows.Err(); err != nil {
		tick.Fail(ctx, err, "クラウドアカウント一覧の走査が途中で終わりました。今回のポーリングで取得しないアカウントがあります")
	}
}

// cloudTrailLookupRequest は CloudTrail LookupEvents API のリクエスト Body です。
type cloudTrailLookupRequest struct {
	StartTime  int64 `json:"StartTime"`
	EndTime    int64 `json:"EndTime"`
	MaxResults int   `json:"MaxResults"`
}

// cloudTrailResource は CloudTrail イベント内のリソース情報です。
type cloudTrailResource struct {
	ResourceName string `json:"ResourceName"`
	ResourceType string `json:"ResourceType"`
}

// cloudTrailEvent は CloudTrail LookupEvents のイベント1件です。
type cloudTrailEvent struct {
	EventName       string               `json:"EventName"`
	SourceIPAddress string               `json:"SourceIPAddress"`
	Username        string               `json:"Username"`
	Resources       []cloudTrailResource `json:"Resources"`
}

// cloudTrailResponse は CloudTrail LookupEvents のレスポンスです。
type cloudTrailResponse struct {
	Events []cloudTrailEvent `json:"Events"`
}

// pollAWS は CloudTrail LookupEvents API で直近5分のイベントを取得します。
// Returns count of new events ingested.
func (p *Poller) pollAWS(ctx context.Context, intg Integration) (int, error) {
	accessKey, _ := intg.Config["access_key_id"].(string)
	secretKey, _ := intg.Config["secret_access_key"].(string)
	if accessKey == "" || secretKey == "" {
		// credentials 未設定 — スキップ
		return 0, nil
	}

	region := intg.Region
	if region == "" {
		region = "us-east-1"
	}

	now := time.Now().UTC()
	startTime := now.Add(-5 * time.Minute)

	reqBody := cloudTrailLookupRequest{
		StartTime:  startTime.Unix(),
		EndTime:    now.Unix(),
		MaxResults: 50,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("CloudTrailリクエストBodyのシリアライズ失敗: %w", err)
	}

	endpoint := fmt.Sprintf("https://cloudtrail.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("CloudTrailリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents")

	sigV4Sign(req, bodyBytes, "cloudtrail", region, accessKey, secretKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("CloudTrail API呼び出し失敗: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("CloudTrailレスポンス読み取り失敗: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CloudTrail APIエラー (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var ctResp cloudTrailResponse
	if err := json.Unmarshal(respBytes, &ctResp); err != nil {
		return 0, fmt.Errorf("CloudTrailレスポンスのパース失敗: %w", err)
	}

	count := 0
	for _, evt := range ctResp.Events {
		// リソース名を結合
		resourceNames := make([]string, 0, len(evt.Resources))
		for _, r := range evt.Resources {
			if r.ResourceName != "" {
				resourceNames = append(resourceNames, r.ResourceName)
			}
		}
		resource := strings.Join(resourceNames, ",")

		identity := map[string]interface{}{
			"username": evt.Username,
		}

		p.publishCloudEvent(ctx, intg, evt.EventName, evt.SourceIPAddress, resource, identity)
		count++
	}

	slog.Debug("AWS CloudTrail ポーリング完了", "integration", intg.Name, "region", region, "events", count)
	return count, nil
}

// azureActivityLogName は operationName オブジェクトの value フィールドです。
type azureOperationName struct {
	Value string `json:"value"`
}

// azureActivityLogEntry は Azure Monitor Activity Log の1エントリです。
type azureActivityLogEntry struct {
	OperationName   azureOperationName     `json:"operationName"`
	Caller          string                 `json:"caller"`
	CallerIPAddress string                 `json:"callerIpAddress"`
	Properties      map[string]interface{} `json:"properties"`
}

// azureActivityLogResponse は Azure Monitor Activity Logs API のレスポンスです。
type azureActivityLogResponse struct {
	Value []azureActivityLogEntry `json:"value"`
}

// pollAzure は Azure Monitor Activity Logs API で直近5分のイベントを取得します。
func (p *Poller) pollAzure(ctx context.Context, intg Integration) (int, error) {
	tenantID, _ := intg.Config["tenant_id"].(string)
	clientID, _ := intg.Config["client_id"].(string)
	clientSecret, _ := intg.Config["client_secret"].(string)
	subscriptionID, _ := intg.Config["subscription_id"].(string)

	if clientID == "" || tenantID == "" || clientSecret == "" || subscriptionID == "" {
		// credentials 未設定 — スキップ
		return 0, nil
	}

	// Azure AD からアクセストークンを取得
	const resource = "https://management.azure.com/"
	token, err := azureGetToken(p.client, tenantID, clientID, clientSecret, resource)
	if err != nil {
		return 0, fmt.Errorf("azureトークン取得失敗: %w", err)
	}

	startTime := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=eventTimestamp ge '%s'",
		subscriptionID, startTime,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return 0, fmt.Errorf("azure Activity Logリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("azure Activity Log API呼び出し失敗: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("azure Activity Logレスポンス読み取り失敗: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("azure Activity Log APIエラー (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var logResp azureActivityLogResponse
	if err := json.Unmarshal(respBytes, &logResp); err != nil {
		return 0, fmt.Errorf("azure Activity Logレスポンスのパース失敗: %w", err)
	}

	count := 0
	for _, entry := range logResp.Value {
		// eventType = operationName.value の最後の '/' 以降
		opName := entry.OperationName.Value
		eventType := opName
		if idx := strings.LastIndex(opName, "/"); idx >= 0 && idx < len(opName)-1 {
			eventType = opName[idx+1:]
		}

		identity := map[string]interface{}{
			"caller":     entry.Caller,
			"properties": entry.Properties,
		}

		p.publishCloudEvent(ctx, intg, eventType, entry.CallerIPAddress, opName, identity)
		count++
	}

	slog.Debug("Azure Activity Log ポーリング完了", "integration", intg.Name, "events", count)
	return count, nil
}

// gcpLogProtoPayload は Cloud Logging エントリの protoPayload フィールドです。
type gcpLogProtoPayload struct {
	MethodName      string                 `json:"methodName"`
	RequestMetadata map[string]interface{} `json:"requestMetadata"`
}

// gcpLogResource は Cloud Logging エントリの resource フィールドです。
type gcpLogResource struct {
	Type string `json:"type"`
}

// gcpLogEntry は Cloud Logging entries:list API の1エントリです。
type gcpLogEntry struct {
	ProtoPayload gcpLogProtoPayload `json:"protoPayload"`
	Resource     gcpLogResource     `json:"resource"`
}

// gcpLogResponse は Cloud Logging entries:list API のレスポンスです。
type gcpLogResponse struct {
	Entries []gcpLogEntry `json:"entries"`
}

// gcpLogRequest は Cloud Logging entries:list API のリクエスト Body です。
type gcpLogRequest struct {
	ResourceNames []string `json:"resourceNames"`
	Filter        string   `json:"filter"`
	OrderBy       string   `json:"orderBy"`
	PageSize      int      `json:"pageSize"`
}

// pollGCP は Cloud Logging entries:list API で直近5分のイベントを取得します。
func (p *Poller) pollGCP(ctx context.Context, intg Integration) (int, error) {
	serviceAccountJSON, _ := intg.Config["service_account_json"].(string)
	if serviceAccountJSON == "" {
		// credentials 未設定 — スキップ
		return 0, nil
	}

	// サービスアカウントJSONからプロジェクトIDを取得
	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(serviceAccountJSON), &sa); err != nil {
		return 0, fmt.Errorf("GCPサービスアカウントJSONのパース失敗: %w", err)
	}
	projectID := sa.ProjectID
	if projectID == "" {
		return 0, fmt.Errorf("サービスアカウントJSONにproject_idがありません")
	}

	// GCP OAuth2 アクセストークンを取得
	const scope = "https://www.googleapis.com/auth/logging.read"
	token, err := gcpGetToken(p.client, serviceAccountJSON, scope)
	if err != nil {
		return 0, fmt.Errorf("GCPトークン取得失敗: %w", err)
	}

	// Cloud Logging entries:list リクエストを構築
	startTime := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	filter := fmt.Sprintf(
		`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" AND timestamp>="%s"`,
		projectID, startTime,
	)

	reqBody := gcpLogRequest{
		ResourceNames: []string{fmt.Sprintf("projects/%s", projectID)},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      50,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("cloud Loggingリクエストbodyのシリアライズ失敗: %w", err)
	}

	const loggingURL = "https://logging.googleapis.com/v2/entries:list"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loggingURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("cloud Loggingリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cloud Logging API呼び出し失敗: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("cloud Loggingレスポンス読み取り失敗: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("cloud Logging APIエラー (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var logResp gcpLogResponse
	if err := json.Unmarshal(respBytes, &logResp); err != nil {
		return 0, fmt.Errorf("cloud Loggingレスポンスのパース失敗: %w", err)
	}

	count := 0
	for _, entry := range logResp.Entries {
		methodName := entry.ProtoPayload.MethodName

		// eventType = methodName の最後の '.' 以降
		eventType := methodName
		if idx := strings.LastIndex(methodName, "."); idx >= 0 && idx < len(methodName)-1 {
			eventType = methodName[idx+1:]
		}

		// callerIp を requestMetadata から取得
		callerIP, _ := entry.ProtoPayload.RequestMetadata["callerIp"].(string)

		resource := entry.Resource.Type

		identity := map[string]interface{}{
			"requestMetadata": entry.ProtoPayload.RequestMetadata,
		}

		p.publishCloudEvent(ctx, intg, eventType, callerIP, resource, identity)
		count++
	}

	slog.Debug("GCP Cloud Logging ポーリング完了", "integration", intg.Name, "project", projectID, "events", count)
	return count, nil
}
