// Package main provides the detection engine server.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/siem"
	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// storeAdapter adapts *store.AlertStore to satisfy detection.AlertStore and detection.DetectionStore.
type storeAdapter struct {
	alertStore    *store.AlertStore
	incidentStore *store.IncidentStore
	pool          *pgxpool.Pool
}

// newStoreAdapter wraps a store.AlertStore to satisfy detection interfaces.
func newStoreAdapter(s *store.AlertStore, pool *pgxpool.Pool) *storeAdapter {
	return &storeAdapter{alertStore: s, pool: pool}
}

// setIncidentStore attaches an IncidentStore so AutoCreateIncident can be used.
func (a *storeAdapter) setIncidentStore(is *store.IncidentStore) {
	a.incidentStore = is
}

// CreateCorrelationIncident satisfies detection.IncidentCreator. It creates an
// incident summarising an agent's correlated activity (the set of MITRE
// techniques it triggered within the window) and returns the new incident ID.
// Title/severity are built by detection.BuildCorrelationIncidentContent so a
// multi-technique kill chain is a single, higher-severity case rather than N
// per-technique fragments.
func (a *storeAdapter) CreateCorrelationIncident(ctx context.Context, agentID string, techniques []string, alertCount int) (string, error) {
	if a.incidentStore == nil {
		return "", fmt.Errorf("CreateCorrelationIncident: incidentStore が設定されていません")
	}

	// エージェントのホスト名を取得（取得失敗時は UUID をフォールバックとして使用）
	displayName := agentID
	if a.pool != nil {
		var hostname string
		if err := a.pool.QueryRow(ctx,
			`SELECT COALESCE(hostname, '') FROM agents WHERE id = $1::uuid`, agentID,
		).Scan(&hostname); err == nil && hostname != "" {
			displayName = hostname
		}
	}

	title, description, severity := detection.BuildCorrelationIncidentContent(displayName, techniques, alertCount)
	inc := &store.Incident{
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      "open",
	}
	return a.incidentStore.Insert(ctx, inc)
}

// LinkAlerts satisfies detection.IncidentCreator. It attaches the constituent
// alert IDs to the incident so an analyst can drill down from the correlated
// case to its underlying alerts. Idempotent (LinkAlert uses ON CONFLICT DO
// NOTHING); blanks are skipped.
func (a *storeAdapter) LinkAlerts(ctx context.Context, incidentID string, alertIDs []string) error {
	if a.incidentStore == nil {
		return fmt.Errorf("LinkAlerts: incidentStore が設定されていません")
	}
	for _, id := range alertIDs {
		if id == "" {
			continue
		}
		if err := a.incidentStore.LinkAlert(ctx, incidentID, id); err != nil {
			return err
		}
	}
	return nil
}

// GetRecentEvents satisfies detection.AlertStore.
// It queries the events table for recent entries for the given agent.
func (a *storeAdapter) GetRecentEvents(agentID string, limit int) ([]detection.EventSummary, error) {
	if a.pool == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := a.pool.Query(ctx, `
		SELECT event_type, raw_data, "time"
		FROM events
		WHERE agent_id = $1
		ORDER BY "time" DESC
		LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetRecentEvents: %w", err)
	}
	defer rows.Close()

	var summaries []detection.EventSummary
	for rows.Next() {
		var eventType string
		var rawData []byte
		var ts time.Time
		if err := rows.Scan(&eventType, &rawData, &ts); err != nil {
			continue
		}
		var data map[string]interface{}
		_ = json.Unmarshal(rawData, &data)
		summaries = append(summaries, detection.EventSummary{
			Type:      eventType,
			Timestamp: ts,
			Summary:   summarizeRaw(eventType, data),
		})
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return summaries, nil
}

// summarizeRaw builds a one-line summary from raw event data for AI context.
func summarizeRaw(eventType string, data map[string]interface{}) string {
	if data == nil {
		return eventType
	}
	str := func(key string) string {
		if v, ok := data[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	switch eventType {
	case "process":
		img := str("image")
		cmd := str("cmdline")
		if cmd != "" {
			return img + " " + cmd
		}
		return img
	case "file":
		return str("operation") + " " + str("path")
	case "network":
		dst := str("dst_ip")
		port := str("dst_port")
		if port != "" {
			return dst + ":" + port
		}
		return dst
	case "dns":
		return str("query")
	case "registry":
		return str("operation") + " " + str("key")
	default:
		for _, k := range []string{"image", "path", "dst_ip", "query", "key"} {
			if v := str(k); v != "" {
				return v
			}
		}
		return eventType
	}
}

// GetAlertHistory satisfies detection.AlertStore.
func (a *storeAdapter) GetAlertHistory(agentID string, days int) ([]detection.AlertSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := a.alertStore.GetAlertHistory(ctx, agentID, days)
	if err != nil {
		return nil, fmt.Errorf("GetAlertHistory: %w", err)
	}

	summaries := make([]detection.AlertSummary, len(rows))
	for i, r := range rows {
		summaries[i] = detection.AlertSummary{
			Title:     r.Title,
			Severity:  r.Severity,
			CreatedAt: r.CreatedAt,
			Status:    r.Status,
		}
	}
	return summaries, nil
}

// SaveAlert satisfies detection.DetectionStore.
func (a *storeAdapter) SaveAlert(ctx context.Context, alert *detection.StoredAlert) error {
	sa := &store.StoredAlert{
		ID:           alert.ID,
		AgentID:      alert.AgentID,
		Hostname:     alert.Hostname,
		OS:           alert.OS,
		Severity:     alert.Severity,
		Status:       alert.Status,
		Title:        alert.Title,
		AnomalyScore: &alert.AnomalyScore,
		CreatedAt:    alert.CreatedAt,
		UpdatedAt:    alert.UpdatedAt,
	}
	if alert.RuleID != "" {
		sa.RuleID = &alert.RuleID
	}
	if alert.RuleName != "" {
		sa.RuleName = &alert.RuleName
	}
	if alert.Description != "" {
		sa.Description = &alert.Description
	}
	if alert.MITRETech != "" {
		sa.MITRETech = &alert.MITRETech
	}
	// Full ATT&CK technique set → ai_mitre_tags (TEXT[]), so a correlation alert
	// credits every technique it detected. The alerts read path scans this as
	// []string (see store.scanAlert).
	sa.AIMITRETags = alert.MITRETags
	sa.EventIDs = alert.EventIDs
	if len(alert.RawEvent) > 0 {
		sa.RawEvent = alert.RawEvent
	}
	return a.alertStore.SaveAlert(ctx, sa)
}

// UpdateAlert satisfies detection.DetectionStore.
func (a *storeAdapter) UpdateAlert(ctx context.Context, id string, update detection.AlertUpdate) error {
	var analysisUpdate *store.AIAnalysisUpdate
	if update.AIAnalysis != nil {
		an := update.AIAnalysis
		mitreTags := make([]string, 0, len(an.AttackTechniques))
		for _, t := range an.AttackTechniques {
			mitreTags = append(mitreTags, t.ID)
		}
		analysisUpdate = &store.AIAnalysisUpdate{
			IsThreat:    an.IsThreat,
			Severity:    an.Severity,
			Confidence:  an.Confidence,
			ThreatName:  an.ThreatName,
			Summary:     an.Summary,
			Report:      an.DetailedReport,
			AttackChain: an.AttackChain,
			MITRETags:   mitreTags,
		}
	}
	return a.alertStore.UpdateAlert(ctx, id, update.Status, analysisUpdate)
}

// GetAlert satisfies detection.DetectionStore.
func (a *storeAdapter) GetAlert(ctx context.Context, id string) (*detection.StoredAlert, error) {
	sa, err := a.alertStore.GetAlert(ctx, id)
	if err != nil {
		return nil, err
	}

	da := &detection.StoredAlert{
		ID:        sa.ID,
		AgentID:   sa.AgentID,
		Hostname:  sa.Hostname,
		OS:        sa.OS,
		Severity:  sa.Severity,
		Status:    sa.Status,
		Title:     sa.Title,
		EventIDs:  sa.EventIDs,
		CreatedAt: sa.CreatedAt,
		UpdatedAt: sa.UpdatedAt,
	}
	if sa.RuleID != nil {
		da.RuleID = *sa.RuleID
	}
	if sa.RuleName != nil {
		da.RuleName = *sa.RuleName
	}
	if sa.Description != nil {
		da.Description = *sa.Description
	}
	if sa.MITRETech != nil {
		da.MITRETech = *sa.MITRETech
	}
	if sa.AnomalyScore != nil {
		da.AnomalyScore = *sa.AnomalyScore
	}
	return da, nil
}

// ListActiveSuppressions satisfies detection.SuppressionLoader.
//
// クエリの実体は internal/detection の PoolSuppressionLoader に移した
// (2026-08-14)。server-api の AlertPipeline も抑制を見るようになり、同じ SQL が
// 2 箇所に必要になったためである。**両プロセスが同じ行・同じ解釈を見ること**が
// 抑制では特に効く——片方でだけ抑制されると、運用者からは「効いたり効かなかったり
// する」としか見えない。
func (a *storeAdapter) ListActiveSuppressions(ctx context.Context) ([]detection.SuppressionRule, error) {
	return detection.NewPoolSuppressionLoader(a.pool).ListActiveSuppressions(ctx)
}

// ListActiveIOCs satisfies detection.IOCLoader.
// Loads all active IOC entries for the in-memory cache.
func (a *storeAdapter) ListActiveIOCs(ctx context.Context) ([]detection.IOCRecord, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT id, type, value, COALESCE(description,''), severity, COALESCE(confidence,50)
		FROM ioc_entries
		WHERE is_active = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("ListActiveIOCs: %w", err)
	}
	defer rows.Close()

	var records []detection.IOCRecord
	for rows.Next() {
		var r detection.IOCRecord
		if err := rows.Scan(&r.ID, &r.Type, &r.Value, &r.Description, &r.Severity, &r.Confidence); err == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

// ─── SIEM Forwarder Adapter ───────────────────────────────────────────────────

// siemForwarderAdapter adapts *siem.Forwarder to detection.SIEMForwarder.
type siemForwarderAdapter struct {
	f *siem.Forwarder
}

func (a *siemForwarderAdapter) Forward(ctx context.Context, alert *detection.SIEMAlertPayload) {
	a.f.Forward(ctx, &siem.AlertPayload{
		ID:             alert.ID,
		AgentID:        alert.AgentID,
		Hostname:       alert.Hostname,
		OS:             alert.OS,
		RuleName:       alert.RuleName,
		Severity:       alert.Severity,
		Status:         alert.Status,
		MITRETechnique: alert.MITRETechnique,
		AIThreatName:   alert.AIThreatName,
		AISummary:      alert.AISummary,
		CreatedAt:      alert.CreatedAt,
	})
}

// IsolateAgent satisfies detection.RiskCommander.
// It updates the agent status directly and records the isolation metadata.
func (a *storeAdapter) IsolateAgent(ctx context.Context, agentID, reason string) error {
	_, err := a.pool.Exec(ctx, `
		UPDATE agents
		SET status = 'isolated',
		    isolated_at = NOW(),
		    isolated_reason = $2,
		    isolated_by = 'risk_monitor',
		    updated_at = NOW()
		WHERE id = $1::uuid AND status != 'isolated'`,
		agentID, reason,
	)
	return err
}

// SaveResponseAction satisfies detection.DetectionStore.
func (a *storeAdapter) SaveResponseAction(ctx context.Context, action *detection.ResponseActionLog) error {
	row := &store.ResponseActionRow{
		ID:         action.ID,
		AgentID:    action.AgentID,
		ActionType: action.ActionType,
		ExecutedBy: action.ExecutedBy,
		Success:    action.Success,
		ExecutedAt: action.ExecutedAt,
	}
	if action.AlertID != "" {
		row.AlertID = &action.AlertID
	}
	if action.Target != "" {
		row.Target = &action.Target
	}
	if action.Reason != "" {
		row.Reason = &action.Reason
	}
	if action.Error != "" {
		row.ErrorMsg = &action.Error
	}
	return a.alertStore.SaveResponseAction(ctx, row)
}
