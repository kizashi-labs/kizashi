package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// CorrelationRule defines a trigger/follow event pair for real-time correlation.
type CorrelationRule struct {
	ID                string
	Name              string
	TriggerEventType  string
	FollowEventType   string
	TimeWindowSeconds int
	MinCount          int
	AlertTitle        string
	AlertSeverity     int
}

// WindowEvent is an event stored in the time window buffer.
type WindowEvent struct {
	AgentID   string
	EventType string
	Timestamp time.Time
	Data      map[string]interface{}
}

// RealtimeCorrelator subscribes to NATS alert events and detects correlated patterns.
type RealtimeCorrelator struct {
	pool         *pgxpool.Pool
	nc           *nats.Conn
	rules        []CorrelationRule
	eventWindows map[string][]WindowEvent
	mu           sync.Mutex
	iocMatcher   *detection.IOCMatcher // optional; enriches correlated events with IOC checks
}

// NewRealtimeCorrelator creates a new RealtimeCorrelator.
func NewRealtimeCorrelator(pool *pgxpool.Pool, nc *nats.Conn) *RealtimeCorrelator {
	return &RealtimeCorrelator{
		pool:         pool,
		nc:           nc,
		rules:        []CorrelationRule{},
		eventWindows: make(map[string][]WindowEvent),
	}
}

// WithIOCMatcher attaches a detection.IOCMatcher to the correlator.
// When set, each correlated alert is enriched with IOC match details before
// being persisted to the database.
func (r *RealtimeCorrelator) WithIOCMatcher(m *detection.IOCMatcher) *RealtimeCorrelator {
	r.iocMatcher = m
	return r
}

// Run starts the real-time correlation engine.
func (r *RealtimeCorrelator) Run(ctx context.Context) {
	slog.Info("リアルタイム相関エンジンを開始しました")

	// Load initial rules
	trackRun(ctx, "realtime_correlator", r.loadRules)

	// Subscribe to NATS alerts.new if nc is available
	var sub *nats.Subscription
	if r.nc != nil {
		var err error
		sub, err = r.nc.Subscribe("alerts.new", func(msg *nats.Msg) {
			r.handleAlertMessage(ctx, msg.Data)
		})
		if err != nil {
			fail(ctx, err, "alerts.newへのサブスクリプションに失敗しました")
		} else {
			slog.Info("NATS alerts.newサブジェクトを購読しました")
			defer sub.Unsubscribe()
		}
	}

	// Reload rules every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("リアルタイム相関エンジンを停止しました")
			return
		case <-ticker.C:
			trackRun(ctx, "realtime_correlator", r.loadRules)
		}
	}
}

// loadRules loads correlation rules from the database.
func (r *RealtimeCorrelator) loadRules(ctx context.Context) {
	// Check if correlation_rules table exists
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name = 'correlation_rules'
	)`).Scan(&exists)
	if err != nil {
		fail(ctx, err, "リアルタイム相関: ルール表の有無を確認できませんでした。ルールは1件も読み込まれません")
		return
	}
	if !exists {
		return
	}

	rows, err := r.pool.Query(ctx,
		`SELECT id, name, trigger_event_type, follow_event_type,
		        time_window_seconds, alert_title, alert_severity
		 FROM correlation_rules
		 WHERE enabled = TRUE`,
	)
	if err != nil {
		fail(ctx, err, "相関ルールの読み込みに失敗しました")
		return
	}
	defer rows.Close()

	var rules []CorrelationRule
	for rows.Next() {
		var rule CorrelationRule
		rule.MinCount = 1 // default
		if err := rows.Scan(
			&rule.ID, &rule.Name,
			&rule.TriggerEventType, &rule.FollowEventType,
			&rule.TimeWindowSeconds,
			&rule.AlertTitle, &rule.AlertSeverity,
		); err == nil {
			rules = append(rules, rule)
		}
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "相関ルールを読み切れませんでした。切り詰められたルール集合を入れ替えると、検知が黙って減ります。前回のルールを保持し、次回の再読み込みでやり直します")
		return
	}

	r.mu.Lock()
	r.rules = rules
	r.mu.Unlock()

	slog.Info("相関ルールを再読み込みしました", "count", len(rules))
}

// handleAlertMessage processes an incoming alert NATS message.
func (r *RealtimeCorrelator) handleAlertMessage(ctx context.Context, data []byte) {
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		// このアラートは相関に載りません。相関は複数のアラートをまたいで
		// インシデントに昇格させる経路なので、落ちた1件は「相関しなかった」
		// ではなく「見ていない」です。
		// **ここは回の中ではありません** —— NATS の購読コールバックで、
		// 1通ごとに呼ばれます。`fail` は記録先が無いので静かに終わります。
		// 部品ごとの件数（edr_background_failures_total）なら外に出ます。
		metrics.BackgroundFailed("realtime_correlator", err,
			"相関: アラートのメッセージを解釈できず、相関に載せませんでした")
		return
	}

	agentID, _ := payload["agent_id"].(string)
	eventType, _ := payload["event_type"].(string)
	if agentID == "" || eventType == "" {
		// Try alternate field names
		agentID, _ = payload["agent_id"].(string)
		eventType, _ = payload["type"].(string)
	}
	if agentID == "" && eventType == "" {
		return
	}

	event := WindowEvent{
		AgentID:   agentID,
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Data:      payload,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rule := range r.rules {
		if rule.TriggerEventType != eventType && rule.FollowEventType != eventType {
			continue
		}

		windowKey := fmt.Sprintf("%s:%s", rule.ID, agentID)

		// Add event to window
		r.eventWindows[windowKey] = append(r.eventWindows[windowKey], event)

		// Prune events older than the time window
		cutoff := time.Now().Add(-time.Duration(rule.TimeWindowSeconds) * time.Second)
		var fresh []WindowEvent
		for _, ev := range r.eventWindows[windowKey] {
			if ev.Timestamp.After(cutoff) {
				fresh = append(fresh, ev)
			}
		}
		r.eventWindows[windowKey] = fresh

		// Count trigger and follow events
		triggerCount := 0
		followCount := 0
		for _, ev := range fresh {
			if ev.EventType == rule.TriggerEventType {
				triggerCount++
			}
			if ev.EventType == rule.FollowEventType {
				followCount++
			}
		}

		// Fire if we have both trigger and follow events (or minCount met)
		totalCount := triggerCount + followCount
		minCount := rule.MinCount
		if minCount <= 0 {
			minCount = 1
		}
		if totalCount >= minCount && triggerCount > 0 && followCount > 0 {
			// Optionally enrich with IOC matches before creating the alert.
			var iocMatches []detection.IOCMatch
			if r.iocMatcher != nil {
				iocMatches = r.iocMatcher.CheckEvent(payload)
			}
			go r.createCorrelatedAlert(ctx, rule, agentID, totalCount, iocMatches)
			// Clear window after firing to avoid duplicate alerts
			delete(r.eventWindows, windowKey)
		}
	}
}

// createCorrelatedAlert inserts a correlated alert into the database and publishes to NATS.
// iocMatches is an optional slice of IOC hits to include in the alert description.
func (r *RealtimeCorrelator) createCorrelatedAlert(
	ctx context.Context,
	rule CorrelationRule,
	agentID string,
	matchCount int,
	iocMatches []detection.IOCMatch,
) {
	description := fmt.Sprintf(
		"Correlation rule '%s' matched %d events for agent %s within %d seconds",
		rule.Name, matchCount, agentID, rule.TimeWindowSeconds,
	)

	// Enrich description with IOC match details when available.
	if len(iocMatches) > 0 {
		description += fmt.Sprintf("\nIOC matches (%d):", len(iocMatches))
		for _, hit := range iocMatches {
			description += fmt.Sprintf("\n  - %s %s (field: %s, severity: %d)",
				hit.IOC.Type, hit.Value, hit.MatchedOn, hit.IOC.Severity)
		}
	}

	var alertID string
	err := r.pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status)
		 VALUES ($1, $2, $3, $4, 'open')
		 RETURNING id`,
		agentID, rule.AlertTitle, description, rule.AlertSeverity,
	).Scan(&alertID)
	if err != nil {
		fail(ctx, err, "相関アラートの作成に失敗しました", "rule", rule.Name)
		return
	}

	slog.Info("相関アラートを作成しました", "rule", rule.Name, "agent", agentID, "alert_id", alertID,
		"ioc_matches", len(iocMatches))

	// Publish correlated alert event
	if r.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"alert_id":    alertID,
			"rule_id":     rule.ID,
			"rule_name":   rule.Name,
			"agent_id":    agentID,
			"match_count": matchCount,
			"ioc_matches": len(iocMatches),
		})
		if err := r.nc.Publish("alerts.correlated", payload); err != nil {
			fail(ctx, err, "alerts.correlatedの公開に失敗しました")
		}
	}
}
