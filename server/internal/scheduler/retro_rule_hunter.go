package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// ruleEvaluator is the subset of *detectionrules.RuleEngine the hunter needs.
type ruleEvaluator interface {
	Evaluate(ctx context.Context, evt interface{}) ([]*detectionrules.RuleMatch, error)
}

// RetroRuleHunter re-evaluates recent historical process events against Sigma
// rules that were ENABLED after those events happened. The live engine only sees
// "new events × current rules"; a rule added today never fires on yesterday's
// activity. This covers the other half — "historical events × new rules" — so an
// attack that occurred before its detection rule existed is still caught. It
// advances a watermark over rule-creation time so each new rule is retro-hunted
// exactly once. Idempotent and best-effort (missing tables ⇒ skip silently).
type RetroRuleHunter struct {
	pool      *pgxpool.Pool
	eval      ruleEvaluator
	lookback  time.Duration
	interval  time.Duration
	maxEvents int
	maxAlerts int
}

// NewRetroRuleHunter constructs a hunter. lookbackHours<=0 defaults to 24.
func NewRetroRuleHunter(pool *pgxpool.Pool, eval ruleEvaluator, lookbackHours int, interval time.Duration) *RetroRuleHunter {
	if lookbackHours <= 0 {
		lookbackHours = 24
	}
	if interval <= 0 {
		interval = time.Hour
	}
	return &RetroRuleHunter{
		pool:      pool,
		eval:      eval,
		lookback:  time.Duration(lookbackHours) * time.Hour,
		interval:  interval,
		maxEvents: 5000,
		maxAlerts: 200,
	}
}

// Run hunts once on startup, then every interval, until ctx is cancelled.
func (h *RetroRuleHunter) Run(ctx context.Context) {
	if h.pool == nil || h.eval == nil {
		return
	}
	h.ensureState(ctx)
	h.hunt(ctx)
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.hunt(ctx)
		}
	}
}

func (h *RetroRuleHunter) ensureState(ctx context.Context) {
	_, _ = h.pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS retro_rule_state (
			id INT PRIMARY KEY DEFAULT 1,
			last_rule_ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	_, _ = h.pool.Exec(ctx, `INSERT INTO retro_rule_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`)
}

func (h *RetroRuleHunter) hunt(ctx context.Context) {
	var watermark time.Time
	if err := h.pool.QueryRow(ctx, `SELECT last_rule_ts FROM retro_rule_state WHERE id=1`).Scan(&watermark); err != nil {
		return // state missing — skip
	}

	// Rule IDs enabled since the watermark = the "new" rules to retro-hunt.
	newRules := map[string]struct{}{}
	var maxTS time.Time = watermark
	rows, err := h.pool.Query(ctx,
		`SELECT id::text, created_at FROM rules WHERE enabled = true AND created_at > $1 ORDER BY created_at`, watermark)
	if err != nil {
		return
	}
	for rows.Next() {
		var id string
		var ts time.Time
		if rows.Scan(&id, &ts) == nil {
			newRules[id] = struct{}{}
			if ts.After(maxTS) {
				maxTS = ts
			}
		}
	}
	rows.Close()

	if len(newRules) == 0 {
		return
	}
	slog.Info("レトロルールハンター: 新規ルールを履歴照合します", "rules", len(newRules))

	evRows, err := h.pool.Query(ctx,
		`SELECT event_id::text, agent_id::text, raw_data, time
		   FROM events
		  WHERE event_type = 'process' AND time > NOW() - $1::interval
		  ORDER BY time DESC LIMIT $2`,
		fmt.Sprintf("%d seconds", int(h.lookback.Seconds())), h.maxEvents)
	if err != nil {
		return
	}
	defer evRows.Close()

	created := 0
	for evRows.Next() {
		if created >= h.maxAlerts {
			break
		}
		var eventID, agentID string
		var raw []byte
		var ts time.Time
		if evRows.Scan(&eventID, &agentID, &raw, &ts) != nil {
			continue
		}
		flat := map[string]interface{}{}
		if json.Unmarshal(raw, &flat) != nil {
			continue
		}
		if _, ok := flat["platform"]; !ok {
			flat["platform"] = "linux"
		}
		matches, err := h.eval.Evaluate(ctx, flat)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if _, isNew := newRules[m.RuleID]; !isNew {
				continue // only alert for rules newer than the event
			}
			if h.createRetroRuleAlert(ctx, eventID, agentID, m, ts) {
				created++
			}
		}
	}
	if created > 0 {
		slog.Warn("レトロルールハンター: 過去のイベントに新規ルール一致を検出", "alerts", created)
	}

	// Advance the watermark past the newest rule processed.
	_, _ = h.pool.Exec(ctx, `UPDATE retro_rule_state SET last_rule_ts = $1 WHERE id = 1`, maxTS)
}

func (h *RetroRuleHunter) createRetroRuleAlert(ctx context.Context, eventID, agentID string, m *detectionrules.RuleMatch, occurredAt time.Time) bool {
	// Dedup: one retro alert per (event, rule).
	var existing int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE source='retro_rule' AND description LIKE $1`,
		"%"+eventID+"%"+m.RuleName+"%").Scan(&existing)
	if existing > 0 {
		return false
	}
	sev := m.Severity
	if sev < 1 {
		sev = 3
	}
	title := "[RETRO] 過去のイベントに新規ルール一致: " + m.RuleName
	desc := fmt.Sprintf("レトロアクティブ照合: 発生後に追加された検知ルール「%s」が過去の process イベントに一致。発生時刻: %s\n\nイベントID: %s / ルール: %s",
		m.RuleName, occurredAt.Format("2006-01-02 15:04:05 MST"), eventID, m.RuleName)

	var alertID string
	var err error
	if agentID != "" && agentID != "00000000-0000-0000-0000-000000000000" {
		err = h.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, agent_id, description, source, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3::uuid, $4, 'retro_rule', NOW()) RETURNING id::text`,
			title, sev, agentID, desc).Scan(&alertID)
	} else {
		err = h.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, description, source, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3, 'retro_rule', NOW()) RETURNING id::text`,
			title, sev, desc).Scan(&alertID)
	}
	if err != nil {
		slog.Warn("レトロルールハンター: アラート作成失敗", "error", err)
		return false
	}
	return true
}
