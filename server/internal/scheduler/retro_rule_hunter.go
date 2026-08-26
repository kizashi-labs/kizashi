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
	trackRun(ctx, "retro_rule_hunter", h.hunt)
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			trackRun(ctx, "retro_rule_hunter", h.hunt)
		}
	}
}

// ensureState seeds the single watermark row. Migration 443 declares the table
// and seeds the row; this stays because it is the one statement here the
// runtime role is allowed to issue, and it recovers a database that was
// unreachable at boot without disabling the component for the lifetime of the
// process. The CREATE TABLE that used to sit above it is gone — under the
// least-privilege role it could only ever fail, because PostgreSQL checks the
// schema's CREATE privilege before it checks whether the table exists. The rule
// and the measurement are in runtime_ddl_test.go.
//
// The error is no longer discarded. A failed seed makes hunt()'s SELECT find no
// row, hunt() reads that as "state missing — skip", and the retro rule hunter
// then does nothing at all, every tick, with nothing said anywhere.
func (h *RetroRuleHunter) ensureState(ctx context.Context) error {
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO retro_rule_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {
		return fmt.Errorf("状態行を用意できませんでした: %w", err)
	}
	return nil
}

func (h *RetroRuleHunter) hunt(ctx context.Context) {
	if err := h.ensureState(ctx); err != nil {
		fail(ctx, err, "レトロルールハンター: 状態を用意できないため今回のパスを見送ります")
		return
	}

	var watermark time.Time
	if err := h.pool.QueryRow(ctx, `SELECT last_rule_ts FROM retro_rule_state WHERE id=1`).Scan(&watermark); err != nil {
		// 行が無いのか読めなかったのか、どちらでも「今回は何もしない」で
		// 戻ります。前者は初回、後者は毎回です。区別が付かないと、
		// レトロハントが一度も走っていないことに気づけません。
		fail(ctx, err, "レトロハント: 基準時刻を読めないため何もしませんでした")
		return
	}

	// Rule IDs enabled since the watermark = the "new" rules to retro-hunt.
	newRules := map[string]struct{}{}
	var maxTS time.Time = watermark
	rows, err := h.pool.Query(ctx,
		`SELECT id::text, created_at FROM rules WHERE enabled = true AND created_at > $1 ORDER BY created_at`, watermark)
	if err != nil {
		// 黙って戻ると、回らなかった回と何も無かった回が同じになります。
		fail(ctx, err, "レトロハント: 対象を取得できませんでした")
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
	// 切り詰められても取りこぼしはありません。この問い合わせは created_at 昇順
	// なので、落ちるのは常に新しい側で、maxTS はそれより手前に留まります。
	// 読めなかったルールは watermark の先にあるまま、次回に回ります。
	if err := rows.Err(); err != nil {
		fail(ctx, err, "レトロルールハンター: 新規ルールの走査が途中で終わりました。"+
			"残りは次回のパスで処理されます")
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
		fail(ctx, err, "レトロハント: 過去イベントを取得できませんでした")
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
			// このイベントは新しいルールと照合されません。飛ばすと、
			// watermark は「照合済み」として進みます。二度と戻りません。
			fail(ctx, err, "レトロハント: イベントを評価できませんでした", "event", eventID)
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
	// ここは取りこぼしになります。watermark は「このルール群は履歴と
	// 照合し終えた」という宣言なので、履歴を読み切れないまま進めると、
	// 走査できなかった区間はそのルールにとって永久に未照合のまま
	// 「照合済み」になります。進めなければ次回やり直せます。
	if err := evRows.Err(); err != nil {
		fail(ctx, err, "レトロルールハンター: 履歴の走査が途中で終わりました。"+
			"watermark を進めず、次回のパスでやり直します",
			"rules", len(newRules), "alerts", created)
		return
	}

	if created > 0 {
		slog.Warn("レトロルールハンター: 過去のイベントに新規ルール一致を検出", "alerts", created)
	}

	// Advance the watermark past the newest rule processed.
	// **書けないと watermark が進まず、次回も同じ区間を走ります。**
	// 取りこぼしはしませんが、進んでいないことは外から分かりません。
	if _, err := h.pool.Exec(ctx,
		`UPDATE retro_rule_state SET last_rule_ts = $1 WHERE id = 1`, maxTS); err != nil {
		fail(ctx, err, "レトロルールハンター: watermark を進められませんでした")
	}
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
		fail(ctx, err, "レトロルールハンター: アラート作成失敗")
		return false
	}
	return true
}
