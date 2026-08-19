package detection

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/edr-platform/server/internal/tick"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CurateService operationalises staged curate (roadmap P1) against the live rules
// table: it turns the pure CurateBatch decision and the field-support gate into
// DB-backed rounds, an FP auto-quarantine pass, and a status view, so the same
// logic is driven by both the admin API and the curate scheduler instead of the
// curate-analyze CLI + manual SQL. SigmaHQ rules are imported disabled; a round
// enables a bounded, field-supported batch and the FP monitor disables any that
// turn noisy — the two together make auto-enabling community rules safe.
type CurateService struct {
	db  CurateDB
	pub CuratePublisher
}

// CurateDB is the slice of *pgxpool.Pool the service needs (so a pool satisfies it
// directly, and tests can fake it).
type CurateDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// CuratePublisher fires rules.invalidate so detection + the API Sigma pipeline
// reload after curate changes the enabled set (same subject the rule-edit path
// uses). May be nil — changes still apply on the next poll/restart.
type CuratePublisher interface {
	Publish(subject string, data []byte) error
}

// NewCurateService builds a CurateService over the given pool and (optional) publisher.
func NewCurateService(db CurateDB, pub CuratePublisher) *CurateService {
	return &CurateService{db: db, pub: pub}
}

// CurateCategoryStat is the per-category breakdown of synced-rule curate state.
type CurateCategoryStat struct {
	Category    string `json:"category"`
	Total       int    `json:"total"`
	Supported   int    `json:"supported"`   // field-supported (enablable) — includes already-enabled
	Enabled     int    `json:"enabled"`     // enabled=true
	Deferred    int    `json:"deferred"`    // supported, disabled, not quarantined → a future round
	Pending     int    `json:"pending"`     // field-unsupported → never enabled (false green)
	Quarantined int    `json:"quarantined"` // auto/manually disabled for noise
	// Duplicate counts rules held back because a builtin already covers the same
	// technique×logsource. Separate from Deferred on purpose: deferred resolves by
	// running another round, an overlap never does.
	Duplicate int `json:"duplicate"`
}

// CurateStatus is the analyze view: per-category stats plus a TOTAL roll-up.
type CurateStatus struct {
	Categories []CurateCategoryStat `json:"categories"`
	Total      CurateCategoryStat   `json:"total"`
}

// Status computes, live from rule content, how many synced rules are
// enabled/deferred/pending/quarantined per logsource category. Counts are derived
// from the field-support gate (not just stored curate_state) so they stay accurate
// even if telemetry coverage changed since the last round.
func (s *CurateService) Status(ctx context.Context) (*CurateStatus, error) {
	rows, err := s.db.Query(ctx,
		`SELECT content, enabled, COALESCE(curate_state,'') FROM rules WHERE source='sigmahq'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	supported := SupportedSigmaFields()
	byCat := map[string]*CurateCategoryStat{}
	total := CurateCategoryStat{Category: "TOTAL"}

	for rows.Next() {
		var content, state string
		var enabled bool
		if err := rows.Scan(&content, &enabled, &state); err != nil {
			return nil, err
		}
		cat := RuleCategory(content)
		st := byCat[cat]
		if st == nil {
			st = &CurateCategoryStat{Category: cat}
			byCat[cat] = st
		}
		ok, _ := RuleFieldSupportWith(content, supported)
		st.Total++
		total.Total++
		switch {
		case enabled:
			st.Enabled++
			st.Supported++
			total.Enabled++
			total.Supported++
		case state == "quarantined":
			st.Quarantined++
			total.Quarantined++
		case state == "builtin_duplicate":
			// Still field-supported — it is withheld for overlap, not inertness.
			st.Duplicate++
			st.Supported++
			total.Duplicate++
			total.Supported++
		case ok:
			st.Deferred++
			st.Supported++
			total.Deferred++
			total.Supported++
		default:
			st.Pending++
			total.Pending++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := &CurateStatus{Total: total}
	for _, st := range byCat {
		out.Categories = append(out.Categories, *st)
	}
	// Most-enablable first, then by name for stability.
	sortCategoryStats(out.Categories)
	return out, nil
}

// CurateRoundResult summarises one curate round.
type CurateRoundResult struct {
	Enabled   int `json:"enabled"`
	Deferred  int `json:"deferred"`
	Pending   int `json:"pending"`
	Duplicate int `json:"duplicate"` // skipped: technique×logsource already covered by a builtin
	// SkippedDuplicates lists what the overlap gate withheld. Reported so a round
	// that enables little is self-explaining, and so an over-broad gate is visible
	// rather than silently shrinking detection coverage.
	SkippedDuplicates []string `json:"skipped_duplicates,omitempty"`
	EnabledIDs        []string `json:"enabled_ids,omitempty"`
}

// RunRound enables one bounded, field-supported batch of synced rules. categories
// (nil = all) scopes which logsource categories the round considers; perCategoryCap
// (<=0 = no cap) bounds how many rules per category turn on this round so each
// rules.invalidate reloads a bounded set. Quarantined rules are never reconsidered.
// Publishes rules.invalidate when anything was enabled.
func (s *CurateService) RunRound(ctx context.Context, categories []string, perCategoryCap int) (*CurateRoundResult, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, content FROM rules
		   WHERE source='sigmahq' AND enabled=false
		     AND (curate_state IS NULL OR curate_state IN ('pending','deferred'))`)
	if err != nil {
		return nil, err
	}
	var filter map[string]bool
	if len(categories) > 0 {
		filter = make(map[string]bool, len(categories))
		for _, c := range categories {
			filter[c] = true
		}
	}
	var batch []SyncedRule
	for rows.Next() {
		var id, content string
		if err := rows.Scan(&id, &content); err != nil {
			rows.Close()
			return nil, err
		}
		cat := RuleCategory(content)
		if filter != nil && !filter[cat] {
			continue
		}
		batch = append(batch, SyncedRule{ID: id, Category: cat, Content: content})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	plan := CurateBatchWith(batch, perCategoryCap, SupportedSigmaFields(), BuiltinCoverage())
	res := &CurateRoundResult{
		Enabled: len(plan.Enable), Deferred: len(plan.Deferred), Pending: len(plan.Pending),
		Duplicate: len(plan.Duplicate), SkippedDuplicates: plan.Duplicate,
		EnabledIDs: plan.Enable,
	}

	if len(plan.Enable) > 0 {
		if _, err := s.db.Exec(ctx,
			`UPDATE rules SET enabled=true, curate_state='enabled', curated_at=now(), quarantine_reason=NULL
			   WHERE id = ANY($1) AND source='sigmahq' AND enabled=false`, plan.Enable); err != nil {
			return nil, err
		}
	}
	// Stamp the leftovers so the status view / next round have an explicit reason.
	s.stampCurateState(ctx, "deferred", plan.Deferred)
	s.stampCurateState(ctx, "pending", plan.Pending)
	// A distinct state, not 'deferred': deferred means "next round", but an overlap
	// does not resolve by waiting. Recording why keeps these visible in the status
	// view and lets them be re-considered wholesale if a builtin is ever removed.
	s.stampCurateState(ctx, "builtin_duplicate", plan.Duplicate)
	if len(plan.Enable) > 0 {
		s.invalidate()
	}
	return res, nil
}

// stampCurateState records why a synced rule was left disabled this round.
//
// **落ちても次の周回が同じ判定をやり直すので、要求そのものは失敗させま
// せん。** 消えるのは理由の方です —— 状態ビューは「まだ見ていない」と
// 「見たうえで見送った」を区別できなくなり、**同じルールを毎周回
// 判定し直していることが、外からは分かりません。**
//
// `tick.FailComponent` は両方の呼ばれ方に合います。curate スケジューラ
// から来たときは**その回を成功として刻ませません**し、管理 API から
// 来たとき（回がありません）は部品ごとの件数だけが動きます。
//
// 切り出してあるのは、**通る木では `err != nil` の枝を一度も通らない**
// からです —— `CurateDB` の偽物に失敗させて直接呼びます
// （`curate_stamp_report_test.go`）。
func (s *CurateService) stampCurateState(ctx context.Context, state string, ids []string) {
	if len(ids) == 0 {
		return
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE rules SET curate_state=$2 WHERE id = ANY($1) AND source='sigmahq' AND enabled=false`,
		ids, state); err != nil {
		tick.FailComponent(ctx, "curate_stamp", err,
			"curate の見送り理由を記録できませんでした。状態ビューでは未判定と区別がつきません",
			"curate_state", state, "rules", len(ids))
	}
}

// MonitorFP disables curate-enabled synced rules that produced at least threshold
// alerts within window — the safety net that lets rounds auto-advance. A freshly
// auto-enabled community rule that suddenly floods alerts is almost always noisy
// (the FP target is ≤3/24h fleet-wide), so it is quarantined rather than left on.
// Only curate-enabled rules are touched — seeded/custom/operator-enabled rules and
// true-positive producers from before the curate era are never affected. Returns
// the quarantined rule IDs. Publishes rules.invalidate when any were disabled.
func (s *CurateService) MonitorFP(ctx context.Context, window time.Duration, threshold int) ([]string, error) {
	if threshold <= 0 {
		return nil, nil
	}
	interval := fmt.Sprintf("%d seconds", int(window.Seconds()))
	rows, err := s.db.Query(ctx,
		`SELECT a.rule_id::text, COUNT(*)
		   FROM alerts a JOIN rules r ON r.id = a.rule_id
		  WHERE r.source='sigmahq' AND r.enabled=true AND r.curate_state='enabled'
		    AND a.created_at > now() - $1::interval
		  GROUP BY a.rule_id
		 HAVING COUNT(*) >= $2`, interval, threshold)
	if err != nil {
		return nil, err
	}
	var noisy []string
	var maxCount int
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		noisy = append(noisy, id)
		if n > maxCount {
			maxCount = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(noisy) == 0 {
		return nil, nil
	}
	reason := fmt.Sprintf("FP自動隔離: 直近%sで閾値%d件以上のアラート(最大%d件)", window, threshold, maxCount)
	if _, err := s.Quarantine(ctx, noisy, reason); err != nil {
		return nil, err
	}
	return noisy, nil
}

// Quarantine disables the given synced rules and records why, so they are excluded
// from future rounds. Publishes rules.invalidate when any rows changed.
func (s *CurateService) Quarantine(ctx context.Context, ids []string, reason string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE rules SET enabled=false, curate_state='quarantined', quarantined_at=now(), quarantine_reason=$2
		   WHERE id = ANY($1) AND source='sigmahq'`, ids, reason)
	if err != nil {
		return 0, err
	}
	n := int(tag.RowsAffected())
	if n > 0 {
		s.invalidate()
	}
	return n, nil
}

// FieldGap is one missing telemetry field and how many enabled-but-inert Sigma
// rules reference it.
type FieldGap struct {
	Field string `json:"field"`
	Rules int    `json:"rules"`
}

// FieldGapReport scans enabled Sigma rules and reports those that are field-
// UNSUPPORTED — enabled yet unable to ever match because they select on a field the
// telemetry does not emit (a "false green"). Results are aggregated by the missing
// field, turning the manual field-support audit into a live, ranked telemetry
// roadmap: emitting the top field would resurrect that many currently-inert rules
// (measured 2026-07-02: OriginalFileName=74, Initiated=41, …). Returns the total
// inert-rule count and the gaps sorted most-rules-first. This is the field-based
// complement to InertRules (which is firing-based): FieldGap says a rule CANNOT
// fire and names the missing field; InertRules says a rule DIDN'T fire.
func (s *CurateService) FieldGapReport(ctx context.Context) (inert int, gaps []FieldGap, err error) {
	rows, err := s.db.Query(ctx,
		`SELECT content FROM rules WHERE source='sigmahq' AND enabled=true`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	supported := SupportedSigmaFields()
	freq := map[string]int{}
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return 0, nil, err
		}
		if len(RuleSelectedFields(content)) == 0 {
			continue // no parseable selection → not a field-gap case
		}
		ok, unsup := RuleFieldSupportWith(content, supported)
		if ok {
			continue
		}
		inert++
		for _, f := range unsup {
			freq[f]++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	for f, n := range freq {
		gaps = append(gaps, FieldGap{Field: f, Rules: n})
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Rules != gaps[j].Rules {
			return gaps[i].Rules > gaps[j].Rules
		}
		return gaps[i].Field < gaps[j].Field
	})
	return inert, gaps, nil
}

// ReconcileQuarantined enforces the invariant that a quarantined rule is disabled.
// Direct enable paths (a category-wide `UPDATE rules SET enabled=true`, a manual
// curate batch) can re-enable a rule without clearing curate_state='quarantined',
// so an FP rule that MonitorFP auto-quarantined starts firing again unnoticed
// (observed 2026-07-01: 3 rules, 424 FP/24h). This re-disables any such row and
// returns the count. Publishes rules.invalidate when any changed.
func (s *CurateService) ReconcileQuarantined(ctx context.Context) (int, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE rules SET enabled=false
		   WHERE source='sigmahq' AND curate_state='quarantined' AND enabled=true`)
	if err != nil {
		return 0, err
	}
	n := int(tag.RowsAffected())
	if n > 0 {
		s.invalidate()
	}
	return n, nil
}

// InertRules returns the names of curate-enabled Sigma rules that produced ZERO
// alerts within `window` despite being enabled longer than `minAge`. These are
// "enabled but silently inert" — the class of silent failure (a rule referencing a
// field the telemetry never emits, a broken alias) that goes unnoticed because the
// rule looks active. Same alerts↔rules join as MonitorFP (sigmahq alerts carry
// rule_id), so a rule with no matching alert rows never fired. The caller surfaces
// the count as a metric/log so an operator investigates before trusting coverage.
func (s *CurateService) InertRules(ctx context.Context, minAge, window time.Duration) ([]string, error) {
	rows, err := s.db.Query(ctx, `
		SELECT r.name
		  FROM rules r
		 WHERE r.source='sigmahq' AND r.enabled=true AND r.curate_state='enabled'
		   AND r.curated_at IS NOT NULL AND r.curated_at < now() - $1::interval
		   AND NOT EXISTS (
		       SELECT 1 FROM alerts a
		        WHERE a.rule_id = r.id AND a.created_at > now() - $2::interval)
		 ORDER BY r.curated_at
		 LIMIT 500`,
		fmt.Sprintf("%d seconds", int(minAge.Seconds())),
		fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// FalseGreenRules returns the names of ENABLED SigmaHQ rules that are field-
// UNSUPPORTED — enabled yet unable to fire because, on every path its condition
// can take, the detection selects a field live telemetry never populates. This is
// the static, field-contract complement to InertRules: where InertRules infers
// inertness from a week of zero alerts (and so only catches a rule long after it
// was mistakenly enabled), this flags a false green the instant it appears —
// whether from a rule enabled outside the curate field-support gate (a
// category-wide `UPDATE rules SET enabled=true`, a manual enable) or from
// telemetry coverage regressing after a rule was enabled. The curate scheduler
// surfaces the count as a metric/log so the field contract of the enabled set
// (driven to zero 2026-07-03) does not silently rot.
func (s *CurateService) FalseGreenRules(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT name, content FROM rules WHERE source='sigmahq' AND enabled=true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	supported := SupportedSigmaFields()
	var names []string
	for rows.Next() {
		var name, content string
		if err := rows.Scan(&name, &content); err != nil {
			return nil, err
		}
		if ok, _ := RuleFieldSupportWith(content, supported); !ok {
			names = append(names, name)
		}
	}
	return names, rows.Err()
}

func (s *CurateService) invalidate() {
	if s.pub != nil {
		_ = s.pub.Publish("rules.invalidate", []byte("{}"))
	}
}

func sortCategoryStats(stats []CurateCategoryStat) {
	for i := 1; i < len(stats); i++ {
		for j := i; j > 0; j-- {
			a, b := stats[j-1], stats[j]
			if a.Supported > b.Supported || (a.Supported == b.Supported && a.Category <= b.Category) {
				break
			}
			stats[j-1], stats[j] = stats[j], stats[j-1]
		}
	}
}
