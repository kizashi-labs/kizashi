package scheduler

// ComplianceAlerter turns the collected compliance-posture data (endpoint
// encryption + hardening assessments) into actionable alerts. It closes the
// loop opened by the dormant-feature work: agents now report disk-encryption
// state and hardening results, so an endpoint that is unencrypted or fails its
// hardening baseline should surface as an open alert rather than only nudging a
// scorecard number.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	// complianceCheckInterval is how often posture is re-evaluated. Compliance
	// state changes slowly, so this is far coarser than health monitoring.
	complianceCheckInterval = 30 * time.Minute
	// complianceDedupWindow suppresses repeat alerts for the same endpoint; a
	// persistent misconfiguration should not spam a new alert every cycle.
	complianceDedupWindow = 24 * time.Hour
	// hardeningScoreThreshold is the pass-rate below which a hardening baseline
	// is considered failing.
	hardeningScoreThreshold = 60.0
	// complianceSeverity is a medium-severity signal (alerts.severity is 1–10).
	complianceSeverity = 4
)

// ComplianceAlerter scans encryption/hardening posture and raises alerts.
type ComplianceAlerter struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewComplianceAlerter creates a ComplianceAlerter.
func NewComplianceAlerter(pool *pgxpool.Pool, nc *nats.Conn) *ComplianceAlerter {
	return &ComplianceAlerter{pool: pool, nc: nc}
}

// Run starts the periodic compliance-posture check. Designed to run as a goroutine.
func (a *ComplianceAlerter) Run(ctx context.Context) {
	ticker := time.NewTicker(complianceCheckInterval)
	defer ticker.Stop()
	slog.Info("コンプライアンスアラーター起動")
	// Evaluate once shortly after startup, then on every tick.
	a.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.check(ctx)
		}
	}
}

// complianceIssue holds a detected posture problem for one endpoint.
type complianceIssue struct {
	agentID     string
	hostname    string
	kind        string // "encryption" | "hardening"
	description string
}

func (a *ComplianceAlerter) check(ctx context.Context) {
	var issues []complianceIssue
	issues = append(issues, a.checkEncryption(ctx)...)
	issues = append(issues, a.checkHardening(ctx)...)
	for _, issue := range issues {
		a.maybeCreateAlert(ctx, issue)
	}
}

// checkEncryption finds endpoints that reported disk encryption as disabled.
// Endpoints that never reported (no row) are excluded — absence is "unknown",
// not "unencrypted".
func (a *ComplianceAlerter) checkEncryption(ctx context.Context) []complianceIssue {
	rows, err := a.pool.Query(ctx, `
		SELECT ag.id::text, ag.hostname, COALESCE(e.method,'')
		FROM endpoint_encryption e
		JOIN agents ag ON ag.id = e.agent_id
		WHERE e.encrypted IS FALSE
		LIMIT 200`)
	if err != nil {
		slog.Debug("暗号化コンプライアンスチェックをスキップ", "error", err)
		return nil
	}
	defer rows.Close()

	var issues []complianceIssue
	for rows.Next() {
		var id, hostname, method string
		if scanErr := rows.Scan(&id, &hostname, &method); scanErr != nil {
			continue
		}
		desc := "エンドポイントのディスク暗号化が無効です。データ保護のため暗号化を有効化してください。"
		if method != "" {
			desc = fmt.Sprintf("エンドポイントのディスク暗号化（%s）が無効です。データ保護のため暗号化を有効化してください。", method)
		}
		issues = append(issues, complianceIssue{
			agentID: id, hostname: hostname, kind: "encryption", description: desc,
		})
	}
	return issues
}

// checkHardening finds endpoints whose most-recent hardening assessment scores
// below the pass-rate threshold.
func (a *ComplianceAlerter) checkHardening(ctx context.Context) []complianceIssue {
	rows, err := a.pool.Query(ctx, `
		SELECT DISTINCT ON (ha.agent_id)
		       ag.id::text, ag.hostname, ha.score, ha.passed_checks, ha.failed_checks
		FROM hardening_assessments ha
		JOIN agents ag ON ag.id = ha.agent_id
		WHERE ha.status = 'completed'
		ORDER BY ha.agent_id, ha.assessed_at DESC NULLS LAST, ha.created_at DESC`)
	if err != nil {
		slog.Debug("ハードニングコンプライアンスチェックをスキップ", "error", err)
		return nil
	}
	defer rows.Close()

	var issues []complianceIssue
	for rows.Next() {
		var id, hostname string
		var score float64
		var passed, failed int
		if scanErr := rows.Scan(&id, &hostname, &score, &passed, &failed); scanErr != nil {
			continue
		}
		if score >= hardeningScoreThreshold {
			continue
		}
		desc := fmt.Sprintf(
			"エンドポイントのハードニング合格率が %.0f%%（%d/%d 合格）で閾値 %.0f%% を下回っています。設定を是正してください。",
			score, passed, passed+failed, hardeningScoreThreshold,
		)
		issues = append(issues, complianceIssue{
			agentID: id, hostname: hostname, kind: "hardening", description: desc,
		})
	}
	return issues
}

// maybeCreateAlert creates an alert unless a same-kind compliance alert for this
// endpoint already exists within complianceDedupWindow.
func (a *ComplianceAlerter) maybeCreateAlert(ctx context.Context, issue complianceIssue) {
	title := a.titleFor(issue)

	var existing int
	_ = a.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE agent_id = $1::uuid
		   AND title = $2
		   AND created_at > NOW() - $3::INTERVAL`,
		issue.agentID, title,
		fmt.Sprintf("%.0f seconds", complianceDedupWindow.Seconds()),
	).Scan(&existing)
	if existing > 0 {
		return
	}

	var alertID string
	err := a.pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status, source)
		 VALUES ($1::uuid, $2, $3, $4, 'open', 'compliance_posture')
		 RETURNING id::text`,
		issue.agentID, title, issue.description, complianceSeverity,
	).Scan(&alertID)
	if err != nil {
		slog.Error("コンプライアンスアラートの作成に失敗しました", "agent_id", issue.agentID, "error", err)
		return
	}

	slog.Info("コンプライアンスアラートを作成しました",
		"alert_id", alertID, "agent_id", issue.agentID, "hostname", issue.hostname, "kind", issue.kind)

	if a.nc != nil {
		payload, _ := json.Marshal(map[string]string{
			"alert_id": alertID, "agent_id": issue.agentID,
			"hostname": issue.hostname, "kind": issue.kind, "description": issue.description,
		})
		if pubErr := a.nc.Publish("alerts.new", payload); pubErr != nil {
			slog.Warn("alerts.new NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}
}

func (a *ComplianceAlerter) titleFor(issue complianceIssue) string {
	if issue.kind == "encryption" {
		return fmt.Sprintf("エンドポイント %s 暗号化コンプライアンス警告", issue.hostname)
	}
	return fmt.Sprintf("エンドポイント %s ハードニングコンプライアンス警告", issue.hostname)
}
