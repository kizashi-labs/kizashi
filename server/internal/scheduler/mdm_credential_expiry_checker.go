package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// MDMCredentialExpiryChecker raises alerts when MDM integration credentials
// (APNs p12, ABM server token, AE SA key, etc.) are approaching expiry.
// It runs daily and mirrors the severity ladder of the TLS cert checker:
// 30 / 7 / 1 day thresholds.
//
// Expiry data comes from the mdm_integrations.credential_expiry column,
// which is populated by the /sync endpoint on each adapter run — so the
// scheduler reads passive data and does NOT re-contact upstream APIs.
type MDMCredentialExpiryChecker struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

func NewMDMCredentialExpiryChecker(pool *pgxpool.Pool, nc *nats.Conn) *MDMCredentialExpiryChecker {
	return &MDMCredentialExpiryChecker{pool: pool, nc: nc}
}

// Run starts the checker: first run after 2 minutes (staggered after
// TLS cert checker to avoid alert-creation pileups at startup), then
// every 24 hours.
func (c *MDMCredentialExpiryChecker) Run(ctx context.Context) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	slog.Info("MDM資格情報有効期限チェッカーを起動しました")

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			trackRun(ctx, "mdm_credential_expiry_checker", c.check)
		case <-ticker.C:
			trackRun(ctx, "mdm_credential_expiry_checker", c.check)
		}
	}
}

type mdmIntegrationRow struct {
	integType   string
	displayName string
	expiry      time.Time
}

func (c *MDMCredentialExpiryChecker) check(ctx context.Context) {
	// Skip gracefully if the column doesn't exist (fresh clone without
	// migration 233 applied). `to_regclass` + `information_schema.columns`
	// is the standard probe.
	var hasColumn bool
	err := c.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public'
			  AND table_name='mdm_integrations'
			  AND column_name='credential_expiry'
		)
	`).Scan(&hasColumn)
	if err != nil {
		fail(ctx, err, "mdm_integrations列の存在確認に失敗しました")
		return
	}
	if !hasColumn {
		slog.Debug("mdm_integrations.credential_expiry 列が無いためスキップします")
		return
	}

	// Only check integrations that are enabled and have a stored expiry.
	// Disabled integrations still in the DB (e.g. APNs cert uploaded but
	// not yet toggled on) would spam alerts for credentials not in use.
	rows, err := c.pool.Query(ctx, `
		SELECT integration_type, display_name, credential_expiry
		FROM mdm_integrations
		WHERE enabled = true AND credential_expiry IS NOT NULL
	`)
	if err != nil {
		fail(ctx, err, "MDM統合一覧の取得に失敗しました")
		return
	}
	defer rows.Close()

	var items []mdmIntegrationRow
	for rows.Next() {
		var r mdmIntegrationRow
		if scanErr := rows.Scan(&r.integType, &r.displayName, &r.expiry); scanErr != nil {
			continue
		}
		items = append(items, r)
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "MDM統合一覧の走査が途中で終わりました。期限切れ警告が出ない統合があります")
	}
	rows.Close()

	slog.Info("MDM資格情報チェック対象", "count", len(items))

	for _, it := range items {
		c.evaluate(ctx, it)
	}
}

func (c *MDMCredentialExpiryChecker) evaluate(ctx context.Context, it mdmIntegrationRow) {
	daysLeft := int(time.Until(it.expiry).Hours() / 24)
	severity, title, notify := expirySeverity(daysLeft, it.displayName)
	if !notify {
		return
	}
	c.maybeCreateAlert(ctx, it, title, daysLeft, severity)
}

// expirySeverity maps a days-remaining count to the alert severity ladder.
// Pulled out as a pure function so the ladder can be unit-tested without
// a DB. Returns notify=false when the credential is healthy enough that
// no alert should be raised (> 30 days).
func expirySeverity(daysLeft int, displayName string) (severity int, title string, notify bool) {
	switch {
	case daysLeft < 1:
		return 9, fmt.Sprintf("MDM資格情報が期限切れ: %s", displayName), true
	case daysLeft < 7:
		return 7, fmt.Sprintf("MDM資格情報がまもなく期限切れ (残り%d日): %s", daysLeft, displayName), true
	case daysLeft < 30:
		return 3, fmt.Sprintf("MDM資格情報の有効期限が近づいています (残り%d日): %s", daysLeft, displayName), true
	default:
		return 0, "", false
	}
}

// maybeCreateAlert writes an alert row if no similar one exists in the
// last 24 hours, keyed on integration_type in the title. Dedup prevents
// the daily scheduler from creating 30 duplicate rows during a 30-day
// runway.
func (c *MDMCredentialExpiryChecker) maybeCreateAlert(
	ctx context.Context,
	it mdmIntegrationRow,
	title string,
	daysLeft int,
	severity int,
) {
	// LIKE escape: a display_name containing '%' or '_' would turn into
	// SQL wildcards and silently suppress unrelated alerts. We use '\' as
	// the escape char matching the explicit ESCAPE clause below.
	safeName := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(it.displayName)
	var existing int
	_ = c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE title LIKE $1 ESCAPE '\' AND created_at > NOW() - INTERVAL '24 hours'
	`, fmt.Sprintf("%%%s%%", safeName)).Scan(&existing)

	if existing > 0 {
		slog.Debug("MDM資格情報アラートは重複のためスキップします", "integration", it.integType)
		return
	}

	description := fmt.Sprintf(
		"MDM統合 %s (%s) の資格情報は %s に期限切れになります（残り %d 日）。管理画面から更新してください。",
		it.displayName, it.integType, it.expiry.Format("2006-01-02"), daysLeft,
	)

	var alertID string
	err := c.pool.QueryRow(ctx, `
		INSERT INTO alerts (title, description, severity, status)
		VALUES ($1, $2, $3, 'open')
		RETURNING id::text
	`, title, description, severity).Scan(&alertID)
	if err != nil {
		fail(ctx, err, "MDM資格情報アラートの作成に失敗しました", "integration", it.integType)
		return
	}

	slog.Info("MDM資格情報アラートを作成しました",
		"alert_id", alertID,
		"integration", it.integType,
		"days_left", daysLeft,
		"severity", severity,
	)

	if c.nc != nil {
		payload, _ := json.Marshal(map[string]any{
			"alert_id":    alertID,
			"integration": it.integType,
			"days_left":   daysLeft,
			"severity":    severity,
			"expires":     it.expiry.Format(time.RFC3339),
		})
		if pubErr := c.nc.Publish("alerts.new", payload); pubErr != nil {
			fail(ctx, pubErr, "alerts.new NATSパブリッシュに失敗しました")
		}
	}
}
