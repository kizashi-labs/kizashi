package scheduler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// CertExpiryChecker checks TLS certificate expiry daily and creates alerts.
type CertExpiryChecker struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewCertExpiryChecker creates a new CertExpiryChecker.
func NewCertExpiryChecker(pool *pgxpool.Pool, nc *nats.Conn) *CertExpiryChecker {
	return &CertExpiryChecker{pool: pool, nc: nc}
}

// Run starts the checker: first run after 1 minute, then every 24 hours.
// Designed to be called as a goroutine.
func (c *CertExpiryChecker) Run(ctx context.Context) {
	// First check after 1 minute, then every 24 hours.
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	slog.Info("証明書有効期限チェッカーを起動しました")

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.checkCerts(ctx)
		case <-ticker.C:
			c.checkCerts(ctx)
		}
	}
}

// certRow holds a row from the certificates table.
type certRow struct {
	id     string
	domain string
}

// checkCerts queries the certificates table and checks each domain's TLS cert.
func (c *CertExpiryChecker) checkCerts(ctx context.Context) {
	slog.Info("TLS証明書の有効期限チェックを開始します")

	// Check if the certificates table exists.
	var tableExists bool
	err := c.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public'
			  AND tablename  = 'certificates'
		)`,
	).Scan(&tableExists)
	if err != nil {
		slog.Warn("certificatesテーブルの存在確認に失敗しました", "error", err)
		return
	}
	if !tableExists {
		slog.Debug("certificatesテーブルが存在しないためスキップします")
		return
	}

	rows, err := c.pool.Query(ctx,
		`SELECT id::text, domain FROM certificates WHERE domain IS NOT NULL AND domain <> ''`,
	)
	if err != nil {
		slog.Error("証明書一覧の取得に失敗しました", "error", err)
		return
	}
	defer rows.Close()

	var certs []certRow
	for rows.Next() {
		var r certRow
		if scanErr := rows.Scan(&r.id, &r.domain); scanErr != nil {
			continue
		}
		certs = append(certs, r)
	}
	rows.Close()

	slog.Info("証明書チェック対象", "count", len(certs))

	for _, cert := range certs {
		c.checkDomainCert(ctx, cert)
	}
}

// checkDomainCert dials the domain on port 443, reads the certificate expiry,
// and creates alerts as needed.
func (c *CertExpiryChecker) checkDomainCert(ctx context.Context, cert certRow) {
	addr := cert.domain + ":443"

	// Use a short dial timeout so we don't block the loop.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := (&tls.Dialer{
		Config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // intentional: we only need the expiry date
	}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		slog.Warn("TLS接続に失敗しました", "domain", cert.domain, "error", err)
		return
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		slog.Warn("TLS接続の型アサーションに失敗しました", "domain", cert.domain)
		return
	}

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		slog.Warn("ピア証明書が取得できませんでした", "domain", cert.domain)
		return
	}

	expiry := peerCerts[0].NotAfter
	daysLeft := int(time.Until(expiry).Hours() / 24)

	slog.Info("証明書の有効期限を確認しました",
		"domain", cert.domain,
		"expires", expiry.Format(time.RFC3339),
		"days_left", daysLeft,
	)

	// Determine severity based on days remaining.
	var severity int
	var alertTitle string
	switch {
	case daysLeft < 1:
		severity = 9
		alertTitle = fmt.Sprintf("証明書期限切れ: %s", cert.domain)
	case daysLeft < 7:
		severity = 7
		alertTitle = fmt.Sprintf("証明書まもなく期限切れ (残り%d日): %s", daysLeft, cert.domain)
	case daysLeft < 30:
		severity = 3
		alertTitle = fmt.Sprintf("証明書の有効期限が近づいています (残り%d日): %s", daysLeft, cert.domain)
	default:
		// Certificate is healthy — no alert needed.
		return
	}

	c.maybeCreateCertAlert(ctx, cert, alertTitle, expiry, daysLeft, severity)
}

// maybeCreateCertAlert creates an alert for the certificate only if no similar
// alert was already raised in the last 24 hours (deduplication).
func (c *CertExpiryChecker) maybeCreateCertAlert(
	ctx context.Context,
	cert certRow,
	title string,
	expiry time.Time,
	daysLeft int,
	severity int,
) {
	// Deduplication: skip if an alert with the same domain title exists in the last 24h.
	var existing int
	_ = c.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE title LIKE $1
		   AND created_at > NOW() - INTERVAL '24 hours'`,
		fmt.Sprintf("%%%s%%", cert.domain),
	).Scan(&existing)

	if existing > 0 {
		slog.Debug("証明書アラートは重複のためスキップします", "domain", cert.domain)
		return
	}

	description := fmt.Sprintf(
		"ドメイン %s のTLS証明書は %s に期限切れになります（残り %d 日）。",
		cert.domain, expiry.Format("2006-01-02"), daysLeft,
	)

	var alertID string
	err := c.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, description, severity, status)
		 VALUES ($1, $2, $3, 'open')
		 RETURNING id::text`,
		title, description, severity,
	).Scan(&alertID)
	if err != nil {
		slog.Error("証明書アラートの作成に失敗しました", "domain", cert.domain, "error", err)
		return
	}

	slog.Info("証明書アラートを作成しました",
		"alert_id", alertID,
		"domain", cert.domain,
		"days_left", daysLeft,
		"severity", severity,
	)

	// Publish NATS notification so consumers can react immediately.
	if c.nc != nil {
		payload, _ := json.Marshal(map[string]any{
			"alert_id":  alertID,
			"domain":    cert.domain,
			"days_left": daysLeft,
			"severity":  severity,
			"expires":   expiry.Format(time.RFC3339),
		})
		if pubErr := c.nc.Publish("alerts.new", payload); pubErr != nil {
			slog.Warn("alerts.new NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}
}
