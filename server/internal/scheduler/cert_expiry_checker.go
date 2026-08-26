package scheduler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// The statuses monitored_certificates.status may hold. The column carries a
// CHECK constraint naming exactly these four; a value outside the set fails the
// UPDATE with 23514, so they are spelled out here rather than inline.
const (
	certStatusValid    = "valid"
	certStatusExpiring = "expiring_soon"
	certStatusExpired  = "expired"
	certStatusError    = "error"
)

// certAlertSource tags the alerts this checker raises so the duplicate check can
// find its own work instead of matching any alert that happens to mention the
// domain.
const certAlertSource = "cert_expiry"

// **握手は通ったのに、読む証明書が無い2つの形です。**
//
// どちらも `error` 値を持たない失敗でした。`fail` は error を要るので、
// この2つだけ `slog.Warn` に残っていて —— **Warn は運用の設定で最初に
// 切られる段**です。行には `status='error'` が入るので画面には出ますが、
// **その回は成功として刻まれ続けました**。名前のある error を作って
// `fail` に渡します。
var (
	errNotATLSConn       = errors.New("TLS接続の型アサーションに失敗しました")
	errNoPeerCertificate = errors.New("ピア証明書が0件でした")
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
			trackRun(ctx, "cert_expiry_checker", c.checkCerts)
		case <-ticker.C:
			trackRun(ctx, "cert_expiry_checker", c.checkCerts)
		}
	}
}

// certRow holds a row from monitored_certificates.
type certRow struct {
	id     string
	domain string
	port   int
}

// checkCerts reads the monitored certificates and checks each one.
//
// This used to read a table called `certificates`, behind an
// EXISTS-on-pg_tables guard that returned at Debug level when it was absent. No
// migration creates that table — operators register domains through
// POST /admin/certificates, which writes monitored_certificates (migration 223)
// — so the guard held on every run and not one certificate has ever been
// checked. The console reads monitored_certificates directly and COALESCEs a
// NULL expires_at to NOW(), so every registered domain displayed as
// status=valid with days_remaining=0, for ever.
func (c *CertExpiryChecker) checkCerts(ctx context.Context) {
	slog.Info("TLS証明書の有効期限チェックを開始します")

	rows, err := c.pool.Query(ctx,
		`SELECT id::text, domain, port FROM monitored_certificates
		 WHERE domain IS NOT NULL AND domain <> ''`,
	)
	if err != nil {
		fail(ctx, err, "証明書一覧の取得に失敗しました")
		return
	}
	defer rows.Close()

	var certs []certRow
	for rows.Next() {
		var r certRow
		if scanErr := rows.Scan(&r.id, &r.domain, &r.port); scanErr != nil {
			continue
		}
		certs = append(certs, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		fail(ctx, rowsErr, "証明書一覧の読み出しに失敗しました")
		return
	}
	rows.Close()

	slog.Info("証明書チェック対象", "count", len(certs))

	for _, cert := range certs {
		c.checkDomainCert(ctx, cert)
	}
}

// certVerdict is what a certificate's expiry means, decided without touching the
// database or the network so it can be tested directly. Getting it wrong is
// hard to see from outside: an out-of-range severity is rejected by the alerts
// CHECK constraint and an unknown status by the monitored_certificates one, and
// both rejections surface only as one failed run — the row keeps its old status
// and the console shows no difference.
type certVerdict struct {
	status   string
	title    string
	severity int
	alert    bool
}

// classifyCert maps an expiry date onto the console status and, when action is
// needed, an alert title and severity.
//
// Expiry is decided by comparing the timestamps, not by the day count: the day
// count truncates toward zero, so a certificate with eleven hours left has
// daysLeft == 0. The previous ladder treated that as already expired and told
// the responder so, which is both wrong and the opposite of useful — there is
// still time to renew.
func classifyCert(domain string, expiry, now time.Time) certVerdict {
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	switch {
	case !expiry.After(now):
		return certVerdict{
			status:   certStatusExpired,
			title:    fmt.Sprintf("証明書期限切れ: %s", domain),
			severity: 9,
			alert:    true,
		}
	case daysLeft < 7:
		return certVerdict{
			status:   certStatusExpiring,
			title:    fmt.Sprintf("証明書まもなく期限切れ (残り%d日): %s", daysLeft, domain),
			severity: 7,
			alert:    true,
		}
	case daysLeft < 30:
		return certVerdict{
			status:   certStatusExpiring,
			title:    fmt.Sprintf("証明書の有効期限が近づいています (残り%d日): %s", daysLeft, domain),
			severity: 3,
			alert:    true,
		}
	default:
		return certVerdict{status: certStatusValid}
	}
}

// checkDomainCert dials the monitored host, reads the certificate, records what
// it found, and raises an alert when the verdict calls for one.
func (c *CertExpiryChecker) checkDomainCert(ctx context.Context, cert certRow) {
	port := cert.port
	if port <= 0 {
		port = 443
	}
	addr := net.JoinHostPort(cert.domain, strconv.Itoa(port))

	// Use a short dial timeout so we don't block the loop.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := (&tls.Dialer{
		Config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // intentional: we only need the expiry date
	}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		fail(ctx, err, "TLS接続に失敗しました", "domain", cert.domain, "port", port)
		c.recordCertUnreachable(ctx, cert)
		return
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		fail(ctx, fmt.Errorf("%w (%T)", errNotATLSConn, conn),
			"証明書を読めませんでした", "domain", cert.domain, "port", port)
		c.recordCertUnreachable(ctx, cert)
		return
	}

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		fail(ctx, errNoPeerCertificate,
			"証明書を読めませんでした", "domain", cert.domain, "port", port)
		c.recordCertUnreachable(ctx, cert)
		return
	}

	expiry := peerCerts[0].NotAfter
	issuer := peerCerts[0].Issuer.CommonName
	now := time.Now()
	daysLeft := int(expiry.Sub(now).Hours() / 24)
	verdict := classifyCert(cert.domain, expiry, now)

	slog.Info("証明書の有効期限を確認しました",
		"domain", cert.domain,
		"expires", expiry.Format(time.RFC3339),
		"days_left", daysLeft,
		"status", verdict.status,
	)

	c.recordCertState(ctx, cert, expiry, issuer, verdict.status)

	if !verdict.alert {
		return
	}
	c.maybeCreateCertAlert(ctx, cert, verdict, expiry, daysLeft)
}

// recordCertState writes what the check found back to the row the console reads.
// Without this the admin certificates page shows every monitored domain as
// valid with no expiry, which is exactly the state a monitoring page exists to
// rule out.
func (c *CertExpiryChecker) recordCertState(
	ctx context.Context, cert certRow, expiry time.Time, issuer, status string,
) {
	if _, err := c.pool.Exec(ctx,
		`UPDATE monitored_certificates
		 SET expires_at = $2, issuer = $3, status = $4, last_checked = NOW()
		 WHERE id = $1::uuid`,
		cert.id, expiry, issuer, status,
	); err != nil {
		fail(ctx, err, "証明書の状態更新に失敗しました", "domain", cert.domain)
	}
}

// recordCertUnreachable marks a host the checker could not reach. A domain that
// cannot be dialled is not the same as one whose certificate is fine, and
// leaving the row untouched makes the two indistinguishable on the console.
func (c *CertExpiryChecker) recordCertUnreachable(ctx context.Context, cert certRow) {
	if _, err := c.pool.Exec(ctx,
		`UPDATE monitored_certificates
		 SET status = $2, last_checked = NOW()
		 WHERE id = $1::uuid`,
		cert.id, certStatusError,
	); err != nil {
		fail(ctx, err, "証明書の状態更新に失敗しました", "domain", cert.domain)
	}
}

// maybeCreateCertAlert creates an alert for the certificate unless this checker
// already raised one at least as severe for the same domain in the last 24
// hours.
//
// The severity floor matters. The duplicate check used to match any alert whose
// title contained the domain, so the "30 days left" notice suppressed the
// "expired" alert that followed it — the escalation an operator actually needs
// was the one guaranteed to be swallowed.
func (c *CertExpiryChecker) maybeCreateCertAlert(
	ctx context.Context,
	cert certRow,
	verdict certVerdict,
	expiry time.Time,
	daysLeft int,
) {
	var existing int
	_ = c.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE source = $1
		   AND title LIKE $2
		   AND severity >= $3
		   AND created_at > NOW() - INTERVAL '24 hours'`,
		certAlertSource, fmt.Sprintf("%%%s%%", cert.domain), verdict.severity,
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
		`INSERT INTO alerts (title, description, severity, status, source)
		 VALUES ($1, $2, $3, 'open', $4)
		 RETURNING id::text`,
		verdict.title, description, verdict.severity, certAlertSource,
	).Scan(&alertID)
	if err != nil {
		fail(ctx, err, "証明書アラートの作成に失敗しました", "domain", cert.domain)
		return
	}

	slog.Info("証明書アラートを作成しました",
		"alert_id", alertID,
		"domain", cert.domain,
		"days_left", daysLeft,
		"severity", verdict.severity,
	)

	// Publish NATS notification so consumers can react immediately.
	if c.nc != nil {
		payload, _ := json.Marshal(map[string]any{
			"alert_id":  alertID,
			"domain":    cert.domain,
			"days_left": daysLeft,
			"severity":  verdict.severity,
			"expires":   expiry.Format(time.RFC3339),
		})
		if pubErr := c.nc.Publish("alerts.new", payload); pubErr != nil {
			fail(ctx, pubErr, "alerts.new NATSパブリッシュに失敗しました")
		}
	}
}
