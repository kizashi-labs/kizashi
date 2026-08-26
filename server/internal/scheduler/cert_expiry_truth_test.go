package scheduler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CertExpiryChecker read a table called `certificates`, behind a guard that
// returned quietly when it did not exist. No migration creates it. Operators
// register domains through POST /admin/certificates, which writes
// monitored_certificates. Reproduced against the migrated schema: registering a
// domain and running a full check cycle examined zero certificates, raised zero
// alerts, and left the row exactly as inserted —
//
//	status="valid" days_remaining=0 expires_at IS NULL=true
//
// The console COALESCEs a NULL expires_at to NOW(), so every monitored domain
// displayed as valid and expiring today, for ever. A monitoring page whose only
// possible answer is "fine" is worse than no page: it is relied upon.
//
// These tests serve real TLS on loopback with a certificate whose NotAfter the
// test chooses, so the whole path — dial, read, classify, record, alert — runs
// against something true. Each test uses its own loopback address so the
// duplicate check in one cannot reach another's alerts.
//
// Mutation-tested at 19 mutations, 18 killed. The survivor is the rows.Err()
// check added to checkCerts: pgx sets it on a mid-iteration failure, which a
// SELECT of a handful of local rows will not produce, so no test here can
// distinguish its presence. It is recorded rather than covered by a test that
// only appears to check it.

func certPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// serveTLSUntil starts a TLS listener on the given loopback address whose
// certificate expires at notAfter, and returns the port it is listening on.
//
// Note this cannot be a live public domain: the sandbox's egress proxy
// terminates TLS, so dialling expired.badssl.com returns the proxy's
// certificate with a month left on it. A local listener is the only way to
// assert on an expiry the test actually chose.
func serveTLSUntil(t *testing.T, host string, notAfter time.Time) int {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		Issuer:       pkix.Name{CommonName: "Kizashi Test CA"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IPAddresses:  []net.IP{net.ParseIP(host)},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	ln, err := tls.Listen("tcp", net.JoinHostPort(host, "0"), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// The handshake is all the checker needs; reading one byte drives it.
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return port
}

// monitorDomain registers a domain the way POST /admin/certificates does and
// removes it, plus any alert raised for it, when the test ends.
func monitorDomain(t *testing.T, pool *pgxpool.Pool, domain string, port int) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO monitored_certificates (domain, port) VALUES ($1,$2) RETURNING id::text`,
		domain, port).Scan(&id); err != nil {
		t.Fatalf("register domain: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE source=$1 AND title LIKE $2`,
			certAlertSource, "%"+domain+"%")
		_, _ = pool.Exec(c, `DELETE FROM monitored_certificates WHERE id=$1::uuid`, id)
	})
	return id
}

// certState is the row the admin console reads back.
type certState struct {
	status      string
	issuer      string
	expiresAt   *time.Time
	lastChecked time.Time
}

func readCertState(t *testing.T, pool *pgxpool.Pool, id string) certState {
	t.Helper()
	var s certState
	if err := pool.QueryRow(context.Background(),
		`SELECT status, issuer, expires_at, last_checked FROM monitored_certificates WHERE id=$1::uuid`,
		id).Scan(&s.status, &s.issuer, &s.expiresAt, &s.lastChecked); err != nil {
		t.Fatalf("read cert state: %v", err)
	}
	return s
}

// certAlerts returns this checker's alerts for a domain, most severe first.
func certAlerts(t *testing.T, pool *pgxpool.Pool, domain string) []int {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT severity FROM alerts WHERE source=$1 AND title LIKE $2 ORDER BY severity DESC`,
		certAlertSource, "%"+domain+"%")
	if err != nil {
		t.Fatalf("read alerts: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var s int
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// TestCertificateClassification is the pure half, and the important one: an
// out-of-range severity is rejected by alerts_severity_check and an unknown
// status by monitored_certificates_status_check, and both failures are
// discarded by the callers. A wrong verdict is therefore invisible through the
// database — it has to be asserted here.
func TestCertificateClassification(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		expiry   time.Time
		status   string
		severity int
		alert    bool
	}{
		{"expired yesterday", now.Add(-24 * time.Hour), certStatusExpired, 9, true},
		{"expired one second ago", now.Add(-time.Second), certStatusExpired, 9, true},
		{"eleven hours left is not expired", now.Add(11 * time.Hour), certStatusExpiring, 7, true},
		{"three days left", now.Add(3 * 24 * time.Hour), certStatusExpiring, 7, true},
		{"twenty days left", now.Add(20 * 24 * time.Hour), certStatusExpiring, 3, true},
		{"ninety days left", now.Add(90 * 24 * time.Hour), certStatusValid, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCert("example.test", tc.expiry, now)
			if got.status != tc.status {
				t.Errorf("status = %q, want %q", got.status, tc.status)
			}
			if got.alert != tc.alert {
				t.Errorf("alert = %v, want %v", got.alert, tc.alert)
			}
			if !tc.alert {
				return
			}
			if got.severity != tc.severity {
				t.Errorf("severity = %d, want %d", got.severity, tc.severity)
			}
			if got.severity < 1 || got.severity > 10 {
				t.Errorf("severity %d is outside alerts_severity_check (1..10); the "+
					"INSERT would fail with 23514 and the error is discarded", got.severity)
			}
			if got.title == "" {
				t.Error("no title — the responder gets an alert that says nothing")
			}
		})
	}
}

// TestAnExpiringCertificateIsRecordedAndAlerted is the core gate. It fails on
// any build where the checker reads a table nobody writes, because then nothing
// is examined at all.
func TestAnExpiringCertificateIsRecordedAndAlerted(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.2"
	expiry := time.Now().Add(3 * 24 * time.Hour).Truncate(time.Second)
	port := serveTLSUntil(t, host, expiry)
	id := monitorDomain(t, pool, host, port)

	before := readCertState(t, pool, id)
	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())
	after := readCertState(t, pool, id)

	if after.expiresAt == nil {
		t.Fatal("expires_at is still NULL after a full check cycle. The checker " +
			"examined nothing, and the console shows this domain as valid and " +
			"expiring today.")
	}
	if d := after.expiresAt.Sub(expiry); d > time.Minute || d < -time.Minute {
		t.Errorf("expires_at = %v, want %v", after.expiresAt, expiry)
	}
	if after.status != certStatusExpiring {
		t.Errorf("status = %q, want %q for a certificate with three days left",
			after.status, certStatusExpiring)
	}
	if after.issuer == "" {
		t.Error("issuer was not recorded, so the console cannot say who to renew with")
	}
	if !after.lastChecked.After(before.lastChecked) {
		t.Error("last_checked did not advance, so an operator cannot tell whether " +
			"the check is running at all")
	}

	if got := certAlerts(t, pool, host); len(got) == 0 {
		t.Error("no alert for a certificate three days from expiry")
	} else if got[0] != 7 {
		t.Errorf("alert severity = %d, want 7", got[0])
	}
}

// TestAHealthyCertificateRaisesNoAlert is the floor. Without it the fix could be
// "always alert", which trains the operator to ignore the alert.
func TestAHealthyCertificateRaisesNoAlert(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.3"
	port := serveTLSUntil(t, host, time.Now().Add(200*24*time.Hour))
	id := monitorDomain(t, pool, host, port)

	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())

	if s := readCertState(t, pool, id); s.status != certStatusValid {
		t.Errorf("status = %q, want %q for a certificate with 200 days left",
			s.status, certStatusValid)
	}
	if got := certAlerts(t, pool, host); len(got) != 0 {
		t.Errorf("%d alert(s) for a healthy certificate", len(got))
	}
}

// TestTheMonitoredPortIsUsed. The API stores a port per domain and defaults it
// to 443; the checker appended ":443" unconditionally, so every domain
// monitored on 8443 or 9443 was silently dialled on the wrong port. This test
// serves on an ephemeral port, which 443 will never be.
func TestTheMonitoredPortIsUsed(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.4"
	port := serveTLSUntil(t, host, time.Now().Add(3*24*time.Hour))
	id := monitorDomain(t, pool, host, port)

	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())

	if s := readCertState(t, pool, id); s.status != certStatusExpiring {
		t.Errorf("status = %q, want %q — the certificate served on port %d was not "+
			"reached, so the registered port is being ignored", s.status,
			certStatusExpiring, port)
	}
}

// TestAnEscalationIsNotSuppressedByAnEarlierNotice. The duplicate check matched
// any alert whose title contained the domain, so the "30 days left" notice
// suppressed the "expired" alert that followed it for 24 hours — the one
// escalation that matters was the one guaranteed to be swallowed.
func TestAnEscalationIsNotSuppressedByAnEarlierNotice(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.5"
	port := serveTLSUntil(t, host, time.Now().Add(-24*time.Hour))
	id := monitorDomain(t, pool, host, port)

	// Yesterday's low-severity notice for the same domain.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO alerts (title, description, severity, status, source)
		 VALUES ($1, 'earlier notice', 3, 'open', $2)`,
		"証明書の有効期限が近づいています (残り20日): "+host, certAlertSource); err != nil {
		t.Fatalf("seed prior alert: %v", err)
	}

	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())

	if s := readCertState(t, pool, id); s.status != certStatusExpired {
		t.Errorf("status = %q, want %q", s.status, certStatusExpired)
	}
	sevs := certAlerts(t, pool, host)
	if len(sevs) == 0 || sevs[0] < 9 {
		t.Errorf("alert severities = %v: the expiry alert was suppressed by the "+
			"earlier low-severity notice", sevs)
	}
}

// TestSomebodyElsesAlertDoesNotSuppressThisOne. The duplicate check matched on
// the domain appearing anywhere in any alert's title. A detection alert naming
// the same host — which is exactly what a compromised host produces — therefore
// silenced the certificate alert for a day. Scoping the check to this checker's
// own source is what stops one subsystem muting another.
func TestSomebodyElsesAlertDoesNotSuppressThisOne(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.8"
	port := serveTLSUntil(t, host, time.Now().Add(3*24*time.Hour))
	monitorDomain(t, pool, host, port)

	var otherID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO alerts (title, description, severity, status, source)
		 VALUES ($1, 'unrelated finding', 9, 'open', 'detection') RETURNING id::text`,
		"C2通信を検出: "+host).Scan(&otherID); err != nil {
		t.Fatalf("seed unrelated alert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id=$1::uuid`, otherID)
	})

	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())

	if got := certAlerts(t, pool, host); len(got) == 0 {
		t.Error("the certificate alert was suppressed by an unrelated alert that " +
			"merely mentions the same host")
	}
}

// TestTheSameVerdictIsNotAlertedTwice keeps the other side honest: the check
// runs daily, and an operator who gets the same severity-3 notice every day
// stops reading them.
func TestTheSameVerdictIsNotAlertedTwice(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.6"
	port := serveTLSUntil(t, host, time.Now().Add(20*24*time.Hour))
	monitorDomain(t, pool, host, port)

	c := NewCertExpiryChecker(pool, nil)
	c.checkCerts(context.Background())
	first := len(certAlerts(t, pool, host))
	if first == 0 {
		t.Fatal("no alert on the first check")
	}
	c.checkCerts(context.Background())

	if got := len(certAlerts(t, pool, host)); got != first {
		t.Errorf("alerts went from %d to %d on a second check of the same "+
			"certificate", first, got)
	}
}

// TestAnUnreachableHostIsRecordedAsError. Leaving the row untouched makes a host
// nobody can dial indistinguishable from one whose certificate is fine.
func TestAnUnreachableHostIsRecordedAsError(t *testing.T) {
	pool := certPool(t)
	const host = "127.0.0.7"
	// Nothing is listening here.
	id := monitorDomain(t, pool, host, 1)

	NewCertExpiryChecker(pool, nil).checkCerts(context.Background())

	s := readCertState(t, pool, id)
	if s.status != certStatusError {
		t.Errorf("status = %q, want %q for a host that could not be dialled",
			s.status, certStatusError)
	}
	if got := certAlerts(t, pool, host); len(got) != 0 {
		t.Errorf("%d alert(s) raised for an unreachable host; that is a connectivity "+
			"problem, not a certificate expiry", len(got))
	}
}

// TestTheCertStatusesWrittenAreOnesTheSchemaAccepts. Every status this checker
// writes goes through a CHECK constraint. Both UPDATE sites now report a
// rejection through `fail`, but the row still keeps its old status, so the
// console shows no difference — the value has to be right in the first place.
func TestTheCertStatusesWrittenAreOnesTheSchemaAccepts(t *testing.T) {
	pool := certPool(t)
	ctx := context.Background()
	for _, s := range []string{certStatusValid, certStatusExpiring, certStatusExpired, certStatusError} {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO monitored_certificates (domain, port, status) VALUES ($1,443,$2) RETURNING id::text`,
			"status-probe-"+s, s).Scan(&id); err != nil {
			t.Errorf("the schema rejects status %q, which the checker writes: %v", s, err)
			continue
		}
		_, _ = pool.Exec(ctx, `DELETE FROM monitored_certificates WHERE id=$1::uuid`, id)
	}
}
