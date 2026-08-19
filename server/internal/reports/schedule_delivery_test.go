package reports

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/email"
)

// Two loops used to consume scheduled_reports: this Scheduler and a second one
// in internal/scheduler (ReportGenerator). The second was written against
// column names the table does not have — it looked for next_run_at, found
// nothing, and so selected due reports with no time filter at all. Measured
// against the migrated schema: three ticks produced three full reports for a
// schedule whose next_run was a day away, and its
// `UPDATE scheduled_reports SET next_run_at = ...` failed with 42703 into a
// discarded error, so the schedule never advanced. At a 5-minute tick that is
// 288 reports per schedule per day, none of them delivered, for ever.
//
// That loop is gone. These tests hold the surviving one to the three things it
// was doing right, so the deletion cannot quietly become a regression:
// the due filter, delivery to every recipient, and advancing the schedule in
// the real table using the real column names.

// fakeSMTP is a minimal SMTP server that records the recipients and message
// bodies it is given. It advertises no extensions, so email.Sender skips
// STARTTLS, and no auth is configured, so it skips AUTH.
type fakeSMTP struct {
	ln         net.Listener
	mu         sync.Mutex
	recipients []string
	bodies     []string
	wg         sync.WaitGroup
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSMTP{ln: ln}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeSMTP) addr() (string, int) {
	host, portStr, _ := net.SplitHostPort(f.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }

	w("220 fake ESMTP")
	var body strings.Builder
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.bodies = append(f.bodies, body.String())
				f.mu.Unlock()
				body.Reset()
				w("250 OK")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			// No extension lines: nothing to negotiate, so no STARTTLS.
			w("250 fake")
		case strings.HasPrefix(upper, "MAIL FROM"):
			w("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			addr := line[strings.Index(line, ":")+1:]
			f.mu.Lock()
			f.recipients = append(f.recipients, strings.Trim(strings.TrimSpace(addr), "<>"))
			f.mu.Unlock()
			w("250 OK")
		case strings.HasPrefix(upper, "DATA"):
			inData = true
			w("354 send it")
		case strings.HasPrefix(upper, "QUIT"):
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func (f *fakeSMTP) delivered() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.recipients...), append([]string(nil), f.bodies...)
}

// senderTo builds an email.Sender aimed at the fake server. Its fields are
// unexported and only NewSenderFromEnv constructs one, so the environment is
// the seam.
func senderTo(t *testing.T, f *fakeSMTP) *email.Sender {
	t.Helper()
	host, port := f.addr()
	t.Setenv("SMTP_HOST", host)
	t.Setenv("SMTP_PORT", strconv.Itoa(port))
	t.Setenv("SMTP_USERNAME", "")
	t.Setenv("SMTP_PASSWORD", "")
	t.Setenv("SMTP_FROM", "edr@example.com")
	s := email.NewSenderFromEnv()
	if s == nil {
		t.Fatal("NewSenderFromEnv returned nil with SMTP_HOST set")
	}
	return s
}

// TestOnlyDueSchedulesRun is the filter the deleted loop did not have.
func TestOnlyDueSchedulesRun(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		r    *ScheduledReport
		want bool
	}{
		{"next run is in the future",
			&ScheduledReport{Enabled: true, NextRun: now.Add(24 * time.Hour)}, false},
		{"next run has passed",
			&ScheduledReport{Enabled: true, NextRun: now.Add(-time.Minute)}, true},
		{"next run is exactly now",
			&ScheduledReport{Enabled: true, NextRun: now}, true},
		{"disabled schedules never run",
			&ScheduledReport{Enabled: false, NextRun: now.Add(-24 * time.Hour)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDue(tc.r, now); got != tc.want {
				t.Errorf("isDue = %v, want %v. Without this filter every enabled "+
					"schedule fires on every tick.", got, tc.want)
			}
		})
	}
}

// TestARunScheduleReachesEveryRecipient is the core delivery gate.
func TestARunScheduleReachesEveryRecipient(t *testing.T) {
	pool := covSchedPool(t)
	f := startFakeSMTP(t)
	s := NewScheduler(pool, NewGenerator(pool), senderTo(t, f))

	r := &ScheduledReport{
		Name: "delivery-gate", ReportType: "executive_summary",
		Schedule: "0 8 * * 1", Format: "json",
		Recipients: []string{"soc@example.com", "ciso@example.com"},
		Enabled:    true,
	}
	if err := s.AddSchedule(context.Background(), r); err != nil {
		t.Fatalf("AddSchedule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM scheduled_reports WHERE id=$1`, r.ID)
	})

	s.runReport(context.Background(), r, time.Now().UTC())

	got, bodies := f.delivered()
	for _, want := range r.Recipients {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no message was delivered to %s (delivered to %v). A scheduled "+
				"report that generates a file and mails nobody is a report nobody reads.",
				want, got)
		}
	}
	if len(bodies) < len(r.Recipients) {
		t.Fatalf("%d message bodies for %d recipients", len(bodies), len(r.Recipients))
	}

	// The HTML body specifically, not the whole message: the Subject header also
	// carries the report name, so asserting on the raw message would pass even
	// with an empty body.
	body := bodies[0]
	if i := strings.Index(body, "\n\n"); i >= 0 {
		body = body[i+2:]
	}
	if !strings.Contains(body, "<h2>delivery-gate</h2>") {
		t.Errorf("the body does not name the report it is about:\n%s", bodies[0])
	}

	// Each recipient's own address has to appear in their copy's To: header —
	// the envelope alone is not what the reader sees.
	var headers []string
	for _, m := range bodies {
		for _, line := range strings.Split(m, "\n") {
			if strings.HasPrefix(line, "To: ") {
				headers = append(headers, strings.TrimSpace(strings.TrimPrefix(line, "To: ")))
			}
		}
	}
	for _, want := range r.Recipients {
		found := false
		for _, h := range headers {
			if h == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no message carries a To: header for %s (headers: %v). The "+
				"recipient sees a message addressed to somebody else.", want, headers)
		}
	}
}

// TestRunningAScheduleAdvancesItInTheDatabase. The deleted loop wrote its next
// run into a column that does not exist and discarded the 42703, so it re-ran
// every tick for ever. The columns are asserted by reading them back, not by
// trusting the UPDATE's error return — the surviving code discards it too.
func TestRunningAScheduleAdvancesItInTheDatabase(t *testing.T) {
	pool := covSchedPool(t)
	ctx := context.Background()
	s := NewScheduler(pool, NewGenerator(pool), nil)

	r := &ScheduledReport{
		Name: "advance-gate", ReportType: "executive_summary",
		Schedule: "0 8 * * 1", Format: "json", Enabled: true,
	}
	if err := s.AddSchedule(ctx, r); err != nil {
		t.Fatalf("AddSchedule: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM scheduled_reports WHERE id=$1`, r.ID) })

	before := time.Now().UTC()
	s.runReport(ctx, r, before)

	var lastRun, nextRun *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT last_run, next_run FROM scheduled_reports WHERE id=$1`, r.ID).
		Scan(&lastRun, &nextRun); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if lastRun == nil {
		t.Error("last_run was not recorded, so nothing can tell whether the report ran")
	}
	if nextRun == nil {
		t.Fatal("next_run was not recorded — the schedule never advances and the " +
			"report regenerates on every tick")
	}
	if !nextRun.After(before) {
		t.Errorf("next_run = %v is not after the run at %v, so this schedule is "+
			"immediately due again", nextRun, before)
	}
}

// TestAnUnparseableScheduleStillAdvances covers the other arm of the same
// statement. parseCron accepts only "0 H * * D"; anything else — a real cron
// expression with a minute field, an older row, a hand-edited one — takes the
// fallback branch in runReport. AddSchedule rejects such an expression, so the
// row is inserted directly: the point is what happens to a row that is already
// in the table, which is exactly the situation LoadFromDB puts the scheduler in.
// If the fallback ever produced a time in the past the schedule would be
// permanently due, which is the failure the deleted loop had.
func TestAnUnparseableScheduleStillAdvances(t *testing.T) {
	pool := covSchedPool(t)
	ctx := context.Background()
	s := NewScheduler(pool, NewGenerator(pool), nil)

	r := &ScheduledReport{
		Name: "bad-cron-gate", ReportType: "executive_summary",
		Schedule: "*/5 * * * *", Format: "json", Enabled: true,
	}
	if err := s.AddSchedule(ctx, r); err == nil {
		t.Fatal("AddSchedule accepted a cron expression parseCron cannot read; the " +
			"row would be created with a next_run nobody computed")
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO scheduled_reports (name, report_type, schedule, format, enabled, next_run)
		 VALUES ($1,$2,$3,$4,true, NOW() - INTERVAL '1 hour') RETURNING id::text`,
		r.Name, r.ReportType, r.Schedule, r.Format).Scan(&r.ID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM scheduled_reports WHERE id=$1`, r.ID) })

	before := time.Now().UTC()
	s.runReport(ctx, r, before)

	var nextRun *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT next_run FROM scheduled_reports WHERE id=$1`, r.ID).Scan(&nextRun); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if nextRun == nil {
		t.Fatal("next_run was not recorded for a schedule parseCron could not read")
	}
	if !nextRun.After(before) {
		t.Errorf("next_run = %v is not after the run at %v. A schedule whose cron "+
			"expression this parser does not understand would regenerate and remail "+
			"its report on every tick, for ever.", nextRun, before)
	}
}

// TestTheScheduleColumnsThisCodeWritesExist is the schema contract for this one
// path, asserted against the live table rather than the migration text.
func TestTheScheduleColumnsThisCodeWritesExist(t *testing.T) {
	pool := covSchedPool(t)
	for _, col := range []string{"last_run", "next_run", "recipients", "enabled", "schedule", "format"} {
		var exists bool
		if err := pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			   WHERE table_schema='public' AND table_name='scheduled_reports' AND column_name=$1)`,
			col).Scan(&exists); err != nil {
			t.Fatalf("introspect: %v", err)
		}
		if !exists {
			t.Errorf("scheduled_reports has no column %q, which this scheduler reads "+
				"or writes. A missing column here silently removes a filter or "+
				"discards a write.", col)
		}
	}
}
