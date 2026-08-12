package metrics

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// An alert rule that names a metric nobody emits is indistinguishable from a
// healthy system: it stays silent either way. Nothing turns red, no dashboard
// gaps, no error log — the alert simply never fires.
//
// Two shipped rules were in exactly that state until 2026-08-04:
//
//	CriticalAlertsUnacknowledged → edr_alerts_open_total    (no such metric)
//	AgentOffline                 → edr_agents_offline_total (no such metric)
//
// and the nearest real gauge (edr_open_alerts) was declared but never written,
// so it reported 0 forever. This is the same silent-failure shape as the T1110
// builtin that selected on an EventID our auth telemetry never carries: the rule
// existed, looked reasonable in review, and could not match anything.
//
// This test pins the alert-rule → metric-name contract. It deliberately checks
// only `edr_*` names: everything else in the rule file comes from exporters this
// repo does not own (node_exporter, postgres_exporter, the NATS monitoring
// endpoint, and Prometheus's own `up`).

var edrMetricRef = regexp.MustCompile(`edr_[a-z0-9_]+`)

// alertRulesPath locates deploy/prometheus_alerts.yml from this package.
func alertRulesPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "deploy", "prometheus_alerts.yml")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("アラートルールが見つかりません (%s): %v", p, err)
	}
	return p
}

// exportedMetricNames returns every metric name the /metrics endpoint actually
// serves. This is the authoritative set — it covers both the hand-written
// fmt.Fprintf block and everything promauto registered into the default
// registry, which is exactly what Prometheus would scrape.
func exportedMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("/metrics が %d を返しました", rec.Code)
	}
	names := map[string]bool{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "<name>{labels} value" or "<name> value"
		name := line
		if i := strings.IndexAny(name, "{ "); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			names[name] = true
			// Histograms/summaries expose <name>_bucket/_sum/_count; a rule may
			// key on either the base name or a suffixed series.
			for _, suf := range []string{"_bucket", "_sum", "_count"} {
				names[strings.TrimSuffix(name, suf)] = true
			}
		}
	}
	return names
}

// TestAlertRulesReferenceRealMetrics fails when deploy/prometheus_alerts.yml
// names an edr_* metric the server does not export.
func TestAlertRulesReferenceRealMetrics(t *testing.T) {
	raw, err := os.ReadFile(alertRulesPath(t))
	if err != nil {
		t.Fatalf("アラートルールを読めません: %v", err)
	}
	exported := exportedMetricNames(t)

	// Only `expr:` lines reference metrics. Group names (edr_api, edr_host, …) and
	// prose in annotations are not queries, so scanning the whole file would
	// produce false failures.
	var missing []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !isExprContext(trimmed) {
			continue
		}
		for _, name := range edrMetricRef.FindAllString(trimmed, -1) {
			if seen[name] || exported[name] {
				continue
			}
			seen[name] = true
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("アラートルールが %q を参照していますが、/metrics はこの名前を出力していません。"+
			"存在しないメトリクスを参照するルールは永久に沈黙し、正常な状態と区別できません", name)
	}
}

// exprState tracks whether the current line belongs to an `expr:` block, which
// may be a single line or a `|` literal spanning several.
var inExprBlock bool

// isExprContext reports whether a rule-file line is part of an alert expression.
// A multi-line `expr: |` block continues until the next rule key.
func isExprContext(trimmed string) bool {
	switch {
	case strings.HasPrefix(trimmed, "expr:"):
		inExprBlock = strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, ">-")
		return true
	case trimmed == "":
		return false
	case strings.HasPrefix(trimmed, "- alert:"), strings.HasPrefix(trimmed, "for:"),
		strings.HasPrefix(trimmed, "labels:"), strings.HasPrefix(trimmed, "annotations:"),
		strings.HasPrefix(trimmed, "- name:"), strings.HasPrefix(trimmed, "rules:"),
		strings.HasPrefix(trimmed, "groups:"):
		inExprBlock = false
		return false
	}
	return inExprBlock
}

// TestDetectionPipelineAlertsExist pins the specific rules added for the
// detection pipeline. The 2026-07-26 Windows measurement could not distinguish
// "server-detect produced no detections" from "there was nothing to detect",
// because every stateful detector and every DB rule lives in that one process.
// The metrics to tell them apart already existed (engine.go monitorConsumerLag +
// DetectionLastEventTimestamp) and Prometheus already scraped detection:8081 —
// only the rules that fire on them were missing.
func TestDetectionPipelineAlertsExist(t *testing.T) {
	raw, err := os.ReadFile(alertRulesPath(t))
	if err != nil {
		t.Fatalf("アラートルールを読めません: %v", err)
	}
	body := string(raw)
	for _, name := range []string{
		"EDRDetectionDown",
		"EDRDetectionPipelineStalled",
		"EDRDetectionConsumerLagging",
	} {
		if !strings.Contains(body, "alert: "+name) {
			t.Errorf("アラート %q が prometheus_alerts.yml にありません。"+
				"検知経路が丸ごと落ちている状態を検出できなくなります", name)
		}
	}
}
