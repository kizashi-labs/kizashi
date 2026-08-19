// Package metrics provides Prometheus metrics and lightweight atomic counters
// for the EDR platform backend.
package metrics

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/expfmt"
)

// Atomic counters (legacy — kept for backward compat with existing callers).
var (
	HTTPRequests   atomic.Int64 // total HTTP requests handled
	HTTPErrors     atomic.Int64 // HTTP 4xx/5xx responses
	AlertsCreated  atomic.Int64 // alerts persisted
	EventsIngested atomic.Int64 // raw events received
	AgentsOnline   atomic.Int64 // last-known online agent count
	RulesLoaded    atomic.Int64 // number of compiled rules
	NotifsSent     atomic.Int64 // notification dispatches
	NotifsError    atomic.Int64 // notification dispatch failures

	startTime = time.Now()
)

// Prometheus metrics.
var (
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	ActiveAgents = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_active_agents",
		Help: "Number of online agents",
	})

	// IOCHashAbsent counts events that reached hash IOC matching carrying no
	// hash at all.
	//
	// **「既知マルウェアに当たらなかった」と「当てるものが無かった」を
	// 分けるための数です。** どちらも一致0件になるので、この数が伸びて
	// いるあいだ、ハッシュ照合は実質動いていません。
	//
	// 0 でないこと自体は異常ではありません（読めないファイル、権限不足）。
	// **総イベント数に対する比率を見てください。**
	IOCHashAbsent = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "edr_ioc_hash_absent_total",
			Help: "Process/file events that reached hash IOC matching with no hash",
		},
	)

	TotalAlerts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_alerts_total",
			Help: "Total number of alerts created",
		},
		[]string{"severity"},
	)

	// OpenAlerts / OpenAlertsCritical / AgentsOffline back the alerting rules in
	// deploy/prometheus_alerts.yml. All three used to be either absent or declared
	// and never written, so the rules that referenced them could not fire:
	//
	//	CriticalAlertsUnacknowledged → edr_alerts_open_total  (never existed)
	//	AgentOffline                 → edr_agents_offline_total (never existed)
	//
	// and the nearest real gauge (edr_open_alerts) had no writer, so it reported 0
	// forever. An alert rule pointing at a metric nobody emits is indistinguishable
	// from a healthy system: it stays silent either way. TestAlertRulesReferenceRealMetrics
	// now pins the alert-rule → metric-name contract so this cannot recur.
	//
	// Populated by the 60s poller in cmd/api/main.go alongside AgentsOnline.
	OpenAlerts = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_open_alerts",
		Help: "Number of currently open alerts",
	})

	// OpenAlertsCritical is the open-alert count restricted to critical severity
	// (>= 10; see sigmaLevelToInt). Kept as its own gauge rather than a severity
	// label on OpenAlerts: only this one cut drives an alert rule, and a plain
	// gauge needs no cardinality budget.
	OpenAlertsCritical = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_open_alerts_critical",
		Help: "Number of currently open alerts at critical severity",
	})

	// AgentsOffline is the count of agents whose status is 'offline'. Note this is
	// NOT (total - online): agents.status also carries 'inactive' for retired
	// hosts, which must not be alerted on (see P5-10).
	AgentsOffline = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_agents_offline",
		Help: "Number of agents currently reporting status='offline'",
	})

	// CurateInertRules counts curate-enabled Sigma rules that have not fired within
	// the canary window despite being enabled past the grace period. A rising value
	// means "enabled but silently inert" rules — the class of silent failure that
	// let broken field references go unnoticed. Alert when > 0.
	CurateInertRules = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_curate_inert_rules",
		Help: "Curate-enabled Sigma rules with zero fires in the canary window (silently inert)",
	})

	// CurateFieldGap ranks the telemetry fields that, if the agent emitted them,
	// would resurrect the most currently-inert enabled Sigma rules. Labelled by
	// field so a dashboard shows the highest-leverage field to add next (e.g.
	// OriginalFileName=74). A live recall roadmap derived from the field-support gate.
	CurateFieldGap = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "edr_curate_field_gap_rules",
		Help: "Enabled-but-inert Sigma rules that a missing telemetry field would unlock, by field",
	}, []string{"field"})

	// CurateFalseGreenRules counts ENABLED Sigma rules that are field-unsupported —
	// enabled yet unable to fire because their detection selects a field live
	// telemetry never populates. Unlike CurateInertRules (inferred from zero alert
	// history), this is the static field-contract check and flags a false green the
	// instant it appears. It was driven to 0 on 2026-07-03; any rise means a rule was
	// enabled outside the field-support gate or telemetry coverage regressed. Alert
	// when > 0.
	CurateFalseGreenRules = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_curate_false_green_rules",
		Help: "Enabled Sigma rules that are field-unsupported (enabled but cannot fire)",
	})

	// BackupLastSuccessTimestamp is the Unix time of the last *verified* successful
	// automatic DB backup. The key backup SLO signal: alert when
	// time() - edr_backup_last_success_timestamp_seconds exceeds the backup interval
	// (e.g. > 48h) to catch silently-failing backups before they're needed in a
	// disaster. 0 until the first successful backup.
	BackupLastSuccessTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_backup_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last verified successful automatic DB backup",
	})

	// BackupFailures counts automatic backups that failed to produce a valid dump —
	// pg_dump errored OR the integrity check (non-empty + pg_dump completion marker)
	// rejected the output. A non-zero rate means backups are broken; alert on it.
	BackupFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "edr_backup_failures_total",
		Help: "Automatic DB backups that failed (pg_dump error or failed integrity check)",
	})

	// DetectionLastEventTimestamp is the Unix time the detection engine last
	// processed an event — a dead-man's-switch for the ingestion→NATS→detection
	// pipeline. Alert when time() - edr_detection_last_event_timestamp_seconds
	// exceeds a few minutes: the pipeline has silently stalled and NO detection is
	// happening even though the process still looks alive (health probe passes).
	DetectionLastEventTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_detection_last_event_timestamp_seconds",
		Help: "Unix timestamp the detection engine last processed an event (pipeline dead-man's-switch)",
	})

	// DetectionConsumerPending is the JetStream detection consumer's pending
	// (undelivered) message count. A sustained rise means detection is falling
	// behind ingestion — backpressure that precedes an outright stall. Alert on a
	// high or steadily growing value.
	DetectionConsumerPending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_detection_consumer_pending",
		Help: "JetStream detection consumer pending (undelivered) message count",
	})

	// CurateQuarantineReconciled counts rules the reconciler re-disabled because they
	// were curate_state='quarantined' yet still enabled=true (FP rules that kept
	// firing). Increments are a hygiene signal; a steady rise means an enable path is
	// re-enabling quarantined rules without clearing their state.
	CurateQuarantineReconciled = promauto.NewCounter(prometheus.CounterOpts{
		Name: "edr_curate_quarantine_reconciled_total",
		Help: "Rules re-disabled by the reconciler (quarantined but still enabled)",
	})

	DBQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"query"},
	)

	NATSMessagesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_nats_messages_processed_total",
			Help: "Total NATS messages processed",
		},
		[]string{"subject"},
	)

	AuthAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_auth_attempts_total",
			Help: "Total authentication attempts",
		},
		[]string{"result"}, // success, failure, mfa_required
	)

	// IOC / threat intelligence
	IOCMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_ioc_matches_total",
			Help: "Total IOC indicator matches against incoming events",
		},
		[]string{"ioc_type"}, // ip, domain, hash, url, email
	)

	IOCCheckDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "edr_ioc_check_duration_seconds",
		Help:    "Duration of a single IOC look-up against the in-memory set",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05},
	})

	// SigmaCategoryMismatch counts Sigma rule matches whose logsource.category
	// does not correspond to the triggering event's actual type -- e.g. a
	// network_connection-scoped rule matching an image_load event purely because
	// a field name (like Image) happens to be shared across categories. Found
	// live 2026-07-20 ("Network Connection Initiated Via Notepad.EXE" firing on
	// a benign image_load event, see docs/技術的負債と改善計画.md P4-9): the Sigma
	// evaluator never checked logsource.category at all. Shadow mode only --
	// counted and logged, NOT filtered, until the mapping below is validated
	// against the live rule corpus (some rules may need multiple accepted
	// categories or a correction). A sustained non-zero rate here across many
	// distinct rules indicates real false-positive exposure; a handful of
	// one-off rules may just need the mapping refined.
	SigmaCategoryMismatch = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_sigma_category_mismatch_total",
			Help: "Sigma rule matches whose logsource.category did not match the triggering event's type (shadow mode, not filtered)",
		},
		[]string{"rule"},
	)

	// Detection rule engine
	RuleEngineEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_rule_evaluations_total",
			Help: "Total detection rule evaluations",
		},
		[]string{"rule_type", "result"}, // sigma/yara/ml, match/no_match/error
	)

	// RulesPlatformGated counts rule evaluations an OS gate
	// skipped, labelled by the event's platform. The gate shipped in #356 but was
	// inert in production until 2026-08-04: agents never set EventBatch.Platform, so
	// every event arrived as "unknown" and the gate's fail-open branch ran every
	// rule regardless of OS.
	//
	// Now that agents stamp their OS, this counter is how the gate's activation is
	// observed. A rule whose platform label is WRONG stops matching without any
	// error — this counter is the only externally visible sign. A jump after an
	// agent rollout, especially paired with a drop in detections for one OS, means a
	// mislabelled rule went dark; check rules.platform for it.
	RulesPlatformGated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_rules_platform_gated_total",
			Help: "Rule evaluations skipped because the rule's platform excludes the event's OS",
		},
		[]string{"platform"},
	)

	RuleEngineDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_rule_engine_duration_seconds",
			Help:    "Time spent evaluating a detection rule against one event",
			Buckets: []float64{0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
		},
		[]string{"rule_type"},
	)

	// DetectionsByEngine counts confirmed detections (matches that became alerts)
	// broken down by the engine that produced them and the MITRE technique, so
	// dashboards can show which detection layers are actually firing in the field.
	DetectionsByEngine = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_detections_total",
			Help: "Total detections by engine and MITRE technique",
		},
		[]string{"engine", "mitre"}, // engine: sigma/behavioral/heuristic/yara/ioc/chain; mitre: T#### or none
	)

	// SchedulerRuns counts completed ticks of each background worker.
	//
	// Forty workers run on tickers in internal/scheduler and, before this,
	// three of them emitted any metric at all. There was no run-record table
	// either, so from outside a running process "ran and had nothing to do" and
	// "never ran once" looked identical. hunt_scheduler is what that costs: it
	// wakes every fifteen minutes, finds saved_hunt_queries has no `scheduled`
	// column, returns, and has executed zero hunts on every deployment that has
	// ever existed. Nothing but reading the code would tell you.
	//
	// A worker whose counter is not climbing is not running. Alert on that.
	SchedulerRuns = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_scheduler_runs_total",
			Help: "Completed ticks per background scheduler",
		},
		[]string{"scheduler"},
	)

	// SchedulerLastRunTimestamp is when each worker last finished a tick.
	//
	// The counter above says whether it is running; this says how long ago,
	// which is what a stalled worker looks like — a counter that stopped
	// climbing is only visible against a rate window, a timestamp that stopped
	// moving is visible at a glance.
	SchedulerLastRunTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_scheduler_last_run_timestamp_seconds",
			Help: "Unix time of the last completed tick, per background scheduler",
		},
		[]string{"scheduler"},
	)

	// BackgroundFailures counts passes that a background component gave up on.
	//
	// The scheduler package has trackRun, which knows when a tick starts and
	// ends and can therefore record the outcome. The other background workers
	// in this codebase — the NATS subscribers, the enrichment pollers, the
	// Elasticsearch shipper, the webhook and email notifiers — have no such
	// frame. They are loops or callbacks, and their failure paths all ended
	// the same way: log, return.
	//
	// これらにも報告する相手はいません。届かなかった Webhook、送られな
	// かった通知、Elasticsearch に流れなかったドキュメント、エンリッチ
	// されなかったアラート — 運用者から見えるのは、どれも「無い」です。
	// 送るものが無かったのか、送れなかったのかは区別が付きません。
	//
	// component ごとに数えるので、止まっている経路がどれかまで分かります。
	BackgroundFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_background_failures_total",
			Help: "Passes a background component gave up on, by component",
		},
		[]string{"component"},
	)

	// BackgroundLastFailureTimestamp is when each component last gave up.
	//
	// A counter alone cannot distinguish "failed a hundred times last March"
	// from "failing right now"; against a rate window it can, but the
	// timestamp says it without one.
	BackgroundLastFailureTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_background_last_failure_timestamp_seconds",
			Help: "Unix time a background component last gave up, by component",
		},
		[]string{"component"},
	)

	// SchedulerFailures counts ticks that gave up before finishing their work.
	//
	// SchedulerRuns above answers "is it running". It does not answer "is it
	// doing anything", and those are different questions: trackRun increments
	// whether the tick renewed forty certificates or returned on its first
	// query error. A worker erroring out on every tick has a counter climbing
	// as steadily as a healthy one.
	//
	// 背景ワーカーには報告する相手がいません。失敗したことは slog に出ます
	// が、ログは見に行った人にしか届きません。証明書の更新が3日前から毎回
	// 失敗していても、画面に出るのは「更新された証明書が無い」だけです。
	// 更新が要らなかったのと区別がつきません。
	SchedulerFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_scheduler_failures_total",
			Help: "Ticks that ended early with an error, per background scheduler",
		},
		[]string{"scheduler"},
	)

	// SchedulerLastSuccessTimestamp is when each worker last finished its work.
	//
	// Paired with SchedulerLastRunTimestamp: the two moving together is health,
	// the run timestamp moving while this one stays put is a worker that wakes
	// up and fails. That gap is the alertable condition.
	SchedulerLastSuccessTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_scheduler_last_success_timestamp_seconds",
			Help: "Unix time of the last tick that completed without error",
		},
		[]string{"scheduler"},
	)

	// SchedulerRunSeconds is how long each tick took.
	//
	// Included because a worker that has started overrunning its own interval
	// is the other way a scheduler stops doing its job, and it does not show up
	// in a run count.
	SchedulerRunSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_scheduler_run_duration_seconds",
			Help:    "Duration of each scheduler tick",
			Buckets: prometheus.ExponentialBuckets(0.01, 4, 8), // 10ms … ~11min
		},
		[]string{"scheduler"},
	)

	// FileBurstObservations counts every file event offered to the ransomware
	// mass-modification detector (T1486), labelled by the action it carried and by
	// what the detector did with it.
	//
	// This exists because a controlled experiment could not be explained: 200
	// destructive operations on 200 distinct paths, delivered within 5 seconds
	// (verified present in `events` and in the JetStream sequence), did not trip a
	// detector whose threshold is 60 distinct paths in 5 seconds. Nine hypotheses
	// were eliminated from the outside — msgID collision, publish loss, dedup
	// cooldown, path exclusion, action-matching, and more — without reaching an
	// answer, because nothing between the database and the detector is observable.
	//
	// platform answers the question these counters were added for, which is
	// per-OS and not per-agent: "does the Linux sensor ever emit a delete?" The
	// first live read could not answer it — the counter aggregated every agent, so
	// 31 deletes looked like Linux emitting deletes when all 31 came from the one
	// Windows host. agent_id would be the obvious label and is the wrong one: it is
	// unbounded, and worse, it is attacker-influenceable input. Platform is folded
	// to a fixed set for the same reason (see metrics.PlatformLabel).
	//
	// outcome:
	//   counted        — accepted into a bucket
	//   ignored_action — not a destructive action (create/access/attrib)
	//   ignored_path   — empty path, so the event cannot be counted as distinct
	//
	// A flat counter means the events never arrive; a rising "counted" with no
	// alert means they arrive and the window never fills. Those are different bugs
	// in different components, and they were indistinguishable until now.
	// See docs/死蔵経路の全数棚卸し_20260810.md §10 / §13.
	FileBurstObservations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_fileburst_observations_total",
			Help: "File events offered to the T1486 burst detector, by action and outcome",
		},
		[]string{"platform", "action", "outcome"},
	)

	// FileBurstBucketPaths reports the distinct-path count of the bucket that was
	// just touched, so a scrape shows how close the window actually gets to the
	// firing threshold. scope is "host" when the telemetry carries no process
	// identity (every Linux/macOS file collector today) and "process" otherwise.
	FileBurstBucketPaths = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_fileburst_bucket_paths",
			Help: "Distinct destructively-touched paths currently in the last-touched burst bucket",
		},
		[]string{"platform", "scope"},
	)

	// RemediationTriggers counts every alert offered to the auto-remediation engine
	// and what the engine decided, so "it never ran" can be told apart from "it ran
	// and matched nothing".
	//
	// remediation_logs has been empty for four months across 400k+ alerts, yet every
	// part of the path checks out: the engine is wired into AlertPipeline, four
	// builtin rules are loaded and enabled, the always-on rule fires on ANY alert at
	// severity >= 9, "critical" maps to 10 so that is reachable, and execution
	// persists through persistLog. No defect was found and it still produced nothing.
	//
	// outcome:
	//   offered         — TriggerOnAlert was entered at all (the one fact nothing else records)
	//   excluded_host   — the agent is on the exclusion list
	//   no_rules        — the engine holds no rules
	//   no_match        — rules exist, none matched this alert
	//   cooldown        — matched but throttled
	//   executed        — actions ran
	//
	// A flat "offered" means the engine is never reached — which would point at the
	// two-pipeline split, since TriggerOnAlert is called only from AlertPipeline
	// (server-api) and never from server-detect's Engine, where most severity-9
	// alerts come from. See docs/死蔵経路の全数棚卸し_20260810.md §16.
	RemediationTriggers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_remediation_triggers_total",
			Help: "Alerts offered to the auto-remediation engine, by outcome",
		},
		[]string{"outcome"},
	)

	// AlertInsertFailures counts detection matches that were generated but FAILED
	// to persist to the alerts table — the silent-break class where a source
	// detects but produces zero alerts (e.g. a non-UUID rule_id into the uuid
	// column, SQLSTATE 22P02, which broke six sources in 2026-06). A non-zero rate
	// on any source label means that source's detections are being lost — alert on
	// it. Labelled by source so the broken source is identifiable at a glance.
	AlertInsertFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_alert_insert_failures_total",
			Help: "Detection matches that failed to persist as alerts, by source",
		},
		[]string{"source"}, // heuristic/yara/ioc/memory/credential_access/sigma/…
	)

	// AlertsDeduped counts detection matches suppressed by the engine's time-window
	// dedup (same agent+title re-asserting within alertDedupWindow). A high rate on a
	// source label is expected for state-condition rules (e.g. exposed-RDP matching
	// every flow); it quantifies how much alert-flood the dedup is absorbing.
	AlertsDeduped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_alerts_deduped_total",
			Help: "Detection matches suppressed as duplicates within the dedup window, by source",
		},
		[]string{"source"},
	)

	// SLA / alert response
	AlertSLABreaches = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_alert_sla_breaches_total",
			Help: "Number of alerts that exceeded their SLA target response time",
		},
		[]string{"severity"},
	)

	AlertResponseTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_alert_response_seconds",
			Help:    "Time from alert creation to first status change (acknowledge/investigate)",
			Buckets: []float64{60, 300, 900, 1800, 3600, 7200, 14400, 28800},
		},
		[]string{"severity"},
	)

	// DB connection pool
	DBPoolAcquired = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_db_pool_acquired_connections",
		Help: "Number of currently acquired (in-use) database connections",
	})

	DBPoolIdle = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_db_pool_idle_connections",
		Help: "Number of idle database connections in the pool",
	})

	DBPoolWaitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "edr_db_pool_wait_duration_seconds",
		Help:    "Time spent waiting to acquire a database connection from the pool",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
	})

	// WebSocket / real-time
	WSConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "edr_ws_active_connections",
		Help: "Number of active WebSocket client connections",
	})

	WSMessagesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_ws_messages_total",
			Help: "Total WebSocket messages broadcast to clients",
		},
		[]string{"event_type"},
	)

	// Incident / playbook
	PlaybookExecutions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_playbook_executions_total",
			Help: "Total playbook execution runs",
		},
		[]string{"playbook_name", "result"}, // success, error, timeout
	)

	IncidentsCreated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_incidents_total",
			Help: "Total incidents created",
		},
		[]string{"severity"},
	)
)

// Handler writes the /metrics response in Prometheus text exposition format
// using the legacy atomic counters. The promhttp.Handler() in router.go
// serves the full Prometheus registry including the vars above.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		uptimeSeconds := time.Since(startTime).Seconds()

		fmt.Fprintf(w, "# HELP edr_uptime_seconds Seconds since the service started\n")
		fmt.Fprintf(w, "# TYPE edr_uptime_seconds gauge\n")
		fmt.Fprintf(w, "edr_uptime_seconds %.1f\n\n", uptimeSeconds)

		fmt.Fprintf(w, "# HELP edr_http_requests_total Total HTTP requests handled\n")
		fmt.Fprintf(w, "# TYPE edr_http_requests_total counter\n")
		fmt.Fprintf(w, "edr_http_requests_total %d\n\n", HTTPRequests.Load())

		fmt.Fprintf(w, "# HELP edr_http_errors_total Total HTTP 4xx/5xx responses\n")
		fmt.Fprintf(w, "# TYPE edr_http_errors_total counter\n")
		fmt.Fprintf(w, "edr_http_errors_total %d\n\n", HTTPErrors.Load())

		fmt.Fprintf(w, "# HELP edr_alerts_created_total Total alerts created\n")
		fmt.Fprintf(w, "# TYPE edr_alerts_created_total counter\n")
		fmt.Fprintf(w, "edr_alerts_created_total %d\n\n", AlertsCreated.Load())

		fmt.Fprintf(w, "# HELP edr_events_ingested_total Total raw events received\n")
		fmt.Fprintf(w, "# TYPE edr_events_ingested_total counter\n")
		fmt.Fprintf(w, "edr_events_ingested_total %d\n\n", EventsIngested.Load())

		fmt.Fprintf(w, "# HELP edr_agents_online Current number of online agents\n")
		fmt.Fprintf(w, "# TYPE edr_agents_online gauge\n")
		fmt.Fprintf(w, "edr_agents_online %d\n\n", AgentsOnline.Load())

		fmt.Fprintf(w, "# HELP edr_rules_loaded Number of compiled detection rules\n")
		fmt.Fprintf(w, "# TYPE edr_rules_loaded gauge\n")
		fmt.Fprintf(w, "edr_rules_loaded %d\n\n", RulesLoaded.Load())

		fmt.Fprintf(w, "# HELP edr_notifications_sent_total Total notification dispatches\n")
		fmt.Fprintf(w, "# TYPE edr_notifications_sent_total counter\n")
		fmt.Fprintf(w, "edr_notifications_sent_total %d\n\n", NotifsSent.Load())

		fmt.Fprintf(w, "# HELP edr_notifications_errors_total Notification dispatch failures\n")
		fmt.Fprintf(w, "# TYPE edr_notifications_errors_total counter\n")
		fmt.Fprintf(w, "edr_notifications_errors_total %d\n\n", NotifsError.Load())

		// Also serve the promauto/default-registry metrics (IOC matches, rule
		// evaluations, per-engine detections, etc.). Previously these were
		// registered but never exposed on this endpoint — only the API server's
		// promhttp mount showed them, so the detection/ingestion services hid them.
		if mfs, err := prometheus.DefaultGatherer.Gather(); err == nil {
			enc := expfmt.NewEncoder(w, expfmt.NewFormat(expfmt.TypeTextPlain))
			for _, mf := range mfs {
				_ = enc.Encode(mf)
			}
		}
	}
}

// BackgroundFailed records that a background component could not finish a pass,
// and logs why.
//
// 制御は変えません。呼び出し側はこれまで通り、そこで戻るなり空を返すなり
// します。変わるのは、それが外から見えるかどうかだけです。
//
// component は経路の名前です（"notify"、"es_shipper"、"event_forwarder" …）。
// ラベルなので、リクエストごとに変わる値を入れてはいけません。
func BackgroundFailed(component string, err error, msg string, args ...any) {
	slog.Error(msg, append(args, "component", component, "error", err)...)
	BackgroundFailures.WithLabelValues(component).Inc()
	BackgroundLastFailureTimestamp.WithLabelValues(component).Set(float64(time.Now().Unix()))
}

// AlertDropped records an alert that was decided on and could not be written.
//
// BackgroundFailed とは別に数えます。背景処理の失敗は「今回の分が遅れる」
// ことが多いのに対し、これは「出すと決めた警報が、出ないまま終わった」
// です。混ぜると、後者が前者の件数に埋もれます。
//
// 行き先は AlertInsertFailures です。同じ事実のための counter を新しく
// 作りかけて、既にあることに気づきました。二つあると、片方に警報を
// 貼った人は「見ている」と思ったまま、もう片方の source を見落とします。
// 検知エンジン側 (sigma/ioc/chain/…) と、こちら側 (mobile_mtd/anomaly/
// vuln_scan/…) は互いに素なので、1本にまとめて初めて全部が見えます。
func AlertDropped(source string, err error, title string) {
	slog.Error("出すと決めたアラートを記録できませんでした",
		"source", source, "title", title, "error", err)
	AlertInsertFailures.WithLabelValues(source).Inc()
}

// PlatformLabel folds an agent-reported platform string into the fixed set used
// as a metric label.
//
// The value arrives from the endpoint, so it is untrusted: using it verbatim
// lets anything that can register an agent mint unbounded label values and blow
// up the metrics cardinality. Anything unrecognised becomes "other" — a label
// whose growth is capped at one.
func PlatformLabel(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	case "darwin", "macos":
		return "darwin"
	case "":
		return "unknown"
	default:
		return "other"
	}
}
