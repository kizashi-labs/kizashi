// Package detection — StatAnomalyDetector implements statistical anomaly detection
// using Welford's online algorithm for numerically stable running mean/variance.
//
// This detector tracks per-user-per-metric baselines in memory and can detect
// anomalies in real time as events stream in, without requiring a batch job.
// Baselines are optionally persisted to/loaded from the ueba_baselines table.
package detection

import (
	"context"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// ─── Types ───────────────────────────────────────────────────

// MetricBaseline tracks the statistical baseline for a single user+metric pair
// using Welford's online algorithm.
type MetricBaseline struct {
	Mean    float64
	StdDev  float64
	Min     float64
	Max     float64
	SampleN int
	// M2 is the running sum of squared deviations (Welford internal state).
	m2        float64
	UpdatedAt time.Time
}

// AnomalyResult describes whether a sampled value is anomalous and by how much.
type AnomalyResult struct {
	MetricName string
	Baseline   float64 // current mean
	Actual     float64
	ZScore     float64
	IsAnomaly  bool
	Severity   string // low / medium / high / critical
}

// ─── Detector ────────────────────────────────────────────────

// StatAnomalyDetector detects statistical anomalies using Z-score and Welford's
// online algorithm.  It is safe for concurrent use.
type StatAnomalyDetector struct {
	mu        sync.RWMutex
	baselines map[string]*MetricBaseline // key: "userKey:metricName"
}

// NewStatAnomalyDetector creates a new, empty StatAnomalyDetector.
func NewStatAnomalyDetector() *StatAnomalyDetector {
	return &StatAnomalyDetector{
		baselines: make(map[string]*MetricBaseline),
	}
}

// baselineKey returns the map key for a user+metric pair.
func baselineKey(userKey, metric string) string {
	return userKey + ":" + metric
}

// UpdateBaseline updates the running baseline for a user+metric pair using
// Welford's online algorithm for numerical stability.
//
// Algorithm:
//
//	n++
//	delta  = x - mean
//	mean  += delta / n
//	delta2 = x - mean
//	M2    += delta * delta2
//	variance = M2 / (n-1)  if n > 1 else 0
//	stddev   = sqrt(variance)
func (d *StatAnomalyDetector) UpdateBaseline(userKey, metric string, value float64) {
	key := baselineKey(userKey, metric)

	d.mu.Lock()
	defer d.mu.Unlock()

	b, exists := d.baselines[key]
	if !exists {
		b = &MetricBaseline{
			Min: value,
			Max: value,
		}
		d.baselines[key] = b
	}

	b.SampleN++
	delta := value - b.Mean
	b.Mean += delta / float64(b.SampleN)
	delta2 := value - b.Mean
	b.m2 += delta * delta2

	if b.SampleN > 1 {
		variance := b.m2 / float64(b.SampleN-1)
		b.StdDev = math.Sqrt(variance)
	} else {
		b.StdDev = 0
	}

	if value < b.Min {
		b.Min = value
	}
	if value > b.Max {
		b.Max = value
	}
	b.UpdatedAt = time.Now()
}

// CheckAnomaly checks whether value is anomalous for the given user+metric.
//
// Z-score thresholds → Severity:
//   - |Z| ≥ 4.0  → critical
//   - |Z| ≥ 3.0  → high
//   - |Z| ≥ 2.0  → medium
//   - otherwise  → low (not anomalous)
func (d *StatAnomalyDetector) CheckAnomaly(userKey, metric string, value float64) AnomalyResult {
	key := baselineKey(userKey, metric)

	d.mu.RLock()
	b, exists := d.baselines[key]
	d.mu.RUnlock()

	result := AnomalyResult{
		MetricName: metric,
		Actual:     value,
	}

	if !exists || b.SampleN < 3 {
		// Too few samples to form a meaningful baseline.
		return result
	}

	result.Baseline = b.Mean

	var zScore float64
	if b.StdDev > 0 {
		zScore = (value - b.Mean) / b.StdDev
	} else if value > b.Mean {
		// Zero variance: any higher value is infinitely anomalous; cap at 5.
		zScore = 5.0
	}

	result.ZScore = zScore
	absZ := math.Abs(zScore)

	switch {
	case absZ >= 4.0:
		result.IsAnomaly = true
		result.Severity = "critical"
	case absZ >= 3.0:
		result.IsAnomaly = true
		result.Severity = "high"
	case absZ >= 2.0:
		result.IsAnomaly = true
		result.Severity = "medium"
	default:
		result.Severity = "low"
	}

	return result
}

// ─── DB Persistence ──────────────────────────────────────────

// LoadBaselinesFromDB loads ueba_baselines from the database into memory.
// pool must be *pgxpool.Pool.
func (d *StatAnomalyDetector) LoadBaselinesFromDB(pool interface{}) error {
	p, ok := pool.(*pgxpool.Pool)
	if !ok {
		return nil
	}

	ctx := context.Background()

	// Check if the table exists before querying it.
	tableExists := store.TableIsThere(ctx, p, "ueba_baselines")
	if !tableExists {
		slog.Debug("anomaly_detector: ueba_baselines table does not exist yet")
		return nil
	}

	rows, err := p.Query(ctx, `
		SELECT user_key, metric_name, mean, std_dev, sample_count, updated_at
		FROM ueba_baselines
	`)
	if err != nil {
		slog.Warn("anomaly_detector: failed to load baselines", "error", err)
		return err
	}
	defer rows.Close()

	d.mu.Lock()
	defer d.mu.Unlock()

	loaded := 0
	for rows.Next() {
		var userKey, metricName string
		var mean, stdDev float64
		var sampleCount int
		var updatedAt time.Time

		if err := rows.Scan(&userKey, &metricName, &mean, &stdDev, &sampleCount, &updatedAt); err != nil {
			continue
		}

		key := baselineKey(userKey, metricName)
		d.baselines[key] = &MetricBaseline{
			Mean:      mean,
			StdDev:    stdDev,
			SampleN:   sampleCount,
			UpdatedAt: updatedAt,
		}
		loaded++
	}
	if err := rows.Err(); err != nil {
		// **途中までのベースラインで異常判定を始めません。**
		// 下の "loaded baselines count=N" が、全件読めたときと同じ姿で
		// 出ます。足りないベースラインの分だけ、異常が異常に見えなく
		// なります。
		slog.Error("anomaly_detector: ベースラインの読み出しが途中で失敗しました", "error", err)
		return err
	}

	slog.Info("anomaly_detector: loaded baselines", "count", loaded)
	return nil
}

// SaveBaselinesToDB persists current in-memory baselines back to ueba_baselines.
// pool must be *pgxpool.Pool.
func (d *StatAnomalyDetector) SaveBaselinesToDB(pool interface{}) error {
	p, ok := pool.(*pgxpool.Pool)
	if !ok {
		return nil
	}

	ctx := context.Background()

	// Ensure the table exists.
	tableExists := store.TableIsThere(ctx, p, "ueba_baselines")
	if !tableExists {
		slog.Debug("anomaly_detector: ueba_baselines table does not exist — skipping save")
		return nil
	}

	d.mu.RLock()
	// Copy snapshot to avoid holding the lock during DB writes.
	type entry struct {
		userKey    string
		metricName string
		b          MetricBaseline
	}
	entries := make([]entry, 0, len(d.baselines))
	for k, b := range d.baselines {
		// Split key back into userKey:metricName
		idx := -1
		for i, c := range k {
			if c == ':' {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}
		entries = append(entries, entry{
			userKey:    k[:idx],
			metricName: k[idx+1:],
			b:          *b,
		})
	}
	d.mu.RUnlock()

	saved := 0
	for _, e := range entries {
		// Same two-generation column split as ueba_anomalies: migration 121 created
		// this table with username/baseline_value/std_deviation/sample_days
		// (username and baseline_value are NOT NULL with no default), and 205
		// bolted on user_key/mean/std_dev/sample_count for the Go code without
		// relaxing the originals. Writing only the 205 names failed every insert,
		// so no baseline was ever persisted — which also means CheckAnomaly had
		// nothing to restore on restart.
		//
		// The casts are load-bearing: username is VARCHAR(255) while user_key is
		// TEXT, so reusing one placeholder across both without casting makes
		// Postgres deduce a single conflicting type and reject the statement.
		//
		// ueba_advanced_handler.go selects by username, so dropping the NOT NULL
		// instead would leave that view empty while the write "succeeded".
		_, err := p.Exec(ctx, `
			INSERT INTO ueba_baselines (
				username, baseline_value, std_deviation, sample_days,
				user_key, metric_name, mean, std_dev, sample_count, updated_at
			) VALUES (
				$1::text, $3::numeric, $4::numeric, $5::int,
				$1::text, $2, $3::numeric, $4::numeric, $5::int, $6
			)
			ON CONFLICT (user_key, metric_name) DO UPDATE
			SET mean           = EXCLUDED.mean,
			    std_dev        = EXCLUDED.std_dev,
			    sample_count   = EXCLUDED.sample_count,
			    baseline_value = EXCLUDED.baseline_value,
			    std_deviation  = EXCLUDED.std_deviation,
			    sample_days    = EXCLUDED.sample_days,
			    updated_at     = EXCLUDED.updated_at
		`, e.userKey, e.metricName, e.b.Mean, e.b.StdDev, e.b.SampleN, e.b.UpdatedAt)
		if err != nil {
			metrics.BackgroundFailed("anomaly_baseline", err, "anomaly_detector: failed to save baseline",
				"user_key", e.userKey,
				"metric", e.metricName,
				"error", err)
			continue
		}
		saved++
	}

	slog.Info("anomaly_detector: saved baselines", "count", saved)
	return nil
}
