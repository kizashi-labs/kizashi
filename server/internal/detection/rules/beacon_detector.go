// Package rules — beacon_detector.go
//
// BeaconDetector flags likely C2 beaconing: regular, low-jitter outbound connections
// from one endpoint to one destination. Unlike signature rules it needs no process
// artefact, so it catches implants (Cobalt Strike, Sliver, etc.) whose network call-home
// has no distinctive command line — the gap signature/LOLBin rules cannot cover.
//
// Approach: per (agentID, destIP) keep the connection timestamps within a window. Once
// enough are seen, estimate a base period and fold every inter-arrival onto its nearest
// harmonic of that period; if most intervals fold cleanly and the folded jitter is low with
// the base period in a C2-like band, the traffic is periodic → flag it. Harmonic folding
// makes this robust to sleep JITTER and MISSED check-ins (2×/3× gaps) that defeat a naive
// stddev/mean gate. A per-key cooldown prevents repeated alerts for one ongoing beacon.
//
// This is inherently heuristic (legitimate heartbeats also beacon), so it emits a
// medium-severity "suspected" alert for analyst review rather than auto-response.
package rules

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// BeaconConfig tunes the periodicity detector.
type BeaconConfig struct {
	MinEvents    int           // minimum connections before assessing regularity
	Window       time.Duration // observation window
	MinInterval  time.Duration // ignore faster-than-this base periods (normal chatter)
	MaxInterval  time.Duration // ignore slower-than-this base periods
	MaxJitterCV  float64       // max coefficient of variation of the HARMONIC-FOLDED intervals
	HarmonicTol  float64       // per-beat tolerance: |folded-P|/P within this counts as "clean"
	MinCleanFrac float64       // min fraction of intervals that must fold cleanly onto a harmonic
	Cooldown     time.Duration // min interval between alerts for the same (agent,dst)

	// Payload-size regularity — a second, timing-independent beacon axis. C2
	// implants send near-constant-size check-ins (a fixed-shape task poll), so a
	// low coefficient of variation of bytes_sent is a strong C2 indicator on its
	// own. Two uses: (1) it lets a JITTERED beacon whose timing narrowly misses
	// MaxJitterCV still fire when the payload is uniform (JitterRelaxFactor), and
	// (2) it raises alert severity/confidence when timing already fired. The size
	// signal is only consulted when byte telemetry is actually present (mean>0);
	// with no size data the detector behaves exactly as the timing-only version.
	SizeRegularCV     float64 // max CV of bytes_sent to call the payload "uniform"
	JitterRelaxFactor float64 // timing-jitter budget multiplier when payload is uniform
}

// DefaultBeaconConfig catches real-world C2 call-home while keeping FP low. Unlike a raw
// coefficient-of-variation gate (which only sees near-perfect periodicity), it folds each
// inter-arrival onto the nearest harmonic of the base period FIRST, so it is robust to the
// two ways implants defeat naive periodicity detection: (1) sleep JITTER (Cobalt Strike
// `sleep 60 30%`) and (2) MISSED check-ins that create 2×/3× gaps. Base period must sit in
// the 10s–2h band; ≥75% of intervals must fold cleanly (rejects random traffic); folded
// jitter ≤30%.
func DefaultBeaconConfig() BeaconConfig {
	return BeaconConfig{
		MinEvents:    8,
		Window:       2 * time.Hour,
		MinInterval:  10 * time.Second,
		MaxInterval:  2 * time.Hour,
		MaxJitterCV:  0.30,
		HarmonicTol:  0.35,
		MinCleanFrac: 0.75,
		Cooldown:     1 * time.Hour,
		// A uniform payload is CV ≤ 15%; when present it extends the folded-jitter
		// budget by 1.5× (0.30 → 0.45), catching heavily-jittered implants that a
		// timing-only gate misses. Kept conservative so noise cannot exploit it.
		SizeRegularCV:     0.15,
		JitterRelaxFactor: 1.5,
	}
}

// BeaconMatch describes a detected beacon.
type BeaconMatch struct {
	AgentID      string
	DstIP        string
	Count        int
	MeanInterval time.Duration // base period P (harmonic-folded)
	JitterCV     float64       // coefficient of variation of the folded intervals
	MissedBeats  int           // intervals that folded onto a 2×+ harmonic (skipped check-ins)
	PayloadCV    float64       // coefficient of variation of bytes_sent (-1 = no size data)
	SizeRegular  bool          // payload sizes were uniform (CV ≤ SizeRegularCV)
	JitterRelax  bool          // fired via the size-assisted relaxed jitter gate
}

// BeaconDetector tracks per-destination connection cadence per agent.
type BeaconDetector struct {
	mu       sync.Mutex
	cfg      BeaconConfig
	conns    map[string][]time.Time // groupKey → connection timestamps (ascending)
	sizes    map[string][]uint64    // groupKey → bytes_sent per connection (lockstep with conns)
	lastFire map[string]time.Time   // groupKey → last alert time
}

// NewBeaconDetector creates a detector with the default configuration.
func NewBeaconDetector() *BeaconDetector {
	return &BeaconDetector{
		cfg:      DefaultBeaconConfig(),
		conns:    make(map[string][]time.Time),
		sizes:    make(map[string][]uint64),
		lastFire: make(map[string]time.Time),
	}
}

// Observe records an outbound connection (agentID → dstIP) carrying bytesSent bytes at the
// current time and returns a BeaconMatch if the destination's traffic now looks like a
// beacon, else nil. Pass bytesSent=0 when size telemetry is unavailable; the size axis is
// then simply not consulted.
func (b *BeaconDetector) Observe(agentID, dstIP string, bytesSent uint64) *BeaconMatch {
	return b.observeAt(agentID, dstIP, bytesSent, time.Now())
}

// observeAt is the time-injectable core (tests pass controlled timestamps).
func (b *BeaconDetector) observeAt(agentID, dstIP string, bytesSent uint64, now time.Time) *BeaconMatch {
	if dstIP == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	gk := agentID + "|" + dstIP
	cutoff := now.Add(-b.cfg.Window)

	buf := append(b.conns[gk], now)
	szBuf := append(b.sizes[gk], bytesSent)
	// Prune timestamps older than the window (buf is ascending); prune sizes in lockstep.
	i := 0
	for i < len(buf) && buf[i].Before(cutoff) {
		i++
	}
	buf = buf[i:]
	szBuf = szBuf[i:]
	// Bound memory for very chatty destinations.
	const maxKeep = 512
	if len(buf) > maxKeep {
		buf = buf[len(buf)-maxKeep:]
		szBuf = szBuf[len(szBuf)-maxKeep:]
	}
	b.conns[gk] = buf
	b.sizes[gk] = szBuf

	if len(buf) < b.cfg.MinEvents {
		return nil
	}
	if last, ok := b.lastFire[gk]; ok && now.Sub(last) < b.cfg.Cooldown {
		return nil
	}

	res := analyzeBeacon(buf, b.cfg)

	// Payload-size axis: uniform bytes_sent is an independent C2 signal.
	payloadCV, hasSize := payloadRegularity(szBuf)
	sizeRegular := hasSize && payloadCV <= b.cfg.SizeRegularCV

	// Firing decision. Primary path = the strict timing gate (unchanged). Relaxed
	// path = timing is in-band and mostly-periodic but its folded jitter narrowly
	// exceeds MaxJitterCV, AND the payload is uniform — the size signal confirms the
	// C2 hypothesis that timing alone was too jittery to assert.
	relaxed := false
	if !res.ok && sizeRegular && res.inBand &&
		res.cleanFrac >= b.cfg.MinCleanFrac &&
		res.foldedCV <= b.cfg.MaxJitterCV*b.cfg.JitterRelaxFactor {
		relaxed = true
	}
	if !res.ok && !relaxed {
		return nil
	}

	b.lastFire[gk] = now
	cv := payloadCV
	if !hasSize {
		cv = -1
	}
	return &BeaconMatch{
		AgentID:      agentID,
		DstIP:        dstIP,
		Count:        len(buf),
		MeanInterval: res.period,
		JitterCV:     res.foldedCV,
		MissedBeats:  res.missed,
		PayloadCV:    cv,
		SizeRegular:  sizeRegular,
		JitterRelax:  relaxed,
	}
}

// payloadRegularity returns the coefficient of variation of the non-zero byte counts
// and whether enough size samples were present to judge. Zero-valued samples (no size
// telemetry for that connection) are ignored; if fewer than 3 non-zero samples remain or
// the mean is zero, hasSize is false and the size axis is not used.
func payloadRegularity(sizes []uint64) (cv float64, hasSize bool) {
	vals := make([]float64, 0, len(sizes))
	for _, s := range sizes {
		if s > 0 {
			vals = append(vals, float64(s))
		}
	}
	if len(vals) < 3 {
		return 0, false
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	if mean <= 0 {
		return 0, false
	}
	var sq float64
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	return math.Sqrt(sq/float64(len(vals))) / mean, true
}

// beaconResult is the outcome of periodicity analysis.
type beaconResult struct {
	period    time.Duration // estimated base period P
	foldedCV  float64       // jitter (CV) of the harmonic-folded intervals
	missed    int           // count of intervals that folded onto a 2×+ harmonic
	cleanFrac float64       // fraction of intervals that folded cleanly onto a harmonic
	inBand    bool          // base period P sits within [MinInterval, MaxInterval]
	ok        bool          // strict timing gate: periodic beacon on timing alone
}

// analyzeBeacon decides whether a series of connection timestamps is beacon-like.
//
// It first estimates a base period P as the MEDIAN inter-arrival (robust to a minority of
// missed or extra beats), then folds every interval onto its nearest harmonic of P
// (folded = d / round(d/P)). Folding normalises 2×/3× gaps from skipped check-ins back to
// the base period, so the coefficient of variation of the FOLDED intervals reflects true
// sleep jitter rather than being blown up by outliers. A fraction guard (MinCleanFrac)
// requires most intervals to actually fold cleanly onto a harmonic, which rejects random
// traffic that happens to share a median. Fires when: base P is in the C2 band, ≥MinCleanFrac
// of intervals are within HarmonicTol of a harmonic, and folded jitter ≤ MaxJitterCV.
func analyzeBeacon(ts []time.Time, cfg BeaconConfig) beaconResult {
	if len(ts) < 2 {
		return beaconResult{}
	}
	sorted := make([]time.Time, len(ts))
	copy(sorted, ts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		if d := sorted[i].Sub(sorted[i-1]).Seconds(); d > 0 {
			intervals = append(intervals, d)
		}
	}
	if len(intervals) < cfg.MinEvents-1 {
		return beaconResult{}
	}

	// Robust base-period estimate: median interval.
	period := medianFloat(intervals)
	if period <= 0 {
		return beaconResult{}
	}

	// Fold each interval onto the nearest harmonic and measure how cleanly it fits.
	folded := make([]float64, 0, len(intervals))
	clean, missed := 0, 0
	for _, d := range intervals {
		k := math.Round(d / period)
		if k < 1 {
			k = 1
		}
		f := d / k
		folded = append(folded, f)
		if math.Abs(f-period)/period <= cfg.HarmonicTol {
			clean++
			if k >= 2 {
				missed++
			}
		}
	}
	cleanFrac := float64(clean) / float64(len(intervals))

	// Mean/CV of the folded intervals (true jitter with missed-beat outliers removed).
	var sum float64
	for _, f := range folded {
		sum += f
	}
	meanFolded := sum / float64(len(folded))
	var sq float64
	for _, f := range folded {
		diff := f - meanFolded
		sq += diff * diff
	}
	foldedCV := math.Sqrt(sq/float64(len(folded))) / meanFolded

	res := beaconResult{
		period:    time.Duration(period * float64(time.Second)),
		foldedCV:  foldedCV,
		missed:    missed,
		cleanFrac: cleanFrac,
	}
	res.inBand = res.period >= cfg.MinInterval && res.period <= cfg.MaxInterval
	if !res.inBand {
		return res
	}
	if cleanFrac < cfg.MinCleanFrac || foldedCV > cfg.MaxJitterCV {
		return res
	}
	res.ok = true
	return res
}

// medianFloat returns the median of xs (xs is not modified).
func medianFloat(xs []float64) float64 {
	c := make([]float64, len(xs))
	copy(c, xs)
	sort.Float64s(c)
	n := len(c)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// ToRuleMatch converts a BeaconMatch into the engine's RuleMatch for alerting.
func (m *BeaconMatch) ToRuleMatch() *RuleMatch {
	missedNote := ""
	if m.MissedBeats > 0 {
		// Skipped check-ins folded back onto the base period strengthen the
		// C2 hypothesis (jittered/evasive sleep) rather than weaken it.
		missedNote = fmt.Sprintf("・欠落チェックイン %d 回を調和折り畳みで補正", m.MissedBeats)
	}

	// A uniform payload is an independent C2 confirmation: raise the severity and
	// annotate. A relaxed-gate fire (timing too jittery on its own) is reported as
	// size-assisted so the analyst knows what carried the detection.
	sev := 7
	sizeNote := ""
	if m.SizeRegular {
		sev = 8
		sizeNote = fmt.Sprintf("・ペイロード均一(サイズ変動 %.0f%%)", m.PayloadCV*100)
		if m.JitterRelax {
			sizeNote += "→ジッタ大でもサイズ均一によりビーコン判定"
		}
	}

	return &RuleMatch{
		RuleName:    "C2ビーコン疑い（定期的な外部通信）",
		RuleType:    "behavioral",
		Severity:    sev,
		Title:       "[BEHAVIORAL] C2ビーコン疑い（定期的な外部通信）",
		Description: fmt.Sprintf("%s への通信が %d 回、基本周期 %s・ジッタ %.0f%%%s%s で観測されました（ビーコン型C2の疑い）", m.DstIP, m.Count, m.MeanInterval.Round(time.Second), m.JitterCV*100, missedNote, sizeNote),
		MITRETags:   []string{"T1071", "T1571"},
	}
}
