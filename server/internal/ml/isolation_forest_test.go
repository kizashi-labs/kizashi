package ml

import (
	"math"
	"math/rand"
	"testing"
)

func TestIsolationForestTrain(t *testing.T) {
	forest := NewIsolationForest(50, 64)
	if forest.IsTrained() {
		t.Error("forest should not be trained before Train() is called")
	}

	// Generate normal data clustered around 0.5.
	rng := rand.New(rand.NewSource(42))
	data := make([][]float64, 200)
	for i := range data {
		data[i] = []float64{
			0.4 + rng.Float64()*0.2,
			0.4 + rng.Float64()*0.2,
			0.4 + rng.Float64()*0.2,
		}
	}

	forest.Train(data)
	if !forest.IsTrained() {
		t.Error("forest should be trained after Train()")
	}
}

func TestIsolationForestTrainEmpty(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	forest.Train(nil)
	if forest.IsTrained() {
		t.Error("forest should not be trained after Train(nil)")
	}
	forest.Train([][]float64{})
	if forest.IsTrained() {
		t.Error("forest should not be trained after Train(empty)")
	}
}

func TestIsolationForestScore(t *testing.T) {
	forest := NewIsolationForest(100, 128)
	rng := rand.New(rand.NewSource(42))

	// Normal data: tightly clustered around (0.5, 0.5).
	normal := make([][]float64, 200)
	for i := range normal {
		normal[i] = []float64{
			0.5 + rng.Float64()*0.1 - 0.05,
			0.5 + rng.Float64()*0.1 - 0.05,
		}
	}
	forest.Train(normal)

	normalScore := forest.Score([]float64{0.5, 0.5})
	anomalyScore := forest.Score([]float64{10.0, 10.0})

	t.Logf("normal score: %.4f, anomaly score: %.4f", normalScore, anomalyScore)

	if anomalyScore <= normalScore {
		t.Errorf("anomaly score (%.4f) should be higher than normal score (%.4f)",
			anomalyScore, normalScore)
	}
}

func TestIsolationForestScoreRange(t *testing.T) {
	forest := NewIsolationForest(50, 64)
	rng := rand.New(rand.NewSource(7))

	data := make([][]float64, 100)
	for i := range data {
		data[i] = []float64{rng.Float64(), rng.Float64()}
	}
	forest.Train(data)

	// Scores should be in (0, 1] for any input.
	samples := [][]float64{
		{0.5, 0.5},
		{0.0, 0.0},
		{1.0, 1.0},
		{100.0, -100.0},
	}
	for _, s := range samples {
		score := forest.Score(s)
		if score <= 0 || score > 1.0 {
			t.Errorf("score %.4f out of expected (0,1] range for sample %v", score, s)
		}
	}
}

func TestIsolationForestUntrainedScore(t *testing.T) {
	forest := NewIsolationForest(10, 32)
	score := forest.Score([]float64{1.0, 2.0})
	if score != 0.5 {
		t.Errorf("untrained forest should return 0.5, got %.4f", score)
	}
}

func TestIsolationForestDefaults(t *testing.T) {
	// Passing 0 should fall back to defaults (100 trees, 256 samples).
	forest := NewIsolationForest(0, 0)
	if forest.numTrees != 100 {
		t.Errorf("expected numTrees=100, got %d", forest.numTrees)
	}
	if forest.sampleSize != 256 {
		t.Errorf("expected sampleSize=256, got %d", forest.sampleSize)
	}
}

func TestCFactor(t *testing.T) {
	if got := cFactor(1); got != 0.0 {
		t.Errorf("cFactor(1) = %.4f, want 0.0", got)
	}
	if got := cFactor(0); got != 0.0 {
		t.Errorf("cFactor(0) = %.4f, want 0.0", got)
	}
	// For n > 1, cFactor should be positive.
	for _, n := range []int{2, 10, 100, 256} {
		if got := cFactor(n); got <= 0 {
			t.Errorf("cFactor(%d) = %.4f, expected > 0", n, got)
		}
	}
	// cFactor should be monotonically increasing with n.
	prev := cFactor(2)
	for _, n := range []int{10, 50, 100, 256} {
		cur := cFactor(n)
		if cur <= prev {
			t.Errorf("cFactor not increasing: cFactor(%d)=%.4f <= prev=%.4f", n, cur, prev)
		}
		prev = cur
	}
}

func TestSubsample(t *testing.T) {
	data := make([][]float64, 100)
	for i := range data {
		data[i] = []float64{float64(i)}
	}

	sample := subsample(data, 50)
	if len(sample) != 50 {
		t.Errorf("expected 50 samples, got %d", len(sample))
	}

	// When data has fewer rows than requested size, return all.
	small := data[:10]
	full := subsample(small, 50)
	if len(full) != 10 {
		t.Errorf("expected 10 (all data), got %d", len(full))
	}

	// Exact size: return all as-is.
	exact := subsample(data, 100)
	if len(exact) != 100 {
		t.Errorf("expected 100, got %d", len(exact))
	}
}

func TestUEBAScorer(t *testing.T) {
	scorer := NewUEBAScorer()

	// Normal user — low-risk activity.
	scorer.UpdateProfile("user-normal", "user", UserBehaviorFeatures{
		LoginHour: 9, IsOffHours: false, IsNewLocation: false,
	})
	normalScore := scorer.GetRiskScore("user-normal")

	// Risky user — multiple high-risk indicators.
	scorer.UpdateProfile("user-risky", "user", UserBehaviorFeatures{
		LoginHour:      2,
		IsOffHours:     true,
		IsNewLocation:  true,
		PrivilegeEscal: true,
		MassDownload:   true,
		FailedLogins:   10,
	})
	riskyScore := scorer.GetRiskScore("user-risky")

	t.Logf("normal score: %.1f, risky score: %.1f", normalScore, riskyScore)

	if riskyScore <= normalScore {
		t.Errorf("risky score (%.1f) should exceed normal score (%.1f)", riskyScore, normalScore)
	}
	if riskyScore > 100 {
		t.Errorf("risk score should not exceed 100, got %.1f", riskyScore)
	}
	if normalScore < 0 {
		t.Errorf("risk score should not be negative, got %.1f", normalScore)
	}
}

func TestUEBAScorerUnknownEntity(t *testing.T) {
	scorer := NewUEBAScorer()
	score := scorer.GetRiskScore("nobody")
	if score != 0 {
		t.Errorf("unknown entity should return 0 risk score, got %.2f", score)
	}
}

func TestUEBAScorerGetTopRiskyEntities(t *testing.T) {
	scorer := NewUEBAScorer()

	for i := 0; i < 5; i++ {
		id := "user-" + string(rune('A'+i))
		scorer.UpdateProfile(id, "user", UserBehaviorFeatures{
			FailedLogins: i * 3,
			IsOffHours:   i%2 == 0,
		})
	}

	top := scorer.GetTopRiskyEntities(3)
	if len(top) != 3 {
		t.Errorf("expected 3 top entities, got %d", len(top))
	}
	// Verify descending order.
	for i := 1; i < len(top); i++ {
		if top[i].RiskScore > top[i-1].RiskScore {
			t.Errorf("entities not sorted by risk: [%d]=%.1f > [%d]=%.1f",
				i, top[i].RiskScore, i-1, top[i-1].RiskScore)
		}
	}
}

func TestUEBAScorerGetTopRiskyEntities_FewerThanN(t *testing.T) {
	scorer := NewUEBAScorer()
	scorer.UpdateProfile("only-one", "user", UserBehaviorFeatures{LoginHour: 9})

	top := scorer.GetTopRiskyEntities(10)
	if len(top) != 1 {
		t.Errorf("expected 1 entity, got %d", len(top))
	}
}

func TestUEBAScorerTrainOnProfiles_TooFew(t *testing.T) {
	scorer := NewUEBAScorer()
	// Add fewer than 10 profiles — TrainOnProfiles should be a no-op.
	for i := 0; i < 5; i++ {
		scorer.UpdateProfile("u"+string(rune('0'+i)), "user", UserBehaviorFeatures{LoginHour: i})
	}
	scorer.TrainOnProfiles()
	// Forest should still be untrained.
	if scorer.forest.IsTrained() {
		t.Error("forest should not be trained with fewer than 10 profiles")
	}
}

func TestUEBAScorerTrainOnProfiles_EnoughData(t *testing.T) {
	scorer := NewUEBAScorer()
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 15; i++ {
		scorer.UpdateProfile("user-"+string(rune('A'+i)), "user", UserBehaviorFeatures{
			LoginHour:      int(rng.Float64() * 23),
			DataTransferGB: rng.Float64() * 5,
			FailedLogins:   int(rng.Float64() * 3),
		})
	}
	scorer.TrainOnProfiles()
	if !scorer.forest.IsTrained() {
		t.Error("forest should be trained with 15 profiles")
	}
}

func TestProcessLineageAnalyzer(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()

	tests := []struct {
		parent     string
		child      string
		suspicious bool
	}{
		{"winword.exe", "powershell.exe", true},
		{"winword.exe", "cmd.exe", true},
		{"excel.exe", "powershell.exe", true},
		{"outlook.exe", "cmd.exe", true},
		{"apache2", "bash", true},
		{"nginx", "bash", true},
		{"services.exe", "cmd.exe", true},
		{"iexplore.exe", "cmd.exe", true},
		{"schtasks.exe", "powershell.exe", true},
		{"sudo", "bash", true},
		// Non-suspicious pairs.
		{"explorer.exe", "notepad.exe", false},
		{"chrome.exe", "chrome.exe", false},
		{"bash", "ls", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.parent+"->"+tc.child, func(t *testing.T) {
			result := analyzer.Analyze(tc.parent, tc.child)
			if result.IsSuspicious != tc.suspicious {
				t.Errorf("Analyze(%q, %q).IsSuspicious = %v, want %v",
					tc.parent, tc.child, result.IsSuspicious, tc.suspicious)
			}
			if tc.suspicious {
				if result.Reason == "" {
					t.Error("suspicious result should have a reason")
				}
				if result.Severity == "" {
					t.Error("suspicious result should have a severity")
				}
			}
		})
	}
}

func TestBehavioralEngine(t *testing.T) {
	engine := NewBehavioralEngine()

	t.Run("suspicious process event", func(t *testing.T) {
		detections := engine.ProcessEvent("agent-1", "winword.exe", "powershell.exe", 0, 0, "")
		if len(detections) == 0 {
			t.Error("expected at least one detection for winword.exe -> powershell.exe")
		}
		if detections[0].Type != "suspicious_process_lineage" {
			t.Errorf("expected type suspicious_process_lineage, got %q", detections[0].Type)
		}
		if detections[0].AgentID != "agent-1" {
			t.Errorf("expected AgentID=agent-1, got %q", detections[0].AgentID)
		}
		if detections[0].Severity == "" {
			t.Error("detection should have a severity")
		}
	})

	t.Run("benign process event", func(t *testing.T) {
		detections := engine.ProcessEvent("agent-2", "explorer.exe", "notepad.exe", 0, 0, "")
		if len(detections) != 0 {
			t.Errorf("expected no detections for benign pair, got %d", len(detections))
		}
	})
}

// Benchmark Isolation Forest scoring.
func BenchmarkIsolationForestScore(b *testing.B) {
	forest := NewIsolationForest(100, 256)
	rng := rand.New(rand.NewSource(42))
	data := make([][]float64, 300)
	for i := range data {
		data[i] = []float64{rng.Float64(), rng.Float64(), rng.Float64()}
	}
	forest.Train(data)
	sample := []float64{0.5, 0.5, 0.5}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = forest.Score(sample)
	}
}

// BenchmarkIsolationForestTrain measures training performance.
func BenchmarkIsolationForestTrain(b *testing.B) {
	rng := rand.New(rand.NewSource(99))
	data := make([][]float64, 500)
	for i := range data {
		data[i] = []float64{rng.Float64(), rng.Float64(), rng.Float64(), rng.Float64()}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forest := NewIsolationForest(50, 64)
		forest.Train(data)
	}
}

// BenchmarkUEBAScorerUpdateProfile measures profile update throughput.
func BenchmarkUEBAScorerUpdateProfile(b *testing.B) {
	scorer := NewUEBAScorer()
	features := UserBehaviorFeatures{
		LoginHour:    9,
		IsOffHours:   false,
		FailedLogins: 1,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.UpdateProfile("bench-user", "user", features)
	}
}

// ensure math import is used
var _ = math.Pi
