package ml

import (
	"math"
	"sync"
	"time"
)

// UEBAScorer computes risk scores for users/entities based on behavioral features.
type UEBAScorer struct {
	mu       sync.RWMutex
	profiles map[string]*UserProfile // key: user_id or agent_id
	forest   *IsolationForest
}

// UserProfile holds behavioral statistics for a single user/entity.
type UserProfile struct {
	EntityID       string
	EntityType     string      // "user" or "agent"
	LoginHours     [24]float64 // hourly login frequency
	AvgSessionMins float64
	TypicalSrcIPs  map[string]int
	AlertCount     int
	FailedLogins   int
	DataTransferGB float64
	LastUpdated    time.Time
	RiskScore      float64
}

// NewUEBAScorer creates a new UEBA scorer.
func NewUEBAScorer() *UEBAScorer {
	return &UEBAScorer{
		profiles: make(map[string]*UserProfile),
		forest:   NewIsolationForest(100, 256),
	}
}

// UpdateProfile updates the behavioral profile for an entity.
func (s *UEBAScorer) UpdateProfile(entityID, entityType string, features UserBehaviorFeatures) {
	s.mu.Lock()
	defer s.mu.Unlock()

	profile, exists := s.profiles[entityID]
	if !exists {
		profile = &UserProfile{
			EntityID:      entityID,
			EntityType:    entityType,
			TypicalSrcIPs: make(map[string]int),
		}
		s.profiles[entityID] = profile
	}

	// Update rolling averages
	if features.LoginHour >= 0 && features.LoginHour < 24 {
		profile.LoginHours[features.LoginHour]++
	}
	if features.SrcIP != "" {
		profile.TypicalSrcIPs[features.SrcIP]++
	}
	profile.AlertCount += features.NewAlerts
	profile.FailedLogins += features.FailedLogins
	profile.DataTransferGB += features.DataTransferGB
	profile.LastUpdated = time.Now()

	// Compute risk score
	profile.RiskScore = s.computeRiskScore(profile, features)
}

// UserBehaviorFeatures represents features for a single event/session.
type UserBehaviorFeatures struct {
	LoginHour      int
	SrcIP          string
	NewAlerts      int
	FailedLogins   int
	DataTransferGB float64
	IsOffHours     bool
	IsNewLocation  bool
	PrivilegeEscal bool
	MassDownload   bool
}

// GetRiskScore returns the current risk score (0-100) for an entity.
func (s *UEBAScorer) GetRiskScore(entityID string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.profiles[entityID]; ok {
		return p.RiskScore
	}
	return 0
}

// GetTopRiskyEntities returns the top N riskiest entities.
func (s *UEBAScorer) GetTopRiskyEntities(n int) []UserProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profiles := make([]UserProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		profiles = append(profiles, *p)
	}

	// Sort by risk score descending (simple selection)
	for i := 0; i < len(profiles)-1; i++ {
		for j := i + 1; j < len(profiles); j++ {
			if profiles[j].RiskScore > profiles[i].RiskScore {
				profiles[i], profiles[j] = profiles[j], profiles[i]
			}
		}
	}

	if n > len(profiles) {
		n = len(profiles)
	}
	return profiles[:n]
}

// computeRiskScore calculates a 0-100 risk score from behavioral indicators.
func (s *UEBAScorer) computeRiskScore(profile *UserProfile, current UserBehaviorFeatures) float64 {
	score := 0.0

	// Off-hours activity (+20)
	if current.IsOffHours {
		score += 20
	}

	// New/unusual source IP (+15)
	if current.IsNewLocation {
		score += 15
	}

	// Failed logins (+10 per, capped at 30)
	loginPenalty := math.Min(float64(profile.FailedLogins)*10, 30)
	score += loginPenalty

	// Privilege escalation attempt (+25)
	if current.PrivilegeEscal {
		score += 25
	}

	// Mass download (+20)
	if current.MassDownload {
		score += 20
	}

	// High alert count (+1 per alert, capped at 20)
	alertPenalty := math.Min(float64(profile.AlertCount), 20)
	score += alertPenalty

	// Large data transfer (>1GB = +10, >10GB = +20)
	if profile.DataTransferGB > 10 {
		score += 20
	} else if profile.DataTransferGB > 1 {
		score += 10
	}

	// Use Isolation Forest for anomaly component if trained
	if s.forest.IsTrained() {
		vec := profileToVector(profile, current)
		anomalyScore := s.forest.Score(vec)
		// Map [0.5, 1.0] → [0, 30] additional score
		if anomalyScore > 0.5 {
			score += (anomalyScore - 0.5) * 60
		}
	}

	return math.Min(score, 100)
}

// profileToVector converts a user profile to a feature vector for IF.
func profileToVector(p *UserProfile, f UserBehaviorFeatures) []float64 {
	offHours := 0.0
	if f.IsOffHours {
		offHours = 1.0
	}
	newLoc := 0.0
	if f.IsNewLocation {
		newLoc = 1.0
	}
	privEsc := 0.0
	if f.PrivilegeEscal {
		privEsc = 1.0
	}
	mass := 0.0
	if f.MassDownload {
		mass = 1.0
	}
	return []float64{
		float64(f.LoginHour),
		offHours,
		newLoc,
		privEsc,
		mass,
		float64(p.AlertCount),
		float64(p.FailedLogins),
		p.DataTransferGB,
		float64(len(p.TypicalSrcIPs)),
	}
}

// TrainOnProfiles retrains the Isolation Forest on all current profiles.
func (s *UEBAScorer) TrainOnProfiles() {
	s.mu.RLock()
	profiles := make([]*UserProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		profiles = append(profiles, p)
	}
	s.mu.RUnlock()

	if len(profiles) < 10 {
		return // Not enough data to train
	}

	data := make([][]float64, len(profiles))
	for i, p := range profiles {
		data[i] = profileToVector(p, UserBehaviorFeatures{})
	}
	s.forest.Train(data)
}
