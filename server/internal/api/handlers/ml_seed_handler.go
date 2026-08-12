package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/ml"
	"github.com/gin-gonic/gin"
)

// MLSeedHandler provides endpoints to seed ML training data and trigger retraining.
type MLSeedHandler struct {
	engine *ml.BehavioralEngine
}

// NewMLSeedHandler creates a new MLSeedHandler.
func NewMLSeedHandler(engine *ml.BehavioralEngine) *MLSeedHandler {
	return &MLSeedHandler{engine: engine}
}

// SeedTrainingData handles POST /api/v1/admin/ml/seed
// Seeds the UEBA model with synthetic baseline data for initial training.
func (h *MLSeedHandler) SeedTrainingData(c *gin.Context) {
	// Seed with synthetic "normal" behavioral profiles
	// This gives the Isolation Forest a baseline to compare against
	normalProfiles := []struct {
		entityID string
		features ml.UserBehaviorFeatures
	}{
		// Normal 9-5 office worker
		{"seed-user-001", ml.UserBehaviorFeatures{LoginHour: 9, IsOffHours: false, IsNewLocation: false}},
		{"seed-user-002", ml.UserBehaviorFeatures{LoginHour: 8, IsOffHours: false, IsNewLocation: false}},
		{"seed-user-003", ml.UserBehaviorFeatures{LoginHour: 10, IsOffHours: false, IsNewLocation: false}},
		{"seed-user-004", ml.UserBehaviorFeatures{LoginHour: 9, IsOffHours: false, IsNewLocation: false, FailedLogins: 1}},
		{"seed-user-005", ml.UserBehaviorFeatures{LoginHour: 14, IsOffHours: false, IsNewLocation: false}},
		// Slightly elevated but normal
		{"seed-user-006", ml.UserBehaviorFeatures{LoginHour: 7, IsOffHours: false, IsNewLocation: false, DataTransferGB: 0.5}},
		{"seed-user-007", ml.UserBehaviorFeatures{LoginHour: 17, IsOffHours: false, IsNewLocation: false}},
		{"seed-user-008", ml.UserBehaviorFeatures{LoginHour: 11, IsOffHours: false, IsNewLocation: false, FailedLogins: 2}},
		// Remote workers (slightly different patterns)
		{"seed-user-009", ml.UserBehaviorFeatures{LoginHour: 8, IsOffHours: false, IsNewLocation: true}},
		{"seed-user-010", ml.UserBehaviorFeatures{LoginHour: 10, IsOffHours: false, IsNewLocation: true, DataTransferGB: 0.3}},
		// Anomalous patterns
		{"seed-anomaly-001", ml.UserBehaviorFeatures{LoginHour: 2, IsOffHours: true, IsNewLocation: true, FailedLogins: 10, DataTransferGB: 5.0}},
		{"seed-anomaly-002", ml.UserBehaviorFeatures{LoginHour: 23, IsOffHours: true, PrivilegeEscal: true, MassDownload: true}},
	}

	for _, p := range normalProfiles {
		h.engine.UEBA.UpdateProfile(p.entityID, "user", p.features)
	}

	// Trigger immediate training
	h.engine.UEBA.TrainOnProfiles()

	// Also seed the global Isolation Forest
	trainingData := [][]float64{
		{9, 0, 0, 0, 0, 0, 0, 0, 1},
		{8, 0, 0, 0, 0, 1, 0, 0, 1},
		{10, 0, 0, 0, 0, 0, 1, 0, 2},
		{9, 0, 0, 0, 0, 0, 0, 0.5, 1},
		{14, 0, 0, 0, 0, 2, 0, 0, 1},
		{7, 0, 0, 0, 0, 0, 0, 0.3, 3},
		{17, 0, 0, 0, 0, 0, 0, 0, 1},
		{11, 0, 0, 0, 0, 1, 2, 0, 2},
		{8, 0, 1, 0, 0, 0, 0, 0, 5},
		{10, 0, 1, 0, 0, 0, 0, 0.3, 4},
		// Anomalies
		{2, 1, 1, 0, 0, 10, 5, 5.0, 15},
		{23, 1, 0, 1, 1, 8, 3, 10.0, 20},
	}
	h.engine.Forest.Train(trainingData)

	c.JSON(http.StatusOK, gin.H{
		"message":           "ML training data seeded successfully",
		"profiles_seeded":   len(normalProfiles),
		"forest_trained":    true,
		"forest_is_trained": h.engine.Forest.IsTrained(),
	})
}

// TriggerRetrain handles POST /api/v1/admin/ml/retrain
func (h *MLSeedHandler) TriggerRetrain(c *gin.Context) {
	h.engine.UEBA.TrainOnProfiles()
	c.JSON(http.StatusOK, gin.H{
		"message":        "UEBA model retrained",
		"forest_trained": h.engine.Forest.IsTrained(),
	})
}

// ModelStatus handles GET /api/v1/admin/ml/status
func (h *MLSeedHandler) ModelStatus(c *gin.Context) {
	topRisky := h.engine.UEBA.GetTopRiskyEntities(1)
	entitiesTracked := len(h.engine.UEBA.GetTopRiskyEntities(1000))
	highRisk := 0
	for _, e := range h.engine.UEBA.GetTopRiskyEntities(1000) {
		if e.RiskScore >= 70 {
			highRisk++
		}
	}
	_ = topRisky

	c.JSON(http.StatusOK, gin.H{
		"isolation_forest": gin.H{
			"trained":     h.engine.Forest.IsTrained(),
			"num_trees":   100,
			"sample_size": 256,
		},
		"ueba": gin.H{
			"entities_tracked": entitiesTracked,
			"high_risk_count":  highRisk,
		},
		"process_lineage": gin.H{
			"rules_active": 17,
		},
	})
}
