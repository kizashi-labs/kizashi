package ml

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// BehavioralEngine combines all ML-based detection components.
type BehavioralEngine struct {
	UEBA           *UEBAScorer
	ProcessLineage *ProcessLineageAnalyzer
	Chain          *ProcessChainEngine
	Forest         *IsolationForest
}

// NewBehavioralEngine creates a new BehavioralEngine.
func NewBehavioralEngine() *BehavioralEngine {
	return &BehavioralEngine{
		UEBA:           NewUEBAScorer(),
		ProcessLineage: NewProcessLineageAnalyzer(),
		Chain:          NewProcessChainEngine(),
		Forest:         NewIsolationForest(100, 256),
	}
}

// ProcessEvent analyzes a process event for behavioral anomalies.
// pid/ppid are the numeric process IDs (0 if unknown); cmdline is the full
// command line of the new process. Returns a list of detections.
func (e *BehavioralEngine) ProcessEvent(agentID, parentProc, childProc string, pid, ppid uint32, cmdline string) []Detection {
	var detections []Detection

	// ── immediate parent→child lineage check ──────────────────────
	result := e.ProcessLineage.Analyze(parentProc, childProc)
	if result.IsSuspicious {
		detections = append(detections, Detection{
			Type:     "suspicious_process_lineage",
			Severity: result.Severity,
			Message:  result.Reason,
			AgentID:  agentID,
			Details: map[string]string{
				"parent": parentProc,
				"child":  childProc,
				"rule":   result.Rule,
			},
		})
	}

	// ── multi-hop ancestry chain analysis ─────────────────────────
	if e.Chain != nil && pid != 0 {
		chainHits := e.Chain.Analyze(agentID, pid, ppid, childProc, cmdline)
		for _, hit := range chainHits {
			detections = append(detections, Detection{
				Type:     "suspicious_process_chain",
				Severity: hit.Severity,
				Message:  hit.Reason,
				AgentID:  agentID,
				Details: map[string]string{
					"rule_id": hit.RuleID,
					"mitre":   hit.MITRE,
					"chain":   joinChain(hit.Chain),
				},
			})
		}
	}

	return detections
}

func joinChain(chain []string) string {
	return strings.Join(chain, " → ")
}

// Detection represents a behavioral anomaly detection result.
type Detection struct {
	Type     string
	Severity string
	Message  string
	AgentID  string
	UserID   string
	Details  map[string]string
	Score    float64
}

// RunPeriodicTraining periodically retrains the UEBA model.
func (e *BehavioralEngine) RunPeriodicTraining(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Info("retraining UEBA behavioral model")
			e.UEBA.TrainOnProfiles()
		}
	}
}
