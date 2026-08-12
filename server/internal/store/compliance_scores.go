package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceScore mirrors the compliance_scores table.
type ComplianceScore struct {
	ID           string          `json:"id"`
	AgentID      string          `json:"agent_id"`
	Framework    string          `json:"framework"`
	Score        int             `json:"score"`
	TotalChecks  int             `json:"total_checks"`
	PassedChecks int             `json:"passed_checks"`
	Details      json.RawMessage `json:"details"`
	ComputedAt   string          `json:"computed_at"`
}

// ComplianceScoreStore handles compliance_scores database operations.
type ComplianceScoreStore struct {
	pool *pgxpool.Pool
}

// NewComplianceScoreStore creates a new ComplianceScoreStore.
func NewComplianceScoreStore(pool *pgxpool.Pool) *ComplianceScoreStore {
	return &ComplianceScoreStore{pool: pool}
}

func scanComplianceScore(row pgx.Row) (*ComplianceScore, error) {
	var s ComplianceScore
	var computedAt time.Time
	var detailsRaw []byte
	err := row.Scan(
		&s.ID, &s.AgentID, &s.Framework,
		&s.Score, &s.TotalChecks, &s.PassedChecks,
		&detailsRaw, &computedAt,
	)
	if err != nil {
		return nil, err
	}
	s.ComputedAt = computedAt.Format(time.RFC3339)
	if detailsRaw != nil {
		s.Details = json.RawMessage(detailsRaw)
	} else {
		s.Details = json.RawMessage("{}")
	}
	return &s, nil
}

// Upsert inserts or updates a compliance score for an agent+framework pair.
func (s *ComplianceScoreStore) Upsert(ctx context.Context, score *ComplianceScore) (*ComplianceScore, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	details := score.Details
	if details == nil {
		details = json.RawMessage("{}")
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO compliance_scores (agent_id, framework, score, total_checks, passed_checks, details, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (agent_id, framework) DO UPDATE SET
			score         = EXCLUDED.score,
			total_checks  = EXCLUDED.total_checks,
			passed_checks = EXCLUDED.passed_checks,
			details       = EXCLUDED.details,
			computed_at   = NOW()
		RETURNING id, agent_id, framework, score, total_checks, passed_checks, details, computed_at`,
		score.AgentID, score.Framework, score.Score,
		score.TotalChecks, score.PassedChecks, []byte(details),
	)
	result, err := scanComplianceScore(row)
	if err != nil {
		return nil, fmt.Errorf("compliance_scores upsert: %w", err)
	}
	return result, nil
}

// GetByAgent returns the compliance score for a specific agent and framework.
// If framework is empty, it defaults to "CIS".
func (s *ComplianceScoreStore) GetByAgent(ctx context.Context, agentID, framework string) (*ComplianceScore, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if framework == "" {
		framework = "CIS"
	}

	row := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, framework, score, total_checks, passed_checks, details, computed_at
		FROM compliance_scores
		WHERE agent_id = $1 AND framework = $2`,
		agentID, framework,
	)
	result, err := scanComplianceScore(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("compliance score not found for agent %s framework %s", agentID, framework)
		}
		return nil, fmt.Errorf("compliance_scores get_by_agent: %w", err)
	}
	return result, nil
}

// ListAll returns all compliance scores ordered by score ascending (worst first).
func (s *ComplianceScoreStore) ListAll(ctx context.Context) ([]*ComplianceScore, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, framework, score, total_checks, passed_checks, details, computed_at
		FROM compliance_scores
		ORDER BY score ASC, computed_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("compliance_scores list_all: %w", err)
	}
	defer rows.Close()

	var scores []*ComplianceScore
	for rows.Next() {
		sc, err := scanComplianceScore(rows)
		if err != nil {
			continue
		}
		scores = append(scores, sc)
	}
	if scores == nil {
		scores = []*ComplianceScore{}
	}
	return scores, nil
}
