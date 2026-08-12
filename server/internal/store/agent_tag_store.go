package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentTagStore manages agent tag persistence.
type AgentTagStore struct {
	pool *pgxpool.Pool
}

// NewAgentTagStore creates a new AgentTagStore backed by the given pool.
func NewAgentTagStore(pool *pgxpool.Pool) *AgentTagStore {
	return &AgentTagStore{pool: pool}
}

// ListByAgent returns all tag strings for a given agent.
func (s *AgentTagStore) ListByAgent(ctx context.Context, agentID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT tag FROM agent_tags WHERE agent_id = $1 ORDER BY tag`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			continue
		}
		tags = append(tags, tag)
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, nil
}

// Add inserts a tag for an agent. Duplicate tags are silently ignored.
func (s *AgentTagStore) Add(ctx context.Context, agentID, tag string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agent_tags (agent_id, tag) VALUES ($1::uuid, $2) ON CONFLICT DO NOTHING`,
		agentID, tag)
	return err
}

// Remove deletes a tag from an agent.
func (s *AgentTagStore) Remove(ctx context.Context, agentID, tag string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM agent_tags WHERE agent_id = $1::uuid AND tag = $2`,
		agentID, tag)
	return err
}

// ListByTag returns agent IDs that have the specified tag.
func (s *AgentTagStore) ListByTag(ctx context.Context, tag string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT agent_id::text FROM agent_tags WHERE tag = $1 ORDER BY agent_id`, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		agentIDs = append(agentIDs, id)
	}
	if agentIDs == nil {
		agentIDs = []string{}
	}
	return agentIDs, nil
}

// AllTags returns all distinct tags across all agents.
func (s *AgentTagStore) AllTags(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT tag FROM agent_tags ORDER BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			continue
		}
		tags = append(tags, tag)
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, nil
}
