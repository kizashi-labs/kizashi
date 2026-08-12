// Package hunting provides the threat hunting query engine.
package hunting

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// QueryFilter defines a single filter condition.
type QueryFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // eq, neq, contains, gt, lt, in, regex
	Value    string `json:"value"`
}

// HuntingQuery represents a structured threat hunting query.
type HuntingQuery struct {
	ID          string        `json:"id,omitempty"`
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	EventTypes  []string      `json:"event_types"` // process, network, file, dns, registry, auth
	Filters     []QueryFilter `json:"filters"`
	TimeRange   TimeRange     `json:"time_range"`
	Limit       int           `json:"limit"`
	OrderBy     string        `json:"order_by"` // timestamp asc/desc
	AgentIDs    []string      `json:"agent_ids,omitempty"`
}

// TimeRange defines a time window for the query.
type TimeRange struct {
	Start string `json:"start,omitempty"` // RFC3339
	End   string `json:"end,omitempty"`   // RFC3339
	Last  string `json:"last,omitempty"`  // e.g. "1h", "24h", "7d"
}

// HuntingResult contains a single event result.
type HuntingResult struct {
	EventID   string                 `json:"event_id"`
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname"`
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  int                    `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// QueryResult contains the full query result set.
type QueryResult struct {
	Total     int             `json:"total"`
	Returned  int             `json:"returned"`
	TimeTaken string          `json:"time_taken"`
	Results   []HuntingResult `json:"results"`
	Query     *HuntingQuery   `json:"query,omitempty"`
}

// Engine executes hunting queries against the events database.
type Engine struct {
	pool *pgxpool.Pool
}

// NewEngine creates a new hunting Engine.
func NewEngine(pool *pgxpool.Pool) *Engine {
	return &Engine{pool: pool}
}

// Execute runs a hunting query and returns results.
func (e *Engine) Execute(ctx context.Context, q *HuntingQuery) (*QueryResult, error) {
	start := time.Now()

	// Build the query
	sql, args, err := buildSQL(q)
	if err != nil {
		return nil, fmt.Errorf("query build error: %w", err)
	}

	rows, err := e.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query execution error: %w", err)
	}
	defer rows.Close()

	var results []HuntingResult
	for rows.Next() {
		var r HuntingResult
		var rawData []byte
		var agentID, hostname string
		if err := rows.Scan(&r.EventID, &agentID, &hostname, &r.EventType,
			&r.Timestamp, &r.Severity, &rawData); err != nil {
			continue
		}
		r.AgentID = agentID
		r.Hostname = hostname
		r.Data = parseRawData(rawData)
		results = append(results, r)
	}

	if results == nil {
		results = []HuntingResult{}
	}

	return &QueryResult{
		Total:     len(results),
		Returned:  len(results),
		TimeTaken: time.Since(start).String(),
		Results:   results,
		Query:     q,
	}, nil
}

// buildSQL constructs a safe parameterized SQL query from a HuntingQuery.
func buildSQL(q *HuntingQuery) (string, []interface{}, error) {
	var args []interface{}
	argIdx := 1

	// Allowed fields for filtering (whitelist to prevent injection)
	allowedFields := map[string]string{
		"event_type":   "e.event_type",
		"agent_id":     "e.agent_id::text",
		"severity":     "e.severity",
		"hostname":     "a.hostname",
		"process_name": "e.raw_data->>'process_name'",
		"cmdline":      "e.raw_data->>'cmdline'",
		"file_path":    "e.raw_data->>'file_path'",
		"src_ip":       "e.raw_data->>'src_ip'",
		"dst_ip":       "e.raw_data->>'dst_ip'",
		"dst_port":     "e.raw_data->>'dst_port'",
		"domain":       "e.raw_data->>'domain'",
		"username":     "e.raw_data->>'username'",
		"hash":         "e.raw_data->>'hash'",
		"rule_id":      "e.raw_data->>'rule_id'",
	}

	where := []string{"1=1"}

	// Event type filter
	if len(q.EventTypes) > 0 {
		placeholders := make([]string, len(q.EventTypes))
		for i, et := range q.EventTypes {
			args = append(args, et)
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			argIdx++
		}
		where = append(where, fmt.Sprintf("e.event_type IN (%s)", strings.Join(placeholders, ",")))
	}

	// Agent ID filter
	if len(q.AgentIDs) > 0 {
		placeholders := make([]string, len(q.AgentIDs))
		for i, id := range q.AgentIDs {
			args = append(args, id)
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			argIdx++
		}
		where = append(where, fmt.Sprintf("e.agent_id::text IN (%s)", strings.Join(placeholders, ",")))
	}

	// Time range
	if q.TimeRange.Last != "" {
		interval, err := parseLast(q.TimeRange.Last)
		if err != nil {
			return "", nil, err
		}
		args = append(args, interval)
		where = append(where, fmt.Sprintf("e.time >= NOW() - $%d::interval", argIdx))
		argIdx++
	} else {
		if q.TimeRange.Start != "" {
			args = append(args, q.TimeRange.Start)
			where = append(where, fmt.Sprintf("e.time >= $%d::timestamptz", argIdx))
			argIdx++
		}
		if q.TimeRange.End != "" {
			args = append(args, q.TimeRange.End)
			where = append(where, fmt.Sprintf("e.time <= $%d::timestamptz", argIdx))
			argIdx++
		}
	}

	// Custom filters
	for _, f := range q.Filters {
		dbField, ok := allowedFields[f.Field]
		if !ok {
			continue // Skip unknown fields (security)
		}

		switch f.Operator {
		case "eq":
			args = append(args, f.Value)
			where = append(where, fmt.Sprintf("%s = $%d", dbField, argIdx))
			argIdx++
		case "neq":
			args = append(args, f.Value)
			where = append(where, fmt.Sprintf("%s != $%d", dbField, argIdx))
			argIdx++
		case "contains":
			args = append(args, "%"+f.Value+"%")
			where = append(where, fmt.Sprintf("%s ILIKE $%d", dbField, argIdx))
			argIdx++
		case "gt":
			args = append(args, f.Value)
			where = append(where, fmt.Sprintf("%s > $%d", dbField, argIdx))
			argIdx++
		case "lt":
			args = append(args, f.Value)
			where = append(where, fmt.Sprintf("%s < $%d", dbField, argIdx))
			argIdx++
		}
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	orderDir := "DESC"
	if strings.ToLower(q.OrderBy) == "asc" {
		orderDir = "ASC"
	}

	sqlStr := fmt.Sprintf(`
		SELECT
			e.event_id::text,
			e.agent_id::text,
			COALESCE(a.hostname, e.agent_id::text),
			e.event_type,
			e.time,
			COALESCE(e.severity, 0),
			e.raw_data
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE %s
		ORDER BY e.time %s
		LIMIT %d
	`, strings.Join(where, " AND "), orderDir, limit)

	return sqlStr, args, nil
}

// parseLast converts "1h", "24h", "7d" to PostgreSQL interval strings.
func parseLast(last string) (string, error) {
	last = strings.ToLower(strings.TrimSpace(last))
	switch last {
	case "15m":
		return "15 minutes", nil
	case "1h":
		return "1 hour", nil
	case "6h":
		return "6 hours", nil
	case "24h", "1d":
		return "24 hours", nil
	case "7d":
		return "7 days", nil
	case "30d":
		return "30 days", nil
	default:
		return "", fmt.Errorf("unsupported time range: %q (use 15m, 1h, 6h, 24h, 7d, 30d)", last)
	}
}

// parseRawData safely parses JSONB raw_data bytes.
func parseRawData(data []byte) map[string]interface{} {
	if len(data) == 0 {
		return map[string]interface{}{}
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return map[string]interface{}{"_raw": string(data)}
	}
	return result
}
