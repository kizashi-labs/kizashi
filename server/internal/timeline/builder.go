// Package timeline builds chronological attack timelines from all event types.
package timeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TimelineEvent represents a single event in the timeline.
type TimelineEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"` // process/network/file/registry/alert/auth/dns
	Category    string                 `json:"category"`   // execution/persistence/discovery/lateral_movement/exfiltration/c2/defense_evasion
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	AgentID     string                 `json:"agent_id"`
	Hostname    string                 `json:"hostname"`
	Severity    int                    `json:"severity"`
	MITRETech   string                 `json:"mitre_tech,omitempty"`
	IsAlert     bool                   `json:"is_alert"`
	AlertID     string                 `json:"alert_id,omitempty"`
	Data        map[string]interface{} `json:"data"`
	RelatedIDs  []string               `json:"related_ids,omitempty"`
}

// Timeline is the full timeline for an agent or incident.
type Timeline struct {
	AgentID      string           `json:"agent_id"`
	Hostname     string           `json:"hostname"`
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time"`
	Events       []*TimelineEvent `json:"events"`
	TotalEvents  int              `json:"total_events"`
	AlertCount   int              `json:"alert_count"`
	AttackPhases []string         `json:"attack_phases"` // MITRE tactics detected
}

// Builder builds timelines from the database.
type Builder struct {
	pool *pgxpool.Pool
}

// NewBuilder creates a new Builder.
func NewBuilder(pool *pgxpool.Pool) *Builder {
	return &Builder{pool: pool}
}

// categoryFromEventType maps event types to MITRE-aligned categories.
func categoryFromEventType(eventType string, data map[string]interface{}) string {
	switch eventType {
	case "process":
		pname := strings.ToLower(strData(data, "process_name", "image"))
		cmd := strings.ToLower(strData(data, "cmdline", "commandline"))
		if strings.Contains(cmd, "schtasks") || strings.Contains(cmd, "reg add") {
			return "persistence"
		}
		if pname == "net.exe" || pname == "whoami.exe" || pname == "ipconfig.exe" {
			return "discovery"
		}
		return "execution"
	case "network":
		port := strData(data, "destination_port", "dst_port")
		if port == "443" || port == "80" {
			return "c2"
		}
		if port == "445" || port == "135" || port == "139" {
			return "lateral_movement"
		}
		return "exfiltration"
	case "file":
		op := strings.ToLower(strData(data, "operation", "action"))
		if strings.Contains(op, "write") || strings.Contains(op, "create") {
			return "persistence"
		}
		return "defense_evasion"
	case "registry":
		return "persistence"
	case "auth":
		return "lateral_movement"
	case "dns":
		return "c2"
	case "alert":
		return "execution"
	}
	return "execution"
}

// strData extracts a string from a map trying multiple keys.
func strData(data map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := data[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// titleFromEvent generates a human-readable title for an event.
func titleFromEvent(eventType string, data map[string]interface{}) string {
	switch eventType {
	case "process":
		pname := strData(data, "process_name", "image")
		if pname == "" {
			pname = "Unknown Process"
		}
		return "Process: " + pname
	case "network":
		dst := strData(data, "destination_ip", "dst_ip")
		port := strData(data, "destination_port", "dst_port")
		if dst != "" {
			return fmt.Sprintf("Network: %s:%s", dst, port)
		}
		return "Network Connection"
	case "file":
		path := strData(data, "path", "file_path")
		op := strData(data, "operation", "action")
		if path != "" {
			return fmt.Sprintf("File %s: %s", op, path)
		}
		return "File Operation"
	case "registry":
		key := strData(data, "registry_key", "key")
		return "Registry: " + key
	case "auth":
		user := strData(data, "username", "user")
		return "Auth: " + user
	case "dns":
		query := strData(data, "query", "dns_query")
		return "DNS: " + query
	default:
		return strings.ToUpper(eventType[:1]) + eventType[1:] + " Event"
	}
}

// descriptionFromEvent generates a description for an event.
func descriptionFromEvent(eventType string, data map[string]interface{}) string {
	switch eventType {
	case "process":
		cmd := strData(data, "cmdline", "commandline")
		if cmd != "" {
			if len(cmd) > 120 {
				cmd = cmd[:120] + "..."
			}
			return "Cmdline: " + cmd
		}
	case "network":
		proto := strData(data, "protocol")
		return fmt.Sprintf("Protocol: %s", proto)
	case "file":
		op := strData(data, "operation", "action")
		return "Operation: " + op
	}
	return ""
}

// detectAttackPhases derives MITRE tactic names from the events.
func detectAttackPhases(events []*TimelineEvent) []string {
	seen := map[string]bool{}
	for _, e := range events {
		switch e.Category {
		case "execution":
			seen["Execution"] = true
		case "persistence":
			seen["Persistence"] = true
		case "discovery":
			seen["Discovery"] = true
		case "lateral_movement":
			seen["Lateral Movement"] = true
		case "exfiltration":
			seen["Exfiltration"] = true
		case "c2":
			seen["Command & Control"] = true
		case "defense_evasion":
			seen["Defense Evasion"] = true
		}
	}
	phases := make([]string, 0, len(seen))
	for p := range seen {
		phases = append(phases, p)
	}
	sort.Strings(phases)
	return phases
}

// markRelatedEvents links events that share a process name, IP, or file path.
func markRelatedEvents(events []*TimelineEvent) {
	// Map key -> slice of event IDs
	groups := map[string][]string{}
	for _, e := range events {
		keys := []string{}
		if pname := strData(e.Data, "process_name", "image"); pname != "" {
			keys = append(keys, "proc:"+strings.ToLower(pname))
		}
		if ip := strData(e.Data, "destination_ip", "dst_ip"); ip != "" {
			keys = append(keys, "ip:"+ip)
		}
		if path := strData(e.Data, "path", "file_path"); path != "" {
			keys = append(keys, "file:"+strings.ToLower(path))
		}
		for _, k := range keys {
			groups[k] = append(groups[k], e.ID)
		}
	}
	// Build related map
	related := map[string]map[string]bool{}
	for _, ids := range groups {
		if len(ids) <= 1 {
			continue
		}
		for _, id := range ids {
			if related[id] == nil {
				related[id] = map[string]bool{}
			}
			for _, other := range ids {
				if other != id {
					related[id][other] = true
				}
			}
		}
	}
	for _, e := range events {
		if m, ok := related[e.ID]; ok {
			for rid := range m {
				e.RelatedIDs = append(e.RelatedIDs, rid)
			}
			sort.Strings(e.RelatedIDs)
		}
	}
}

// BuildAgentTimeline builds the full timeline for an agent.
func (b *Builder) BuildAgentTimeline(ctx context.Context, agentID string, hours int) (*Timeline, error) {
	if b.pool == nil {
		now := time.Now()
		return &Timeline{
			AgentID:      agentID,
			StartTime:    now.Add(-time.Duration(hours) * time.Hour),
			EndTime:      now,
			Events:       []*TimelineEvent{},
			AttackPhases: []string{},
		}, nil
	}

	now := time.Now()
	startTime := now.Add(-time.Duration(hours) * time.Hour)
	var events []*TimelineEvent

	// Fetch agent events
	rows, err := b.pool.Query(ctx, fmt.Sprintf(`
		SELECT event_id::text, event_type,
		       COALESCE(raw_data, '{}')::text,
		       COALESCE(raw_data->>'hostname', '') AS hostname,
		       time
		FROM events
		WHERE agent_id = $1::uuid
		  AND time >= NOW() - INTERVAL '%d hours'
		ORDER BY time ASC
		LIMIT 800`, hours), agentID)
	if err != nil {
		slog.Warn("timeline: events query failed", "error", err)
	} else {
		defer rows.Close()
		hostname := ""
		for rows.Next() {
			var (
				id     string
				evType string
				rawStr string
				hn     string
				ts     time.Time
			)
			if err := rows.Scan(&id, &evType, &rawStr, &hn, &ts); err != nil {
				continue
			}
			if hn != "" && hostname == "" {
				hostname = hn
			}
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(rawStr), &data); err != nil {
				data = map[string]interface{}{}
			}

			ev := &TimelineEvent{
				ID:          id,
				Timestamp:   ts,
				EventType:   evType,
				AgentID:     agentID,
				Hostname:    hn,
				Category:    categoryFromEventType(evType, data),
				Title:       titleFromEvent(evType, data),
				Description: descriptionFromEvent(evType, data),
				Data:        data,
				RelatedIDs:  []string{},
			}
			events = append(events, ev)
		}
		rows.Close()
		// Update hostname on events
		if hostname != "" {
			for _, e := range events {
				if e.Hostname == "" {
					e.Hostname = hostname
				}
			}
		}
	}

	// Fetch alerts
	alertRows, err := b.pool.Query(ctx, fmt.Sprintf(`
		SELECT al.id::text, COALESCE(al.title,''), COALESCE(al.severity,0)::int,
		       COALESCE(r.name,''), al.created_at
		FROM alerts al
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.agent_id = $1::uuid
		  AND al.created_at >= NOW() - INTERVAL '%d hours'
		ORDER BY al.created_at ASC
		LIMIT 200`, hours), agentID)
	if err != nil {
		slog.Warn("timeline: alerts query failed", "error", err)
	} else {
		defer alertRows.Close()
		for alertRows.Next() {
			var (
				id       string
				title    string
				severity int
				ruleName string
				ts       time.Time
			)
			if err := alertRows.Scan(&id, &title, &severity, &ruleName, &ts); err != nil {
				continue
			}
			ev := &TimelineEvent{
				ID:          id,
				Timestamp:   ts,
				EventType:   "alert",
				AgentID:     agentID,
				Category:    "execution",
				Title:       title,
				Description: "Rule: " + ruleName,
				Severity:    severity,
				IsAlert:     true,
				AlertID:     id,
				Data:        map[string]interface{}{"rule_name": ruleName, "severity": severity},
				RelatedIDs:  []string{},
			}
			events = append(events, ev)
		}
		alertRows.Close()
	}

	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	// Truncate to 1000
	if len(events) > 1000 {
		events = events[:1000]
	}

	// Mark related events
	markRelatedEvents(events)

	alertCount := 0
	for _, e := range events {
		if e.IsAlert {
			alertCount++
		}
	}

	phases := detectAttackPhases(events)

	hostname := ""
	for _, e := range events {
		if e.Hostname != "" {
			hostname = e.Hostname
			break
		}
	}

	if events == nil {
		events = []*TimelineEvent{}
	}

	return &Timeline{
		AgentID:      agentID,
		Hostname:     hostname,
		StartTime:    startTime,
		EndTime:      now,
		Events:       events,
		TotalEvents:  len(events),
		AlertCount:   alertCount,
		AttackPhases: phases,
	}, nil
}

// BuildIncidentTimeline builds a multi-agent timeline for an incident.
func (b *Builder) BuildIncidentTimeline(ctx context.Context, incidentID string) (*Timeline, error) {
	if b.pool == nil {
		return &Timeline{Events: []*TimelineEvent{}, AttackPhases: []string{}}, nil
	}

	now := time.Now()

	// Get alert IDs linked to the incident
	rows, err := b.pool.Query(ctx, `
		SELECT alert_id::text FROM incident_alerts WHERE incident_id = $1::uuid`, incidentID)
	if err != nil {
		slog.Warn("timeline: incident_alerts query failed", "error", err)
		return &Timeline{Events: []*TimelineEvent{}, AttackPhases: []string{}}, nil
	}
	defer rows.Close()

	var alertIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			alertIDs = append(alertIDs, id)
		}
	}
	rows.Close()

	if len(alertIDs) == 0 {
		return &Timeline{Events: []*TimelineEvent{}, AttackPhases: []string{}}, nil
	}

	// Gather agent IDs and timestamps from those alerts
	type alertInfo struct {
		agentID   string
		createdAt time.Time
	}
	var alertInfos []alertInfo

	for _, aid := range alertIDs {
		var agentID string
		var ts time.Time
		err := b.pool.QueryRow(ctx, `
			SELECT COALESCE(agent_id::text, ''), created_at FROM alerts WHERE id = $1::uuid`, aid,
		).Scan(&agentID, &ts)
		if err == nil && agentID != "" {
			alertInfos = append(alertInfos, alertInfo{agentID: agentID, createdAt: ts})
		}
	}

	var allEvents []*TimelineEvent
	startTime := now
	endTime := time.Time{}

	// For each agent+alert, gather events ±30 min
	seen := map[string]bool{}
	for _, info := range alertInfos {
		if seen[info.agentID] {
			continue
		}
		seen[info.agentID] = true
		from := info.createdAt.Add(-30 * time.Minute)
		to := info.createdAt.Add(30 * time.Minute)
		if from.Before(startTime) {
			startTime = from
		}
		if to.After(endTime) {
			endTime = to
		}

		evRows, err := b.pool.Query(ctx, `
			SELECT event_id::text, event_type,
			       COALESCE(raw_data, '{}')::text,
			       COALESCE(raw_data->>'hostname', '') AS hostname,
			       time
			FROM events
			WHERE agent_id = $1::uuid
			  AND time BETWEEN $2 AND $3
			ORDER BY time ASC
			LIMIT 300`, info.agentID, from, to)
		if err != nil {
			slog.Warn("timeline: incident events query failed", "agent_id", info.agentID, "error", err)
			continue
		}
		for evRows.Next() {
			var (
				id     string
				evType string
				rawStr string
				hn     string
				ts     time.Time
			)
			if err := evRows.Scan(&id, &evType, &rawStr, &hn, &ts); err != nil {
				continue
			}
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(rawStr), &data); err != nil {
				data = map[string]interface{}{}
			}
			ev := &TimelineEvent{
				ID:          id,
				Timestamp:   ts,
				EventType:   evType,
				AgentID:     info.agentID,
				Hostname:    hn,
				Category:    categoryFromEventType(evType, data),
				Title:       titleFromEvent(evType, data),
				Description: descriptionFromEvent(evType, data),
				Data:        data,
				RelatedIDs:  []string{},
			}
			allEvents = append(allEvents, ev)
		}
		evRows.Close()
	}

	// Add alert events
	for _, aid := range alertIDs {
		var (
			id       string
			title    string
			severity int
			ruleName string
			agentID  string
			ts       time.Time
		)
		err := b.pool.QueryRow(ctx, `
			SELECT al.id::text, COALESCE(al.title,''), COALESCE(al.severity,0)::int,
			       COALESCE(r.name,''), COALESCE(al.agent_id::text,''), al.created_at
			FROM alerts al
			LEFT JOIN rules r ON r.id = al.rule_id
			WHERE al.id = $1::uuid`, aid,
		).Scan(&id, &title, &severity, &ruleName, &agentID, &ts)
		if err != nil {
			continue
		}
		ev := &TimelineEvent{
			ID:          id,
			Timestamp:   ts,
			EventType:   "alert",
			AgentID:     agentID,
			Category:    "execution",
			Title:       title,
			Description: "Rule: " + ruleName,
			Severity:    severity,
			IsAlert:     true,
			AlertID:     id,
			Data:        map[string]interface{}{"rule_name": ruleName},
			RelatedIDs:  []string{},
		}
		allEvents = append(allEvents, ev)
	}

	// Sort and truncate
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.Before(allEvents[j].Timestamp)
	})
	if len(allEvents) > 1000 {
		allEvents = allEvents[:1000]
	}
	markRelatedEvents(allEvents)

	alertCount := 0
	for _, e := range allEvents {
		if e.IsAlert {
			alertCount++
		}
	}

	if endTime.IsZero() {
		endTime = now
	}
	if allEvents == nil {
		allEvents = []*TimelineEvent{}
	}

	return &Timeline{
		StartTime:    startTime,
		EndTime:      endTime,
		Events:       allEvents,
		TotalEvents:  len(allEvents),
		AlertCount:   alertCount,
		AttackPhases: detectAttackPhases(allEvents),
	}, nil
}

// BuildAlertTimeline builds a timeline for ±15 min around an alert.
func (b *Builder) BuildAlertTimeline(ctx context.Context, alertID string) (*Timeline, error) {
	if b.pool == nil {
		return &Timeline{Events: []*TimelineEvent{}, AttackPhases: []string{}}, nil
	}

	// Get alert details
	var (
		agentID  string
		title    string
		severity int
		ruleName string
		ts       time.Time
	)
	err := b.pool.QueryRow(ctx, `
		SELECT COALESCE(al.agent_id::text,''), COALESCE(al.title,''),
		       COALESCE(al.severity,0)::int, COALESCE(r.name,''), al.created_at
		FROM alerts al
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.id = $1::uuid`, alertID,
	).Scan(&agentID, &title, &severity, &ruleName, &ts)
	if err != nil {
		slog.Warn("timeline: alert not found", "alert_id", alertID, "error", err)
		return &Timeline{Events: []*TimelineEvent{}, AttackPhases: []string{}}, nil
	}

	from := ts.Add(-6 * time.Hour)
	to := ts.Add(6 * time.Hour)

	var events []*TimelineEvent

	// Add the alert itself
	alertEv := &TimelineEvent{
		ID:          alertID,
		Timestamp:   ts,
		EventType:   "alert",
		AgentID:     agentID,
		Category:    "execution",
		Title:       title,
		Description: "Rule: " + ruleName,
		Severity:    severity,
		IsAlert:     true,
		AlertID:     alertID,
		Data:        map[string]interface{}{"rule_name": ruleName, "severity": severity},
		RelatedIDs:  []string{},
	}
	events = append(events, alertEv)

	if agentID != "" {
		evRows, err := b.pool.Query(ctx, `
			SELECT event_id::text, event_type,
			       COALESCE(raw_data, '{}')::text,
			       COALESCE(raw_data->>'hostname', '') AS hostname,
			       time
			FROM events
			WHERE agent_id = $1::uuid
			  AND time BETWEEN $2 AND $3
			ORDER BY time ASC
			LIMIT 2000`, agentID, from, to)
		if err == nil {
			for evRows.Next() {
				var (
					id     string
					evType string
					rawStr string
					hn     string
					ets    time.Time
				)
				if err := evRows.Scan(&id, &evType, &rawStr, &hn, &ets); err != nil {
					continue
				}
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(rawStr), &data); err != nil {
					data = map[string]interface{}{}
				}
				ev := &TimelineEvent{
					ID:          id,
					Timestamp:   ets,
					EventType:   evType,
					AgentID:     agentID,
					Hostname:    hn,
					Category:    categoryFromEventType(evType, data),
					Title:       titleFromEvent(evType, data),
					Description: descriptionFromEvent(evType, data),
					Data:        data,
					RelatedIDs:  []string{},
				}
				events = append(events, ev)
			}
			evRows.Close()
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	if len(events) > 1000 {
		events = events[:1000]
	}
	markRelatedEvents(events)

	alertCount := 0
	for _, e := range events {
		if e.IsAlert {
			alertCount++
		}
	}

	if events == nil {
		events = []*TimelineEvent{}
	}

	return &Timeline{
		AgentID:      agentID,
		StartTime:    from,
		EndTime:      to,
		Events:       events,
		TotalEvents:  len(events),
		AlertCount:   alertCount,
		AttackPhases: detectAttackPhases(events),
	}, nil
}
