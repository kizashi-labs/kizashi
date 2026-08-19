// Package processtree builds process parent-child trees from stored events.
package processtree

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// suspiciousProcessNames lists process names that warrant investigation.
var suspiciousProcessNames = map[string]bool{
	"powershell.exe": true,
	"cmd.exe":        true,
	"wscript.exe":    true,
	"mshta.exe":      true,
	"regsvr32.exe":   true,
	"rundll32.exe":   true,
	"certutil.exe":   true,
	"cmstp.exe":      true,
}

// suspiciousCmdPatterns are substrings that flag a cmdline as suspicious.
var suspiciousCmdPatterns = []string{
	"-enc",
	"-encodedcommand",
	"/c whoami",
	"downloadstring",
	"iex(",
	"invoke-expression",
	"frombase64",
}

// suspiciousParentChild maps parent process names to suspicious child names (T-codes).
var suspiciousParentChild = map[string]map[string]string{
	"winword.exe": {
		"powershell.exe": "T1566.001",
		"cmd.exe":        "T1566.001",
		"wscript.exe":    "T1566.001",
	},
	"excel.exe": {
		"powershell.exe": "T1566.001",
		"cmd.exe":        "T1566.001",
	},
	"explorer.exe": {
		"cmd.exe": "T1059.003",
	},
	"svchost.exe": {
		"powershell.exe": "T1055",
		"cmd.exe":        "T1055",
		"wscript.exe":    "T1055",
	},
}

// ProcessNode represents a single process in the tree.
type ProcessNode struct {
	PID        int            `json:"pid"`
	PPID       int            `json:"ppid"`
	Name       string         `json:"process_name"`
	CmdLine    string         `json:"cmdline"`
	Username   string         `json:"username"`
	StartTime  time.Time      `json:"start_time"`
	EndTime    *time.Time     `json:"end_time,omitempty"`
	AgentID    string         `json:"agent_id"`
	Hostname   string         `json:"hostname"`
	Suspicious bool           `json:"suspicious"`
	MITRETech  string         `json:"mitre_tech,omitempty"`
	AlertIDs   []string       `json:"alert_ids,omitempty"`
	Children   []*ProcessNode `json:"children"`
	Depth      int            `json:"depth"`
	EventID    string         `json:"event_id"`
	ParentName string         `json:"parent_name,omitempty"`
}

// ProcessTree is the full tree structure for an agent.
type ProcessTree struct {
	AgentID         string         `json:"agent_id"`
	Hostname        string         `json:"hostname"`
	TimeRange       string         `json:"time_range"`
	Roots           []*ProcessNode `json:"roots"`
	NodeCount       int            `json:"node_count"`
	SuspiciousCount int            `json:"suspicious_count"`
}

// Builder builds process trees from the database.
type Builder struct {
	pool *pgxpool.Pool
}

// NewBuilder creates a new Builder.
func NewBuilder(pool *pgxpool.Pool) *Builder {
	return &Builder{pool: pool}
}

// isSuspicious checks whether a process name/cmdline is suspicious.
func isSuspicious(name, cmdline string) bool {
	lname := strings.ToLower(name)
	if suspiciousProcessNames[lname] {
		lcmd := strings.ToLower(cmdline)
		for _, pat := range suspiciousCmdPatterns {
			if strings.Contains(lcmd, pat) {
				return true
			}
		}
	}
	return false
}

// mitreFromParentChild returns the MITRE technique if the parent-child pair is suspicious.
func mitreFromParentChild(parentName, childName string) string {
	if children, ok := suspiciousParentChild[strings.ToLower(parentName)]; ok {
		if tech, ok := children[strings.ToLower(childName)]; ok {
			return tech
		}
	}
	return ""
}

// setDepths recursively assigns depth to children.
func setDepths(node *ProcessNode, depth int) {
	node.Depth = depth
	for _, child := range node.Children {
		setDepths(child, depth+1)
	}
}

// BuildTree builds a process tree for the given agent over the last N hours.
func (b *Builder) BuildTree(ctx context.Context, agentID string, hours int) (*ProcessTree, error) {
	if b.pool == nil {
		return &ProcessTree{AgentID: agentID, TimeRange: strconv.Itoa(hours) + "h", Roots: []*ProcessNode{}}, nil
	}

	// Fetch process events — check both table name variants gracefully.
	rows, err := b.pool.Query(ctx, `
		SELECT
			e.event_id::text,
			COALESCE(e.raw_data->>'pid', '0')          AS pid,
			COALESCE(e.raw_data->>'ppid', '0')         AS ppid,
			COALESCE(e.raw_data->>'process_name', COALESCE(e.raw_data->>'image_path', '')) AS pname,
			COALESCE(e.raw_data->>'command_line', '') AS cmdline,
			COALESCE(e.raw_data->>'username', '') AS username,
			COALESCE(e.raw_data->>'parent_name', COALESCE(e.raw_data->>'parent_image', '')) AS parent_name,
			COALESCE(a.hostname, '') AS hostname,
			e.time
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE e.agent_id = $1::uuid
		  AND e.event_type = 'process'
		  AND e.time >= NOW() - ($2 * INTERVAL '1 hour')
		ORDER BY e.time ASC
		LIMIT 500`,
		agentID, hours)
	if err != nil {
		slog.Warn("processtree: query failed", "agent_id", agentID, "error", err)
		return nil, err
	}
	defer rows.Close()

	// pid -> node map
	pidMap := make(map[int]*ProcessNode)
	var allNodes []*ProcessNode
	hostname := ""

	for rows.Next() {
		var (
			eventID    string
			pidStr     string
			ppidStr    string
			pname      string
			cmdline    string
			username   string
			parentName string
			hn         string
			ts         time.Time
		)
		if err := rows.Scan(&eventID, &pidStr, &ppidStr, &pname, &cmdline, &username, &parentName, &hn, &ts); err != nil {
			continue
		}
		pid, _ := strconv.Atoi(pidStr)
		ppid, _ := strconv.Atoi(ppidStr)
		if hn != "" && hostname == "" {
			hostname = hn
		}

		node := &ProcessNode{
			PID:        pid,
			PPID:       ppid,
			Name:       pname,
			CmdLine:    cmdline,
			Username:   username,
			StartTime:  ts,
			AgentID:    agentID,
			Hostname:   hn,
			EventID:    eventID,
			Children:   []*ProcessNode{},
			ParentName: parentName,
			AlertIDs:   []string{},
		}

		// Suspicious detection. The parent/child half runs below, once every
		// row is in pidMap and the parent can actually be named.
		if isSuspicious(pname, cmdline) {
			node.Suspicious = true
		}

		// If duplicate PID (process restart), keep latest
		pidMap[pid] = node
		allNodes = append(allNodes, node)
	}
	if err := rows.Err(); err != nil {
		// **途中までのプロセス木を返しません。** 親が読めていない子は
		// 根として並び、**攻撃の連鎖がそこで切れて見えます。**
		slog.Error("processtree: 行の読み出しが途中で失敗しました", "error", err)
		return nil, err
	}

	// The parent's name comes from the event, and from the parent's own row when
	// the event does not carry one.
	//
	// The agent resolves the parent on the endpoint while it is still alive
	// (collector.ParentResolver) and ingestion writes it to raw_data. That is
	// the better source: it names a parent that started long before this query's
	// window, which the pidMap fallback below cannot.
	//
	// Before either existed, ParentName was empty on every node — the proto
	// carried no parent at all — and mitreFromParentChild(parentName, pname) was
	// called with an empty parent on every row, so the whole technique table
	// (Office spawning a shell, a browser spawning PowerShell) could never match.
	// The fallback keeps events written by an older agent working.
	for _, node := range allNodes {
		if node.ParentName == "" && node.PPID != 0 {
			if parent, ok := pidMap[node.PPID]; ok {
				node.ParentName = parent.Name
			}
		}
		if tech := mitreFromParentChild(node.ParentName, node.Name); tech != "" {
			node.Suspicious = true
			node.MITRETech = tech
		}
	}

	// Build tree
	var roots []*ProcessNode
	for _, node := range allNodes {
		if parent, ok := pidMap[node.PPID]; ok && node.PPID != 0 {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	// Assign depths
	for _, root := range roots {
		setDepths(root, 0)
	}

	suspCount := 0
	for _, n := range allNodes {
		if n.Suspicious {
			suspCount++
		}
	}

	if roots == nil {
		roots = []*ProcessNode{}
	}

	return &ProcessTree{
		AgentID:         agentID,
		Hostname:        hostname,
		TimeRange:       strconv.Itoa(hours) + "h",
		Roots:           roots,
		NodeCount:       len(allNodes),
		SuspiciousCount: suspCount,
	}, nil
}

// GetProcessDetails returns a single process detail by event ID.
func (b *Builder) GetProcessDetails(ctx context.Context, eventID string) (*ProcessNode, error) {
	if b.pool == nil {
		return nil, nil
	}

	var rawData []byte
	var ts time.Time
	var agentID string

	err := b.pool.QueryRow(ctx, `
		SELECT event_id::text, agent_id::text, raw_data, time
		FROM events
		WHERE event_id = $1::uuid`, eventID,
	).Scan(&eventID, &agentID, &rawData, &ts)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, err
	}

	strField := func(key string, fallbacks ...string) string {
		if v, ok := data[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		for _, fb := range fallbacks {
			if v, ok := data[fb]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}

	pidStr := strField("pid")
	ppidStr := strField("ppid")
	pid, _ := strconv.Atoi(pidStr)
	ppid, _ := strconv.Atoi(ppidStr)
	pname := strField("process_name", "image")
	cmdline := strField("cmdline", "commandline")
	username := strField("username", "user")
	parentName := strField("parent_name", "parent_image")
	hostname := strField("hostname")

	node := &ProcessNode{
		PID:        pid,
		PPID:       ppid,
		Name:       pname,
		CmdLine:    cmdline,
		Username:   username,
		StartTime:  ts,
		AgentID:    agentID,
		Hostname:   hostname,
		EventID:    eventID,
		Children:   []*ProcessNode{},
		ParentName: parentName,
		AlertIDs:   []string{},
	}
	if isSuspicious(pname, cmdline) {
		node.Suspicious = true
	}
	if tech := mitreFromParentChild(parentName, pname); tech != "" {
		node.Suspicious = true
		node.MITRETech = tech
	}
	return node, nil
}

// SearchProcesses searches processes by name for the given agent.
func (b *Builder) SearchProcesses(ctx context.Context, agentID, name string, hours int) ([]*ProcessNode, error) {
	if b.pool == nil {
		return []*ProcessNode{}, nil
	}

	rows, err := b.pool.Query(ctx, `
		SELECT
			event_id::text,
			COALESCE(raw_data->>'pid', '0')          AS pid,
			COALESCE(raw_data->>'ppid', '0')         AS ppid,
			COALESCE(raw_data->>'process_name', COALESCE(raw_data->>'image_path', '')) AS pname,
			COALESCE(raw_data->>'command_line', COALESCE(raw_data->>'cmdline', '')) AS cmdline,
			COALESCE(raw_data->>'username', COALESCE(raw_data->>'user', '')) AS username,
			COALESCE(raw_data->>'parent_name', COALESCE(raw_data->>'parent_image', '')) AS parent_name,
			COALESCE((SELECT a.hostname FROM agents a WHERE a.id = events.agent_id), '') AS hostname,
			time
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND (raw_data->>'process_name' ILIKE $2 OR raw_data->>'image_path' ILIKE $2)
		  AND time >= NOW() - ($3 * INTERVAL '1 hour')
		ORDER BY time DESC
		LIMIT 200`,
		agentID, "%"+name+"%", hours)
	if err != nil {
		slog.Warn("processtree: search failed", "agent_id", agentID, "name", name, "error", err)
		return nil, err
	}
	defer rows.Close()

	var results []*ProcessNode
	for rows.Next() {
		var (
			eventID    string
			pidStr     string
			ppidStr    string
			pname      string
			cmdline    string
			username   string
			parentName string
			hn         string
			ts         time.Time
		)
		if err := rows.Scan(&eventID, &pidStr, &ppidStr, &pname, &cmdline, &username, &parentName, &hn, &ts); err != nil {
			continue
		}
		pid, _ := strconv.Atoi(pidStr)
		ppid, _ := strconv.Atoi(ppidStr)
		node := &ProcessNode{
			PID:        pid,
			PPID:       ppid,
			Name:       pname,
			CmdLine:    cmdline,
			Username:   username,
			StartTime:  ts,
			AgentID:    agentID,
			Hostname:   hn,
			EventID:    eventID,
			Children:   []*ProcessNode{},
			ParentName: parentName,
			AlertIDs:   []string{},
		}
		if isSuspicious(pname, cmdline) {
			node.Suspicious = true
		}
		if tech := mitreFromParentChild(parentName, pname); tech != "" {
			node.Suspicious = true
			node.MITRETech = tech
		}
		results = append(results, node)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if results == nil {
		results = []*ProcessNode{}
	}
	return results, nil
}

// SearchSuspiciousAllAgents returns suspicious processes across all agents.
func (b *Builder) SearchSuspiciousAllAgents(ctx context.Context, hours int) ([]*ProcessNode, error) {
	if b.pool == nil {
		return []*ProcessNode{}, nil
	}

	// Build IN clause for suspicious process names.
	nameList := make([]string, 0, len(suspiciousProcessNames))
	for n := range suspiciousProcessNames {
		nameList = append(nameList, n)
	}

	// Build cmdline pattern for suspicious patterns.
	patternWhere := ""
	for _, pat := range suspiciousCmdPatterns {
		if patternWhere != "" {
			patternWhere += " OR "
		}
		patternWhere += "LOWER(COALESCE(raw_data->>'command_line', raw_data->>'cmdline', '')) LIKE '%" + strings.ReplaceAll(pat, "'", "''") + "%'"
	}

	// Build name IN clause.
	nameWhere := ""
	for i, n := range nameList {
		if i > 0 {
			nameWhere += ", "
		}
		nameWhere += "'" + strings.ReplaceAll(n, "'", "''") + "'"
	}

	query := `
		SELECT
			event_id::text,
			agent_id::text,
			COALESCE(raw_data->>'pid', '0')          AS pid,
			COALESCE(raw_data->>'ppid', '0')         AS ppid,
			COALESCE(raw_data->>'process_name', COALESCE(raw_data->>'image_path', '')) AS pname,
			COALESCE(raw_data->>'command_line', COALESCE(raw_data->>'cmdline', '')) AS cmdline,
			COALESCE(raw_data->>'username', COALESCE(raw_data->>'user', '')) AS username,
			COALESCE(raw_data->>'parent_name', COALESCE(raw_data->>'parent_image', '')) AS parent_name,
			COALESCE((SELECT a.hostname FROM agents a WHERE a.id = events.agent_id), '') AS hostname,
			time
		FROM events
		WHERE event_type = 'process'
		  AND time >= NOW() - ($1 * INTERVAL '1 hour')
		  AND (
			LOWER(COALESCE(raw_data->>'process_name', raw_data->>'image_path', '')) IN (` + nameWhere + `)
			AND (` + patternWhere + `)
		  )
		ORDER BY time DESC
		LIMIT 500`

	rows, err := b.pool.Query(ctx, query, hours)
	if err != nil {
		slog.Warn("processtree: suspicious all-agent query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	var results []*ProcessNode
	for rows.Next() {
		var (
			eventID    string
			agentID    string
			pidStr     string
			ppidStr    string
			pname      string
			cmdline    string
			username   string
			parentName string
			hn         string
			ts         time.Time
		)
		if err := rows.Scan(&eventID, &agentID, &pidStr, &ppidStr, &pname, &cmdline, &username, &parentName, &hn, &ts); err != nil {
			continue
		}
		pid, _ := strconv.Atoi(pidStr)
		ppid, _ := strconv.Atoi(ppidStr)
		node := &ProcessNode{
			PID:        pid,
			PPID:       ppid,
			Name:       pname,
			CmdLine:    cmdline,
			Username:   username,
			StartTime:  ts,
			AgentID:    agentID,
			Hostname:   hn,
			EventID:    eventID,
			Suspicious: true,
			Children:   []*ProcessNode{},
			ParentName: parentName,
			AlertIDs:   []string{},
		}
		if tech := mitreFromParentChild(parentName, pname); tech != "" {
			node.MITRETech = tech
		}
		results = append(results, node)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if results == nil {
		results = []*ProcessNode{}
	}
	return results, nil
}
