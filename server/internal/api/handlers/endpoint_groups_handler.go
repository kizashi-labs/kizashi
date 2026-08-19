package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EndpointGroupsHandler manages rule-based endpoint groups. Group membership
// is evaluated live against the agents table.
type EndpointGroupsHandler struct{ pool *pgxpool.Pool }

func NewEndpointGroupsHandler(pool *pgxpool.Pool) *EndpointGroupsHandler {
	return &EndpointGroupsHandler{pool: pool}
}

type egMembershipRule struct {
	ID       string `json:"id"`
	Field    string `json:"field"`    // hostname | os | department | ip_range
	Operator string `json:"operator"` // contains | equals | matches
	Value    string `json:"value"`
}

type egPolicyRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// ruleCondition converts one rule into a SQL condition + args. Returns "" when
// the rule cannot match anything (unknown field / empty value), keeping the
// behaviour honest instead of matching everything.
func ruleCondition(r egMembershipRule, argIdx int) (string, []any) {
	val := strings.TrimSpace(r.Value)
	if val == "" {
		return "", nil
	}
	var col string
	switch r.Field {
	case "hostname":
		col = "a.hostname"
	case "os":
		col = "a.os_type"
	case "ip_range":
		// CIDR containment over the agent's IP list.
		if _, _, err := net.ParseCIDR(val); err == nil {
			return fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(a.ip_addresses) ip WHERE ip << $%d::inet)", argIdx), []any{val}
		}
		return fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(a.ip_addresses) ip WHERE host(ip) = $%d)", argIdx), []any{val}
	default:
		// department etc. have no agent attribute yet → no matches.
		return "FALSE", []any{}
	}
	switch r.Operator {
	case "equals":
		return fmt.Sprintf("LOWER(%s) = LOWER($%d)", col, argIdx), []any{val}
	case "matches":
		return fmt.Sprintf("%s ~* $%d", col, argIdx), []any{val}
	default: // contains
		return fmt.Sprintf("%s ILIKE $%d", col, argIdx), []any{"%" + val + "%"}
	}
}

// evaluateMembers returns the agents matching ALL rules (AND). No rules → no
// members (a group without rules is an empty shell, not "everything").
//
// 読めなかったときは error を返します。以前は、そこまでに読めた分だけを
// 返していました。グループは EDR ポリシーの適用先なので、「このグループは
// 12台」という表示は「12台に配られている」と読まれます。クエリが途中で
// 失敗すれば、その数は本当の台数と何の関係もありません。多い方に外れるか
// 少ない方に外れるかも分かりません。
func (h *EndpointGroupsHandler) evaluateMembers(ctx context.Context, rules []egMembershipRule) ([]gin.H, error) {
	members := []gin.H{}
	if len(rules) == 0 {
		return members, nil
	}
	conds := []string{}
	args := []any{}
	for _, r := range rules {
		cond, a := ruleCondition(r, len(args)+1)
		if cond == "" {
			continue
		}
		conds = append(conds, cond)
		args = append(args, a...)
	}
	if len(conds) == 0 {
		return members, nil
	}
	query := fmt.Sprintf(`
		SELECT a.id::text, a.hostname, a.os_type,
		       COALESCE((SELECT host(ipx) FROM unnest(a.ip_addresses) ipx LIMIT 1), ''),
		       a.last_seen
		FROM agents a
		WHERE %s
		ORDER BY a.hostname
		LIMIT 500`, strings.Join(conds, " AND "))
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostname, osType, ip string
		var lastSeen *time.Time
		if err := rows.Scan(&id, &hostname, &osType, &ip, &lastSeen); err != nil {
			continue
		}
		status := "offline"
		lastSeenStr := ""
		if lastSeen != nil {
			lastSeenStr = lastSeen.UTC().Format(time.RFC3339)
			if time.Since(*lastSeen) < 10*time.Minute {
				status = "online"
			} else if time.Since(*lastSeen) < time.Hour {
				status = "warning"
			}
		}
		members = append(members, gin.H{
			"id": id, "hostname": hostname, "os": osType,
			"ip_address": ip, "last_seen": lastSeenStr, "status": status,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return members, nil
}

// List returns all groups with live membership.
// GET /api/v1/admin/endpoint-groups
func (h *EndpointGroupsHandler) List(c *gin.Context) {
	ctx := c.Request.Context()
	groups := []gin.H{}

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, type, description, parent_id, rules, policies
		FROM endpoint_groups ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"groups": groups})
		return
	}
	defer rows.Close()

	type groupRow struct {
		id, name, typ, description string
		parentID                   *string
		rulesRaw, policiesRaw      []byte
	}
	var grs []groupRow
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.id, &g.name, &g.typ, &g.description, &g.parentID, &g.rulesRaw, &g.policiesRaw); err != nil {
			continue
		}
		grs = append(grs, g)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("List: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, gin.H{"groups": groups})
		return
	}
	rows.Close()

	for _, g := range grs {
		var rules []egMembershipRule
		_ = json.Unmarshal(g.rulesRaw, &rules)
		if rules == nil {
			rules = []egMembershipRule{}
		}
		var policies []egPolicyRef
		_ = json.Unmarshal(g.policiesRaw, &policies)
		if policies == nil {
			policies = []egPolicyRef{}
		}
		endpoints, err := h.evaluateMembers(ctx, rules)
		if err != nil {
			// 所属端末を取りこぼすと、グループが実際より小さく見える。
			c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
			return
		}
		groups = append(groups, gin.H{
			"id":             g.id,
			"name":           g.name,
			"type":           g.typ,
			"description":    g.description,
			"parent_id":      g.parentID,
			"rules":          rules,
			"policies":       policies,
			"endpoints":      endpoints,
			"endpoint_count": len(endpoints),
			"policy_count":   len(policies),
		})
	}
	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

type egUpsertRequest struct {
	Name        string             `json:"name"`
	Type        string             `json:"type"`
	Description string             `json:"description"`
	ParentID    *string            `json:"parent_id"`
	Rules       []egMembershipRule `json:"rules"`
	Policies    []egPolicyRef      `json:"policies"`
}

func (r *egUpsertRequest) normalize() ([]byte, []byte) {
	switch r.Type {
	case "department", "os", "location", "custom":
	default:
		r.Type = "custom"
	}
	if r.Rules == nil {
		r.Rules = []egMembershipRule{}
	}
	if r.Policies == nil {
		r.Policies = []egPolicyRef{}
	}
	rulesRaw, _ := json.Marshal(r.Rules)
	policiesRaw, _ := json.Marshal(r.Policies)
	return rulesRaw, policiesRaw
}

// Create adds a group.
// POST /api/v1/admin/endpoint-groups
func (h *EndpointGroupsHandler) Create(c *gin.Context) {
	var req egUpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	rulesRaw, policiesRaw := req.normalize()
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO endpoint_groups (name, type, description, parent_id, rules, policies)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb) RETURNING id`,
		req.Name, req.Type, req.Description, req.ParentID, rulesRaw, policiesRaw,
	).Scan(&id)
	if err != nil {
		// e.g. parent_id referencing a non-existent group (FK) or a malformed
		// UUID is client error → 400, not a server fault.
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "親グループ(parent_id)などの入力値が不正です"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// Update edits a group.
// PUT /api/v1/admin/endpoint-groups/:id
func (h *EndpointGroupsHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req egUpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	rulesRaw, policiesRaw := req.normalize()
	ct, err := h.pool.Exec(c.Request.Context(), `
		UPDATE endpoint_groups
		SET name=$2, type=$3, description=$4, parent_id=$5, rules=$6::jsonb, policies=$7::jsonb, updated_at=NOW()
		WHERE id=$1`,
		id, req.Name, req.Type, req.Description, req.ParentID, rulesRaw, policiesRaw)
	if err != nil {
		// Distinguish bad input (FK/invalid parent_id → 400) from an unexpected
		// DB fault (500). Only a genuine zero-row update is "not found".
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "親グループ(parent_id)などの入力値が不正です"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "グループが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "message": "グループを更新しました"})
}

// Delete removes a group.
// DELETE /api/v1/admin/endpoint-groups/:id
func (h *EndpointGroupsHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `DELETE FROM endpoint_groups WHERE id=$1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "グループが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}
