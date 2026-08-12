package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ThreatActorHandler serves the threat_actors intel store (adversary SDOs
// imported from STIX plus manual entries). It replaces the former empty-array
// stubs at /threat-intel/actors.
type ThreatActorHandler struct {
	pool *pgxpool.Pool
}

// NewThreatActorHandler creates a ThreatActorHandler.
func NewThreatActorHandler(pool *pgxpool.Pool) *ThreatActorHandler {
	return &ThreatActorHandler{pool: pool}
}

// threatActor mirrors a threat_actors row for JSON responses. The trailing
// display fields (threat_level, motivation, …) are not columns yet; they are
// filled with safe defaults so the existing actors UI — previously fed by an
// empty-array stub — renders real data without assuming a richer shape than the
// store currently tracks.
type threatActor struct {
	ID           string   `json:"id"`
	STIXID       string   `json:"stix_id,omitempty"`
	Name         string   `json:"name"`
	ActorType    string   `json:"actor_type"`
	Description  string   `json:"description,omitempty"`
	Aliases      []string `json:"aliases"`
	MalwareTypes []string `json:"malware_types"`
	MITREIDs     []string `json:"mitre_ids"`
	Labels       []string `json:"labels"`
	Source       string   `json:"source"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	// Display-only fields (defaults; not persisted yet). Arrays are always
	// non-nil so the detail UI can .map/.length over them without crashing.
	ThreatLevel      string   `json:"threat_level"`
	Motivation       []string `json:"motivation"`
	TargetIndustries []string `json:"target_industries"`
	TargetRegions    []string `json:"target_regions"`
	OriginCountry    string   `json:"origin_country"`
	OriginFlag       string   `json:"origin_flag"`
	CampaignCount    int      `json:"campaign_count"`
	IOCCount         int      `json:"ioc_count"`
	Campaigns        []any    `json:"campaigns"`
	IOCs             []any    `json:"iocs"`
	TTPs             []any    `json:"ttps"`
	Reports          []any    `json:"reports"`
}

// deriveThreatLevel gives the UI a sensible severity from the SDO type until a
// real threat_level is tracked.
func deriveThreatLevel(actorType string) string {
	switch actorType {
	case "threat-actor", "intrusion-set":
		return "high"
	case "malware", "tool":
		return "medium"
	default:
		return "low"
	}
}

const threatActorCols = `id, COALESCE(stix_id,''), name, actor_type, COALESCE(description,''),
	aliases, malware_types, mitre_ids, labels, source,
	first_seen::text, last_seen::text`

func scanThreatActor(rows interface {
	Scan(...any) error
}) (threatActor, error) {
	var a threatActor
	err := rows.Scan(&a.ID, &a.STIXID, &a.Name, &a.ActorType, &a.Description,
		&a.Aliases, &a.MalwareTypes, &a.MITREIDs, &a.Labels, &a.Source,
		&a.FirstSeen, &a.LastSeen)
	// Guarantee non-nil arrays (JSON [] not null) so the UI can .map/.slice
	// safely, and fill the display-only defaults.
	a.Aliases = nonNilStrs(a.Aliases)
	a.MalwareTypes = nonNilStrs(a.MalwareTypes)
	a.MITREIDs = nonNilStrs(a.MITREIDs)
	a.Labels = nonNilStrs(a.Labels)
	a.Motivation = []string{}
	a.TargetIndustries = []string{}
	a.TargetRegions = []string{}
	a.Campaigns = []any{}
	a.IOCs = []any{}
	a.TTPs = []any{}
	a.Reports = []any{}
	a.ThreatLevel = deriveThreatLevel(a.ActorType)
	return a, err
}

// List handles GET /threat-intel/actors.
// Filters: type (actor_type), q (name substring). Paginated via limit/offset.
// Returns a bare JSON array to preserve the previous stub's response shape.
func (h *ThreatActorHandler) List(c *gin.Context) {
	if !tableExists(c, h.pool, "threat_actors") {
		c.JSON(http.StatusOK, []threatActor{})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := `SELECT ` + threatActorCols + ` FROM threat_actors WHERE 1=1`
	args := []any{}
	n := 1
	if t := strings.TrimSpace(c.Query("type")); t != "" {
		query += " AND actor_type = $" + strconv.Itoa(n)
		args = append(args, t)
		n++
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		query += " AND name ILIKE '%' || $" + strconv.Itoa(n) + " || '%'"
		args = append(args, q)
		n++
	}
	query += " ORDER BY last_seen DESC LIMIT $" + strconv.Itoa(n) + " OFFSET $" + strconv.Itoa(n+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	actors := []threatActor{}
	for rows.Next() {
		if a, err := scanThreatActor(rows); err == nil {
			actors = append(actors, a)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, actors)
}

// Get handles GET /threat-intel/actors/:id. The id may be the row UUID, the
// STIX id, or an exact (case-insensitive) name.
func (h *ThreatActorHandler) Get(c *gin.Context) {
	if !tableExists(c, h.pool, "threat_actors") {
		c.JSON(http.StatusNotFound, gin.H{"error": "actor not found"})
		return
	}
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+threatActorCols+` FROM threat_actors
		 WHERE id::text = $1 OR stix_id = $1 OR lower(name) = lower($1)
		 LIMIT 1`, id)
	a, err := scanThreatActor(row)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "actor not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// Create handles POST /threat-intel/actors (manual entry; stix_id stays NULL).
func (h *ThreatActorHandler) Create(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		ActorType   string   `json:"actor_type"`
		Description string   `json:"description"`
		Aliases     []string `json:"aliases"`
		Labels      []string `json:"labels"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ActorType == "" {
		req.ActorType = "threat-actor"
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO threat_actors (name, actor_type, description, aliases, labels, source)
		 VALUES ($1, $2, $3, $4::text[], $5::text[], 'manual')
		 RETURNING id`,
		req.Name, req.ActorType, req.Description,
		nonNilStrs(req.Aliases), nonNilStrs(req.Labels),
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// threatActorUpsert carries the fields the STIX importer persists.
type threatActorUpsert struct {
	STIXID       string
	Name         string
	ActorType    string
	Description  string
	Aliases      []string
	MalwareTypes []string
	MITREIDs     []string
	Labels       []string
}

// upsertThreatActor inserts or refreshes a threat_actors row keyed by stix_id.
// A re-import unions the array fields and refreshes last_seen so intel is
// enriched rather than duplicated. Shared by the STIX importer.
func upsertThreatActor(ctx context.Context, pool *pgxpool.Pool, a threatActorUpsert) error {
	if a.STIXID == "" || a.Name == "" {
		return nil
	}
	if a.ActorType == "" {
		a.ActorType = "threat-actor"
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO threat_actors
		  (stix_id, name, actor_type, description, aliases, malware_types, mitre_ids, labels, source)
		VALUES ($1, $2, $3, $4, $5::text[], $6::text[], $7::text[], $8::text[], 'stix-import')
		ON CONFLICT (stix_id) DO UPDATE SET
		  name          = EXCLUDED.name,
		  description   = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE threat_actors.description END,
		  aliases       = ARRAY(SELECT DISTINCT unnest(threat_actors.aliases || EXCLUDED.aliases)),
		  malware_types = ARRAY(SELECT DISTINCT unnest(threat_actors.malware_types || EXCLUDED.malware_types)),
		  mitre_ids     = ARRAY(SELECT DISTINCT unnest(threat_actors.mitre_ids || EXCLUDED.mitre_ids)),
		  labels        = ARRAY(SELECT DISTINCT unnest(threat_actors.labels || EXCLUDED.labels)),
		  last_seen     = NOW(),
		  updated_at    = NOW()`,
		a.STIXID, a.Name, a.ActorType, a.Description,
		nonNilStrs(a.Aliases), nonNilStrs(a.MalwareTypes), nonNilStrs(a.MITREIDs), nonNilStrs(a.Labels),
	)
	return err
}

// nonNilStrs returns a non-nil slice so a nil maps to an empty text[] literal.
func nonNilStrs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// tableExists reports whether a public table exists (used to degrade gracefully
// before the migration has run).
func tableExists(c *gin.Context, pool *pgxpool.Pool, table string) bool {
	var exists bool
	err := pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		 WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists)
	return err == nil && exists
}
