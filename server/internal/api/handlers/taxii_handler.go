package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const taxiiContentType = "application/taxii+json;version=2.1"

// TAXIIHandler implements a TAXII 2.1 server stub.
type TAXIIHandler struct {
	pool *pgxpool.Pool
}

// NewTAXIIHandler creates a new TAXIIHandler.
func NewTAXIIHandler(pool *pgxpool.Pool) *TAXIIHandler {
	return &TAXIIHandler{pool: pool}
}

// taxiiJSON responds with the TAXII content-type header.
func taxiiJSON(c *gin.Context, code int, obj interface{}) {
	c.Header("Content-Type", taxiiContentType)
	c.JSON(code, obj)
}

// GetDiscovery handles GET /taxii2/
func (h *TAXIIHandler) GetDiscovery(c *gin.Context) {
	taxiiJSON(c, http.StatusOK, gin.H{
		"title":       "Kizashi TAXII Server",
		"description": "EDR Platform Threat Intelligence",
		"contact":     "admin@edr-platform.local",
		"api_roots":   []string{"/taxii2/api1/"},
	})
}

// GetAPIRoot handles GET /taxii2/api1/
func (h *TAXIIHandler) GetAPIRoot(c *gin.Context) {
	taxiiJSON(c, http.StatusOK, gin.H{
		"title":              "Kizashi API Root",
		"description":        "Default TAXII API root for EDR threat intelligence",
		"versions":           []string{"taxii-2.1"},
		"max_content_length": 10485760, // 10 MB
	})
}

type taxiiCollection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types"`
}

func (h *TAXIIHandler) tableExists(c *gin.Context, table string) bool {
	var exists bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)`, table).Scan(&exists)
	return err == nil && exists
}

// GetCollections handles GET /taxii2/api1/collections/
func (h *TAXIIHandler) GetCollections(c *gin.Context) {
	iocCount := 0
	if h.tableExists(c, "ioc_entries") {
		_ = h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM ioc_entries`).Scan(&iocCount)
	}

	collections := []taxiiCollection{
		{
			ID:          "ioc-indicators",
			Title:       "IOC Indicators",
			Description: "All IOC indicators from the EDR platform",
			CanRead:     true,
			CanWrite:    true,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
		{
			ID:          "threat-actors",
			Title:       "Threat Actors",
			Description: "Threat actor intelligence data",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		},
	}

	taxiiJSON(c, http.StatusOK, gin.H{"collections": collections})
}

// GetCollection handles GET /taxii2/api1/collections/:id/
func (h *TAXIIHandler) GetCollection(c *gin.Context) {
	id := c.Param("id")

	var col taxiiCollection
	switch id {
	case "ioc-indicators":
		col = taxiiCollection{
			ID:          "ioc-indicators",
			Title:       "IOC Indicators",
			Description: "All IOC indicators from the EDR platform",
			CanRead:     true,
			CanWrite:    true,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		}
	case "threat-actors":
		col = taxiiCollection{
			ID:          "threat-actors",
			Title:       "Threat Actors",
			Description: "Threat actor intelligence data",
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{"application/stix+json;version=2.1"},
		}
	default:
		taxiiJSON(c, http.StatusNotFound, gin.H{"title": "Not Found", "description": "Collection not found"})
		return
	}

	taxiiJSON(c, http.StatusOK, col)
}

// stixIndicatorObject represents a STIX 2.1 indicator object.
type stixIndicatorObject struct {
	Type        string `json:"type"`
	SpecVersion string `json:"spec_version"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
	ValidFrom   string `json:"valid_from"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
}

func iocToSTIXPattern(iocType, value string) string {
	switch iocType {
	case "ip", "ipv4":
		return "[ipv4-addr:value = '" + value + "']"
	case "domain":
		return "[domain-name:value = '" + value + "']"
	case "url":
		return "[url:value = '" + value + "']"
	case "sha256":
		return "[file:hashes.'SHA-256' = '" + value + "']"
	case "sha1":
		return "[file:hashes.'SHA-1' = '" + value + "']"
	case "md5":
		return "[file:hashes.'MD5' = '" + value + "']"
	case "hash":
		// Feeds store every hash flavour under the canonical "hash" type, so
		// pick the STIX hash key by digest length instead of emitting a lossy
		// artifact pattern.
		switch len(value) {
		case 64:
			return "[file:hashes.'SHA-256' = '" + value + "']"
		case 40:
			return "[file:hashes.'SHA-1' = '" + value + "']"
		case 32:
			return "[file:hashes.'MD5' = '" + value + "']"
		}
		return "[file:hashes.'SHA-256' = '" + value + "']"
	default:
		return "[artifact:payload_bin = '" + value + "']"
	}
}

// GetObjects handles GET /taxii2/api1/collections/:id/objects/
func (h *TAXIIHandler) GetObjects(c *gin.Context) {
	collectionID := c.Param("id")

	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	addedAfter := c.Query("added_after")

	if collectionID == "threat-actors" {
		h.serveThreatActors(c, limit, addedAfter)
		return
	}

	if collectionID != "ioc-indicators" {
		taxiiJSON(c, http.StatusNotFound, gin.H{"title": "Not Found", "description": "Collection not found"})
		return
	}

	if !h.tableExists(c, "ioc_entries") {
		taxiiJSON(c, http.StatusOK, gin.H{
			"type":    "bundle",
			"id":      "bundle--" + uuid.New().String(),
			"objects": []interface{}{},
		})
		return
	}

	type iocRow struct {
		id          string
		iocType     string
		value       string
		description string
		createdAt   time.Time
	}

	var iocRows []iocRow

	if addedAfter != "" {
		pgrows, qErr := h.pool.Query(c.Request.Context(),
			`SELECT id, type, value, description, created_at FROM ioc_entries
			 WHERE created_at > $1 ORDER BY created_at ASC LIMIT $2`,
			addedAfter, limit)
		if qErr != nil {
			taxiiJSON(c, http.StatusInternalServerError, gin.H{"title": "Internal Server Error", "description": qErr.Error()})
			return
		}
		defer pgrows.Close()
		for pgrows.Next() {
			var r iocRow
			if scanErr := pgrows.Scan(&r.id, &r.iocType, &r.value, &r.description, &r.createdAt); scanErr == nil {
				iocRows = append(iocRows, r)
			}
		}
		if err := pgrows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	} else {
		pgrows, qErr := h.pool.Query(c.Request.Context(),
			`SELECT id, type, value, description, created_at FROM ioc_entries
			 ORDER BY created_at ASC LIMIT $1`, limit)
		if qErr != nil {
			taxiiJSON(c, http.StatusInternalServerError, gin.H{"title": "Internal Server Error", "description": qErr.Error()})
			return
		}
		defer pgrows.Close()
		for pgrows.Next() {
			var r iocRow
			if scanErr := pgrows.Scan(&r.id, &r.iocType, &r.value, &r.description, &r.createdAt); scanErr == nil {
				iocRows = append(iocRows, r)
			}
		}
		if err := pgrows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var objects []interface{}
	for _, r := range iocRows {
		ts := r.createdAt.UTC().Format(time.RFC3339)
		obj := stixIndicatorObject{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          "indicator--" + r.id,
			Name:        r.iocType + ":" + r.value,
			Description: r.description,
			Pattern:     iocToSTIXPattern(r.iocType, r.value),
			PatternType: "stix",
			ValidFrom:   ts,
			Created:     ts,
			Modified:    ts,
		}
		objects = append(objects, obj)
	}
	if objects == nil {
		objects = []interface{}{}
	}

	taxiiJSON(c, http.StatusOK, gin.H{
		"type":    "bundle",
		"id":      "bundle--" + uuid.New().String(),
		"objects": objects,
	})
}

// stixActorObject is a STIX 2.1 threat-actor / malware / intrusion-set / tool
// SDO emitted by the threat-actors TAXII collection.
type stixActorObject struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`
	MalwareTypes []string `json:"malware_types,omitempty"`
	IsFamily     *bool    `json:"is_family,omitempty"` // required on malware SDOs
	Labels       []string `json:"labels,omitempty"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
}

// serveThreatActors emits the threat_actors store as STIX 2.1 SDOs in a TAXII
// bundle, replacing the former empty-bundle stub. Supports added_after
// (created_at) and limit like the ioc-indicators collection.
func (h *TAXIIHandler) serveThreatActors(c *gin.Context, limit int, addedAfter string) {
	empty := gin.H{"type": "bundle", "id": "bundle--" + uuid.New().String(), "objects": []interface{}{}}
	if !h.tableExists(c, "threat_actors") {
		taxiiJSON(c, http.StatusOK, empty)
		return
	}

	q := `SELECT id, COALESCE(stix_id,''), name, actor_type, COALESCE(description,''),
	         aliases, malware_types, labels, created_at, updated_at
	      FROM threat_actors`
	args := []interface{}{}
	if addedAfter != "" {
		q += " WHERE created_at > $1 ORDER BY created_at ASC LIMIT $2"
		args = append(args, addedAfter, limit)
	} else {
		q += " ORDER BY created_at ASC LIMIT $1"
		args = append(args, limit)
	}
	rows, err := h.pool.Query(c.Request.Context(), q, args...)
	if err != nil {
		taxiiJSON(c, http.StatusInternalServerError, gin.H{"title": "Internal Server Error", "description": err.Error()})
		return
	}
	defer rows.Close()

	objects := []interface{}{}
	for rows.Next() {
		var (
			id, stixID, name, actorType, desc string
			aliases, malwareTypes, labels     []string
			created, modified                 time.Time
		)
		if rows.Scan(&id, &stixID, &name, &actorType, &desc, &aliases, &malwareTypes, &labels, &created, &modified) != nil {
			continue
		}
		objects = append(objects, buildStixActor(id, stixID, name, actorType, desc, aliases, malwareTypes, labels, created, modified))
	}
	if err := rows.Err(); err != nil {
		slog.Warn("threat-actors row iteration error", "error", err)
	}
	taxiiJSON(c, http.StatusOK, gin.H{"type": "bundle", "id": "bundle--" + uuid.New().String(), "objects": objects})
}

// buildStixActor maps a threat_actors row to a STIX SDO. The STIX type follows
// actor_type; a stored stix_id is reused so re-imports round-trip, otherwise a
// deterministic id is derived from the row id.
func buildStixActor(id, stixID, name, actorType, desc string, aliases, malwareTypes, labels []string, created, modified time.Time) stixActorObject {
	stixType := stixTypeForActor(actorType)
	sid := stixID
	if sid == "" {
		sid = stixType + "--" + id
	}
	obj := stixActorObject{
		Type:        stixType,
		SpecVersion: "2.1",
		ID:          sid,
		Name:        name,
		Description: desc,
		Labels:      labels,
		Created:     created.UTC().Format(time.RFC3339),
		Modified:    modified.UTC().Format(time.RFC3339),
	}
	if stixType == "malware" {
		// malware SDOs carry malware_types + required is_family, not aliases.
		obj.MalwareTypes = malwareTypes
		isFamily := false
		obj.IsFamily = &isFamily
	} else {
		obj.Aliases = aliases
	}
	return obj
}

// stixTypeForActor maps a threat_actors.actor_type to its STIX SDO type.
func stixTypeForActor(actorType string) string {
	switch actorType {
	case "intrusion-set", "malware", "tool", "campaign":
		return actorType
	default:
		return "threat-actor"
	}
}

// AddObjects handles POST /taxii2/api1/collections/:id/objects/
func (h *TAXIIHandler) AddObjects(c *gin.Context) {
	collectionID := c.Param("id")
	if collectionID != "ioc-indicators" {
		taxiiJSON(c, http.StatusForbidden, gin.H{"title": "Forbidden", "description": "Collection is read-only or does not exist"})
		return
	}

	var bundle struct {
		Type    string       `json:"type" binding:"required"`
		Objects []stixObject `json:"objects"`
	}
	if err := c.ShouldBindJSON(&bundle); err != nil {
		taxiiJSON(c, http.StatusBadRequest, gin.H{"title": "Bad Request", "description": err.Error()})
		return
	}

	if strings.ToLower(bundle.Type) != "bundle" {
		taxiiJSON(c, http.StatusBadRequest, gin.H{"title": "Bad Request", "description": "expected STIX bundle"})
		return
	}

	if !h.tableExists(c, "ioc_entries") {
		taxiiJSON(c, http.StatusServiceUnavailable, gin.H{"title": "Service Unavailable", "description": "IOC table not available"})
		return
	}

	var successCount, failCount int
	now := time.Now().UTC()

	for _, obj := range bundle.Objects {
		if strings.ToLower(obj.Type) != "indicator" {
			continue
		}
		iocType, iocValue, ok := extractIOCFromPattern(obj.Pattern)
		if !ok {
			failCount++
			continue
		}
		description := obj.Description
		if description == "" {
			description = obj.Name
		}
		id := uuid.New().String()
		_, err := h.pool.Exec(c.Request.Context(),
			`INSERT INTO ioc_entries (id, type, value, description, severity, is_active, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, 7, true, $5, $5)
			 ON CONFLICT (type, value) DO UPDATE SET description = EXCLUDED.description, updated_at = EXCLUDED.updated_at`,
			id, iocType, iocValue, description, now)
		if err != nil {
			failCount++
		} else {
			successCount++
		}
	}

	taxiiJSON(c, http.StatusAccepted, gin.H{
		"status":    "complete",
		"successes": successCount,
		"failures":  failCount,
	})
}
