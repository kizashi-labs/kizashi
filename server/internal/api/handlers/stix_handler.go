package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/intel"
)

// STIXHandler handles STIX 2.1 bundle import and export.
type STIXHandler struct {
	pool *pgxpool.Pool
}

// NewSTIXHandler creates a new STIXHandler.
func NewSTIXHandler(pool *pgxpool.Pool) *STIXHandler {
	return &STIXHandler{pool: pool}
}

// stixBundle represents a STIX 2.1 bundle.
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

// stixObject represents any STIX 2.1 object. It carries the union of fields the
// importer reads across SDO types (indicator/malware/threat-actor/relationship).
type stixObject struct {
	Type               string                  `json:"type"`
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Description        string                  `json:"description"`
	Pattern            string                  `json:"pattern"`
	ValidFrom          string                  `json:"valid_from"`
	ValidUntil         string                  `json:"valid_until"`
	Confidence         *int                    `json:"confidence"` // STIX 0-100; pointer to tell "absent" from 0
	Labels             []string                `json:"labels"`
	Aliases            []string                `json:"aliases"` // threat-actor / intrusion-set aliases
	MalwareTypes       []string                `json:"malware_types"`
	ExternalReferences []stixExternalReference `json:"external_references"`
	// relationship SRO fields
	SourceRef string `json:"source_ref"`
	TargetRef string `json:"target_ref"`
}

// stixMITREIDs returns the ATT&CK external IDs referenced by an SDO.
func stixMITREIDs(obj stixObject) []string {
	var ids []string
	for _, ref := range obj.ExternalReferences {
		if strings.EqualFold(ref.SourceName, "mitre-attack") && ref.ExternalID != "" {
			ids = append(ids, ref.ExternalID)
		}
	}
	return ids
}

// stixExternalReference represents an external reference in a STIX object.
type stixExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

// extractIOCFromPattern parses a STIX pattern into an ioc_entries row's
// (type, value). It delegates the pattern grammar to intel.ExtractIOCFromSTIXPattern
// (shared with the TAXII client) and collapses hash sub-types to the canonical
// "hash" — ioc_entries.type has CHECK (type IN ('hash','ip','domain','url','email')),
// so inserting "sha256"/"md5"/"sha1" directly would fail the constraint.
func extractIOCFromPattern(pattern string) (string, string, bool) {
	iocType, value, ok := intel.ExtractIOCFromSTIXPattern(pattern)
	if !ok {
		return "", "", false
	}
	switch iocType {
	case "sha256", "sha1", "md5":
		iocType = "hash"
	}
	return iocType, value, true
}

// iocEntriesTableExists checks whether the ioc_entries table exists in the database.
//
// 確認できなかったときは error を返します。以前は false を返していたので、
// 「テーブルが無い」と「確認できなかった」が同じ扱いでした。取り込みは
// indicator を1件も入れないまま成功として応答し、書き出しは空の STIX
// バンドルを 200 で返します。受け取った外部ツールにとって、空のバンドルは
// 「このプラットフォームには指標が無い」という答えです。
func (h *STIXHandler) iocEntriesTableExists(c *gin.Context) (bool, error) {
	var exists bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'ioc_entries'
		)`).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Import handles POST /api/v1/threat-intel/stix/import.
// It parses a STIX 2.1 bundle and imports its objects into the platform.
//
// The importer is relationship-aware: it makes two passes so an indicator can be
// tagged with the malware / threat-actor it is linked to via STIX relationship
// SROs. Indicator confidence, labels (incl. TLP markings), and valid_until are
// preserved, and a re-import enriches an existing IOC (confidence/tags) rather
// than being dropped.
func (h *STIXHandler) Import(c *gin.Context) {
	var bundle stixBundle
	if err := json.NewDecoder(c.Request.Body).Decode(&bundle); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}

	if strings.ToLower(bundle.Type) != "bundle" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected STIX bundle type, got: " + bundle.Type})
		return
	}

	tableExists, err := h.iocEntriesTableExists(c)
	if err != nil {
		slog.Error("stix: ioc_entries の有無を確認できませんでした", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "取り込み先を確認できませんでした。取り込みは行っていません",
		})
		return
	}
	if !tableExists {
		slog.Warn("ioc_entries table does not exist; indicator objects will be skipped")
	}

	// Pass 1: index named SDOs (malware/threat-actor/intrusion-set/tool) by STIX
	// id, and collect relationships so indicators can be tagged with what they
	// point at.
	sdoName := make(map[string]string)
	relTargets := make(map[string][]string) // source_ref → []target_ref
	for _, obj := range bundle.Objects {
		switch strings.ToLower(obj.Type) {
		case "malware", "threat-actor", "intrusion-set", "tool", "campaign":
			if obj.ID != "" && obj.Name != "" {
				sdoName[obj.ID] = obj.Name
			}
		case "relationship":
			if obj.SourceRef != "" && obj.TargetRef != "" {
				relTargets[obj.SourceRef] = append(relTargets[obj.SourceRef], obj.TargetRef)
			}
		}
	}

	var (
		imported   int
		skipped    int
		typeCounts = map[string]int{"indicator": 0, "malware": 0, "attack-pattern": 0, "threat-actor": 0, "relationship": 0}
	)

	for _, obj := range bundle.Objects {
		objType := strings.ToLower(obj.Type)

		switch objType {
		case "indicator":
			typeCounts["indicator"]++
			if !tableExists {
				skipped++
				continue
			}

			iocType, iocValue, ok := extractIOCFromPattern(obj.Pattern)
			if !ok {
				slog.Warn("STIX import: could not extract IoC from indicator pattern",
					"id", obj.ID, "pattern", obj.Pattern)
				skipped++
				continue
			}

			description := obj.Description
			if description == "" {
				description = obj.Name
			}

			if err := h.upsertIndicator(c, obj, iocType, iocValue, description, sdoName, relTargets); err != nil {
				slog.Warn("STIX import: failed to insert indicator IoC",
					"id", obj.ID, "type", iocType, "value", iocValue, "error", err)
				skipped++
				continue
			}
			imported++

		case "malware", "threat-actor", "intrusion-set", "tool":
			if objType == "malware" {
				typeCounts["malware"]++
			} else {
				typeCounts["threat-actor"]++
			}
			if obj.Name == "" {
				skipped++
				continue
			}
			if err := upsertThreatActor(c.Request.Context(), h.pool, threatActorUpsert{
				STIXID:       obj.ID,
				Name:         obj.Name,
				ActorType:    objType,
				Description:  obj.Description,
				Aliases:      obj.Aliases,
				MalwareTypes: obj.MalwareTypes,
				MITREIDs:     stixMITREIDs(obj),
				Labels:       obj.Labels,
			}); err != nil {
				slog.Warn("STIX import: failed to persist actor SDO", "id", obj.ID, "type", objType, "error", err)
				skipped++
				continue
			}
			imported++

		case "attack-pattern":
			typeCounts["attack-pattern"]++
			mitreIDs := stixMITREIDs(obj)
			slog.Info("STIX import: attack-pattern object", "id", obj.ID, "name", obj.Name, "mitre_ids", mitreIDs)
			imported++

		case "relationship":
			typeCounts["relationship"]++
			// Consumed in pass 1; not an importable object on its own.

		default:
			slog.Debug("STIX import: skipping unsupported object type", "type", obj.Type, "id", obj.ID)
			skipped++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"types":    typeCounts,
	})
}

// upsertIndicator inserts or enriches one indicator IOC, preserving STIX
// confidence, labels/TLP, valid_until, and any linked malware/threat-actor names
// as tags. On conflict it raises confidence to the max seen and unions tags,
// so repeated imports strengthen rather than ignore an IOC.
func (h *STIXHandler) upsertIndicator(c *gin.Context, obj stixObject, iocType, iocValue, description string, sdoName map[string]string, relTargets map[string][]string) error {
	confidence := 50
	if obj.Confidence != nil {
		confidence = clampInt(*obj.Confidence, 0, 100)
	}
	// Severity tracks confidence (STIX 0-100 → 1-10) with a sane floor.
	severity := clampInt(confidence/10, 1, 10)

	tags := stixTags(obj, sdoName, relTargets)

	var expiresAt *time.Time
	if obj.ValidUntil != "" {
		if ts, err := time.Parse(time.RFC3339, obj.ValidUntil); err == nil {
			expiresAt = &ts
		}
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO ioc_entries
		   (id, type, value, description, severity, is_active,
		    confidence, source_feed, tags, first_seen, last_seen, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, true, $6, 'stix-import', $7::text[], $8, $8, $9, $8, $8)
		 ON CONFLICT (type, value) DO UPDATE SET
		    description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE ioc_entries.description END,
		    confidence  = GREATEST(ioc_entries.confidence, EXCLUDED.confidence),
		    severity    = GREATEST(ioc_entries.severity, EXCLUDED.severity),
		    tags        = ARRAY(SELECT DISTINCT unnest(ioc_entries.tags || EXCLUDED.tags)),
		    expires_at  = COALESCE(EXCLUDED.expires_at, ioc_entries.expires_at),
		    -- A re-import with no expiry (or a future one) resurrects an IOC the
		    -- expiry sweeper had deactivated; a stale one stays as-is.
		    is_active   = CASE WHEN EXCLUDED.expires_at IS NULL OR EXCLUDED.expires_at > NOW()
		                       THEN TRUE ELSE ioc_entries.is_active END,
		    last_seen   = EXCLUDED.last_seen,
		    updated_at  = EXCLUDED.updated_at`,
		id, iocType, iocValue, description, severity, confidence, tags, now, expiresAt,
	)
	return err
}

// stixTags builds the tag set for an indicator: its own labels (incl. tlp:*),
// plus the names of any malware / threat-actor SDOs it is related to.
func stixTags(obj stixObject, sdoName map[string]string, relTargets map[string][]string) []string {
	seen := make(map[string]struct{})
	var tags []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		tags = append(tags, t)
	}
	for _, l := range obj.Labels {
		add(l)
	}
	for _, target := range relTargets[obj.ID] {
		if name := sdoName[target]; name != "" {
			add(name)
		}
	}
	if tags == nil {
		return []string{}
	}
	return tags
}

// ─── Export ──────────────────────────────────────────────────────────────────

// stixExportIndicator is a STIX 2.1 indicator SDO emitted by Export.
type stixExportIndicator struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	Confidence  int      `json:"confidence"`
	Labels      []string `json:"labels,omitempty"`
	ValidFrom   string   `json:"valid_from"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
}

// Export handles GET /api/v1/threat-intel/stix/export.
// It emits the platform's active IOCs as a STIX 2.1 bundle of indicator SDOs,
// letting external tooling consume this platform's intelligence.
// Query params: limit (default 1000, max 10000), type (ip|domain|url|hash).
func (h *STIXHandler) Export(c *gin.Context) {
	exists, err := h.iocEntriesTableExists(c)
	if err != nil {
		slog.Error("stix: ioc_entries の有無を確認できませんでした", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "指標を読み出せませんでした。空のバンドルは返しません",
		})
		return
	}
	if !exists {
		c.JSON(http.StatusOK, emptyStixBundle())
		return
	}

	limit := 1000
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 10000 {
		limit = 10000
	}

	args := []interface{}{}
	where := "WHERE is_active = TRUE"
	if t := strings.ToLower(strings.TrimSpace(c.Query("type"))); t != "" {
		args = append(args, t)
		where += " AND type = $1"
	}
	args = append(args, limit)

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, type, value, COALESCE(description,''), COALESCE(confidence,50),
		        COALESCE(tags,'{}'), created_at, updated_at
		 FROM ioc_entries `+where+
			` ORDER BY created_at DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	objects := make([]interface{}, 0)
	for rows.Next() {
		var (
			id, iocType, value, desc string
			confidence               int
			tags                     []string
			created, updated         time.Time
		)
		if err := rows.Scan(&id, &iocType, &value, &desc, &confidence, &tags, &created, &updated); err != nil {
			continue
		}
		objects = append(objects, stixExportIndicator{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          "indicator--" + id,
			Name:        iocType + ":" + value,
			Description: desc,
			Pattern:     iocToSTIXPattern(iocType, value),
			PatternType: "stix",
			Confidence:  confidence,
			Labels:      tags,
			ValidFrom:   created.UTC().Format(time.RFC3339),
			Created:     created.UTC().Format(time.RFC3339),
			Modified:    updated.UTC().Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/stix+json;version=2.1")
	c.JSON(http.StatusOK, gin.H{
		"type":         "bundle",
		"id":           "bundle--" + uuid.New().String(),
		"spec_version": "2.1",
		"objects":      objects,
	})
}

func emptyStixBundle() gin.H {
	return gin.H{
		"type":         "bundle",
		"id":           "bundle--" + uuid.New().String(),
		"spec_version": "2.1",
		"objects":      []interface{}{},
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
