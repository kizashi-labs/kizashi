package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// aptCampaign matches the rich shape the APT-tracker UI renders. The
// threat_campaigns store tracks only the core fields (name/actor/status/…), so
// the detailed collections (infrastructure, malware, TTPs, victims, IOCs) are
// returned as empty non-nil arrays: real campaigns appear without the page —
// previously fed an empty stub — crashing on `.map()` over missing fields.
type aptCampaign struct {
	ID               string   `json:"id"`
	CampaignName     string   `json:"campaign_name"`
	APTGroup         string   `json:"apt_group"`
	APTGroupID       string   `json:"apt_group_id"`
	StartDate        string   `json:"start_date"`
	EndDate          *string  `json:"end_date"`
	Status           string   `json:"status"`     // active|concluded|suspected
	Phase            string   `json:"phase"`      // CampaignPhase
	Confidence       int      `json:"confidence"` // 0-100
	Motivation       string   `json:"motivation"`
	Attribution      string   `json:"attribution"`
	Description      string   `json:"description"`
	TargetSectors    []string `json:"target_sectors"`
	TargetCountries  []string `json:"target_countries"`
	TechniquesUsed   []any    `json:"techniques_used"`
	Infrastructure   []any    `json:"infrastructure"`
	MalwareUsed      []any    `json:"malware_used"`
	IOCs             []any    `json:"iocs"`
	Victims          []any    `json:"victims"`
	RelatedCampaigns []any    `json:"related_campaigns"`
}

// APTList handles GET /threat-intel/apt-campaigns. It maps threat_campaigns rows
// to the APT-tracker's campaign shape (bare array, stub-compatible).
func (h *CampaignsHandler) APTList(c *gin.Context) {
	if !tableExists(c, h.Pool, "threat_campaigns") {
		c.JSON(http.StatusOK, []aptCampaign{})
		return
	}
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), COALESCE(threat_actor,''),
		       status, severity, first_seen, last_seen, COALESCE(ioc_count,0)
		FROM threat_campaigns ORDER BY COALESCE(last_seen, created_at) DESC LIMIT 500`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	campaigns := []aptCampaign{}
	for rows.Next() {
		var (
			id, name, desc, actor, status, severity string
			firstSeen, lastSeen                     *time.Time
			iocCount                                int
		)
		if rows.Scan(&id, &name, &desc, &actor, &status, &severity, &firstSeen, &lastSeen, &iocCount) != nil {
			continue
		}
		ac := aptCampaign{
			ID:               id,
			CampaignName:     name,
			APTGroup:         orUnknown(actor),
			Description:      desc,
			Status:           aptStatus(status),
			Phase:            "initial_access",
			Confidence:       confidenceFromSeverity(severity),
			TargetSectors:    []string{},
			TargetCountries:  []string{},
			TechniquesUsed:   []any{},
			Infrastructure:   []any{},
			MalwareUsed:      []any{},
			IOCs:             []any{},
			Victims:          []any{},
			RelatedCampaigns: []any{},
		}
		if firstSeen != nil {
			ac.StartDate = firstSeen.UTC().Format(time.RFC3339)
		}
		if lastSeen != nil {
			s := lastSeen.UTC().Format(time.RFC3339)
			ac.EndDate = &s
		}
		if ac.Status == "concluded" {
			ac.Phase = "completed"
		}
		campaigns = append(campaigns, ac)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, campaigns)
}

// aptStatus maps threat_campaigns.status to the APT-tracker's status enum.
func aptStatus(status string) string {
	switch status {
	case "monitoring":
		return "suspected"
	case "inactive":
		return "concluded"
	default:
		return "active"
	}
}

func confidenceFromSeverity(sev string) int {
	switch sev {
	case "critical":
		return 90
	case "high":
		return 75
	case "low":
		return 30
	default:
		return 50
	}
}
