package handlers

// CSPM 所見の取り込み口。
//
// このリポジトリに CSPM スキャナ (クラウドへ接続して設定を検査する処理) は
// 無い。自前で書くとクラウド SDK・ロール引受・チェック群が必要で、実際の
// クラウド資格情報が無いと検証もできない。
//
// 代わりに、既存の CSPM ツール (Prowler / ScoutSuite / AWS Security Hub 等)
// の出力を取り込む口を用意する。この製品は Wazuh でも同じ形 — 外部ツールの
// 検知結果を取り込む — を採っているので、設計として揃う。
//
// 受け取る形式はこのファイルで定義する「正規形」。Prowler などが使う代表的な
// 別名キーも読めるようにしてあるが (cspmFieldAliases)、これは各ツールの公開
// フィールド名から起こしたもので、実際の出力に当てて検証はしていない。
// 正規形に寄せる薄い変換 (jq 等) を挟むのが確実。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

// cspmImportRequest は取り込みの本体。
type cspmImportRequest struct {
	Provider    string            `json:"provider"`     // aws | azure | gcp | alibaba
	AccountID   string            `json:"account_id"`   // クラウド側のアカウント識別子
	AccountName string            `json:"account_name"` // 省略時は account_id
	Findings    []json.RawMessage `json:"findings"`
}

// cspmFinding は 1 件の所見の正規形。
type cspmFinding struct {
	CheckID      string
	CheckName    string
	Severity     string
	Passed       bool
	ResourceType string
	ResourceID   string
	ResourceName string
	Region       string
	Description  string
	Remediation  string
	Frameworks   []string
}

// cspmFieldAliases は正規形のキーに対する別名。左が正規名。
// 値の並び順に探し、最初に見つかったものを使う。
var cspmFieldAliases = map[string][]string{
	"check_id":      {"check_id", "CheckID", "checkID", "check"},
	"check_name":    {"check_name", "CheckTitle", "checkTitle", "title"},
	"severity":      {"severity", "Severity"},
	"status":        {"status", "Status"},
	"resource_type": {"resource_type", "ResourceType", "resourceType"},
	"resource_id":   {"resource_id", "ResourceArn", "ResourceId", "resourceId", "resource"},
	"resource_name": {"resource_name", "ResourceName", "resourceName"},
	"region":        {"region", "Region", "location"},
	"description":   {"description", "Description", "StatusExtended", "risk", "Risk"},
	"remediation":   {"remediation", "Remediation", "recommendation"},
}

// cspmSeverityAliases は重大度の正規化。CSPM ツールによって語彙が違う。
// 不明な値は medium に寄せる (黙って落とすより、見えるほうがよい)。
var cspmSeverityAliases = map[string]string{
	"critical": "critical", "crit": "critical",
	"high":   "high",
	"medium": "medium", "moderate": "medium", "warning": "medium",
	"low": "low", "informational": "low", "info": "low",
}

// pickString は m から別名を順に探して最初の文字列を返す。
func pickString(m map[string]any, canonical string) string {
	for _, key := range cspmFieldAliases[canonical] {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch s := v.(type) {
		case string:
			if s != "" {
				return s
			}
		case map[string]any:
			// Prowler の Remediation は {"Recommendation": {"Text": "..."}} の形を取る。
			if rec, ok := s["Recommendation"].(map[string]any); ok {
				if txt, ok := rec["Text"].(string); ok && txt != "" {
					return txt
				}
			}
			if txt, ok := s["Text"].(string); ok && txt != "" {
				return txt
			}
		}
	}
	return ""
}

// pickFrameworks は準拠フレームワーク名を集める。
// 配列 (["CIS","SOC2"]) と、枠名をキーにしたオブジェクト
// ({"CIS-1.5":["2.1.1"]}) の両方を受ける。
func pickFrameworks(m map[string]any) []string {
	var out []string
	for _, key := range []string{"compliance_frameworks", "Compliance", "compliance"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch c := v.(type) {
		case []any:
			for _, e := range c {
				if s, ok := e.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		case map[string]any:
			for name := range c {
				if name != "" {
					out = append(out, name)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{}
}

// parseCSPMFinding は 1 件を正規形に落とす。
// check_id と resource_id は同一性の判定に使うため、欠けていたら受け付けない。
func parseCSPMFinding(raw json.RawMessage) (cspmFinding, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return cspmFinding{}, fmt.Errorf("JSON として読めません: %w", err)
	}

	f := cspmFinding{
		CheckID:      pickString(m, "check_id"),
		CheckName:    pickString(m, "check_name"),
		ResourceType: pickString(m, "resource_type"),
		ResourceID:   pickString(m, "resource_id"),
		ResourceName: pickString(m, "resource_name"),
		Region:       pickString(m, "region"),
		Description:  pickString(m, "description"),
		Remediation:  pickString(m, "remediation"),
		Frameworks:   pickFrameworks(m),
	}
	if f.CheckID == "" {
		return cspmFinding{}, fmt.Errorf("check_id がありません")
	}
	if f.ResourceID == "" {
		return cspmFinding{}, fmt.Errorf("resource_id がありません")
	}
	if f.CheckName == "" {
		f.CheckName = f.CheckID
	}
	if f.ResourceName == "" {
		f.ResourceName = f.ResourceID
	}

	sev := strings.ToLower(strings.TrimSpace(pickString(m, "severity")))
	if norm, ok := cspmSeverityAliases[sev]; ok {
		f.Severity = norm
	} else {
		f.Severity = "medium"
	}

	// PASS した項目は所見ではない。既に開いている同じ所見があれば解消として扱う。
	status := strings.ToLower(strings.TrimSpace(pickString(m, "status")))
	f.Passed = status == "pass" || status == "passed" || status == "ok" || status == "resolved"

	return f, nil
}

// ImportFindings は外部 CSPM ツールの検査結果を取り込む。
// POST /api/v1/cloud/findings/import
//
// 同じ所見を二度取り込んでも行は増えず、last_seen_at が更新される
// (一意性は migration 381 の uq_cspm_findings_identity が担保する)。
func (h *CloudPostureHandler) ImportFindings(c *gin.Context) {
	if c.GetString("role") == "viewer" {
		c.JSON(http.StatusForbidden, gin.H{"error": "閲覧専用ロールでは取り込みできません"})
		return
	}

	var req cspmImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの JSON を読めません: " + err.Error()})
		return
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	switch provider {
	case "aws", "azure", "gcp", "alibaba":
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "provider は aws / azure / gcp / alibaba のいずれかです: " + req.Provider,
		})
		return
	}
	if strings.TrimSpace(req.AccountID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id は必須です"})
		return
	}

	ctx := c.Request.Context()
	accountName := req.AccountName
	if strings.TrimSpace(accountName) == "" {
		accountName = req.AccountID
	}

	// アカウントは無ければ作る。取り込みの起点はここなので、
	// 事前登録を強制しない。
	var accountUUID string
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO cspm_accounts (cloud_provider, account_id, account_name, last_scanned_at, scan_status)
		VALUES ($1, $2, $3, NOW(), 'completed')
		ON CONFLICT (cloud_provider, account_id) DO UPDATE
		   SET account_name    = COALESCE(NULLIF(EXCLUDED.account_name, ''), cspm_accounts.account_name),
		       last_scanned_at = NOW(),
		       scan_status     = 'completed'
		RETURNING id::text`,
		provider, req.AccountID, accountName).Scan(&accountUUID); err != nil {
		slog.Error("CSPM 取り込み: アカウントの登録に失敗しました",
			"provider", provider, "account_id", req.AccountID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アカウントの登録に失敗しました"})
		return
	}

	var imported, resolved int
	rejected := []string{}

	for i, raw := range req.Findings {
		f, err := parseCSPMFinding(raw)
		if err != nil {
			// 1 件の不備で全体を落とさない。何件どう落ちたかは返す。
			rejected = append(rejected, fmt.Sprintf("findings[%d]: %v", i, err))
			continue
		}

		if f.Passed {
			tag, err := h.pool.Exec(ctx, `
				UPDATE cspm_findings
				   SET status = 'resolved', last_seen_at = NOW()
				 WHERE account_id = $1::uuid AND check_id = $2 AND resource_id = $3
				   AND COALESCE(region, '') = $4 AND status = 'open'`,
				accountUUID, f.CheckID, f.ResourceID, f.Region)
			if err != nil {
				rejected = append(rejected, fmt.Sprintf("findings[%d]: 解消の記録に失敗: %v", i, err))
				continue
			}
			resolved += int(tag.RowsAffected())
			continue
		}

		if _, err := h.pool.Exec(ctx, `
			INSERT INTO cspm_findings
			    (account_id, resource_type, resource_id, resource_name, region,
			     check_id, check_name, severity, status, description, remediation,
			     compliance_frameworks, first_seen_at, last_seen_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'open', $9, $10, $11, NOW(), NOW())
			ON CONFLICT (account_id, check_id, resource_id, COALESCE(region, ''))
			   WHERE account_id IS NOT NULL
			DO UPDATE SET
			    resource_type         = EXCLUDED.resource_type,
			    resource_name         = EXCLUDED.resource_name,
			    check_name            = EXCLUDED.check_name,
			    severity              = EXCLUDED.severity,
			    description           = EXCLUDED.description,
			    remediation           = EXCLUDED.remediation,
			    compliance_frameworks = EXCLUDED.compliance_frameworks,
			    last_seen_at          = NOW(),
			    -- 一度 suppressed / accepted_risk にしたものは運用判断なので
			    -- 再検出で勝手に open に戻さない。それ以外は open に戻す。
			    status = CASE WHEN cspm_findings.status IN ('suppressed', 'accepted_risk')
			                  THEN cspm_findings.status ELSE 'open' END`,
			accountUUID, f.ResourceType, f.ResourceID, f.ResourceName, f.Region,
			f.CheckID, f.CheckName, f.Severity, f.Description, f.Remediation, f.Frameworks,
		); err != nil {
			rejected = append(rejected, fmt.Sprintf("findings[%d]: 保存に失敗: %v", i, err))
			continue
		}
		imported++
	}

	if err := h.refreshAccountRollup(ctx, accountUUID); err != nil {
		// 所見自体は入っているので、集計の失敗で 500 にはしない。
		slog.Warn("CSPM 取り込み: アカウント集計の更新に失敗しました",
			"account", accountUUID, "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"account_id": accountUUID,
		"provider":   provider,
		"imported":   imported,
		"resolved":   resolved,
		"rejected":   len(rejected),
		"errors":     rejected,
	})
}

// refreshAccountRollup は cspm_accounts 側の集計値を数え直す。
// posture_score は GetPosture と同じ減点式にそろえる (ずれると画面と一覧で
// 違う点数が出る)。
func (h *CloudPostureHandler) refreshAccountRollup(ctx context.Context, accountUUID string) error {
	_, err := h.pool.Exec(ctx, `
		WITH c AS (
		    SELECT
		        COUNT(*) FILTER (WHERE severity = 'critical') AS crit,
		        COUNT(*) FILTER (WHERE severity = 'high')     AS high,
		        COUNT(*) FILTER (WHERE severity = 'medium')   AS med,
		        COUNT(*) FILTER (WHERE severity = 'low')      AS low
		    FROM cspm_findings
		    WHERE account_id = $1::uuid AND status = 'open'
		)
		UPDATE cspm_accounts a
		   SET critical_findings = c.crit,
		       high_findings     = c.high,
		       posture_score     = GREATEST(0,
		           100 - (c.crit * 5 + c.high * 2 + c.med * 0.5 + c.low * 0.1)),
		       last_scanned_at   = NOW()
		  FROM c
		 WHERE a.id = $1::uuid`, accountUUID)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	return nil
}
