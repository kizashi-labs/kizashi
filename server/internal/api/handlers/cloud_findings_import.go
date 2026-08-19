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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/store"
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

	// 書き込みは store.CSPMStore に一本化してある。自前の AWS スキャナ
	// (internal/cspm/awsscan) も同じ関数を通るので、同一性判定・解決済みの
	// 扱い・集計の更新が経路によってずれない。
	cs := store.NewCSPMStore(h.pool)

	// アカウントは無ければ作る。取り込みの起点はここなので、
	// 事前登録を強制しない。
	accountUUID, err := cs.EnsureAccount(ctx, provider, req.AccountID, accountName)
	if err != nil {
		slog.Error("CSPM 取り込み: アカウントの登録に失敗しました",
			"provider", provider, "account_id", req.AccountID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アカウントの登録に失敗しました"})
		return
	}
	if err := cs.SetScanStatus(ctx, accountUUID, "completed", nil); err != nil {
		slog.Warn("CSPM 取り込み: 取り込み状態の記録に失敗しました",
			"account", accountUUID, "error", err)
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
			n, err := cs.ResolveFinding(ctx, accountUUID, f.CheckID, f.ResourceID, f.Region)
			if err != nil {
				rejected = append(rejected, fmt.Sprintf("findings[%d]: 解消の記録に失敗: %v", i, err))
				continue
			}
			resolved += n
			continue
		}

		// 新規かどうかは取り込み経路では使わない。取り込みは外部ツールの
		// 出力をそのまま入れるもので、通知は元のツール側が担う。
		if _, err := cs.UpsertFinding(ctx, accountUUID, store.CSPMFinding{
			CheckID:      f.CheckID,
			CheckName:    f.CheckName,
			Severity:     f.Severity,
			ResourceType: f.ResourceType,
			ResourceID:   f.ResourceID,
			ResourceName: f.ResourceName,
			Region:       f.Region,
			Description:  f.Description,
			Remediation:  f.Remediation,
			Frameworks:   f.Frameworks,
		}); err != nil {
			rejected = append(rejected, fmt.Sprintf("findings[%d]: 保存に失敗: %v", i, err))
			continue
		}
		imported++
	}

	if err := cs.RefreshRollup(ctx, accountUUID); err != nil {
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
