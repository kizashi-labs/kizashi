package awsscan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/edr-platform/server/internal/store"
)

// Persist はスキャン結果を cspm_findings へ反映する。
//
// 合格した項目は所見を作らず、既に開いている同じ所見を閉じる。
// これで「直したのに古い所見が残り続ける」ことがなくなる。
// 検査できなかった項目 (ScanResult.Errors) は、開いている所見に一切
// 触れない — 読めなかったことを「直った」とみなすと、権限が外れた瞬間に
// 全所見が消えて「問題なし」に見える。
func Persist(ctx context.Context, s *store.CSPMStore, accountUUID string, res *ScanResult) (upserted, resolved int, err error) {
	byID := ChecksByID()

	for _, r := range res.Results {
		check, ok := byID[r.CheckID]
		if !ok {
			slog.Warn("CSPM(AWS): 未知のチェック ID の結果を捨てました", "check_id", r.CheckID)
			continue
		}

		switch r.Status {
		case StatusPass:
			n, err := s.ResolveFinding(ctx, accountUUID, r.CheckID, r.ResourceID, r.Region)
			if err != nil {
				return upserted, resolved, fmt.Errorf("所見の解消に失敗 (%s): %w", r.CheckID, err)
			}
			resolved += n

		case StatusFail:
			f := store.CSPMFinding{
				CheckID:      r.CheckID,
				CheckName:    check.Title,
				Severity:     string(check.Severity),
				ResourceType: r.ResourceType,
				ResourceID:   r.ResourceID,
				ResourceName: r.ResourceName,
				Region:       r.Region,
				Description:  descriptionWithEvidence(check, r),
				Remediation:  check.Remediation,
				Frameworks:   check.Frameworks,
			}
			if err := s.UpsertFinding(ctx, accountUUID, f); err != nil {
				return upserted, resolved, fmt.Errorf("所見の保存に失敗 (%s): %w", r.CheckID, err)
			}
			upserted++
		}
	}

	if err := s.RefreshRollup(ctx, accountUUID); err != nil {
		// 所見自体は入っているので、集計の失敗で全体を失敗にはしない。
		slog.Warn("CSPM(AWS): アカウント集計の更新に失敗しました",
			"account", accountUUID, "error", err)
	}
	return upserted, resolved, nil
}

// descriptionWithEvidence は「何が問題か」に「何を見てそう判定したか」を足す。
// 根拠が残っていないと、担当者は所見を見ても自分で AWS を確認し直すしかない。
func descriptionWithEvidence(c Check, r Result) string {
	if r.Evidence == "" {
		return c.Description
	}
	return c.Description + "\n\n検出内容: " + r.Evidence
}
