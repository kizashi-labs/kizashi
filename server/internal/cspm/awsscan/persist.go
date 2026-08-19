package awsscan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/edr-platform/server/internal/store"
)

// Persist はスキャン結果を cspm_findings へ反映する。
//
// 所見が閉じる経路は 2 つある。どちらも必要で、片方だけでは
// 「直したのに古い所見が残り続ける」状態になる。
//
//  1. 合格に転じた資源 — 資源は在るが判定が pass になった。該当する
//     開いている所見を閉じる。
//  2. 消えた資源 — 資源そのものが削除された。この場合 API 応答に出て
//     こないので pass も fail も生成されず、1 の経路では閉じられない。
//     完走した (項目, リージョン) の組ごとに、今回見えなかった資源の
//     所見を閉じる。
//
// 検査できなかった項目 (ScanResult.Errors) は、開いている所見に一切
// 触れない — 読めなかったことを「直った」とみなすと、権限が外れた瞬間に
// 全所見が消えて「問題なし」に見える。2 の掃除を ScanResult.Completed に
// 限っているのはこのため。
// PersistResult は保存の結果。件数だけでなく New を持つのは、定期スキャンの
// 通知に「何が新しく出たか」を書くため。件数は毎回ほぼ同じ数になるので、
// それだけでは増えたのか変わっていないのか判別できない。
type PersistResult struct {
	// Upserted は今回 fail だった所見の総数 (新規・既存を問わない)。
	Upserted int
	// Resolved は pass に転じて閉じた件数。
	Resolved int
	// Disappeared は資源ごと消えたため閉じた件数。
	Disappeared int
	// New は今回はじめて出た所見。
	New []NewFinding
}

// NewFinding は通知に必要な最小限の情報。所見そのもの (store.CSPMFinding) を
// 持ち回らないのは、通知に説明文や是正手順まで載せると長すぎて読まれないため。
type NewFinding struct {
	CheckID      string
	CheckName    string
	Severity     Severity
	ResourceName string
	Region       string
}

func Persist(ctx context.Context, s *store.CSPMStore, accountUUID string, res *ScanResult) (*PersistResult, error) {
	byID := ChecksByID()
	out := &PersistResult{}

	// 完走した組ごとに、今回見えた資源 ID を集める。消えた資源の判定に使う。
	seen := map[CheckScope][]string{}
	for _, sc := range res.Completed {
		if _, ok := seen[sc]; !ok {
			seen[sc] = []string{}
		}
	}

	for _, r := range res.Results {
		check, ok := byID[r.CheckID]
		if !ok {
			slog.Warn("CSPM(AWS): 未知のチェック ID の結果を捨てました", "check_id", r.CheckID)
			continue
		}
		sc := CheckScope{CheckID: r.CheckID, Region: r.Region}
		if ids, ok := seen[sc]; ok {
			seen[sc] = append(ids, r.ResourceID)
		}

		switch r.Status {
		case StatusPass:
			n, err := s.ResolveFinding(ctx, accountUUID, r.CheckID, r.ResourceID, r.Region)
			if err != nil {
				return nil, fmt.Errorf("所見の解消に失敗 (%s): %w", r.CheckID, err)
			}
			out.Resolved += n

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
			isNew, err := s.UpsertFinding(ctx, accountUUID, f)
			if err != nil {
				return nil, fmt.Errorf("所見の保存に失敗 (%s): %w", r.CheckID, err)
			}
			out.Upserted++
			if isNew {
				out.New = append(out.New, NewFinding{
					CheckID:      r.CheckID,
					CheckName:    check.Title,
					Severity:     check.Severity,
					ResourceName: resourceLabel(r),
					Region:       r.Region,
				})
			}
		}
	}

	// 消えた資源の掃除。完走した組だけを対象にする。
	for sc, ids := range seen {
		n, err := s.ResolveMissingFindings(ctx, accountUUID, sc.CheckID, sc.Region, ids)
		if err != nil {
			return nil, fmt.Errorf("消えた資源の所見解消に失敗 (%s): %w", sc.CheckID, err)
		}
		if n > 0 {
			slog.Info("CSPM(AWS): 資源が見つからなくなった所見を閉じました",
				"account", accountUUID, "check_id", sc.CheckID, "region", sc.Region, "closed", n)
		}
		out.Disappeared += n
	}

	if err := s.RefreshRollup(ctx, accountUUID); err != nil {
		// 所見自体は入っているので、集計の失敗で全体を失敗にはしない。
		slog.Warn("CSPM(AWS): アカウント集計の更新に失敗しました",
			"account", accountUUID, "error", err)
	}
	return out, nil
}

// resourceLabel は通知に出す資源名。名前が空なら ID を使う。
// 空欄のまま出すと、通知を見た担当者が何を直せばよいか分からない。
func resourceLabel(r Result) string {
	if r.ResourceName != "" {
		return r.ResourceName
	}
	return r.ResourceID
}

// descriptionWithEvidence は「何が問題か」に「何を見てそう判定したか」を足す。
// 根拠が残っていないと、担当者は所見を見ても自分で AWS を確認し直すしかない。
func descriptionWithEvidence(c Check, r Result) string {
	if r.Evidence == "" {
		return c.Description
	}
	return c.Description + "\n\n検出内容: " + r.Evidence
}
