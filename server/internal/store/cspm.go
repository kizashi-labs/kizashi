package store

// CSPM 所見の書き込み口。
//
// 所見を入れる経路は 2 つある — 外部ツールの取り込み
// (POST /api/v1/cloud/findings/import) と、自前の AWS スキャナ
// (internal/cspm/awsscan)。同一性判定・解決済みの扱い・集計の更新は
// 両者で完全に同じでなければならないので、ここに 1 つだけ置く。
//
// この製品は検知ルールで「同じ概念を 2 箇所が別実装で持つ」失敗を
// 既に踏んでいる (docs/検知ルールの二重管理とデプロイ.md)。同じ轍を
// 踏まないよう、CSPM 側は最初から単一実装にする。

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CSPMFinding は保存する所見 1 件。
type CSPMFinding struct {
	CheckID      string
	CheckName    string
	Severity     string // critical | high | medium | low
	ResourceType string
	ResourceID   string
	ResourceName string
	Region       string
	Description  string
	Remediation  string
	Frameworks   []string
}

// CSPMStore は cspm_accounts / cspm_findings を扱う。
type CSPMStore struct {
	pool *pgxpool.Pool
}

func NewCSPMStore(pool *pgxpool.Pool) *CSPMStore {
	return &CSPMStore{pool: pool}
}

// EnsureAccount はアカウント行を用意し、その UUID を返す。
// 取り込みの起点になるため事前登録は強制しない。
func (s *CSPMStore) EnsureAccount(ctx context.Context, provider, accountID, accountName string) (string, error) {
	if accountName == "" {
		accountName = accountID
	}
	var uuid string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO cspm_accounts (cloud_provider, account_id, account_name)
		VALUES ($1, $2, $3)
		ON CONFLICT (cloud_provider, account_id) DO UPDATE
		   SET account_name = COALESCE(NULLIF(EXCLUDED.account_name, ''), cspm_accounts.account_name)
		RETURNING id::text`,
		provider, accountID, accountName).Scan(&uuid)
	return uuid, err
}

// UpsertFinding は不合格の所見を入れる。同じ所見の再検出では行を増やさず
// last_seen_at だけを進める。
//
// suppressed / accepted_risk は担当者の判断なので、再検出しても open に
// 戻さない。これを戻すと「見なくてよいと決めたもの」が毎回蘇り、
// 一覧が実質使えなくなる。
func (s *CSPMStore) UpsertFinding(ctx context.Context, accountUUID string, f CSPMFinding) error {
	frameworks := f.Frameworks
	if frameworks == nil {
		frameworks = []string{}
	}
	_, err := s.pool.Exec(ctx, `
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
		    status = CASE WHEN cspm_findings.status IN ('suppressed', 'accepted_risk')
		                  THEN cspm_findings.status ELSE 'open' END`,
		accountUUID, f.ResourceType, f.ResourceID, f.ResourceName, f.Region,
		f.CheckID, f.CheckName, f.Severity, f.Description, f.Remediation, frameworks)
	return err
}

// ResolveFinding は合格だった項目について、開いている所見を閉じる。
// 戻り値は閉じた件数。
func (s *CSPMStore) ResolveFinding(ctx context.Context, accountUUID, checkID, resourceID, region string) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE cspm_findings
		   SET status = 'resolved', last_seen_at = NOW()
		 WHERE account_id = $1::uuid AND check_id = $2 AND resource_id = $3
		   AND COALESCE(region, '') = $4 AND status = 'open'`,
		accountUUID, checkID, resourceID, region)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// RefreshRollup は cspm_accounts 側の集計値を数え直す。
// posture_score の式は GetPosture と揃える。ずれると画面と一覧で
// 違う点数が出る。
func (s *CSPMStore) RefreshRollup(ctx context.Context, accountUUID string) error {
	_, err := s.pool.Exec(ctx, `
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
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// SetScanStatus はスキャンの進行状態を記録する。
// err が非 nil なら scan_error に理由を残し、状態は 'error' にする。
//
// 失敗を 'completed' にしてはいけない。「スキャンした結果 0 件」と
// 「スキャンできなかった」が区別できなくなり、権限設定のミスが
// 「問題なし」として表示される。
func (s *CSPMStore) SetScanStatus(ctx context.Context, accountUUID, status string, scanErr error) error {
	var msg *string
	if scanErr != nil {
		m := scanErr.Error()
		msg = &m
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE cspm_accounts
		   SET scan_status = $2, scan_error = $3,
		       last_scan_started_at = CASE WHEN $2 = 'scanning'
		                                   THEN NOW() ELSE last_scan_started_at END
		 WHERE id = $1::uuid`, accountUUID, status, msg)
	return err
}

// CSPMAccountCredentials はスキャンに必要な引受情報。
type CSPMAccountCredentials struct {
	AccountUUID string
	Provider    string
	AccountID   string
	RoleARN     string
	ExternalID  string
	Regions     []string
	Enabled     bool
}

// Credentials は 1 アカウントの引受情報を返す。未設定なら見つからない扱い。
func (s *CSPMStore) Credentials(ctx context.Context, accountUUID string) (*CSPMAccountCredentials, error) {
	var out CSPMAccountCredentials
	var roleARN, externalID *string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, cloud_provider, account_id, credentials_arn, external_id,
		       COALESCE(regions, '{}'), COALESCE(enabled, true)
		  FROM cspm_accounts WHERE id = $1::uuid`, accountUUID).
		Scan(&out.AccountUUID, &out.Provider, &out.AccountID, &roleARN, &externalID,
			&out.Regions, &out.Enabled)
	if err != nil {
		return nil, err
	}
	if roleARN != nil {
		out.RoleARN = *roleARN
	}
	if externalID != nil {
		out.ExternalID = *externalID
	}
	return &out, nil
}

// SetCredentials はロール ARN と外部 ID を設定する。
func (s *CSPMStore) SetCredentials(ctx context.Context, accountUUID, roleARN, externalID string, regions []string) error {
	if regions == nil {
		regions = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE cspm_accounts
		   SET credentials_arn = $2, external_id = $3, regions = $4
		 WHERE id = $1::uuid`, accountUUID, roleARN, externalID, regions)
	return err
}
