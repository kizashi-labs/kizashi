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
	"time"

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
//
// 戻り値の isNew は「この資源・この項目で今回はじめて出た所見か」。
// 定期スキャンの通知がこれを使う。件数だけでは毎回同じ数が出るので
// 「増えたのか、変わっていないのか」が分からず、通知として役に立たない。
//
// 判定は first_seen_at = last_seen_at で行う。first_seen_at は挿入時にしか
// 書かないので、両者が一致するのは今回挿入された行だけになる。
// なお、一度 resolved になった所見が再発した場合は「新規」にならない
// (行が残っていて first_seen_at が過去のまま)。再発は本来伝える価値が
// あるが、RETURNING からは更新前の status が見えないため、ここでは扱わない。
func (s *CSPMStore) UpsertFinding(ctx context.Context, accountUUID string, f CSPMFinding) (bool, error) {
	frameworks := f.Frameworks
	if frameworks == nil {
		frameworks = []string{}
	}
	var isNew bool
	err := s.pool.QueryRow(ctx, `
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
		                  THEN cspm_findings.status ELSE 'open' END
		RETURNING (first_seen_at = last_seen_at)`,
		accountUUID, f.ResourceType, f.ResourceID, f.ResourceName, f.Region,
		f.CheckID, f.CheckName, f.Severity, f.Description, f.Remediation, frameworks).Scan(&isNew)
	return isNew, err
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

// ResolveMissingFindings は、今回のスキャンで存在が確認できなかった資源の
// 所見を閉じる。戻り値は閉じた件数。
//
// 資源が削除されると API 応答から消えるので、pass も fail も生成されない。
// 判定結果だけを見ていると閉じる契機が無く、実在しない資源の所見が
// 一覧に残り続ける。「設定ミスのある EC2 を作り直して直した」「公開バケットを
// 消した」がどれも解消として扱われず、直したのに消えない状態になる。
// そうなると運用者は一覧そのものを信用しなくなる。
//
// 呼び出し側は、**その項目がそのリージョンで最後まで実行できた場合にのみ**
// これを呼ぶこと。1 件でも読めなかった資源があるなら呼んではいけない。
// 読めなかった資源は応答に出てこないので「消えた」と見分けが付かず、
// 権限が外れた途端に全所見が解消されて「問題なし」に化ける。
//
// seenResourceIDs が空の場合は、その項目・リージョンの開いている所見を
// すべて閉じる。完走した上で資源が 1 つも無かったということなので正しい。
func (s *CSPMStore) ResolveMissingFindings(ctx context.Context, accountUUID, checkID, region string, seenResourceIDs []string) (int, error) {
	if seenResourceIDs == nil {
		seenResourceIDs = []string{}
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE cspm_findings
		   SET status = 'resolved', last_seen_at = NOW()
		 WHERE account_id = $1::uuid
		   AND check_id = $2::text
		   AND COALESCE(region, '') = $3::text
		   AND status = 'open'
		   AND NOT (COALESCE(resource_id, '') = ANY($4::text[]))`,
		accountUUID, checkID, region, seenResourceIDs)
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
	// $2 を明示的にキャストしている。片方は varchar 列への代入、もう片方は
	// リテラルとの比較なので、キャストが無いと PostgreSQL が 1 つの型に
	// 決められず 42P08 (inconsistent types deduced for parameter) で落ちる。
	_, err := s.pool.Exec(ctx, `
		UPDATE cspm_accounts
		   SET scan_status = $2::text, scan_error = $3::text,
		       last_scan_started_at = CASE WHEN $2::text = 'scanning'
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

// ClaimNextScan は定期スキャンの対象を 1 件だけ占有して返す。
// 対象が無ければ (nil, nil)。
//
// なぜ占有が要るか: api は複数レプリカで動く (helm の replicaCount は 2、
// docker-compose.scale.yml も server-api と server-api-2 の 2 台)。
// 素朴にタイマーで回すと全レプリカが同じアカウントを同時にスキャンする。
// AWS API の呼び出しが台数倍になってスロットリングを招くうえ、Persist が
// 並行すると片方の「消えた資源の掃除」がもう片方の書き込み途中の状態を
// 見て所見を閉じ、次の周回で開き直す ---所見が点滅する。
//
// leader election の仕組みはこのコードベースに無いので、既にある
// scan_status を占有標識として使う。UPDATE 1 文で条件判定と確保を同時に
// 行うため、勝つのは 1 レプリカだけになる。migration 426 で
// scan_status='scanning' の部分索引を張ってあるので、この検索は軽い。
//
// staleAfter は「'scanning' のまま放置された行を再び対象にする」までの
// 時間。プロセスが検査中に落ちると scan_status は 'scanning' で残り、
// これが無いとそのアカウントは二度とスキャンされない。落ちたことが
// 画面にも出ないので、最も気づきにくい止まり方になる。
// awsscan.ScanTimeout より十分長い値を渡すこと。
//
// minInterval は前回完了からの最短間隔。スキャンは顧客の AWS に対する
// API 呼び出しなので、短くしても得は無い。
func (s *CSPMStore) ClaimNextScan(ctx context.Context, minInterval, staleAfter time.Duration) (*CSPMAccountCredentials, error) {
	var out CSPMAccountCredentials
	var roleARN, externalID *string
	err := s.pool.QueryRow(ctx, `
		WITH due AS (
		    SELECT id
		      FROM cspm_accounts
		     WHERE cloud_provider = 'aws'
		       AND COALESCE(enabled, true)
		       AND COALESCE(credentials_arn, '') <> ''
		       AND COALESCE(external_id, '') <> ''
		       AND (last_scanned_at IS NULL
		            OR last_scanned_at < NOW() - $1::interval)
		       AND (COALESCE(scan_status, 'idle') <> 'scanning'
		            OR last_scan_started_at IS NULL
		            OR last_scan_started_at < NOW() - $2::interval)
		     ORDER BY last_scanned_at ASC NULLS FIRST
		     FOR UPDATE SKIP LOCKED
		     LIMIT 1
		)
		UPDATE cspm_accounts a
		   SET scan_status = 'scanning', scan_error = NULL, last_scan_started_at = NOW()
		  FROM due
		 WHERE a.id = due.id
		RETURNING a.id::text, a.cloud_provider, a.account_id,
		          a.credentials_arn, a.external_id,
		          COALESCE(a.regions, '{}'), COALESCE(a.enabled, true)`,
		minInterval, staleAfter).
		Scan(&out.AccountUUID, &out.Provider, &out.AccountID, &roleARN, &externalID,
			&out.Regions, &out.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		// 対象が無いのは正常。エラーにすると毎周回でログが埋まる。
		return nil, nil
	}
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
