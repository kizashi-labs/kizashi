package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SuppressionConditions defines the matching criteria for a suppression rule.
//
// **ここに無いキーは、書き戻しで消えます。** conditions は JSONB なので、
// 読み手（detection.PoolSuppressionLoader の SELECT）が知っているキーを
// この構造体が知らないと、UI や API から同じ行を更新した瞬間に
// json.Marshal がそのキーを落とし、**条件がひとつ緩くなった状態で**
// 保存されます。抑制でそれが起きると、絞り込みが消えて対象が広がる方向に
// 外れる——最も気づきにくい壊れ方です。
//
// そのため、読み手のキーとここのタグが一致していることを
// TestSuppressionConditionKeysMatchTheReader が検査します。
// キーを増やすときは loader・matcher・この構造体の 3 箇所を揃えてください。
type SuppressionConditions struct {
	RuleName       string `json:"rule_name,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	SeverityMax    int    `json:"severity_max,omitempty"`
	MITRETechnique string `json:"mitre_technique,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
	// HostnameRegex は Hostname の部分一致では表せない「フリート命名」を
	// 絞るための Go(RE2) 正規表現です。アンカー付きの多分岐
	// （例: `(?i)^(k8s-node-|kube-|ci-runner-)`）を 1 行で書けます。
	// コンパイルできない値は**一致しません**（＝抑制しません）。
	HostnameRegex string `json:"hostname_regex,omitempty"`
	// CommandLine / ParentProcess は detection 側が読んでいたのに
	// ここに無く、書き戻しで消える状態でした（本 PR で追加）。
	CommandLine   string `json:"command_line_contains,omitempty"`
	ParentProcess string `json:"parent_process,omitempty"`
}

// SuppressionRule represents a rule that suppresses matching alerts.
type SuppressionRule struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Description   string                `json:"description,omitempty"`
	Conditions    SuppressionConditions `json:"conditions"`
	DurationH     int                   `json:"duration_h"`
	IsActive      bool                  `json:"is_active"`
	HitCount      int                   `json:"hit_count"`
	CreatedBy     *string               `json:"created_by,omitempty"`
	CreatedByName string                `json:"created_by_name,omitempty"`
	ExpiresAt     *time.Time            `json:"expires_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// ErrSuppressionNotFound is returned when the target rule does not exist.
//
// **消えたルールへの更新を成功として返さない。** 抑制ルールの編集画面で
// 保存が通ったように見えて何も変わらないと、運用者は「保存した条件で
// 抑制されている」と信じたまま次の判断をする。
var ErrSuppressionNotFound = errors.New("suppression rule not found")

// SuppressionStore handles suppression rule persistence.
type SuppressionStore struct {
	pool *pgxpool.Pool
}

func NewSuppressionStore(db *DB) *SuppressionStore {
	return &SuppressionStore{pool: db.Pool()}
}

// List returns all suppression rules newest-first.
func (s *SuppressionStore) List(ctx context.Context, activeOnly bool) ([]*SuppressionRule, error) {
	where := ""
	if activeOnly {
		where = "WHERE sr.is_active = TRUE AND (sr.expires_at IS NULL OR sr.expires_at > NOW())"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT sr.id, sr.name, COALESCE(sr.description,''),
		       sr.conditions, sr.duration_h, sr.is_active, sr.hit_count,
		       sr.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       sr.expires_at, sr.created_at, sr.updated_at
		FROM suppression_rules sr
		LEFT JOIN users u ON u.id = sr.created_by
		`+where+`
		ORDER BY sr.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*SuppressionRule
	for rows.Next() {
		r := &SuppressionRule{}
		var condJSON []byte
		var createdBy *string
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description,
			&condJSON, &r.DurationH, &r.IsActive, &r.HitCount,
			&createdBy, &r.CreatedByName,
			&r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		_ = json.Unmarshal(condJSON, &r.Conditions)
		r.CreatedBy = createdBy
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*SuppressionRule{}
	}
	return rules, nil
}

// Insert creates a new suppression rule.
func (s *SuppressionStore) Insert(ctx context.Context, r *SuppressionRule) error {
	condJSON, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		-- **両方の旗に同じ値を書きます**（SetActive の注記を参照）。
		-- 片方だけ書くと、書かなかった側の既定 (TRUE) が残り、
		-- 無効にしたつもりのルールが適用され続けます。
		INSERT INTO suppression_rules
		  (name, description, conditions, duration_h, is_active, enabled, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, $6::uuid, $7)`,
		r.Name, r.Description, string(condJSON), r.DurationH,
		r.IsActive, nilIfEmpty(r.CreatedBy), r.ExpiresAt,
	)
	return err
}

// GetIsActive returns the rule's current on/off value.
//
// **省略された旗を「有効」と読まないために要ります。** 更新要求に
// is_active が無いとき、既定を true にすると、**無効にしてあったルールを
// 名前だけ直して保存した瞬間に有効化します**。運用者は何も有効化していない
// つもりなので、抑制が突然効き始めた理由が分かりません。
func (s *SuppressionStore) GetIsActive(ctx context.Context, id string) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx,
		"SELECT is_active FROM suppression_rules WHERE id = $1", id).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrSuppressionNotFound
	}
	return active, err
}

// Delete removes a suppression rule.
func (s *SuppressionStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM suppression_rules WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// IncrHitCount atomically increments the hit_count for the given rule.
//
// **この数は「効いていないルール」を見つけるためのものです。** 落ちると
// ヒット0のまま残り、実際は毎日抑制しているルールが「もう要らない」と
// 判断されます。呼び出し側が何をするかは呼び出し側が決めます。
func (s *SuppressionStore) IncrHitCount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE suppression_rules SET hit_count = hit_count + 1 WHERE id = $1", id,
	)
	return err
}

// SetActive toggles a rule's active flags.
//
// **旗は2つあります。** 列が is_active と enabled の2つあり、いまは
// ここが両方に同じ値を書く唯一の書き手です。
//
// もう 1 つの書き手 (internal/suppression.Engine) は撤去しましたが、
// **その API が残したデータは消えません。** 読み手
// (detection.PoolSuppressionLoader) が両方 TRUE を要求するのはそのためで、
// ここで片方だけ落とすと、もう片方の既定 (TRUE) が残ります。
// **両方に同じ値を書きます。**
func (s *SuppressionStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE suppression_rules SET is_active=$2, enabled=$2, updated_at=NOW() WHERE id=$1",
		id, active,
	)
	return err
}

// Update replaces the editable fields of an existing rule.
//
// **conditions は列ごと置き換える。** 部分更新にすると「画面から条件を1つ
// 消した」と「画面がそのキーを知らないので送らなかった」が区別できず、
// 消したはずの条件が残る。抑制ルールで条件が残る方向の間違いは、
// **消えたままのアラート**として現れ、攻撃されていないことと見分けがつかない。
// 呼び出し側は編集後の条件を丸ごと渡すこと。
//
// duration_h だけは 0 を「未指定」として既存値を残す。0 時間の抑制は
// 意味を成さず、送り手が持っていないだけの値で既存設定を潰さないため。
//
// 旗は Insert / SetActive と同じく2つに同じ値を書く（is_active と enabled）。
// 片方だけ書くと、書かなかった側の既定 TRUE が残る。
func (s *SuppressionStore) Update(ctx context.Context, r *SuppressionRule) error {
	condJSON, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE suppression_rules
		   SET name = $2, description = $3, conditions = $4,
		       duration_h = COALESCE(NULLIF($5, 0), duration_h),
		       is_active = $6, enabled = $6,
		       expires_at = $7, updated_at = NOW()
		 WHERE id = $1`,
		r.ID, r.Name, r.Description, string(condJSON),
		r.DurationH, r.IsActive, r.ExpiresAt,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrSuppressionNotFound
	}
	return nil
}
