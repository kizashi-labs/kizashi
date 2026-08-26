package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"strings"
	"time"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// AlertStore handles all alert-related database operations.
type AlertStore struct {
	pool      *pgxpool.Pool
	encryptor *tenantcrypto.Encryptor
	// publisher is an optional NATS connection used to emit investigation
	// trigger messages when a high-severity alert is saved.
	publisher *nats.Conn
}

// WithPublisher attaches a NATS connection to the AlertStore so that
// SaveAlert can publish investigation trigger messages for high-severity
// alerts.  Calling this with nil is a no-op.
func (s *AlertStore) WithPublisher(nc *nats.Conn) *AlertStore {
	s.publisher = nc
	return s
}

func NewAlertStore(db *DB) *AlertStore {
	return &AlertStore{pool: db.Pool()}
}

// Pool exposes the underlying connection pool for operations not covered by AlertStore methods.
func (s *AlertStore) Pool() *pgxpool.Pool { return s.pool }

// WithEncryptor attaches a tenant Encryptor to the AlertStore, enabling
// AES-256-GCM encryption of raw_event data at rest.  Calling this with a nil
// encryptor is a no-op (encryption remains disabled).
func (s *AlertStore) WithEncryptor(enc *tenantcrypto.Encryptor) *AlertStore {
	s.encryptor = enc
	return s
}

// StoredAlert mirrors the alerts table.
type StoredAlert struct {
	ID            string   `json:"id"`
	RuleID        *string  `json:"rule_id,omitempty"`
	RuleName      *string  `json:"rule_name,omitempty"`
	AgentID       string   `json:"agent_id"`
	Hostname      string   `json:"agent_hostname"`
	OS            string   `json:"agent_os"`
	Severity      int      `json:"severity"`
	Status        string   `json:"status"`
	Title         string   `json:"title"`
	Description   *string  `json:"description,omitempty"`
	EventIDs      []string `json:"event_ids,omitempty"`
	MITRETech     *string  `json:"mitre_technique,omitempty"`
	AnomalyScore  *float64 `json:"anomaly_score,omitempty"`
	AIAnalyzed    bool     `json:"ai_analyzed"`
	AIIsThreat    *bool    `json:"ai_is_threat,omitempty"`
	AISeverity    *int     `json:"ai_severity,omitempty"`
	AIConfidence  *float64 `json:"ai_confidence,omitempty"`
	AIThreatName  *string  `json:"ai_threat_name,omitempty"`
	AISummary     *string  `json:"ai_summary,omitempty"`
	AIReport      *string  `json:"ai_report,omitempty"`
	AIAttackChain []string `json:"ai_attack_chain,omitempty"`
	AIMITRETags   []string `json:"ai_mitre_tags,omitempty"`
	// Tags are the operator-applied labels written by POST /alerts/bulk-tag.
	// Stored as a JSONB array of strings; always serialised, never omitted, so
	// a client can tell "no tags" from "this build does not report tags".
	Tags           []string   `json:"tags"`
	AssignedTo     *string    `json:"assigned_to,omitempty"`
	AssignedToName *string    `json:"assigned_to_name,omitempty"`
	CommentCount   int        `json:"comment_count"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	// RawEvent holds the original triggering event payload.  When encryption is
	// enabled on the AlertStore the value stored in the database is an
	// AES-256-GCM ciphertext encoded as "enc:<base64>"; callers receive the
	// decrypted JSON here.
	RawEvent json.RawMessage `json:"raw_event,omitempty"`
	// RawEventUnavailable explains why RawEvent is empty when the payload could
	// not be produced.
	//
	// **「生イベントが無いアラート」と「生イベントを出せなかったアラート」を
	// 同じ姿にしないための欄です。** 復号に失敗したことをログにだけ書くと、
	// アナリストの画面では鍵の設定ミスと「もともと生イベントの無い検知」が
	// 区別できません。空欄の理由は応答に載せます。
	RawEventUnavailable *string `json:"raw_event_unavailable,omitempty"`
	// TenantID is used as the encryption scope key.  It is not persisted as its
	// own column but is required when encryption is active.
	TenantID string `json:"-"`
}

// encryptedRawEventPrefix is prepended to the base64-encoded ciphertext so
// readers can distinguish encrypted values from plain-text JSON.
const encryptedRawEventPrefix = "enc:"

// IsEncryptedRawEvent reports whether a stored raw_event value is ciphertext.
func IsEncryptedRawEvent(stored string) bool {
	return strings.HasPrefix(stored, encryptedRawEventPrefix)
}

// encryptionTenant returns the tenant whose key scopes this alert's raw_event.
//
// **本番で `StoredAlert.TenantID` を設定する箇所は1つもありません。**
// テナントの出どころは ctx で、そこから `store.Connect` の PrepareConn が
// Postgres の `app.tenant_id` を設定し、`alerts.tenant_id` 列の DEFAULT が
// それを読みます。暗号化の範囲も同じ ctx から取ります —— **同じ出どころ
// なので、行の tenant_id と鍵のテナントは構造上ずれません。**
//
// これを `a.TenantID` だけで見ていたあいだ、encryptor を付けても
// 暗号化は一度も起きませんでした。単体テストはテナントを引数で渡して
// いたので緑のままでした。実際に DB に書いて確かめて出ました
// （alert_encryption_roundtrip_test.go）。
func encryptionTenant(ctx context.Context, a *StoredAlert) string {
	if a.TenantID != "" {
		return a.TenantID
	}
	return TenantFromContext(ctx)
}

// prepareRawEvent returns the value to be stored in the raw_event column.
// When an encryptor and a tenant are available the JSON payload is encrypted
// with AES-256-GCM and returned as "enc:<base64>".  Otherwise the raw JSON is
// returned unchanged.  A nil or empty RawEvent results in a nil return value
// (the column will be left NULL).
func (s *AlertStore) prepareRawEvent(ctx context.Context, a *StoredAlert) (*string, error) {
	if len(a.RawEvent) == 0 {
		return nil, nil
	}

	tenant := encryptionTenant(ctx, a)
	if s.encryptor == nil || tenant == "" {
		// No encryption configured — store as plain JSON string.
		plain := string(a.RawEvent)
		return &plain, nil
	}

	ciphertext, err := s.encryptor.Encrypt(ctx, tenant, []byte(a.RawEvent))
	if err != nil {
		return nil, fmt.Errorf("alertstore: encrypt raw_event for alert %s: %w", a.ID, err)
	}

	encoded := encryptedRawEventPrefix + base64.StdEncoding.EncodeToString(ciphertext)
	return &encoded, nil
}

// decodeRawEvent turns the stored column value back into JSON.
//
// 平文と暗号文が混在します。`enc:` が付いていないものは、暗号化を有効に
// する前に書かれた行で、そのまま JSON です。移行はしません —— 前置きの
// 有無で1行ずつ判断できるので、既存の行を書き換える理由がありません。
//
// **書き込み側より先に、こちらが入っている必要があります。** 以前ここは
// `enc:` が付いていたら代入しない、という書き方でした。暗号化を有効に
// した瞬間から、アナリストの画面は生イベントの無いアラートで埋まります
// —— このブランチがずっと追ってきた形そのものです。復号できないことと、
// 生イベントが無いことが、同じ姿になります。
func (s *AlertStore) decodeRawEvent(ctx context.Context, tenantID string, stored *string) (json.RawMessage, error) {
	return DecodeRawEvent(ctx, s.encryptor, tenantID, stored)
}

// DecodeRawEvent is the one place that knows how a stored raw_event is encoded.
//
// エクスポートも同じ規則で読む必要があります。前置きの判定を2箇所に
// 書くと、**片方だけ直したときに、書いたものが片方からは読めなくなります。**
// このブランチで「写しだけが正しくなる」形を何度も見たので、関数を1つに
// して両方から呼びます。
func DecodeRawEvent(ctx context.Context, enc *tenantcrypto.Encryptor, tenantID string, stored *string) (json.RawMessage, error) {
	s := &AlertStore{encryptor: enc}
	return s.decodeRawEventImpl(ctx, tenantID, stored)
}

func (s *AlertStore) decodeRawEventImpl(ctx context.Context, tenantID string, stored *string) (json.RawMessage, error) {
	if stored == nil || *stored == "" {
		return nil, nil
	}
	if !strings.HasPrefix(*stored, encryptedRawEventPrefix) {
		return json.RawMessage(*stored), nil
	}
	if s.encryptor == nil {
		return nil, fmt.Errorf("暗号化された raw_event ですが、encryptor が設定されていません")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("暗号化された raw_event ですが、テナントが分かりません")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(*stored, encryptedRawEventPrefix))
	if err != nil {
		return nil, fmt.Errorf("base64 を読めません: %w", err)
	}
	plain, err := s.encryptor.Decrypt(ctx, tenantID, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("復号できません: %w", err)
	}
	return json.RawMessage(plain), nil
}

// SaveAlert inserts a new alert.  If the AlertStore has an Encryptor configured
// and the alert carries a non-empty TenantID, the raw_event field is encrypted
// with AES-256-GCM before being written to the database.
func (s *AlertStore) SaveAlert(ctx context.Context, a *StoredAlert) error {
	rawEventVal, err := s.prepareRawEvent(ctx, a)
	if err != nil {
		// アラート自体は保存します。暗号化できないことを理由にアラートを
		// 落とす方が損が大きいためで、これは変えません。
		//
		// ただし、保存されたアラートには生イベントが付きません。開いた
		// 分析官が見るのは「生イベントの無いアラート」で、もともと生
		// イベントを持たない種類のアラートと区別が付きません。証拠が
		// 消えたことは数えます。
		metrics.BackgroundFailed("alert_raw_event", err,
			"生イベントを暗号化できないまま保存しました（証拠は付いていません）",
			"alert", a.ID)
		rawEventVal = nil
	}

	// agent_id is a uuid column. Agentless alerts — e.g. the cloud
	// suspicious-operation path, which keys off a cloud account, not an endpoint —
	// carry no agent, so AgentID is "". Binding "" to a uuid fails with SQLSTATE
	// 22P02 ("invalid input syntax for type uuid"), which silently drops the alert.
	// Bind NULL instead when there is no agent. (rule_id is already a *string that
	// the caller leaves nil for the same reason.)
	var agentIDArg any
	if a.AgentID != "" {
		agentIDArg = a.AgentID
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO alerts (
			id, rule_id, agent_id, severity, status, title, description,
			mitre_technique, anomaly_score, raw_event, created_at, updated_at,
			ai_mitre_tags, event_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::uuid[])`,
		a.ID, a.RuleID, agentIDArg, a.Severity, a.Status, a.Title,
		a.Description, a.MITRETech, a.AnomalyScore, rawEventVal,
		a.CreatedAt, a.UpdatedAt, a.AIMITRETags, a.EventIDs,
	)
	if err != nil {
		return err
	}

	// Publish an AI investigation trigger for alerts that meet the configured
	// severity threshold.  The threshold is read from system_settings
	// (`ai_auto_investigate_threshold`) and defaults to 7 if unavailable.
	// Failures are non-fatal and only logged.
	if s.publisher != nil && a.Severity >= s.autoInvestigateThreshold(ctx) {
		if pubErr := s.publisher.Publish("edr.investigation.trigger", []byte(a.ID)); pubErr != nil {
			slog.Warn("alertstore: failed to publish investigation trigger",
				"alert_id", a.ID, "error", pubErr)
		}
	}
	return nil
}

// autoInvestigateThreshold reads the AI auto-investigation severity threshold
// from system_settings.  Falls back to 7 when the setting is missing or invalid.
//
// 呼び出し元はアラートの保存中です。設定を読めなかったからといって保存を
// 落とすのは、失う方が大きいので既定値で続けます。ただし黙ってはいけません。
// 閾値を4に設定していたテナントでは、この失敗のあいだ severity 4〜6 の
// アラートが自動調査に回りません。誰も設定を変えていないのに、設定が
// 効かなくなります。行が無いこと（＝未設定）とは分けて記録します。
func (s *AlertStore) autoInvestigateThreshold(ctx context.Context) int {
	const fallback = 7
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'ai_auto_investigate_threshold'`).
		Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return fallback // 未設定。既定値は事実です。
	}
	if err != nil {
		metrics.BackgroundFailed("alert_auto_investigate", err,
			"alertstore: 自動調査の閾値を読めないまま既定値で続行しました", "fallback", fallback)
		return fallback
	}
	var v int
	if jsonErr := json.Unmarshal(raw, &v); jsonErr == nil && v >= 1 && v <= 10 {
		return v
	}
	return fallback
}

// GetAlert retrieves a single alert with agent info.
func (s *AlertStore) GetAlert(ctx context.Context, id string) (*StoredAlert, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			al.id, al.rule_id, r.name,
			COALESCE(al.agent_id::text, ''), COALESCE(ag.hostname, ''),
			COALESCE(ag.os_type, ''),
			al.severity, al.status, al.title, al.description,
			al.mitre_technique, al.anomaly_score,
			al.ai_analyzed, al.ai_is_threat, al.ai_severity,
			al.ai_confidence, al.ai_threat_name, al.ai_summary,
			al.ai_report, al.ai_attack_chain, al.ai_mitre_tags, al.tags,
			al.assigned_to, u.full_name, al.resolved_at, al.created_at, al.updated_at,
			al.tenant_id
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		LEFT JOIN users u ON u.id = al.assigned_to::uuid
		WHERE al.id = $1`, id)

	a, err := scanAlert(row)
	if err != nil {
		return nil, err
	}

	var rawEventStr *string
	readErr := s.pool.QueryRow(ctx,
		`SELECT raw_event FROM alerts WHERE id = $1`, id).Scan(&rawEventStr)
	// 復号の範囲は**行が記録しているテナント**です。ctx のテナントではなく。
	// 背景ジョブのようにテナントを持たない経路から読んでも、行が自分の
	// テナントを覚えているので復号できます。ctx を見ていると、
	// そこから読んだ瞬間に「復号できませんでした」になります。
	a.RawEvent, a.RawEventUnavailable = s.rawEventOrNote(ctx, id, a.TenantID, rawEventStr, readErr)
	return a, nil
}

// rawEventOrNote returns the alert's raw event, or a note saying why it is not
// there.  Exactly one of the two is ever non-empty.
//
// 生イベントを出せないことは、アラート全体を返さない理由にはなりません
// —— 検知そのものは事実だからです。一方で、黙って落とすと「もともと生
// イベントの無い検知」と見分けがつきません。**読めなかった・復号でき
// なかったことは、ログではなく応答に載せます。**
//
// クエリはここでは打ちません。呼び出し側が読んだ結果と、その失敗を
// そのまま受け取ります。DB を用意せずに、この判断だけを試せるように
// するためです（raw_event_note_test.go）。
func (s *AlertStore) rawEventOrNote(
	ctx context.Context, alertID, tenantID string, stored *string, readErr error,
) (json.RawMessage, *string) {
	if readErr != nil {
		return nil, rawEventNote(alertID, "生イベントを読み出せませんでした", readErr)
	}
	raw, err := s.decodeRawEvent(ctx, tenantID, stored)
	if err != nil {
		return nil, rawEventNote(alertID, "生イベントを復号できませんでした", err)
	}
	return raw, nil
}

// rawEventNote records the failure and returns the text shown in its place.
//
// 詳細（鍵の不一致、DB のエラー）はログに残し、応答には「出せなかった」
// ことだけを載せます。内部のエラー文をそのまま画面に出す必要はありません。
func rawEventNote(alertID, what string, err error) *string {
	slog.Error("alertstore: "+what+"。このアラートは生イベント無しで返ります",
		"alert", alertID, "error", err)
	return &what
}

// UpdateAlert updates mutable alert fields.
func (s *AlertStore) UpdateAlert(ctx context.Context, id string, status *string, analysis *AIAnalysisUpdate, assignedTo ...*string) error {
	// Capture previous status BEFORE the update so history tracking is accurate.
	// **読めなかった空文字は、履歴に「何から変わったか」の嘘を残します。**
	// 行が無いのは別（そのアラートが無いだけ）なので、そこは通します。
	var prevStatus string
	if status != nil {
		if err := s.pool.QueryRow(ctx, "SELECT status FROM alerts WHERE id = $1", id).
			Scan(&prevStatus); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("変更前の状態を読めません: %w", err)
		}
	}

	sets := []string{"updated_at = NOW()"}
	args := []interface{}{id}
	i := 2

	if status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", i))
		args = append(args, *status)
		i++
	}

	if len(assignedTo) > 0 && assignedTo[0] != nil {
		if *assignedTo[0] == "" {
			// 空文字 = 割り当て解除 → NULL
			sets = append(sets, "assigned_to = NULL")
		} else {
			sets = append(sets, fmt.Sprintf("assigned_to = $%d", i))
			args = append(args, *assignedTo[0])
			i++
		}
	}

	if analysis != nil {
		sets = append(sets,
			"ai_analyzed = true",
			fmt.Sprintf("ai_is_threat = $%d", i),
			fmt.Sprintf("ai_severity = $%d", i+1),
			fmt.Sprintf("ai_confidence = $%d", i+2),
			fmt.Sprintf("ai_threat_name = $%d", i+3),
			fmt.Sprintf("ai_summary = $%d", i+4),
			fmt.Sprintf("ai_report = $%d", i+5),
			fmt.Sprintf("ai_attack_chain = $%d", i+6),
			fmt.Sprintf("ai_mitre_tags = $%d", i+7),
		)
		args = append(args,
			analysis.IsThreat, analysis.Severity, analysis.Confidence,
			analysis.ThreatName, analysis.Summary, analysis.Report,
			analysis.AttackChain, analysis.MITRETags,
		)
		i += 8
	}

	query := fmt.Sprintf(
		"UPDATE alerts SET %s WHERE id = $1",
		strings.Join(sets, ", "),
	)

	// **状態の変更と、その履歴は1つの変更です。**
	//
	// 履歴の INSERT だけ `_, _ =` で捨てていました。**MTTD/MTTR は
	// `alert_status_changes` から出ます** —— 落ちた分だけ対応時間が
	// 実際より短く出て、しかもそれは行が「無い」のと見分けがつきません。
	// 状態だけ変わって履歴が無い、を残さないよう同じ transaction に
	// 入れます。
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return err
	}

	// Record status change for MTTD/MTTR tracking.
	if status != nil && prevStatus != *status {
		changedBy := "system"
		if len(assignedTo) > 0 && assignedTo[0] != nil {
			changedBy = *assignedTo[0]
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_status_changes (alert_id, from_status, to_status, changed_by)
			VALUES ($1::uuid, $2, $3, $4)`,
			id, prevStatus, *status, changedBy,
		); err != nil {
			return fmt.Errorf("状態変更の履歴を残せませんでした（MTTR が実際より短く出ます）: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// AIAnalysisUpdate contains the AI analysis fields to persist.
type AIAnalysisUpdate struct {
	IsThreat    bool
	Severity    int
	Confidence  float64
	ThreatName  string
	Summary     string
	Report      string
	AttackChain []string
	MITRETags   []string
}

// ListAlerts returns alerts with pagination and filtering.
func (s *AlertStore) ListAlerts(ctx context.Context, filter AlertFilter) ([]*StoredAlert, int, error) {
	where, args := buildAlertWhere(filter)
	countQuery := "SELECT COUNT(*) FROM alerts al " + where
	// COALESCE の対象は StoredAlert 側が非ポインタ (AgentID/Hostname/OS はいずれも
	// string) の3列。alerts.agent_id は NULL 可で、エンドポイント由来でないアラート
	// (MDM デバイスの長期未報告など) は NULL で入る。さらに LEFT JOIN agents は
	// 該当エージェントが削除済みなら hostname/os_type を NULL にする。
	// NULL をそのまま string にスキャンすると Scan がエラーになり、pgx v5 は
	// エラー時に結果セットを fatal 化して閉じるため、以降の行が丸ごと消える
	// (下のループ参照)。SQL 側で潰しておくのが最も確実。
	listQuery := `
		SELECT
			al.id, al.rule_id, r.name,
			COALESCE(al.agent_id::text, ''), COALESCE(ag.hostname, ''),
			COALESCE(ag.os_type, ''),
			al.severity, al.status, al.title, al.description,
			al.mitre_technique, al.anomaly_score,
			al.ai_analyzed, al.ai_is_threat, al.ai_severity,
			al.ai_confidence, al.ai_threat_name, al.ai_summary,
			al.ai_report, al.ai_attack_chain, al.ai_mitre_tags, al.tags,
			al.assigned_to, u.full_name,
			(SELECT COUNT(*) FROM alert_comments ac WHERE ac.alert_id = al.id) AS comment_count,
			al.resolved_at, al.created_at, al.updated_at
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		LEFT JOIN users u ON u.id = al.assigned_to::uuid
		` + where + `
		ORDER BY al.created_at DESC
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) +
		` OFFSET $` + fmt.Sprintf("%d", len(args)+2)

	var total int
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, filter.Limit, filter.Offset)
	rows, err := s.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []*StoredAlert
	for rows.Next() {
		var a StoredAlert

		var tagsRaw []byte
		// ai_mitre_tags と ai_attack_chain はどちらも TEXT[] です。[]string に
		// そのまま読みます。
		//
		// ai_attack_chain は []byte で受けて json.Unmarshal していました。
		// **列が NULL のあいだは動きます。** 値が入った瞬間に pgx が
		// `cannot scan _text into *[]uint8` を返し、Scan が失敗して
		// **一覧が0件で返ります**（この関数は err を rows.Err() 経由で
		// 上げるので、画面には「アラートが1件もありません」ではなく
		// エラーが出ます）。GetAlert 側は詳細が開けなくなります。
		// alert_ai_arrays_test.go が両方を留めています。
		err := rows.Scan(
			&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.Hostname, &a.OS,
			&a.Severity, &a.Status, &a.Title, &a.Description,
			&a.MITRETech, &a.AnomalyScore,
			&a.AIAnalyzed, &a.AIIsThreat, &a.AISeverity,
			&a.AIConfidence, &a.AIThreatName, &a.AISummary,
			&a.AIReport, &a.AIAttackChain, &a.AIMITRETags, &tagsRaw,
			&a.AssignedTo, &a.AssignedToName, &a.CommentCount,
			&a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			continue
		}
		a.Tags = decodeTags(a.ID, tagsRaw)
		alerts = append(alerts, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return alerts, total, nil
}

// AlertStats returns aggregated alert statistics for the dashboard.
func (s *AlertStore) AlertStats(ctx context.Context) (*AlertStatSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'open')          AS open_count,
			COUNT(*) FILTER (WHERE status = 'investigating') AS investigating_count,
			COUNT(*) FILTER (WHERE status = 'resolved')      AS resolved_count,
			COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
			COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS today_count,
			severity,
			COUNT(*) AS sev_count
		FROM alerts
		GROUP BY ROLLUP(severity)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &AlertStatSummary{
		BySeverity: make(map[int]int),
	}

	for rows.Next() {
		var open, investigating, resolved, fp, today int
		var sev *int
		var sevCount int
		if err := rows.Scan(&open, &investigating, &resolved, &fp, &today, &sev, &sevCount); err != nil {
			continue
		}
		if sev == nil {
			stats.Open = open
			stats.Investigating = investigating
			stats.Resolved = resolved
			stats.FalsePositive = fp
			stats.TodayCount = today
			stats.Total = open + investigating + resolved + fp
		} else {
			stats.BySeverity[*sev] = sevCount
		}
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}

// AlertStatSummary aggregates alert counts.
type AlertStatSummary struct {
	Total         int         `json:"total"`
	Open          int         `json:"open"`
	Investigating int         `json:"investigating"`
	Resolved      int         `json:"resolved"`
	FalsePositive int         `json:"false_positive"`
	TodayCount    int         `json:"today_count"`
	BySeverity    map[int]int `json:"by_severity"`
}

// AlertFilter defines list query filters.
type AlertFilter struct {
	Status         string
	AgentID        string
	RuleID         string
	Severity       int
	SeverityMax    int
	Search         string
	MITRETech      string
	FromTime       *time.Time
	ToTime         *time.Time
	AIInvestigated bool // true → only alerts with a persisted ai_summary
	Limit          int
	Offset         int
}

// TopAgent holds per-agent alert aggregation for the dashboard.
type TopAgent struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	AlertCount  int    `json:"alert_count"`
	MaxSeverity int    `json:"max_severity"`
}

// TopThreatenedAgents returns the top N agents by alert count over the past 7 days.
func (s *AlertStore) TopThreatenedAgents(ctx context.Context, limit int) ([]TopAgent, error) {
	rows, err := s.pool.Query(ctx, `
		-- agent_id は NULL 可 (エンドポイントを持たないアラート — MDM デバイスや
		-- クラウド操作由来など)。TopAgent.AgentID / Hostname は非ポインタの string
		-- なので NULL のままだと Scan が落ち、pgx が結果セットを閉じて以降の行が
		-- 丸ごと消える。ListAlerts と同じ理由で SQL 側で潰す。
		-- hostname 側は「エージェント行が無い」と「agent_id 自体が NULL」の二段。
		SELECT COALESCE(al.agent_id::text, ''),
		       COALESCE(ag.hostname, al.agent_id::text, '(エージェント無し)') AS hostname,
		       COUNT(*)                            AS alert_count,
		       MAX(al.severity)                    AS max_severity
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		WHERE al.created_at >= NOW() - INTERVAL '7 days'
		GROUP BY al.agent_id, ag.hostname
		ORDER BY alert_count DESC, max_severity DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []TopAgent
	for rows.Next() {
		var a TopAgent
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.AlertCount, &a.MaxSeverity); err != nil {
			continue
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return agents, nil
}

// RelatedAlert is a lightweight alert summary for correlation views.
type RelatedAlert struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  int       `json:"severity"`
	Status    string    `json:"status"`
	Hostname  string    `json:"hostname"`
	RuleName  string    `json:"rule_name"`
	MITRETech string    `json:"mitre_technique"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"` // why it's related: "same_host" | "same_rule" | "same_mitre"
}

// GetRelated returns alerts correlated with the given alert by shared host, rule, or MITRE technique
// within the past 7 days, excluding the alert itself.
func (s *AlertStore) GetRelated(ctx context.Context, alertID string, limit int) ([]*RelatedAlert, error) {
	rows, err := s.pool.Query(ctx, `
		WITH base AS (
			SELECT agent_id, rule_id, mitre_technique
			FROM alerts WHERE id = $1
		)
		SELECT DISTINCT al.id,
			al.title,
			al.severity,
			al.status,
			-- 二段の COALESCE だけでは足りない: agent_id 自体が NULL なら両方 NULL に
			-- なり、非ポインタの RelatedAlert.Hostname へのスキャンが落ちる
			-- (TopThreatenedAgents で実際に踏んだ)。リテラルで必ず終端させる。
			COALESCE(ag.hostname, al.agent_id::text, '(エージェント無し)') AS hostname,
			COALESCE(r.name, '') AS rule_name,
			COALESCE(al.mitre_technique, '') AS mitre_technique,
			al.created_at,
			CASE
				WHEN al.agent_id    = base.agent_id        THEN 'same_host'
				WHEN al.rule_id     = base.rule_id         THEN 'same_rule'
				WHEN al.mitre_technique IS NOT NULL
				  AND al.mitre_technique = base.mitre_technique THEN 'same_mitre'
				ELSE 'related'
			END AS reason
		FROM alerts al
		CROSS JOIN base
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules  r  ON r.id  = al.rule_id
		WHERE al.id != $1
		  AND al.created_at >= NOW() - INTERVAL '7 days'
		  AND al.status != 'false_positive'
		  AND (
			al.agent_id = base.agent_id
			OR (base.rule_id IS NOT NULL AND al.rule_id = base.rule_id)
			OR (base.mitre_technique IS NOT NULL AND al.mitre_technique = base.mitre_technique)
		  )
		ORDER BY al.created_at DESC
		LIMIT $2`,
		alertID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var related []*RelatedAlert
	for rows.Next() {
		r := &RelatedAlert{}
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Status, &r.Hostname, &r.RuleName, &r.MITRETech, &r.CreatedAt, &r.Reason); err != nil {
			continue
		}
		related = append(related, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if related == nil {
		related = []*RelatedAlert{}
	}
	return related, nil
}

// AlertCountInWindow returns number of alerts created in [NOW-fromHours, NOW-toHours].
func (s *AlertStore) AlertCountInWindow(ctx context.Context, fromHours, toHours int) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE created_at >= NOW() - $1::interval
		  AND created_at <  NOW() - $2::interval`,
		fmt.Sprintf("%d hours", fromHours),
		fmt.Sprintf("%d hours", toHours),
	).Scan(&count)
	return count, err
}

// AlertTimelineBucket represents hourly alert counts.
type AlertTimelineBucket struct {
	Bucket time.Time
	Count  int
}

// AlertTimeline returns hourly alert counts for the past N hours.
func (s *AlertStore) AlertTimeline(ctx context.Context, hours int) ([]AlertTimelineBucket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('hour', created_at) AS bucket, COUNT(*) AS cnt
		FROM alerts
		WHERE created_at >= NOW() - $1::interval
		GROUP BY bucket
		ORDER BY bucket ASC`,
		fmt.Sprintf("%d hours", hours),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []AlertTimelineBucket
	for rows.Next() {
		var b AlertTimelineBucket
		if err := rows.Scan(&b.Bucket, &b.Count); err != nil {
			continue
		}
		buckets = append(buckets, b)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buckets, nil
}

// GetAlertHistory returns recent alert summaries for an agent (used by AI context).
func (s *AlertStore) GetAlertHistory(ctx context.Context, agentID string, days int) ([]AlertSummaryRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT title, severity, created_at, status
		FROM alerts
		WHERE agent_id = $1 AND created_at >= NOW() - $2::interval
		ORDER BY created_at DESC
		LIMIT 20`,
		agentID, fmt.Sprintf("%d days", days),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AlertSummaryRow
	for rows.Next() {
		var r AlertSummaryRow
		if err := rows.Scan(&r.Title, &r.Severity, &r.CreatedAt, &r.Status); err != nil {
			continue
		}
		result = append(result, r)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type AlertSummaryRow struct {
	Title     string
	Severity  int
	CreatedAt time.Time
	Status    string
}

// SaveResponseAction logs a response action.
func (s *AlertStore) SaveResponseAction(ctx context.Context, action *ResponseActionRow) error {
	// success は status_text から導出される生成列なので直接書けない
	// (migration 379)。呼び出し側の bool を語彙に写す。
	status := StatusSuccess
	if !action.Success {
		status = StatusFailure
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO response_actions (
			id, alert_id, agent_id, action_type, target,
			reason, executed_by, status_text, error_msg, executed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		action.ID, action.AlertID, action.AgentID, action.ActionType,
		action.Target, action.Reason, action.ExecutedBy,
		status, action.ErrorMsg, action.ExecutedAt,
	)
	return err
}

type ResponseActionRow struct {
	ID         string
	AlertID    *string
	AgentID    string
	ActionType string
	Target     *string
	Reason     *string
	ExecutedBy string
	Success    bool
	ErrorMsg   *string
	ExecutedAt time.Time
}

// AddComment persists a comment on an alert.
func (s *AlertStore) AddComment(ctx context.Context, alertID, userID, content string) (string, time.Time, error) {
	var id string
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_comments (alert_id, user_id, content)
		VALUES ($1, $2::uuid, $3)
		RETURNING id, created_at`,
		alertID, userID, content,
	).Scan(&id, &createdAt)
	return id, createdAt, err
}

// ListComments retrieves comments for an alert ordered by creation time.
func (s *AlertStore) ListComments(ctx context.Context, alertID string) ([]AlertComment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ac.id, ac.alert_id, COALESCE(ac.user_id::text, ''),
		       COALESCE(u.full_name, ac.user_id::text, 'Unknown'), ac.content, ac.created_at
		FROM alert_comments ac
		LEFT JOIN users u ON u.id = ac.user_id
		WHERE ac.alert_id = $1
		ORDER BY ac.created_at ASC`,
		alertID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []AlertComment
	for rows.Next() {
		var cm AlertComment
		if err := rows.Scan(&cm.ID, &cm.AlertID, &cm.UserID, &cm.UserName, &cm.Content, &cm.CreatedAt); err != nil {
			continue
		}
		comments = append(comments, cm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return comments, nil
}

type AlertComment struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"`
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── Helpers ──────────────────────────────────────────────────

// decodeTags turns the alerts.tags JSONB array into a slice, never nil.
//
// It is decoded from raw bytes rather than scanned straight into []string so a
// malformed value cannot fail the whole Scan. In ListAlerts a Scan error skips
// the row, which would silently drop an alert from the console because of a
// label somebody applied to it.
func decodeTags(alertID string, raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil {
		slog.Warn("tags JSONの解析に失敗しました", "alert_id", alertID, "error", err)
		return []string{}
	}
	if tags == nil {
		return []string{}
	}
	return tags
}

func scanAlert(row pgx.Row) (*StoredAlert, error) {
	var a StoredAlert
	var tagsRaw []byte
	var tenantID *string

	err := row.Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.Hostname, &a.OS,
		&a.Severity, &a.Status, &a.Title, &a.Description,
		&a.MITRETech, &a.AnomalyScore,
		&a.AIAnalyzed, &a.AIIsThreat, &a.AISeverity,
		&a.AIConfidence, &a.AIThreatName, &a.AISummary,
		&a.AIReport, &a.AIAttackChain, &a.AIMITRETags, &tagsRaw,
		&a.AssignedTo, &a.AssignedToName, &a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt,
		&tenantID,
	)
	if err != nil {
		return nil, err
	}
	// tenant_id は raw_event の復号に使う鍵の範囲です。読まないと、
	// **暗号化されたアラートは1件も復号できません。**
	if tenantID != nil {
		a.TenantID = *tenantID
	}

	a.Tags = decodeTags(a.ID, tagsRaw)

	return &a, nil
}

func buildAlertWhere(f AlertFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	i := 1

	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("al.status = $%d", i))
		args = append(args, f.Status)
		i++
	}
	if f.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("al.agent_id = $%d", i))
		args = append(args, f.AgentID)
		i++
	}
	if f.RuleID != "" {
		conditions = append(conditions, fmt.Sprintf("al.rule_id = $%d", i))
		args = append(args, f.RuleID)
		i++
	}
	if f.Severity > 0 {
		conditions = append(conditions, fmt.Sprintf("al.severity >= $%d", i))
		args = append(args, f.Severity)
		i++
	}
	if f.SeverityMax > 0 {
		conditions = append(conditions, fmt.Sprintf("al.severity <= $%d", i))
		args = append(args, f.SeverityMax)
		i++
	}
	if f.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(al.title ILIKE $%d OR al.description ILIKE $%d OR EXISTS (SELECT 1 FROM agents _ag WHERE _ag.id = al.agent_id AND _ag.hostname ILIKE $%d))", i, i, i,
		))
		args = append(args, "%"+f.Search+"%")
		i++
	}
	if f.MITRETech != "" {
		// Match rule-based technique OR any AI-mapped technique in the array
		conditions = append(conditions, fmt.Sprintf(
			"(al.mitre_technique ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(COALESCE(al.ai_mitre_tags, '{}')) _t WHERE _t ILIKE $%d))",
			i, i,
		))
		args = append(args, f.MITRETech+"%")
		i++
	}
	if f.FromTime != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at >= $%d", i))
		args = append(args, *f.FromTime)
		i++
	}
	if f.ToTime != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at <= $%d", i))
		args = append(args, *f.ToTime)
		i++
	}
	if f.AIInvestigated {
		// Only alerts that have a persisted AI investigation summary.
		conditions = append(conditions, "al.ai_summary IS NOT NULL AND al.ai_summary <> ''")
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}
