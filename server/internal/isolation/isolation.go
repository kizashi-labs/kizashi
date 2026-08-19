// Package isolation is the single authorised path for taking an endpoint off
// the network, and for putting it back.
//
// 隔離は 6 つの経路から実行できた。
//
//	handlers.AgentHandler.Isolate          手動隔離
//	handlers.QuarantineActionsHandler      隔離アクション API
//	detection.Engine.applyRuleBasedResponse ルールベース自動隔離
//	detection.PlaybookRunner               プレイブック
//	detection.AIAgent                      AI トリアージ
//	remediation.Engine                     自動修復エンジン
//
// このうち安全弁（冷却期間・時間あたり上限・ドライラン）を通るのは 3 番目だけで、
// response_actions に記録が残るのは 1 番目だけだった。2026-08-13 の実機検証で
// 6 番目が発火し、端末が実際に隔離されたにもかかわらず response_actions に行が
// 無く、agents.status も online のままという状態が観測された。実態と記録が
// 完全に食い違い、「なぜこの端末は通信できないのか」に製品が答えられなかった。
//
// 経路を 1 つずつ塞ぐ方法は 3 回試して 3 回とも次が出てきた。「全部塞いだ」を
// 主張するには、塞ぎ忘れが検出できる構造でなければならない。そこで
//
//   - 隔離の実行はこのパッケージの Gatekeeper だけが行う
//   - NATS の commands.<agent>.isolate / .unisolate を組み立てられる場所を
//     store.CommandStore だけに限る
//   - それ以外の場所からの直接送出を chokepoint_test.go が機械的に検出する
//
// とした。Go では「呼べないこと」を型で強制しきれないため、最後の一段は
// 構造テストが担う。このリポジトリが schema_contract_test / shell_eol_test で
// 使っているのと同じ手口。
package isolation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Origin identifies who decided to isolate. 記録と安全弁の適用可否がここで決まる。
type Origin string

const (
	// OriginManual は人が明示的に押した隔離。安全弁は適用しない。
	// 冷却期間や時間あたり上限は「誤検知が勝手に端末を止める」ことへの対策で、
	// 運用者の意思決定を阻むためのものではない。押した人が結果を引き受ける。
	OriginManual Origin = "manual"
	// OriginQuarantineAction は隔離アクション API 経由。人が起点だが
	// 自動化から叩かれうるので無人扱いにする。
	OriginQuarantineAction Origin = "quarantine_action"
	// OriginRule は detection のルールベース自動隔離。
	OriginRule Origin = "auto_rule"
	// OriginPlaybook はプレイブックの isolate_endpoint アクション。
	OriginPlaybook Origin = "playbook"
	// OriginAITriage は AI 分析による自動隔離。
	OriginAITriage Origin = "ai_triage"
	// OriginRemediation は自動修復エンジン。
	OriginRemediation Origin = "remediation"
)

// Unattended reports whether this origin acts without a human in the loop.
//
// 無人経路だけが AUTO_RESPONSE_ENABLED と安全弁の対象になる。
func (o Origin) Unattended() bool { return o != OriginManual }

// Outcome is what the Gatekeeper actually did.
type Outcome string

const (
	// OutcomeDispatched は隔離コマンドをエージェントへ送出した状態。
	// 送出であって、隔離されたことの確認ではない。確認はエージェントの ack で
	// response_actions が success に進むことによる。
	OutcomeDispatched Outcome = "dispatched"
	// OutcomeDryRun は AUTO_ISOLATE_DRY_RUN により実行しなかった状態。
	OutcomeDryRun Outcome = "dry_run"
	// OutcomeRefused は安全弁（冷却期間・時間あたり上限）が止めた状態。
	OutcomeRefused Outcome = "refused"
	// OutcomeDisabled は AUTO_RESPONSE_ENABLED=false が止めた状態。
	OutcomeDisabled Outcome = "disabled"
	// OutcomeExempt は AUTO_ISOLATE_EXEMPT により対象から外された状態。
	// 冷却期間や時間あたり上限（OutcomeRefused）とは別物である。あちらは
	// 「今は駄目」だが、こちらは「この端末は対象にしない」という恒久の指定。
	OutcomeExempt Outcome = "exempt"
)

// Executed reports whether a command was actually sent to the endpoint.
func (o Outcome) Executed() bool { return o == OutcomeDispatched }

// Request describes one isolation decision.
type Request struct {
	// AgentID は対象エージェント。空なら誤り。
	AgentID string
	// Reason はエージェントと監査記録に載る理由。
	Reason string
	// AlertID は引き金になったアラート。無ければ空。
	AlertID string
	// Origin はどの経路が決めたか。
	Origin Origin
	// TriggeredBy は手動なら利用者 ID、自動なら経路名。空なら Origin を使う。
	TriggeredBy string
	// Label は判断したルール／プレイブックの名前。抑止ログに出す。
	Label string
	// Hostname は分かっていれば埋める。AUTO_ISOLATE_EXEMPT はホスト名でも
	// 指定できるため。空でも Config.HostnameResolver があれば解決される。
	Hostname string
}

// Result is what happened, and enough context to explain it to an operator.
type Result struct {
	Outcome Outcome
	// ActionID は response_actions の行 ID。記録できなかった場合は空。
	ActionID string
	// Reason は抑止された場合にその理由。実行された場合は空。
	Reason string
}

// CommandSender delivers the command to the endpoint.
// store.CommandStore がこれを満たす。
type CommandSender interface {
	IsolateEndpoint(ctx context.Context, agentID, reason, alertID, commandID string) error
	UnisolateEndpoint(ctx context.Context, agentID, reason, commandID string) error
}

// ActionRecorder persists the audit row. store.ResponseActionStore がこれを満たす。
type ActionRecorder interface {
	Record(ctx context.Context, agentID, actionType, status, triggeredBy string, details interface{}) (string, error)
	Complete(ctx context.Context, id, status, errMsg string) error
}

// response_actions.status_text の語彙。migration 382 と 431 の CHECK 制約と対応する。
//
// store の定数を参照しないのは import の向きを一方向に保つため（store は
// isolation を知らないし、知る必要も無い）。値がずれると chokepoint_test が落ちる。
const (
	statusPending    = "pending"
	statusDispatched = "dispatched"
	statusFailure    = "failure"
	statusSuppressed = "suppressed"
)

// ErrNoAgent is returned when a request carries no agent id.
var ErrNoAgent = errors.New("isolation: agent id is required")

// Gatekeeper is the only thing allowed to isolate an endpoint.
type Gatekeeper struct {
	commands CommandSender
	actions  ActionRecorder // nil 可。記録できないだけで隔離自体は行う。
	guard    *guard

	// unattendedEnabled mirrors AUTO_RESPONSE_ENABLED. 手動隔離には効かない。
	unattendedEnabled bool

	// exempt mirrors AUTO_ISOLATE_EXEMPT. 手動隔離には効かない。
	exempt []string
	// hostnameFor resolves agentID → hostname. nil 可。
	hostnameFor func(ctx context.Context, agentID string) string
}

// Config configures a Gatekeeper.
type Config struct {
	// UnattendedEnabled は AUTO_RESPONSE_ENABLED。false なら無人経路の隔離を全て止める。
	UnattendedEnabled bool
	// Cooldown は同じ端末を再隔離するまでの最短間隔。0 で既定値。
	Cooldown time.Duration
	// HourlyBudget は 1 時間あたりに隔離を許す台数。0 で既定値。
	HourlyBudget int
	// DryRun が true なら無人経路は記録だけして隔離しない。
	DryRun bool
	// Exempt は AUTO_ISOLATE_EXEMPT。ホスト名またはエージェント ID を並べる。
	// ここに載った端末は無人経路の対象から外れる（手動隔離は従来どおり通す）。
	//
	// これが要るのは、隔離が外から取り消せないため。エージェントは EDR サーバ以外を
	// 全て遮断するので、隔離はその端末への SSH/RDP も切る。プラットフォーム自身が
	// 動いているホスト——検証機・単一ノード構成・踏み台——では、自動隔離は障害と
	// 締め出しを同時に起こし、復旧には存在するとは限らない帯域外接続（SSM・シリアル
	// コンソール）が要る。
	//
	// 抑制ルールでは代用できない。あちらはアラート自体を落とすため、除外の代わりに
	// 使うとその端末の検知が盲になる。しかも SeverityMax は severity <= N に一致する
	// 条件で、隔離が起きる高 severity 帯とは逆を向いている。この一覧が止めるのは
	// 応答だけで、検知・アラート・スコアリングには手を触れない。
	//
	// 一致はエージェント ID が完全一致、ホスト名が大文字小文字を無視した完全一致。
	//
	// 除外は Cooldown / HourlyBudget より前に見る（Isolate 参照）。安全弁は隔離の
	// 総量を抑えるものだが、これは特定の端末を対象から外すもので、総量に余裕が
	// あっても覆らない。
	Exempt []string
	// HostnameResolver は agentID からホスト名を引く。Exempt をホスト名で
	// 指定できるようにするために要る。nil なら Request.Hostname だけを見る。
	//
	// 呼び出し側にホスト名の記入を任せると、記入し忘れた経路だけ除外が効かなく
	// なる——それは「安全弁があるつもりで無い」という、この変更が塞いでいる形
	// そのものになる。だから解決手段を Gatekeeper 側に持たせる。
	HostnameResolver func(ctx context.Context, agentID string) string
}

// IsExempt reports whether the endpoint is on the exemption list.
//
// 判定の持ち主は Gatekeeper だけである。以前は detection.Engine 側にも同じ検査が
// あり、そちらが先に return するため、除外された端末の隔離判断が response_actions に
// 一切残らなかった。安全弁を二重に持つのは良いが、片方だけが記録を残す二重化は、
// 「除外で止まったのか、応答経路が壊れているのか」を区別できなくする。
func IsExempt(list []string, hostname, agentID string) bool {
	for _, ex := range list {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		if ex == agentID || (hostname != "" && strings.EqualFold(ex, hostname)) {
			return true
		}
	}
	return false
}

// New builds a Gatekeeper. commands が nil の場合は隔離を実行できないので、
// 全ての要求が OutcomeDisabled になる（黙って握り潰すよりは記録が残る）。
func New(commands CommandSender, actions ActionRecorder, cfg Config) *Gatekeeper {
	return &Gatekeeper{
		commands:          commands,
		actions:           actions,
		guard:             newGuard(cfg.Cooldown, cfg.HourlyBudget, cfg.DryRun),
		unattendedEnabled: cfg.UnattendedEnabled,
		exempt:            cfg.Exempt,
		hostnameFor:       cfg.HostnameResolver,
	}
}

// DryRun reports whether unattended isolation is in dry-run mode.
func (g *Gatekeeper) DryRun() bool { return g != nil && g.guard.isDryRun() }

// Isolate takes the endpoint off the network, subject to the safety valves.
//
// 返り値の error は「隔離できなかった」ではなく「記録も送出もできなかった」を意味する。
// 安全弁による抑止は error ではなく Result.Outcome で表す。抑止は異常ではないため。
func (g *Gatekeeper) Isolate(ctx context.Context, req Request) (Result, error) {
	if g == nil {
		return Result{Outcome: OutcomeDisabled, Reason: "隔離経路が構成されていません"}, nil
	}
	if req.AgentID == "" {
		return Result{}, ErrNoAgent
	}
	if req.Origin == "" {
		req.Origin = OriginRemediation // 呼び出し側の記入漏れを無人扱いに倒す
	}
	if req.Reason == "" {
		req.Reason = string(req.Origin)
	}

	if req.Origin.Unattended() {
		if !g.unattendedEnabled {
			return g.suppress(ctx, req, OutcomeDisabled,
				"AUTO_RESPONSE_ENABLED=false のため無人隔離は行いません"), nil
		}
		// 除外は安全弁より前に見る。冷却期間や時間あたり上限は「今は駄目」だが、
		// 除外は「この端末は対象にしない」であって、枠が空いていても覆らない。
		//
		// 黙って落とさず WARN で出す。除外を設定した運用者にとっても
		// 「隔離される状況だった」は知る必要のある事実で、静かなスキップは
		// 応答経路が壊れているのと外形が同じになる。
		if len(g.exempt) > 0 {
			host := req.Hostname
			if host == "" && g.hostnameFor != nil {
				host = g.hostnameFor(ctx, req.AgentID)
			}
			if IsExempt(g.exempt, host, req.AgentID) {
				slog.Warn("自動隔離を除外設定によりスキップしました（検知とアラートは通常どおり）",
					"agent", req.AgentID, "hostname", host,
					"rule", req.Label, "経路", string(req.Origin))
				return g.suppress(ctx, req, OutcomeExempt,
					"AUTO_ISOLATE_EXEMPT に含まれるため隔離しません"), nil
			}
		}
		if v := g.guard.allow(req.AgentID); !v.allow {
			g.guard.logRefusal(req.AgentID, req.Label, req.Origin, v.reason)
			return g.suppress(ctx, req, OutcomeRefused, v.reason), nil
		}
		if g.guard.isDryRun() {
			slog.Warn("自動隔離（ドライラン）: 実際には隔離していません",
				"agent", req.AgentID, "rule", req.Label, "経路", string(req.Origin))
			return g.suppress(ctx, req, OutcomeDryRun,
				"AUTO_ISOLATE_DRY_RUN=true のため記録のみ"), nil
		}
	}

	if g.commands == nil {
		return g.suppress(ctx, req, OutcomeDisabled, "コマンド送出先が構成されていません"), nil
	}

	// 送る前に記録する。ここで採番した id をコマンドに載せることで、エージェントが
	// 返す ack をこの行に対応付けられる。順序が逆だと、送った直後に返ってきた ack を
	// 受け止める先が存在しない。
	actionID := g.record(ctx, req, "isolate", statusPending, nil)

	if err := g.commands.IsolateEndpoint(ctx, req.AgentID, req.Reason, req.AlertID, actionID); err != nil {
		slog.Error("隔離コマンドの送信に失敗しました",
			"agent", req.AgentID, "経路", string(req.Origin), "error", err)
		g.complete(ctx, actionID, statusFailure, err.Error())
		return Result{Outcome: OutcomeDisabled, ActionID: actionID, Reason: err.Error()},
			fmt.Errorf("isolation: dispatch to %s: %w", req.AgentID, err)
	}

	g.complete(ctx, actionID, statusDispatched, "")
	slog.Info("エンドポイントを隔離しました（送出）",
		"agent", req.AgentID, "経路", string(req.Origin), "rule", req.Label)
	return Result{Outcome: OutcomeDispatched, ActionID: actionID}, nil
}

// Unisolate puts the endpoint back on the network.
//
// 解除に安全弁は無い。誤って隔離した端末を戻せないことのほうが危険なため。
func (g *Gatekeeper) Unisolate(ctx context.Context, req Request) (Result, error) {
	if g == nil {
		return Result{Outcome: OutcomeDisabled, Reason: "隔離経路が構成されていません"}, nil
	}
	if req.AgentID == "" {
		return Result{}, ErrNoAgent
	}
	if req.Origin == "" {
		req.Origin = OriginManual
	}
	if req.Reason == "" {
		req.Reason = "隔離解除"
	}
	if g.commands == nil {
		return g.suppress(ctx, req, OutcomeDisabled, "コマンド送出先が構成されていません"), nil
	}

	actionID := g.record(ctx, req, "unisolate", statusPending, nil)

	if err := g.commands.UnisolateEndpoint(ctx, req.AgentID, req.Reason, actionID); err != nil {
		slog.Error("隔離解除コマンドの送信に失敗しました",
			"agent", req.AgentID, "経路", string(req.Origin), "error", err)
		g.complete(ctx, actionID, statusFailure, err.Error())
		return Result{Outcome: OutcomeDisabled, ActionID: actionID, Reason: err.Error()},
			fmt.Errorf("isolation: unisolate dispatch to %s: %w", req.AgentID, err)
	}

	g.complete(ctx, actionID, statusDispatched, "")
	return Result{Outcome: OutcomeDispatched, ActionID: actionID}, nil
}

// suppress records an isolation that was decided but not carried out.
//
// 抑止をログだけにしないのは、「何が止まるはずだったか」を数えるのが
// 段階的有効化の唯一の材料だから。ログの grep では件数を集計できない。
func (g *Gatekeeper) suppress(ctx context.Context, req Request, outcome Outcome, reason string) Result {
	id := g.record(ctx, req, "isolate", statusSuppressed, map[string]string{
		"outcome": string(outcome),
		"reason":  reason,
		"origin":  string(req.Origin),
		"label":   req.Label,
	})
	return Result{Outcome: outcome, ActionID: id, Reason: reason}
}

func (g *Gatekeeper) record(ctx context.Context, req Request, actionType, status string, extra map[string]string) string {
	if g.actions == nil {
		return ""
	}
	details := map[string]string{
		"reason": req.Reason,
		"origin": string(req.Origin),
	}
	if req.AlertID != "" {
		details["alert_id"] = req.AlertID
	}
	if req.Label != "" {
		details["label"] = req.Label
	}
	for k, v := range extra {
		details[k] = v
	}
	by := req.TriggeredBy
	if by == "" {
		by = string(req.Origin)
	}
	id, err := g.actions.Record(ctx, req.AgentID, actionType, status, by, details)
	if err != nil {
		// 記録に失敗しても隔離は続ける。記録できないことより、止めるべき端末を
		// 止めないことのほうが危険。ただし黙らない。
		slog.Error("対応アクションの記録に失敗しました",
			"agent", req.AgentID, "action", actionType, "error", err)
		return ""
	}
	return id
}

func (g *Gatekeeper) complete(ctx context.Context, actionID, status, errMsg string) {
	if g.actions == nil || actionID == "" {
		return
	}
	if err := g.actions.Complete(ctx, actionID, status, errMsg); err != nil {
		slog.Error("対応アクションの更新に失敗しました",
			"action_id", actionID, "status", status, "error", err)
	}
}
