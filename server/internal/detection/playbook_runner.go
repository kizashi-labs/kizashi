package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
)

// PlaybookRunner executes automated response playbooks triggered by alerts.
type PlaybookRunner struct {
	playbooks *store.PlaybookStore
	incidents *store.IncidentStore
	alerts    *store.AlertStore
	isolator  Isolator
	notifier  PlaybookNotifier
}

// errIsolationNotExecuted marks an isolation the Gatekeeper decided not to carry
// out — kill switch, cooldown, hourly cap or dry-run.
//
// **失敗とは別物である。** 何も壊れておらず、何も行われていない。実行ログに
// 「実行済み」として並べると、事後にそのホストは隔離されたと読まれる。
var errIsolationNotExecuted = errors.New("隔離は実行されませんでした")

// PlaybookNotifier sends a text notification (implemented by notification.Dispatcher).
type PlaybookNotifier interface {
	NotifyText(ctx context.Context, message string, severity int) error
}

// NewPlaybookRunner builds a runner.
//
// AUTO_RESPONSE_ENABLED はここでは受け取らない。無人対応のキルスイッチは
// Gatekeeper が一箇所で見る。notify / create_incident / assign_alert は業務を
// 止めないので、隔離を切っても動き続ける（切ったときに運用者の手元の情報が
// 減るのは逆効果）。その線引きも Gatekeeper 側に寄せた結果、この経路は
// 「隔離を頼む」だけになる。
func NewPlaybookRunner(
	playbooks *store.PlaybookStore,
	incidents *store.IncidentStore,
	alerts *store.AlertStore,
	isolator Isolator,
	notifier PlaybookNotifier,
) *PlaybookRunner {
	return &PlaybookRunner{
		playbooks: playbooks,
		incidents: incidents,
		alerts:    alerts,
		isolator:  isolator,
		notifier:  notifier,
	}
}

// Run checks active playbooks against the given alert and executes matching ones.
func (r *PlaybookRunner) Run(ctx context.Context, alert *StoredAlert) {
	if r == nil || r.playbooks == nil {
		return
	}

	matched, err := r.playbooks.ListActiveForAlert(
		ctx,
		alert.Severity,
		alert.RuleName,
		alert.Hostname,
		alert.MITRETech,
		alert.Status,
	)
	if err != nil {
		metrics.BackgroundFailed("playbook_runner", err, "プレイブックの取得に失敗しました")
		return
	}

	for _, pb := range matched {
		go r.execute(ctx, pb, alert)
	}
}

// execute runs all actions of a single playbook for an alert.
func (r *PlaybookRunner) execute(ctx context.Context, pb *store.Playbook, alert *StoredAlert) {
	run := &store.PlaybookRun{
		PlaybookID: pb.ID,
		AlertID:    alert.ID,
		Success:    true,
	}

	r.runActions(ctx, pb, alert, run)

	if err := r.playbooks.RecordRun(ctx, run); err != nil {
		slog.Warn("プレイブック実行ログの記録に失敗しました", "error", err)
	}
}

// runActions runs every action of a playbook and fills in what the run record
// should say about it.
//
// ActionsRun は「実行したアクション」です。以前は成功でも失敗でも追記して
// いたため、隔離に失敗したプレイブックの実行ログにも isolate_endpoint が
// 「実行済み」として並んでいました。ErrorMsg も最後のエラーで上書きされて
// いたので、3件失敗しても記録に残るのは3件目だけです。実行ログは
// 「あのとき自動で何が起きたか」を後から確かめる唯一の記録なので、
// そこが実際より良く見えるのは、記録が無いより悪い状態です。
func (r *PlaybookRunner) runActions(
	ctx context.Context,
	pb *store.Playbook,
	alert *StoredAlert,
	run *store.PlaybookRun,
) {
	var failures []string
	for _, action := range pb.Actions {
		if err := r.runAction(ctx, action, alert); err != nil {
			// 安全弁が止めた分は、失敗でも実行済みでもない。
			// nil を返すと実行ログに「実行済み」として並び、事後には
			// そのホストが隔離されたと読まれる —— 切ったのは運用者なので
			// 失敗として数えるのも誤りで、どちらにも入れない。
			if errors.Is(err, errIsolationNotExecuted) {
				slog.Warn("プレイブックの自動隔離は実行されなかったため記録しません",
					"playbook", pb.ID, "alert", alert.ID, "agent", alert.AgentID, "error", err)
				continue
			}
			slog.Error("プレイブックアクション失敗",
				"playbook", pb.ID,
				"action", action.Type,
				"alert", alert.ID,
				"error", err,
			)
			failures = append(failures, fmt.Sprintf("%s: %v", action.Type, err))
			run.Success = false
			continue
		}
		slog.Info("プレイブックアクション実行",
			"playbook", pb.ID,
			"action", action.Type,
			"alert", alert.ID,
		)
		run.ActionsRun = append(run.ActionsRun, action)
	}
	if len(failures) > 0 {
		run.ErrorMsg = strings.Join(failures, "; ")
	}
}

// runAction dispatches a single playbook action.
func (r *PlaybookRunner) runAction(ctx context.Context, action store.PlaybookAction, alert *StoredAlert) error {
	switch action.Type {
	case "isolate_endpoint":
		// AUTO_RESPONSE_ENABLED も安全弁も response_actions への記録も、判断は
		// すべて Gatekeeper 側にある。この経路は以前 autoResponse だけを見ていて
		// 冷却期間・時間あたり上限・ドライランをどれも通らなかった。経路ごとに
		// 規則が違う状態こそが、隔離が実態と食い違う原因だった。
		if r.isolator == nil {
			return fmt.Errorf("isolation gatekeeper not configured")
		}
		reason := fmt.Sprintf("プレイブック自動隔離: アラート %s (重大度: %d)", alert.Title, alert.Severity)
		// Hostname を載せるのは AUTO_ISOLATE_EXEMPT がホスト名でも書けるため（上記と同じ）。
		res, err := r.isolator.Isolate(ctx, isolation.Request{
			AgentID:  alert.AgentID,
			Hostname: alert.Hostname,
			Reason:   reason,
			AlertID:  alert.ID,
			Origin:   isolation.OriginPlaybook,
			Label:    alert.Title,
		})
		if err != nil {
			return err
		}
		if !res.Outcome.Executed() {
			// **nil を返さない。** nil だと runActions が isolate_endpoint を
			// 実行ログに「実行済み」として並べ、事後にはそのホストが
			// ネットワークから切られたと読まれる。止めたのは安全弁なので
			// 失敗として数えるのも誤りで、どちらにも入れない
			// (runActions が errIsolationNotExecuted を見て飛ばす)。
			slog.Warn("プレイブックの自動隔離は実行されませんでした",
				"alert", alert.ID, "agent", alert.AgentID,
				"結果", string(res.Outcome), "理由", res.Reason)
			return fmt.Errorf("%w: %s", errIsolationNotExecuted, res.Outcome)
		}
		return nil

	case "create_incident":
		if r.incidents == nil {
			return fmt.Errorf("incident store not configured")
		}
		title := action.Title
		if title == "" {
			title = fmt.Sprintf("自動: %s", alert.Title)
		}
		severity := action.Severity
		if severity == 0 {
			severity = alert.Severity
		}
		inc := &store.Incident{
			Title:       title,
			Description: fmt.Sprintf("プレイブックにより自動作成。アラートID: %s", alert.ID),
			Severity:    severity,
			Status:      "open",
		}
		id, err := r.incidents.Insert(ctx, inc)
		if err != nil {
			return err
		}
		// Link the triggering alert
		return r.incidents.LinkAlert(ctx, id, alert.ID)

	case "notify":
		// 以前はここで nil を返していました。通知の口が無いのに
		// 「通知した」という実行ログが残ります。他のアクションと同じく
		// 設定漏れとして報告します。
		if r.notifier == nil {
			return fmt.Errorf("notifier not configured")
		}
		msg := action.Message
		if msg == "" {
			msg = fmt.Sprintf("[自動通知] %s — 重大度: %d / ホスト: %s", alert.Title, alert.Severity, alert.Hostname)
		}
		return r.notifier.NotifyText(ctx, msg, alert.Severity)

	case "assign_alert":
		// これはログを1行出して nil を返すだけでした。コンソールでは
		// 「アラートを割り当て」として選択でき、実行ログには成功として残り、
		// 誰にも割り当てられません。担当者がついたと思われたアラートが
		// 誰の手にも渡らないのが実害なので、実際に割り当てます。
		if r.alerts == nil {
			return fmt.Errorf("alert store not configured")
		}
		if action.UserID == "" {
			return fmt.Errorf("assign_alert に user_id が指定されていません")
		}
		userID := action.UserID
		return r.alerts.UpdateAlert(ctx, alert.ID, nil, nil, &userID)

	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}
}
