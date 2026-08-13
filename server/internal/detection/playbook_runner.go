package detection

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/edr-platform/server/internal/store"
)

// PlaybookRunner executes automated response playbooks triggered by alerts.
type PlaybookRunner struct {
	playbooks *store.PlaybookStore
	incidents *store.IncidentStore
	commander AgentCommander
	notifier  PlaybookNotifier
	// autoResponse mirrors AUTO_RESPONSE_ENABLED. Only the endpoint-isolating
	// action consults it; notify / create_incident / assign_alert are not
	// business-stopping and must keep working when unattended response is off —
	// switching off isolation should make an operator MORE informed, not less.
	autoResponse bool
}

// PlaybookNotifier sends a text notification (implemented by notification.Dispatcher).
type PlaybookNotifier interface {
	NotifyText(ctx context.Context, message string, severity int) error
}

func NewPlaybookRunner(
	playbooks *store.PlaybookStore,
	incidents *store.IncidentStore,
	commander AgentCommander,
	notifier PlaybookNotifier,
	autoResponse bool,
) *PlaybookRunner {
	return &PlaybookRunner{
		playbooks:    playbooks,
		incidents:    incidents,
		commander:    commander,
		notifier:     notifier,
		autoResponse: autoResponse,
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
		slog.Warn("プレイブックの取得に失敗しました", "error", err)
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

	var executedActions []store.PlaybookAction
	var lastErr error

	for _, action := range pb.Actions {
		if err := r.runAction(ctx, action, alert); err != nil {
			slog.Error("プレイブックアクション失敗",
				"playbook", pb.ID,
				"action", action.Type,
				"alert", alert.ID,
				"error", err,
			)
			lastErr = err
			run.Success = false
		} else {
			slog.Info("プレイブックアクション実行",
				"playbook", pb.ID,
				"action", action.Type,
				"alert", alert.ID,
			)
		}
		executedActions = append(executedActions, action)
	}

	run.ActionsRun = executedActions
	if lastErr != nil {
		run.ErrorMsg = lastErr.Error()
	}

	if err := r.playbooks.RecordRun(ctx, run); err != nil {
		slog.Warn("プレイブック実行ログの記録に失敗しました", "error", err)
	}
}

// runAction dispatches a single playbook action.
func (r *PlaybookRunner) runAction(ctx context.Context, action store.PlaybookAction, alert *StoredAlert) error {
	switch action.Type {
	case "isolate_endpoint":
		// AUTO_RESPONSE_ENABLED is the operator's kill switch for unattended
		// response, and it has to mean ALL of it. The Engine's rule-based path
		// (applyRuleBasedResponse) and the AI triage path both honoured it, but this
		// one did not — so a playbook carrying an isolate_endpoint action would keep
		// taking endpoints off the network after an operator believed they had
		// disabled auto-isolation. That is exactly how the switch was used during
		// issue #669 (Amazon Inspector false positives isolating hosts).
		if !r.autoResponse {
			slog.Warn("プレイブックの自動隔離は AUTO_RESPONSE_ENABLED=false のためスキップしました",
				"alert", alert.ID, "agent", alert.AgentID)
			return nil
		}
		if r.commander == nil {
			return fmt.Errorf("commander not configured")
		}
		reason := fmt.Sprintf("プレイブック自動隔離: アラート %s (重大度: %d)", alert.Title, alert.Severity)
		return r.commander.IsolateEndpoint(ctx, alert.AgentID, reason, alert.ID, "")

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
		if r.notifier == nil {
			return nil // skip silently if notifier is not configured
		}
		msg := action.Message
		if msg == "" {
			msg = fmt.Sprintf("[自動通知] %s — 重大度: %d / ホスト: %s", alert.Title, alert.Severity, alert.Hostname)
		}
		return r.notifier.NotifyText(ctx, msg, alert.Severity)

	case "assign_alert":
		// assign_alert is best-effort: the API server will do the actual assignment
		// We publish to NATS so the API can pick it up if needed.
		// For now we just log it — a full implementation would update via store.
		slog.Info("プレイブック assign_alert (スキップ: API経由での割り当てが必要)", "alert", alert.ID)
		return nil

	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}
}
