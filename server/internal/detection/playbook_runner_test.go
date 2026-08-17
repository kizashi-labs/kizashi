package detection

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// recordingCommander (auto_isolate_reachability_test.go) captures isolation requests
// instead of talking to an agent.

// AUTO_RESPONSE_ENABLED is the operator's kill switch for unattended response. The
// Engine's rule-based path and the AI triage path both honoured it; this one did
// not, so a playbook with an isolate_endpoint action kept taking endpoints off the
// network after an operator believed auto-isolation was disabled.
func TestPlaybookRunner_IsolateHonoursAutoResponseSwitch(t *testing.T) {
	action := store.PlaybookAction{Type: "isolate_endpoint"}
	alert := &StoredAlert{ID: "alert-1", AgentID: "agent-1", Title: "t", Severity: 10}

	off := &recordingCommander{}
	r := NewPlaybookRunner(nil, nil, off, nil, false)
	if err := r.runAction(context.Background(), action, alert); err != nil {
		t.Fatalf("skipping isolation must not be an error, got %v", err)
	}
	if len(off.isolated) != 0 {
		t.Errorf("AUTO_RESPONSE_ENABLED=false must suppress playbook isolation, isolated %v", off.isolated)
	}

	on := &recordingCommander{}
	r = NewPlaybookRunner(nil, nil, on, nil, true)
	if err := r.runAction(context.Background(), action, alert); err != nil {
		t.Fatalf("runAction: %v", err)
	}
	if len(on.isolated) != 1 || on.isolated[0] != "agent-1" {
		t.Errorf("AUTO_RESPONSE_ENABLED=true must still isolate, got %v", on.isolated)
	}
}

// recordingNotifier captures playbook notifications instead of dispatching them.
type recordingNotifier struct{ messages []string }

func (n *recordingNotifier) NotifyText(_ context.Context, message string, _ int) error {
	n.messages = append(n.messages, message)
	return nil
}

// Turning off unattended response must make an operator MORE informed, not less:
// the non-destructive actions keep running.
func TestPlaybookRunner_NotifyStillRunsWithAutoResponseOff(t *testing.T) {
	notifier := &recordingNotifier{}
	r := NewPlaybookRunner(nil, nil, nil, notifier, false)
	alert := &StoredAlert{ID: "alert-1", AgentID: "agent-1", Title: "t", Severity: 10}

	if err := r.runAction(context.Background(), store.PlaybookAction{Type: "notify"}, alert); err != nil {
		t.Fatalf("runAction: %v", err)
	}
	if len(notifier.messages) != 1 {
		t.Errorf("AUTO_RESPONSE_ENABLED=false must not suppress notifications, got %d", len(notifier.messages))
	}
}
