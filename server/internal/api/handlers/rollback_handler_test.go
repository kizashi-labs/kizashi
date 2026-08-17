package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/rollback"
)

type fakePlanner struct {
	plan       rollback.RollbackPlan
	reverted   []string
	markRevErr error
	planErr    error
}

func (f *fakePlanner) Plan(_ context.Context, _ string) (rollback.RollbackPlan, error) {
	return f.plan, f.planErr
}
func (f *fakePlanner) MarkReverted(_ context.Context, _ string, paths []string) (int, error) {
	if f.markRevErr != nil {
		return 0, f.markRevErr
	}
	f.reverted = paths
	return len(paths), nil
}

type fakeCmd struct{ restored, deleted []string }

func (f *fakeCmd) RestoreFile(_ context.Context, _, _, path, _ string) error {
	f.restored = append(f.restored, path)
	return nil
}
func (f *fakeCmd) DeleteFile(_ context.Context, _, path, _, _ string) error {
	f.deleted = append(f.deleted, path)
	return nil
}

func newTestHandler(p *fakePlanner, cmd rollback.Commander) *RollbackHandler {
	return &RollbackHandler{svc: p, cmd: cmd}
}

func doReq(h func(*gin.Context), method, url, body, param string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	c.Request = r
	c.Params = gin.Params{{Key: "id", Value: param}}
	h(c)
	return w
}

func TestRollbackHandler_Preview(t *testing.T) {
	p := &fakePlanner{plan: rollback.RollbackPlan{Ops: []rollback.RollbackOp{
		{Path: "/a", Action: rollback.ActionRestore, BackupRef: "bk"},
		{Path: "/b", Action: rollback.ActionRestore, NeedsManual: true},
	}}}
	w := doReq(newTestHandler(p, &fakeCmd{}).Preview, http.MethodGet, "/x", "", "inc-1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		NeedsManual int `json:"needs_manual"`
		Ops         []rollback.RollbackOp
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.NeedsManual != 1 || len(resp.Ops) != 2 {
		t.Fatalf("preview body unexpected: %s", w.Body.String())
	}
}

func TestRollbackHandler_Execute_DispatchesAndMarks(t *testing.T) {
	p := &fakePlanner{plan: rollback.RollbackPlan{Ops: []rollback.RollbackOp{
		{Path: "/a", Action: rollback.ActionRestore, BackupRef: "bk"},
		{Path: "/tmp/x", Action: rollback.ActionDelete},
		{Path: "/manual", Action: rollback.ActionRestore, NeedsManual: true},
	}}}
	cmd := &fakeCmd{}
	w := doReq(newTestHandler(p, cmd).Execute, http.MethodPost, "/x", `{"agent_id":"a1"}`, "inc-1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if len(cmd.restored) != 1 || len(cmd.deleted) != 1 {
		t.Fatalf("dispatch: restored=%v deleted=%v", cmd.restored, cmd.deleted)
	}
	// Only the two dispatched (non-manual) paths are marked reverted.
	if len(p.reverted) != 2 {
		t.Fatalf("reverted should be 2 (manual skipped), got %v", p.reverted)
	}
}

func TestRollbackHandler_Execute_RequiresAgentID(t *testing.T) {
	p := &fakePlanner{}
	w := doReq(newTestHandler(p, &fakeCmd{}).Execute, http.MethodPost, "/x", `{}`, "inc-1")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing agent_id should be 400, got %d", w.Code)
	}
}
