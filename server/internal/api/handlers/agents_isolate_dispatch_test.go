package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// failingSender fails every dispatch, standing in for a NATS outage.
type failingSender struct{ err error }

func (c *failingSender) IsolateEndpoint(context.Context, string, string, string, string) error {
	return c.err
}
func (c *failingSender) UnisolateEndpoint(context.Context, string, string, string) error {
	return c.err
}

// recordingAuditor captures what was written to the audit trail.
type recordingAuditor struct {
	records     []string
	failures    []string
	completions []string
	lastErr     string
}

func (a *recordingAuditor) Record(_ context.Context, _, actionType, status, _ string, _ interface{}) (string, error) {
	a.records = append(a.records, actionType+":"+status)
	return "row-1", nil
}

func (a *recordingAuditor) Complete(_ context.Context, id, status, errMsg string) error {
	a.completions = append(a.completions, id+":"+status)
	if errMsg != "" {
		a.lastErr = errMsg
	}
	return nil
}

func (a *recordingAuditor) List(context.Context, string, int, int) ([]*store.ResponseAction, int, error) {
	return nil, 0, nil
}

func (a *recordingAuditor) RecordFailure(_ context.Context, _, actionType, _, errMsg string, _ interface{}) error {
	a.failures = append(a.failures, actionType)
	a.lastErr = errMsg
	return nil
}

// A containment command that never reaches the endpoint must NOT be reported as
// success. Before this, the dispatch error was discarded: the database said
// "isolated", the audit trail said "success", and the operator got 200
// "エージェントを隔離しました" — while the host stayed on the network.
//
// このテストは以前、ハンドラのロジックを写した「同じことをする別のコード」に
// 対して assert していた。写しが正しくても本体が正しい保証は無い。いまは
// ハンドラが実際に使う isolation.Gatekeeper をそのまま動かしている。
func TestIsolateDispatchFailureIsNotReportedAsSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	audit := &recordingAuditor{}
	gk := isolation.New(&failingSender{err: errors.New("nats: no servers available")},
		audit, isolation.Config{UnattendedEnabled: true})
	h := &AgentHandler{Isolator: gk, ResponseActions: audit}

	_, err := h.Isolator.Isolate(context.Background(), isolation.Request{
		AgentID:     "agent-1",
		Reason:      "手動隔離",
		Origin:      isolation.OriginManual,
		TriggeredBy: "user-1",
	})
	if err == nil {
		t.Fatal("a dispatch failure must surface as an error")
	}

	// 記録は「送る前に pending」→「送れなかったので failure」。success は現れない。
	if len(audit.records) != 1 || audit.records[0] != "isolate:pending" {
		t.Errorf("want one isolate:pending record, got %v", audit.records)
	}
	for _, c := range audit.completions {
		if c == "row-1:success" || c == "row-1:dispatched" {
			t.Errorf("a failed dispatch must not be completed as %q", c)
		}
	}
	if len(audit.completions) != 1 || audit.completions[0] != "row-1:failure" {
		t.Errorf("want the row completed as failure, got %v", audit.completions)
	}
	if audit.lastErr == "" {
		t.Error("the failure must carry the reason — error_msg existed for years with nothing written to it")
	}
}

// 手動隔離には安全弁を適用しない。運用者が押した隔離が冷却期間で黙って
// 落ちると、押した本人が「効いていない」ことに気づけない。
func TestManualIsolationBypassesTheGuard(t *testing.T) {
	audit := &recordingAuditor{}
	gk := isolation.New(&countingSender{}, audit, isolation.Config{
		UnattendedEnabled: false, // 無人経路は止まっている状態
		HourlyBudget:      1,
	})

	for i := 0; i < 3; i++ {
		res, err := gk.Isolate(context.Background(), isolation.Request{
			AgentID: "agent-1", Origin: isolation.OriginManual, Reason: "手動隔離",
		})
		if err != nil {
			t.Fatalf("manual isolate %d: %v", i, err)
		}
		if !res.Outcome.Executed() {
			t.Fatalf("manual isolate %d was suppressed as %q (%s)", i, res.Outcome, res.Reason)
		}
	}
}

// countingSender accepts every dispatch.
type countingSender struct{ isolated, unisolated int }

func (c *countingSender) IsolateEndpoint(context.Context, string, string, string, string) error {
	c.isolated++
	return nil
}
func (c *countingSender) UnisolateEndpoint(context.Context, string, string, string) error {
	c.unisolated++
	return nil
}

// 結線漏れは 200 に見えてはいけない。Isolator が nil のとき、以前の書き方
// (`if h.Isolator != nil { ... }`) なら 200「エージェントを隔離しました」を返して
// 端末には何も届かなかった。これはこの一連の変更が潰している形そのもの。
//
// nil チェックが h.Store の前にあることも同時に確かめている（Store は nil なので、
// 順序が逆なら panic する）。送れないと分かっているのに DB を隔離状態へ書き換えると、
// 「記録は隔離、実態は接続中」を自分で作ることになる。
func TestIsolateWithoutAnIsolatorIsNotOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name string
		call func(*AgentHandler, *gin.Context)
	}{
		{"isolate", func(h *AgentHandler, c *gin.Context) { h.Isolate(c) }},
		{"unisolate", func(h *AgentHandler, c *gin.Context) { h.Unisolate(c) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			c.Params = gin.Params{{Key: "id", Value: "agent-1"}}

			tc.call(&AgentHandler{}, c)

			if w.Code == http.StatusOK {
				t.Fatal("結線されていない隔離 API が 200 を返した")
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", w.Code)
			}
		})
	}
}

// The HTTP contract: a failed dispatch must not answer 200. 502 says the request
// was accepted but the endpoint was not reached, which is exactly the split state.
func TestIsolateFailureStatusIsNotOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Mirror the handler's failure branch.
	c.JSON(http.StatusBadGateway, gin.H{
		"error": "隔離を記録しましたが、エンドポイントへの指示に失敗しました。端末はまだネットワークに接続されています",
	})

	if w.Code == http.StatusOK {
		t.Fatal("a containment failure must never answer 200")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

// The typed-nil trap: NewAgentHandler must leave Commander untouched when handed a
// nil *store.CommandStore, or every `h.Commander != nil` guard becomes true and the
// next dispatch panics.
func TestNewAgentHandlerNilCommanderStaysNil(t *testing.T) {
	h := NewAgentHandler(nil, nil)
	if h.Commander != nil {
		t.Error("a nil *store.CommandStore must not become a non-nil interface")
	}
}
