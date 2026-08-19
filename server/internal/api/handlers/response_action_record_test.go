package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// 対応操作（隔離・スキャン・プロセス停止…）を記録できなかったときに、
// それが部品ごとの件数に出ることを直接確かめます。
//
// **なぜ直接呼ぶのか。** 記録は応答を返す前の副作用で、通る木では
// 失敗しません。`err != nil` の枝は一度も通らないので、
// **`err != nil` を `err == nil` に反転する変異が生き残ります** ——
// 反転すると「記録できたときに失敗を報告し、できなかったときは黙る」に
// なりますが、書き込みが常に成功する検査からは同じに見えます。
//
// 落ちたときに何が起きるか: 応答は「隔離しました」のまま返り、
// **インシデントの時系列からその操作だけが消えます。** 事後の調査は
// 「誰も隔離していないのに端末が切れている」という形で始まります。

func handlerCounterValue(m prometheus.Metric) float64 {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return -1
	}
	return out.GetCounter().GetValue()
}

// stubResponseActions records what it was asked to write, and fails on demand.
type stubResponseActions struct {
	err   error
	calls int
	last  struct {
		agentID, action, status, by string
	}
}

func (s *stubResponseActions) Record(_ context.Context, agentID, actionType, status, triggeredBy string, _ interface{}) (string, error) {
	s.calls++
	s.last.agentID = agentID
	s.last.action = actionType
	s.last.status = status
	s.last.by = triggeredBy
	if s.err != nil {
		return "", s.err
	}
	return "ra-1", nil
}

// Complete / RecordFailure are part of responseAuditor but are not what this
// file is about: it covers the record-write failing (#690 の記録側)。終了状態の
// 更新はここでは起こらないので、呼ばれたことだけ数える。
func (s *stubResponseActions) Complete(context.Context, string, string, string) error {
	return nil
}

func (s *stubResponseActions) RecordFailure(context.Context, string, string, string, string, interface{}) error {
	return nil
}

func (s *stubResponseActions) List(context.Context, string, int, int) ([]*store.ResponseAction, int, error) {
	return nil, 0, nil
}

func testGinContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/a-1/isolate", nil)
	return c
}

func TestAFailedResponseActionRecordIsReported(t *testing.T) {
	const component = "response_action_record"

	cases := []struct {
		name      string
		store     *stubResponseActions
		wantMoved float64
	}{
		{
			name:      "記録できなかったら件数が動く",
			store:     &stubResponseActions{err: errors.New("書き込みを拒否されました")},
			wantMoved: 1,
		},
		{
			name:      "記録できたら件数は動かない",
			store:     &stubResponseActions{},
			wantMoved: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := handlerCounterValue(metrics.BackgroundFailures.WithLabelValues(component))

			h := &AgentHandler{ResponseActions: tc.store}
			h.noteResponseAction(testGinContext(), "a-1", "isolate", "completed", "operator@example.com", nil)

			if tc.store.calls != 1 {
				t.Fatalf("Record の呼び出し回数 = %d, want 1", tc.store.calls)
			}
			if tc.store.last.agentID != "a-1" || tc.store.last.action != "isolate" ||
				tc.store.last.status != "completed" || tc.store.last.by != "operator@example.com" {
				t.Errorf("記録した内容 = %+v。"+
					"引数の順番が入れ替わると、時系列には行が残るのに"+
					"「何を誰が」が別のものになります", tc.store.last)
			}
			after := handlerCounterValue(metrics.BackgroundFailures.WithLabelValues(component))
			if moved := after - before; moved != tc.wantMoved {
				t.Errorf("%s の失敗件数の増分 = %v, want %v。"+
					"報告しないと、時系列の欠落を気づく手段がありません",
					component, moved, tc.wantMoved)
			}
		})
	}
}

// 記録先を持たない構成（`ResponseActions` 未設定）で落ちないこと。
func TestNoResponseActionStoreIsNotAFailure(t *testing.T) {
	const component = "response_action_record"
	before := handlerCounterValue(metrics.BackgroundFailures.WithLabelValues(component))

	h := &AgentHandler{}
	h.noteResponseAction(testGinContext(), "a-1", "isolate", "completed", "operator@example.com", nil)

	if after := handlerCounterValue(metrics.BackgroundFailures.WithLabelValues(component)); after != before {
		t.Errorf("記録先を持たない構成で失敗を報告しました (%v → %v)", before, after)
	}
}
