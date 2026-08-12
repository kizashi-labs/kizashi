package wsbus

import (
	"testing"
)

// mockClient はテスト用の Client 実装
type mockClient struct {
	role     string
	received [][]byte
}

func (m *mockClient) Send(data []byte) {
	m.received = append(m.received, data)
}

func (m *mockClient) Role() string {
	return m.role
}

// newTestHub は各テスト用の独立した Hub を返す
func newTestHub() *Hub {
	return &Hub{clients: make(map[Client]struct{})}
}

// ─── Global ───────────────────────────────────────────────────────────────────

func TestGlobal_NotNil(t *testing.T) {
	if Global() == nil {
		t.Fatal("Global() は nil を返すべきではありません")
	}
}

func TestGlobal_Singleton(t *testing.T) {
	g1, g2 := Global(), Global()
	if g1 != g2 {
		t.Error("Global() は同じインスタンスを返すべきです")
	}
}

// ─── Register / Unregister ────────────────────────────────────────────────────

func TestRegister_IncreasesCount(t *testing.T) {
	h := newTestHub()
	c := &mockClient{role: "admin"}
	h.Register(c)
	if h.ConnectedCount() != 1 {
		t.Errorf("Register 後: ConnectedCount got %d, want 1", h.ConnectedCount())
	}
}

func TestUnregister_DecreasesCount(t *testing.T) {
	h := newTestHub()
	c := &mockClient{role: "admin"}
	h.Register(c)
	h.Unregister(c)
	if h.ConnectedCount() != 0 {
		t.Errorf("Unregister 後: ConnectedCount got %d, want 0", h.ConnectedCount())
	}
}

func TestRegister_MultipleClients(t *testing.T) {
	h := newTestHub()
	h.Register(&mockClient{role: "admin"})
	h.Register(&mockClient{role: "analyst"})
	h.Register(&mockClient{role: "viewer"})
	if h.ConnectedCount() != 3 {
		t.Errorf("3 クライアント登録: got %d, want 3", h.ConnectedCount())
	}
}

func TestUnregister_NonExistentClient_NoError(t *testing.T) {
	h := newTestHub()
	c := &mockClient{}
	// 未登録クライアントの Unregister は panic しない
	h.Unregister(c)
}

// ─── ConnectedCount ───────────────────────────────────────────────────────────

func TestConnectedCount_Empty_ReturnsZero(t *testing.T) {
	h := newTestHub()
	if h.ConnectedCount() != 0 {
		t.Errorf("空 Hub: ConnectedCount got %d, want 0", h.ConnectedCount())
	}
}

// ─── Broadcast ────────────────────────────────────────────────────────────────

func TestBroadcast_SendsToAllClients(t *testing.T) {
	h := newTestHub()
	c1 := &mockClient{role: "admin"}
	c2 := &mockClient{role: "analyst"}
	h.Register(c1)
	h.Register(c2)
	h.Broadcast("alert", map[string]string{"id": "123"})
	if len(c1.received) != 1 {
		t.Errorf("c1 受信数: got %d, want 1", len(c1.received))
	}
	if len(c2.received) != 1 {
		t.Errorf("c2 受信数: got %d, want 1", len(c2.received))
	}
}

func TestBroadcast_NoClients_NoPanic(t *testing.T) {
	h := newTestHub()
	h.Broadcast("alert", map[string]string{"id": "123"})
}

// ─── BroadcastToRole ─────────────────────────────────────────────────────────

func TestBroadcastToRole_SendsOnlyToRole(t *testing.T) {
	h := newTestHub()
	admin := &mockClient{role: "admin"}
	analyst := &mockClient{role: "analyst"}
	h.Register(admin)
	h.Register(analyst)
	h.BroadcastToRole("admin", "alert", map[string]string{"id": "456"})
	if len(admin.received) != 1 {
		t.Errorf("admin 受信数: got %d, want 1", len(admin.received))
	}
	if len(analyst.received) != 0 {
		t.Errorf("analyst は受信しないべき: got %d", len(analyst.received))
	}
}

func TestBroadcastToRole_EmptyRole_SendsToAll(t *testing.T) {
	h := newTestHub()
	c1 := &mockClient{role: "admin"}
	c2 := &mockClient{role: "viewer"}
	h.Register(c1)
	h.Register(c2)
	h.BroadcastToRole("", "event", "data")
	if len(c1.received) != 1 {
		t.Errorf("c1 受信数 (空 role): got %d, want 1", len(c1.received))
	}
	if len(c2.received) != 1 {
		t.Errorf("c2 受信数 (空 role): got %d, want 1", len(c2.received))
	}
}

// ─── marshal ──────────────────────────────────────────────────────────────────

func TestMarshal_InvalidData_ReturnsNil(t *testing.T) {
	h := newTestHub()
	// chan は json.Marshal できないので nil が返るはず
	result := h.marshal("type", make(chan int))
	if result != nil {
		t.Error("marshal (不正データ): nil を返すべきです")
	}
}

func TestMarshal_ValidData_ReturnsJSON(t *testing.T) {
	h := newTestHub()
	result := h.marshal("alert", map[string]string{"id": "1"})
	if result == nil {
		t.Fatal("marshal (有効データ): nil を返すべきではありません")
	}
	if len(result) == 0 {
		t.Error("marshal: 空のバイト列が返されました")
	}
}
