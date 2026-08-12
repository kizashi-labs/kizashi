package cert

import (
	"testing"
)

// ─── NewCAManager ─────────────────────────────────────────────────────────────

func TestNewCAManager_CreatesCA_NotNil(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: 予期しないエラー: %v", err)
	}
	if m == nil {
		t.Fatal("NewCAManager は nil を返すべきではありません")
	}
}

func TestNewCAManager_CAPemNotEmpty(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	if len(m.CAPem()) == 0 {
		t.Error("CAPem: 空です")
	}
}

func TestNewCAManager_TLSConfig_NotNil(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	tlsCfg := m.TLSConfig()
	if tlsCfg == nil {
		t.Error("TLSConfig: nil が返されました")
	}
}

func TestNewCAManager_LoadsExistingCA(t *testing.T) {
	dir := t.TempDir()
	// 最初の呼び出しで CA を生成
	m1, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager (1回目): %v", err)
	}
	pem1 := m1.CAPem()

	// 同じディレクトリで再度呼び出すと既存の CA を読み込む
	m2, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager (2回目): %v", err)
	}
	pem2 := m2.CAPem()

	if string(pem1) != string(pem2) {
		t.Error("既存 CA の再読み込み: PEM が一致しません")
	}
}

func TestNewCAManager_InvalidDir_ReturnsError(t *testing.T) {
	// 書き込み不可のパスではエラーを返すべき (Windows では /dev/null/invalid 等)
	_, err := NewCAManager("\x00invalid\x00path")
	if err == nil {
		t.Error("不正ディレクトリ: エラーを返すべきです")
	}
}

// ─── SignAgent ────────────────────────────────────────────────────────────────

func TestSignAgent_InvalidCSR_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	_, err = m.SignAgent([]byte("not-a-pem"), "agent-001")
	if err == nil {
		t.Error("不正 CSR: エラーを返すべきです")
	}
}

func TestSignAgent_EmptyCSR_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	_, err = m.SignAgent([]byte(""), "agent-001")
	if err == nil {
		t.Error("空 CSR: エラーを返すべきです")
	}
}
