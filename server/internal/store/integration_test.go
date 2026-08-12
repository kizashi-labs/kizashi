//go:build integration

package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/edr-platform/server/internal/store"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func startDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"timescale/timescaledb:latest-pg16",
		tcpostgres.WithDatabase("edrtest"),
		tcpostgres.WithUsername("edr"),
		tcpostgres.WithPassword("testpass"),
		tcpostgres.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("PostgreSQL コンテナ起動失敗: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("接続文字列の取得失敗: %v", err)
	}

	db, err := store.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("store.Connect 失敗: %v", err)
	}
	t.Cleanup(db.Close)

	applyMigrations(t, ctx, db)
	return db
}

func applyMigrations(t *testing.T, ctx context.Context, db *store.DB) {
	t.Helper()

	migrationsDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("マイグレーションディレクトリ読み込み失敗 (%s): %v", migrationsDir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(migrationsDir, e.Name()))
		}
	}
	sort.Strings(files)

	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("マイグレーション読み込み失敗 (%s): %v", f, err)
		}
		if _, err := db.Pool().Exec(ctx, string(sql)); err != nil {
			// 一部のマイグレーションは依存関係でエラーになることがある（冪等でない場合）
			t.Logf("マイグレーション警告 (%s): %v", filepath.Base(f), err)
		}
	}
}

// makeAgent creates a minimal AgentRow for testing.
func makeAgent(id, hostname, os string) *store.AgentRow {
	return &store.AgentRow{
		ID:           id,
		Hostname:     hostname,
		OSType:       os,
		OSVersion:    "1.0",
		AgentVersion: "1.0.0",
		IPAddresses:  []string{"192.168.1.1"},
		Status:       "online",
		Tags:         []string{},
	}
}

// ─── UserStore 統合テスト ─────────────────────────────────────────────────────

func TestUserStore_CreateAndAuthenticate(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	user, err := s.Create(ctx, "alice@example.com", "Secure!Pass1", "Alice", "analyst")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", user.Email, "alice@example.com")
	}
	if user.Role != "analyst" {
		t.Errorf("Role: got %q, want %q", user.Role, "analyst")
	}
	if !user.MustChangePassword {
		t.Error("新規作成ユーザーは MustChangePassword=true のはずです")
	}

	// 正しいパスワードで認証
	authed, err := s.Authenticate(ctx, "alice@example.com", "Secure!Pass1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authed.ID != user.ID {
		t.Errorf("ID不一致: got %q, want %q", authed.ID, user.ID)
	}

	// 誤パスワードで認証失敗
	if _, err = s.Authenticate(ctx, "alice@example.com", "wrongpassword"); err == nil {
		t.Error("誤パスワードでエラーになるはずです")
	}
}

func TestUserStore_GetByID(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	created, err := s.Create(ctx, "bob@example.com", "Pass1234!", "Bob", "viewer")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Errorf("Email: got %q, want %q", got.Email, "bob@example.com")
	}
	if got.FullName != "Bob" {
		t.Errorf("FullName: got %q, want %q", got.FullName, "Bob")
	}
}

func TestUserStore_UpdatePassword_ClearsMustChange(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	user, _ := s.Create(ctx, "carol@example.com", "Pass1234!", "Carol", "analyst")
	if !user.MustChangePassword {
		t.Fatal("新規ユーザーは MustChangePassword=true のはずです")
	}

	if err := s.UpdatePassword(ctx, user.ID, "NewSecure!99"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if err := s.ClearMustChangePassword(ctx, user.ID); err != nil {
		t.Fatalf("ClearMustChangePassword: %v", err)
	}

	updated, _ := s.GetByID(ctx, user.ID)
	if updated.MustChangePassword {
		t.Error("パスワード変更後は MustChangePassword=false のはずです")
	}

	// 新パスワードで認証できることを確認
	if _, err := s.Authenticate(ctx, "carol@example.com", "NewSecure!99"); err != nil {
		t.Errorf("新パスワードで認証失敗: %v", err)
	}
}

func TestUserStore_Deactivate(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	user, _ := s.Create(ctx, "dave@example.com", "Pass1234!", "Dave", "analyst")

	if err := s.SetActive(ctx, user.ID, false); err != nil {
		t.Fatalf("SetActive(false): %v", err)
	}

	// 無効化ユーザーは認証失敗するはず
	if _, err := s.Authenticate(ctx, "dave@example.com", "Pass1234!"); err == nil {
		t.Error("無効化ユーザーは認証失敗するはずです")
	}
}

func TestUserStore_List(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("listuser%d@example.com", i)
		if _, err := s.Create(ctx, email, "Pass1234!", "", "analyst"); err != nil {
			t.Fatalf("Create user%d: %v", i, err)
		}
	}

	users, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) < 3 {
		t.Errorf("最低3ユーザーのはずです、got %d", len(users))
	}
}

func TestUserStore_VerifyCurrentPassword(t *testing.T) {
	db := startDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()

	user, _ := s.Create(ctx, "eve@example.com", "Correct!Pass1", "Eve", "analyst")

	if err := s.VerifyCurrentPassword(ctx, user.ID, "Correct!Pass1"); err != nil {
		t.Errorf("正しいパスワードの検証失敗: %v", err)
	}
	if err := s.VerifyCurrentPassword(ctx, user.ID, "WrongPass"); err == nil {
		t.Error("誤パスワードはエラーになるはずです")
	}
}

// ─── AlertStore 統合テスト ────────────────────────────────────────────────────

func TestAlertStore_SaveAndGet(t *testing.T) {
	db := startDB(t)
	s := store.NewAlertStore(db)
	agentStore := store.NewAgentStore(db)
	ctx := context.Background()

	agentID := uuid.New().String()
	if err := agentStore.UpsertAgent(ctx, makeAgent(agentID, "test-host", "linux")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	now := time.Now().UTC()
	desc := "テスト説明"
	alert := &store.StoredAlert{
		ID:          uuid.New().String(),
		AgentID:     agentID,
		Severity:    7,
		Status:      "open",
		Title:       "テストアラート",
		Description: &desc,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("SaveAlert: %v", err)
	}

	got, err := s.GetAlert(ctx, alert.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if got.Title != "テストアラート" {
		t.Errorf("Title: got %q, want %q", got.Title, "テストアラート")
	}
	if got.Severity != 7 {
		t.Errorf("Severity: got %d, want 7", got.Severity)
	}
	if got.Status != "open" {
		t.Errorf("Status: got %q, want %q", got.Status, "open")
	}
}

// TestAlertStore_SaveAgentlessAlert is a regression test for a live-surfaced bug:
// an agentless alert (the cloud suspicious-operation path keys off a cloud
// account, not an endpoint) carries no agent_id, so AgentID is "". Binding "" to
// the uuid agent_id column failed with SQLSTATE 22P02 ("invalid input syntax for
// type uuid: \"\"") and the alert was silently dropped — cloud detections never
// persisted. SaveAlert must bind NULL for an empty AgentID/RuleID.
func TestAlertStore_SaveAgentlessAlert(t *testing.T) {
	db := startDB(t)
	s := store.NewAlertStore(db)
	ctx := context.Background()

	now := time.Now().UTC()
	desc := "不審なクラウド操作: DeleteTrail"
	tech := "T1098"
	alert := &store.StoredAlert{
		ID:          uuid.New().String(),
		AgentID:     "", // no agent — this is the case that used to fail
		RuleID:      nil,
		Hostname:    "demo-cloudtrail",
		Severity:    7,
		Status:      "open",
		Title:       "不審なクラウド操作を検出: DeleteTrail",
		Description: &desc,
		MITRETech:   &tech,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("エージェント無しアラートの保存に失敗しました (回帰: agent_id 空文字→uuid): %v", err)
	}

	got, err := s.GetAlert(ctx, alert.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if got.Title != alert.Title {
		t.Errorf("Title: got %q, want %q", got.Title, alert.Title)
	}
	if got.AgentID != "" {
		t.Errorf("AgentID: エージェント無しなので空のはずです、got %q", got.AgentID)
	}
	if got.MITRETech == nil || *got.MITRETech != "T1098" {
		t.Errorf("MITRETech: got %v, want T1098", got.MITRETech)
	}
}

func TestAlertStore_ListWithSeverityFilter(t *testing.T) {
	db := startDB(t)
	s := store.NewAlertStore(db)
	agentStore := store.NewAgentStore(db)
	ctx := context.Background()

	agentID := uuid.New().String()
	_ = agentStore.UpsertAgent(ctx, makeAgent(agentID, "filter-host", "windows"))

	now := time.Now().UTC()
	for i, sev := range []int{2, 5, 8} {
		desc := fmt.Sprintf("説明%d", i)
		a := &store.StoredAlert{
			ID:          uuid.New().String(),
			AgentID:     agentID,
			Severity:    sev,
			Status:      "open",
			Title:       fmt.Sprintf("アラート%d", i),
			Description: &desc,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.SaveAlert(ctx, a); err != nil {
			t.Fatalf("SaveAlert %d: %v", i, err)
		}
	}

	alerts, _, err := s.ListAlerts(ctx, store.AlertFilter{Severity: 5, Limit: 100})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	for _, a := range alerts {
		if a.Severity < 5 {
			t.Errorf("severity<5のアラートが含まれています: %d", a.Severity)
		}
	}
	if len(alerts) < 2 {
		t.Errorf("severity>=5のアラートは最低2件のはずです、got %d", len(alerts))
	}
}

func TestAlertStore_UpdateStatus(t *testing.T) {
	db := startDB(t)
	s := store.NewAlertStore(db)
	agentStore := store.NewAgentStore(db)
	ctx := context.Background()

	agentID := uuid.New().String()
	_ = agentStore.UpsertAgent(ctx, makeAgent(agentID, "update-host", "linux"))

	now := time.Now().UTC()
	desc := "更新テスト"
	alert := &store.StoredAlert{
		ID:          uuid.New().String(),
		AgentID:     agentID,
		Severity:    5,
		Status:      "open",
		Title:       "更新テストアラート",
		Description: &desc,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = s.SaveAlert(ctx, alert)

	newStatus := "investigating"
	if err := s.UpdateAlert(ctx, alert.ID, &newStatus, nil); err != nil {
		t.Fatalf("UpdateAlert: %v", err)
	}

	got, _ := s.GetAlert(ctx, alert.ID)
	if got.Status != "investigating" {
		t.Errorf("Status: got %q, want %q", got.Status, "investigating")
	}
}
