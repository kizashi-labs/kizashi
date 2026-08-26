package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
)

// 保管時暗号化を実際に有効にして、書いて読むこと。
//
// **単体では、書き込み側も読み出し側も緑でした。** どちらもテナントを
// 引数で渡して試していたからです。本番でテナントがどこから来るのかは、
// 一度も確かめていませんでした。
//
// 実際に繋いでみると、両側とも動きませんでした:
//
//   - 書き込み: `StoredAlert.TenantID` を設定する箇所が本番に1つも
//     ありません。`prepareRawEvent` は `a.TenantID == ""` で平文の枝に
//     落ちるので、encryptor を付けても暗号化は起きません。
//   - 読み出し: `scanAlert` は `tenant_id` を読みません。`GetAlert` は
//     空のテナントで復号を試み、**すべてのアラートが
//     「復号できませんでした」になります。**
//
// テナントの本当の出どころは Postgres のセッション変数 `app.tenant_id`
// です（`store.Connect` の PrepareConn が ctx から設定し、`alerts.tenant_id`
// 列の DEFAULT がそれを読みます）。暗号化の範囲もそこに合わせます ——
// **同じ出どころなら、行の tenant_id と鍵のテナントは構造上ずれません。**
//
// TEST_DATABASE_URL が無ければ飛ばします。マイグレーション済みの
// PostgreSQL を指してください（scripts/coverage-local.sh が用意します）。

func roundtripDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("DSN を解釈できません: %v", err)
	}
	// 本番と同じ hook。これが無いと app.tenant_id が設定されず、
	// 行の tenant_id は既定値になります。**この検査の要点そのものです。**
	cfg.PrepareConn = prepareConnForTenant
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("接続できません: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("DB に届きません: %v", err)
	}
	return pool
}

func roundtripEncryptor(t *testing.T, pool *pgxpool.Pool) *tenantcrypto.Encryptor {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("マスター鍵を作れません: %v", err)
	}
	ks, err := tenantcrypto.NewDBKeyStore(pool, master)
	if err != nil {
		t.Fatalf("DBKeyStore: %v", err)
	}
	return tenantcrypto.NewEncryptor(ks)
}

// tenantCtx は本番の tenantMiddleware と同じ形でテナントを ctx に置きます。
func tenantCtx(tenant string) context.Context {
	return context.WithValue(context.Background(), TenantContextKey{}, tenant)
}

// makeTenant creates the tenants row that alerts.tenant_id references.
func makeTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id, "roundtrip "+id[:8], "rt-"+id[:8]); err != nil {
		t.Fatalf("テナントを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// makeAgent creates the agents row an alert points at.
//
// GetAlert は agent_id が NULL の行を読めません（`cannot scan NULL into
// *string`）。SaveAlert のコメントは agentless なアラートを明示的に扱って
// いるので、**読めないのは別の欠陥です。** ここでは暗号化を測りたいので、
// エージェントを作って避けます。判断待ちの一覧に記録しました。
func makeAgent(t *testing.T, pool *pgxpool.Pool, tenant string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(tenantCtx(tenant),
		`INSERT INTO agents (id, hostname, os_type, status, source, settings)
		 VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb)`,
		id, "rt-"+id[:8]); err != nil {
		t.Fatalf("エージェントを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id = $1`, id)
	})
	return id
}

func TestAlertRawEventSurvivesEncryptionRoundTrip(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)
	agent := makeAgent(t, pool, tenant)

	s := (&AlertStore{pool: pool}).WithEncryptor(roundtripEncryptor(t, pool))

	const payload = `{"cmd":"whoami","pid":4242}`
	id := uuid.NewString()
	a := &StoredAlert{
		ID: id, AgentID: agent, Severity: 8, Status: "open", Title: "roundtrip",
		RawEvent: json.RawMessage(payload),
	}
	if err := s.SaveAlert(ctx, a); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	// 1. 列に平文が残っていないこと。**暗号化の目的そのものです。**
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT raw_event FROM alerts WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("列を読めません: %v", err)
	}
	if !IsEncryptedRawEvent(stored) {
		t.Errorf("raw_event が平文のままです: %s\n"+
			"encryptor を付けても、テナントが伝わらなければ暗号化されません", stored)
	}
	if stored == payload {
		t.Error("生の JSON がそのまま列に入っています")
	}

	// 2. 行の tenant_id が、暗号化に使ったテナントと同じであること。
	//    ずれると、書いた鍵と読む鍵が違い、二度と復号できません。
	var rowTenant string
	if err := pool.QueryRow(ctx,
		`SELECT tenant_id::text FROM alerts WHERE id = $1`, id).Scan(&rowTenant); err != nil {
		t.Fatalf("tenant_id を読めません: %v", err)
	}
	if rowTenant != tenant {
		t.Errorf("行の tenant_id (%s) と暗号化のテナント (%s) が違います。"+
			"この行はもう復号できません", rowTenant, tenant)
	}

	// 3. 読み出し側が復号して返すこと。
	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("読み出せません: %v", err)
	}
	if got.RawEventUnavailable != nil {
		t.Fatalf("復号できていません: %s", *got.RawEventUnavailable)
	}
	if string(got.RawEvent) != payload {
		t.Errorf("raw_event = %s, want %s", got.RawEvent, payload)
	}
}

// テナントの無い経路（単一テナント構成、背景ジョブ）は平文のまま
// 動き続けること。暗号化を有効にした途端に片方が読めなくなる、
// という形にはしません。
func TestAlertWithoutTenantStaysReadable(t *testing.T) {
	pool := roundtripDB(t)
	s := (&AlertStore{pool: pool}).WithEncryptor(roundtripEncryptor(t, pool))
	agent := makeAgent(t, pool, "")

	const payload = `{"cmd":"id"}`
	id := uuid.NewString()
	ctx := context.Background() // テナント無し

	if err := s.SaveAlert(ctx, &StoredAlert{
		ID: id, AgentID: agent, Severity: 3, Status: "open", Title: "no tenant",
		RawEvent: json.RawMessage(payload),
	}); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("読み出せません: %v", err)
	}
	if got.RawEventUnavailable != nil {
		t.Errorf("テナントの無い平文の行が読めなくなっています: %s",
			*got.RawEventUnavailable)
	}
	if string(got.RawEvent) != payload {
		t.Errorf("raw_event = %s, want %s", got.RawEvent, payload)
	}
}

// 暗号化を有効にする前に書かれた行が、有効にしたあとも読めること。
// 移行しない方針なので、これが崩れると過去の証拠が全部消えます。
func TestPlaintextRowsStillReadAfterEncryptionIsEnabled(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)
	agent := makeAgent(t, pool, tenant)

	const payload = `{"cmd":"legacy"}`
	id := uuid.NewString()

	// 暗号化を有効にする前 —— encryptor 無しの store で書きます。
	before := &AlertStore{pool: pool}
	if err := before.SaveAlert(ctx, &StoredAlert{
		ID: id, AgentID: agent, Severity: 5, Status: "open", Title: "legacy",
		RawEvent: json.RawMessage(payload),
	}); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	// 有効にしたあと。
	after := (&AlertStore{pool: pool}).WithEncryptor(roundtripEncryptor(t, pool))
	got, err := after.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("読み出せません: %v", err)
	}
	if got.RawEventUnavailable != nil {
		t.Errorf("暗号化を有効にしたら、以前の平文の行が読めなくなりました: %s",
			*got.RawEventUnavailable)
	}
	if string(got.RawEvent) != payload {
		t.Errorf("raw_event = %s, want %s", got.RawEvent, payload)
	}
}

// 別のテナントの鍵では復号できないこと。
// これが通ると、テナント分離が暗号の層では効いていないことになります。
func TestAnotherTenantsKeyCannotDecrypt(t *testing.T) {
	pool := roundtripDB(t)
	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	enc := roundtripEncryptor(t, pool)
	s := (&AlertStore{pool: pool}).WithEncryptor(enc)
	agent := makeAgent(t, pool, tenantA)

	id := uuid.NewString()
	if err := s.SaveAlert(tenantCtx(tenantA), &StoredAlert{
		ID: id, AgentID: agent, Severity: 9, Status: "open", Title: "tenant A",
		RawEvent: json.RawMessage(`{"secret":"A"}`),
	}); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	var stored string
	if err := pool.QueryRow(context.Background(),
		`SELECT raw_event FROM alerts WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("列を読めません: %v", err)
	}
	if _, err := DecodeRawEvent(context.Background(), enc, tenantB, &stored); err == nil {
		t.Error("別のテナントの鍵で復号できてしまいました")
	}
}
