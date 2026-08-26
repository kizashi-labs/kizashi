package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// **絞り込めない接続を配らないこと、復旧コードが一度しか使えないこと。**
//
// どちらも `_, _ = pool.Exec(…)` でした。書けなくても先へ進むので、
// 外から見えるのは:
//
//	app.tenant_id が空のまま      RLS のエスケープ節が**全テナントを通す**
//	使用済みの印が書けないまま    **同じ復旧コードが何度でも使える**
//
// どちらも DB が要るので `TEST_DATABASE_URL` が無ければ飛ばします。
// **飛ばした回は緑ではありません** —— それが分かるよう Skip します。

func tenantTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping tenant/backup-code DB tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestAConnectionThatCannotBeTenantScopedIsNotHandedOut.
//
// `prepareConnForTenant` は `(true, nil)` を返していました —— set_config が
// 失敗しても「この接続は使えます」です。**空の `app.tenant_id` は全件
// アクセス**なので、失敗と全権限が同じ形でした。
func TestAConnectionThatCannotBeTenantScopedIsNotHandedOut(t *testing.T) {
	pool := tenantTestPool(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	const tid = "11111111-1111-1111-1111-111111111111"

	// 通る側。設定できたら「使える」と答えること。
	live := context.WithValue(ctx, TenantContextKey{}, tid)
	if ok, perr := prepareConnForTenant(live, conn.Conn()); !ok || perr != nil {
		t.Fatalf("設定できた接続を使えないと答えています: (%v, %v)", ok, perr)
	}
	var got string
	if err := conn.QueryRow(ctx, "SELECT current_setting('app.tenant_id', TRUE)").Scan(&got); err != nil {
		t.Fatalf("読み出し: %v", err)
	}
	if got != tid {
		t.Errorf("app.tenant_id = %q, want %q", got, tid)
	}

	// **設定できない側。** 期限の切れた ctx を渡すと Exec は server へ
	// 届く前に失敗し、接続そのものは生きたままです ——「設定に失敗した
	// のに使える接続」がまさにこの形です。
	dead, cancel := context.WithDeadline(
		context.WithValue(ctx, TenantContextKey{}, tid), time.Now().Add(-time.Second))
	defer cancel()

	ok, perr := prepareConnForTenant(dead, conn.Conn())
	if ok {
		t.Error("設定できなかった接続を「使える」と答えています。**空の " +
			"`app.tenant_id` は RLS のエスケープ節で全テナントを通します**")
	}
	if perr == nil {
		t.Error("error を返していません。`(false, nil)` だと pgx は黙って" +
			"別の接続で retry するので、恒久的な失敗が「too many failed " +
			"attempts」まで見えません")
	}
}

// TestClearingTheTenantFailureDestroysTheConnection —— 消せなかった接続を
// プールに戻さないこと。戻すと、**テナントを持たない次の呼び出しが
// 前のテナントで絞られます。**
func TestClearingTheTenantFailureDestroysTheConnection(t *testing.T) {
	pool := tenantTestPool(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !clearConnTenant(conn.Conn()) {
		t.Error("生きている接続を捨てています")
	}
	var got string
	if err := conn.QueryRow(ctx, "SELECT current_setting('app.tenant_id', TRUE)").Scan(&got); err != nil {
		t.Fatalf("読み出し: %v", err)
	}
	if got != "" {
		t.Errorf("app.tenant_id = %q（消えていません）", got)
	}
	conn.Release()

	// 閉じた接続では消せないので、戻さないこと。
	dead, err := pgx.Connect(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_ = dead.Close(ctx)
	if clearConnTenant(dead) {
		t.Error("消せなかった接続をプールに戻しています。**次にテナントを" +
			"持たない呼び出しがこれを引くと、前のテナントで絞られます**")
	}
}

// TestABackupCodeWorksExactlyOnce.
//
// 使用済みの印は `_, _ =` で捨てられていて、**書けなくても `true` を
// 返していました** —— 一度だけ使えるはずのコードが、何度でも使えます。
func TestABackupCodeWorksExactlyOnce(t *testing.T) {
	pool := tenantTestPool(t)
	ctx := context.Background()
	s := NewUserStore(&DB{pool: pool})

	var userID string
	_, _ = pool.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE user_id IN
		(SELECT id FROM users WHERE email LIKE 'backup-%@example.test')`)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email LIKE 'backup-%@example.test'`)
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, full_name)
		 VALUES ($1, 'x', 'analyst', 'backup code test') RETURNING id::text`,
		"backup-once@example.test").Scan(&userID); err != nil {
		t.Fatalf("ユーザを作れません: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM mfa_backup_codes WHERE user_id=$1::uuid`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id=$1::uuid`, userID)
	})

	if err := s.SaveBackupCodes(ctx, userID, []string{"once-alpha", "once-beta"}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}

	ok, err := s.UseBackupCode(ctx, userID, "once-alpha")
	if err != nil || !ok {
		t.Fatalf("1回目が通りません: ok=%v err=%v", ok, err)
	}
	ok, err = s.UseBackupCode(ctx, userID, "once-alpha")
	if err != nil {
		t.Fatalf("2回目で error: %v", err)
	}
	if ok {
		t.Error("**同じ復旧コードが2回使えました。** MFA の最後の手段が" +
			"使い捨てでなくなっています")
	}

	// もう1本は無事なこと。1本使うと全部が無効、では困ります。
	if ok, err := s.UseBackupCode(ctx, userID, "once-beta"); err != nil || !ok {
		t.Errorf("別のコードまで無効になっています: ok=%v err=%v", ok, err)
	}
}

// TestABackupCodeIsNotAcceptedWhenItCannotBeConsumed.
//
// **上の検査は、元の実装でも通ります。** 印が書ける限り、`_, _ =` でも
// 行は更新されるからです —— 欠陥は「書けなかったとき」にしか出ません。
//
// 読めるが書けない状態を作って測ります（読み取り専用のレプリカ、
// 権限の設定ミス、DB の障害がこの形です）。元の実装はここで
// **`(true, nil)`** —— コードは消費されないまま、認証は通ります。
func TestABackupCodeIsNotAcceptedWhenItCannotBeConsumed(t *testing.T) {
	pool := tenantTestPool(t)
	ctx := context.Background()

	var userID string
	_, _ = pool.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE user_id IN
		(SELECT id FROM users WHERE email LIKE 'backup-%@example.test')`)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email LIKE 'backup-%@example.test'`)
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, full_name)
		 VALUES ($1, 'x', 'analyst', 'backup code readonly') RETURNING id::text`,
		"backup-readonly@example.test").Scan(&userID); err != nil {
		t.Fatalf("ユーザを作れません: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM mfa_backup_codes WHERE user_id=$1::uuid`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id=$1::uuid`, userID)
	})
	if err := NewUserStore(&DB{pool: pool}).SaveBackupCodes(ctx, userID,
		[]string{"ro-alpha"}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}

	// SELECT はできて UPDATE はできない接続。
	roURL, cleanup := readOnlyURL(t, pool)
	defer cleanup()
	roPool, err := pgxpool.New(ctx, roURL)
	if err != nil {
		t.Fatalf("read-only pool: %v", err)
	}
	defer roPool.Close()

	ok, err := NewUserStore(&DB{pool: roPool}).UseBackupCode(ctx, userID, "ro-alpha")
	if ok {
		t.Error("**消費できていないのに認証を通しています。** 復旧コードは" +
			"使用済みにならず、同じコードが何度でも使えます")
	}
	if err == nil {
		t.Error("error を返していません。呼び出し側は 401（コードが違う）と" +
			"500（DB に書けない）を区別できません")
	}
}

// TestOnlyOneConcurrentUseOfABackupCodeSucceeds.
//
// 読んでから使用済みにするまでのあいだに、同じコードが別の要求で使われる
// 場合です。**`WHERE … AND used = FALSE` が無いと、両方とも通ります。**
//
// 窓は狭くありません —— あいだに bcrypt の比較が入るので、数十ミリ秒
// あります。同時に投げれば、条件が無い実装では複数が通ります。
func TestOnlyOneConcurrentUseOfABackupCodeSucceeds(t *testing.T) {
	pool := tenantTestPool(t)
	ctx := context.Background()
	s := NewUserStore(&DB{pool: pool})

	var userID string
	_, _ = pool.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE user_id IN
		(SELECT id FROM users WHERE email LIKE 'backup-%@example.test')`)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email LIKE 'backup-%@example.test'`)
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, full_name)
		 VALUES ($1, 'x', 'analyst', 'backup code race') RETURNING id::text`,
		"backup-race@example.test").Scan(&userID); err != nil {
		t.Fatalf("ユーザを作れません: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM mfa_backup_codes WHERE user_id=$1::uuid`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id=$1::uuid`, userID)
	})
	if err := s.SaveBackupCodes(ctx, userID, []string{"race-alpha"}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}

	const tries = 8
	results := make(chan bool, tries)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < tries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := s.UseBackupCode(context.Background(), userID, "race-alpha")
			if err != nil {
				results <- false
				return
			}
			results <- ok
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	accepted := 0
	for ok := range results {
		if ok {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("同時に %d 回出した同じ復旧コードが %d 回通りました（1 のはずです）。"+
			"**読んでから使用済みにするまでのあいだに、同じコードが"+
			"使えます** —— `WHERE … AND used = FALSE` が要ります",
			tries, accepted)
	}
}

// readOnlyURL builds a DSN for a role that may read mfa_backup_codes but not
// write it, and returns a cleanup that drops the role.
func readOnlyURL(t *testing.T, pool *pgxpool.Pool) (string, func()) {
	t.Helper()
	ctx := context.Background()
	const role = "kizashi_ro_probe"
	for _, stmt := range []string{
		`DROP OWNED BY ` + role,
		`DROP ROLE IF EXISTS ` + role,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role+` LOGIN`); err != nil {
		t.Skipf("読み書きを分けた role を作れません（権限が足りません）: %v", err)
	}
	cleanup := func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DROP OWNED BY `+role)
		_, _ = pool.Exec(c, `DROP ROLE IF EXISTS `+role)
	}
	for _, stmt := range []string{
		`GRANT SELECT ON mfa_backup_codes TO ` + role,
		`GRANT SELECT ON users TO ` + role,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			cleanup()
			t.Skipf("GRANT できません: %v", err)
		}
	}

	cfg := pool.Config().ConnConfig
	host := cfg.Host
	if !strings.HasPrefix(host, "/") {
		host = cfg.Host
	}
	return fmt.Sprintf("postgres://%s@/%s?host=%s&port=%d&sslmode=disable",
		role, cfg.Database, host, cfg.Port), cleanup
}

// **`ctx` を受け取りながら `context.Background()` を使わないこと。**
//
// `TouchSession` がその形でした —— 引数に `ctx` があるのに
// `context.Background()` で問い合わせていて、**要求が打ち切られても
// 走り続け、`prepareConnForTenant` が乗せるテナントも付きません。**
//
// `internal/store` の `context.Background()` は実測 5 か所 (2026-08-12)。
// 残る 4 つには理由があります:
//
//	postgres.go:clearConnTenant   pgx の `AfterRelease` に ctx がありません
//	users.go:Authenticate ×3      goroutine で、**要求より長生きします**
//	                              （応答を返したあとに書きます）
//
// ここは file 単位の名指しです。**広い規則にするなら、上の 4 つに理由を
// 書くところから**ですが、いまは変異が実際に通り抜けた1つを留めます。
func TestTouchSessionUsesTheCallersContext(t *testing.T) {
	src, err := os.ReadFile("live_response.go")
	if err != nil {
		t.Fatalf("live_response.go を読めません: %v", err)
	}
	// **コメントは落とします。** 直したときの説明が `live_response.go` の
	// コメントに残っていて、そのまま数えると自分の説明で落ちます。
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	if strings.Contains(code.String(), "context.Background()") {
		t.Error("`live_response.go` が `context.Background()` を使っています。" +
			"**`ctx` を受け取っているのに使わないと、要求が打ち切られても" +
			"走り続け、テナントの設定も乗りません**")
	}
	if !strings.Contains(string(src), "func (s *LiveResponseStore) TouchSession(ctx context.Context, token string) error") {
		t.Error("`TouchSession` の形が変わっています。**名前や引数が" +
			"変わったなら、この検査も追ってください**")
	}
}
