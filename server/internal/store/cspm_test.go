package store_test

// CSPMStore を実 DB に対して往復させる。
//
// なぜ必要になったか: SetScanStatus は一度も成功したことがないまま出荷された。
// SQL は
//
//	SET scan_status = $2, ... CASE WHEN $2 = 'scanning' THEN ...
//
// で、$2 を varchar 列への代入とリテラル比較の両方に使っていたため、
// PostgreSQL が型を 1 つに決められず必ず
// 42P08 (inconsistent types deduced for parameter $2) で落ちていた。
// ハンドラ側のテストは「引受ロール未設定→400」「provider が aws 以外→501」
// の 2 本だけで、どちらも SetScanStatus に到達する前に return していたので、
// 実行されないコードのまま通っていた。
//
// 構文エラーではないので go vet も staticcheck も見つけられない。この種の
// 「SQL がプレースホルダの型解決で落ちる」欠陥は、実 DB に投げる以外に
// 検出手段が無い。よって CSPMStore の書き込みメソッドは全部ここで一度は
// 実行する。TEST_DATABASE_URL は CI の server ジョブが設定しているので、
// このファイルは CI でも動く (未設定のローカル実行では skip)。

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	uuidpkg "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

func cspmTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed CSPM store tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// cspmTestAccount は一意なアカウントを 1 つ作り、UUID を返す。
// (cloud_provider, account_id) に UNIQUE があるため毎回別 ID を使う。
func cspmTestAccount(t *testing.T, pool *pgxpool.Pool, s *store.CSPMStore) string {
	t.Helper()
	ctx := context.Background()
	acctID := "itest-" + uuidpkg.NewString()[:12]
	uuid, err := s.EnsureAccount(ctx, "aws", acctID, "cspm store itest")
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if uuid == "" {
		t.Fatal("EnsureAccount が空の UUID を返した")
	}
	t.Cleanup(func() {
		// cspm_findings は ON DELETE CASCADE で一緒に消える。
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM cspm_accounts WHERE id = $1::uuid`, uuid)
	})
	return uuid
}

// scanStatusRow は SetScanStatus が書いた 3 列を読む。
func scanStatusRow(t *testing.T, pool *pgxpool.Pool, uuid string) (status string, scanErr *string, startedSet bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `
		SELECT scan_status, scan_error, last_scan_started_at IS NOT NULL
		  FROM cspm_accounts WHERE id = $1::uuid`, uuid).
		Scan(&status, &scanErr, &startedSet)
	if err != nil {
		t.Fatalf("scan_status の読み出し: %v", err)
	}
	return status, scanErr, startedSet
}

// TestSetScanStatusRoundTrip が 42P08 の再発を止める本体。
func TestSetScanStatusRoundTrip(t *testing.T) {
	db := cspmTestDB(t)
	s := store.NewCSPMStore(db.Pool())
	ctx := context.Background()
	uuid := cspmTestAccount(t, db.Pool(), s)

	// 初期状態。EnsureAccount は last_scan_started_at を触らない。
	if _, _, started := scanStatusRow(t, db.Pool(), uuid); started {
		t.Fatal("作成直後に last_scan_started_at が入っている")
	}

	// scanning: 開始時刻が入る。
	if err := s.SetScanStatus(ctx, uuid, "scanning", nil); err != nil {
		t.Fatalf("SetScanStatus(scanning): %v", err)
	}
	status, scanErr, started := scanStatusRow(t, db.Pool(), uuid)
	if status != "scanning" {
		t.Errorf("scan_status = %q, want scanning", status)
	}
	if scanErr != nil {
		t.Errorf("scan_error = %q, want NULL", *scanErr)
	}
	if !started {
		t.Error("scanning にしても last_scan_started_at が入らない")
	}

	// error: 理由が残る。開始時刻は消えない
	// (「いつ始めて失敗したか」が分からなくなるため)。
	wantMsg := "ロールの引き受けに失敗しました"
	if err := s.SetScanStatus(ctx, uuid, "error", errors.New(wantMsg)); err != nil {
		t.Fatalf("SetScanStatus(error): %v", err)
	}
	status, scanErr, started = scanStatusRow(t, db.Pool(), uuid)
	if status != "error" {
		t.Errorf("scan_status = %q, want error", status)
	}
	if scanErr == nil || *scanErr != wantMsg {
		t.Errorf("scan_error = %v, want %q", scanErr, wantMsg)
	}
	if !started {
		t.Error("error 遷移で last_scan_started_at が消えた")
	}

	// completed: 前回の失敗理由が残っていてはいけない。残ると成功後も
	// 画面にエラーが出続ける。
	if err := s.SetScanStatus(ctx, uuid, "completed", nil); err != nil {
		t.Fatalf("SetScanStatus(completed): %v", err)
	}
	status, scanErr, _ = scanStatusRow(t, db.Pool(), uuid)
	if status != "completed" {
		t.Errorf("scan_status = %q, want completed", status)
	}
	if scanErr != nil {
		t.Errorf("completed なのに scan_error = %q が残っている", *scanErr)
	}
}

// TestCredentialsRoundTrip は引受情報の保存と読み出し。
// external_id はスキャナが必須にしている値なので、往復で欠けないことを見る。
func TestCSPMCredentialsRoundTrip(t *testing.T) {
	db := cspmTestDB(t)
	s := store.NewCSPMStore(db.Pool())
	ctx := context.Background()
	uuid := cspmTestAccount(t, db.Pool(), s)

	// 未設定のうちは空文字で返る (nil 参照にならないこと)。
	got, err := s.Credentials(ctx, uuid)
	if err != nil {
		t.Fatalf("Credentials(未設定): %v", err)
	}
	if got.RoleARN != "" || got.ExternalID != "" {
		t.Errorf("未設定なのに値がある: %+v", got)
	}
	if got.Provider != "aws" {
		t.Errorf("provider = %q, want aws", got.Provider)
	}

	roleARN := "arn:aws:iam::123456789012:role/KizashiCSPMReadOnly"
	extID := "itest-external-id"
	regions := []string{"ap-northeast-1", "us-east-1"}
	if err := s.SetCredentials(ctx, uuid, roleARN, extID, regions); err != nil {
		t.Fatalf("SetCredentials: %v", err)
	}

	got, err = s.Credentials(ctx, uuid)
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if got.RoleARN != roleARN {
		t.Errorf("RoleARN = %q, want %q", got.RoleARN, roleARN)
	}
	if got.ExternalID != extID {
		t.Errorf("ExternalID = %q, want %q", got.ExternalID, extID)
	}
	if len(got.Regions) != 2 || got.Regions[0] != "ap-northeast-1" {
		t.Errorf("Regions = %v, want %v", got.Regions, regions)
	}
	if !got.Enabled {
		t.Error("Enabled が false になっている")
	}

	// regions に nil を渡しても落ちない (スキャナは全リージョン走査時に nil を渡す)。
	if err := s.SetCredentials(ctx, uuid, roleARN, extID, nil); err != nil {
		t.Fatalf("SetCredentials(regions=nil): %v", err)
	}
}

// TestFindingLifecycle は不合格→再検出→合格の一巡を DB 上で確かめる。
// スキャナと取り込み API が共有する唯一の書き込み口なので、ここが
// 動かないと両方が黙って何も書かない。
func TestCSPMFindingLifecycle(t *testing.T) {
	db := cspmTestDB(t)
	s := store.NewCSPMStore(db.Pool())
	ctx := context.Background()
	uuid := cspmTestAccount(t, db.Pool(), s)

	f := store.CSPMFinding{
		CheckID:      "s3-public-access-block",
		CheckName:    "S3 バケットのパブリックアクセスブロック",
		Severity:     "high",
		ResourceType: "s3_bucket",
		ResourceID:   "itest-bucket",
		ResourceName: "itest-bucket",
		Region:       "ap-northeast-1",
		Description:  "パブリックアクセスブロックが無効です",
		Remediation:  "PutPublicAccessBlock で 4 項目すべてを有効にしてください",
		Frameworks:   []string{"CIS AWS Foundations"},
	}

	isNew, err := s.UpsertFinding(ctx, uuid, f)
	if err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}
	// 初回は「新規」。定期スキャンの通知はこれで「今回出たもの」を選ぶ。
	if !isNew {
		t.Error("初回の所見が新規として返っていない")
	}
	// 同じ所見の再検出では行が増えない。増えると一覧が重複で埋まる。
	// そして新規でもない ---毎回「新しい所見が出ました」と通知したら、
	// 通知は初日から意味を失う。
	isNew, err = s.UpsertFinding(ctx, uuid, f)
	if err != nil {
		t.Fatalf("UpsertFinding(再検出): %v", err)
	}
	if isNew {
		t.Error("再検出が新規として返っている")
	}
	if n := countFindings(t, db.Pool(), uuid, "open"); n != 1 {
		t.Fatalf("再検出後の open 件数 = %d, want 1", n)
	}

	// 集計が所見に追従する。high 1 件 → high_findings=1, score=98。
	if err := s.RefreshRollup(ctx, uuid); err != nil {
		t.Fatalf("RefreshRollup: %v", err)
	}
	var crit, high int
	var score float64
	if err := db.Pool().QueryRow(ctx, `
		SELECT critical_findings, high_findings, posture_score
		  FROM cspm_accounts WHERE id = $1::uuid`, uuid).
		Scan(&crit, &high, &score); err != nil {
		t.Fatalf("集計の読み出し: %v", err)
	}
	if crit != 0 || high != 1 {
		t.Errorf("critical=%d high=%d, want 0/1", crit, high)
	}
	if score != 98 {
		t.Errorf("posture_score = %v, want 98", score)
	}

	// 合格に転じたら閉じる。resource_id / region まで一致させて閉じるので、
	// 引数がずれていると 0 件になる。
	closed, err := s.ResolveFinding(ctx, uuid, f.CheckID, f.ResourceID, f.Region)
	if err != nil {
		t.Fatalf("ResolveFinding: %v", err)
	}
	if closed != 1 {
		t.Fatalf("閉じた件数 = %d, want 1", closed)
	}
	if n := countFindings(t, db.Pool(), uuid, "open"); n != 0 {
		t.Errorf("解決後の open 件数 = %d, want 0", n)
	}

	// 判断済みの所見は再検出で open に戻さない。
	if _, err := db.Pool().Exec(ctx, `
		UPDATE cspm_findings SET status = 'accepted_risk'
		 WHERE account_id = $1::uuid AND check_id = $2`, uuid, f.CheckID); err != nil {
		t.Fatalf("accepted_risk への更新: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, uuid, f); err != nil {
		t.Fatalf("UpsertFinding(accepted_risk 後): %v", err)
	}
	if n := countFindings(t, db.Pool(), uuid, "accepted_risk"); n != 1 {
		t.Errorf("accepted_risk が open に戻された (accepted_risk 件数 = %d)", n)
	}
}

// TestCSPMResolveMissingFindings は「資源が消えた」経路。
//
// 実アカウント検証で見つかった欠陥の再発防止。検証用に作った SG を
// AWS 側で削除して再スキャンしたところ、所見が open のまま残った。
// 削除された資源は API 応答に出てこないので pass も fail も生成されず、
// ResolveFinding (合格に転じた資源を閉じる経路) では閉じられない。
// 資源を消して問題を解消しても所見が残り続けるため、一覧が実在しない
// 問題で埋まっていく。
func TestCSPMResolveMissingFindings(t *testing.T) {
	db := cspmTestDB(t)
	s := store.NewCSPMStore(db.Pool())
	ctx := context.Background()
	uuid := cspmTestAccount(t, db.Pool(), s)

	const checkID = "aws-ec2-sg-ssh-open"
	const region = "ap-northeast-1"
	mk := func(resourceID string) store.CSPMFinding {
		return store.CSPMFinding{
			CheckID: checkID, CheckName: "SSH が全世界に公開されていない",
			Severity: "high", ResourceType: "AwsEc2SecurityGroup",
			ResourceID: resourceID, ResourceName: resourceID, Region: region,
			Description: "22 番が開いています",
		}
	}
	for _, id := range []string{"sg-alive", "sg-deleted-1", "sg-deleted-2"} {
		if _, err := s.UpsertFinding(ctx, uuid, mk(id)); err != nil {
			t.Fatalf("UpsertFinding(%s): %v", id, err)
		}
	}

	// 別のチェックの所見。掃除が check_id を越えて波及しないこと。
	other := mk("sg-alive")
	other.CheckID = "aws-ec2-sg-rdp-open"
	if _, err := s.UpsertFinding(ctx, uuid, other); err != nil {
		t.Fatalf("UpsertFinding(別チェック): %v", err)
	}
	// 別リージョンの所見。走査していないリージョンを巻き込まないこと。
	otherRegion := mk("sg-alive")
	otherRegion.Region = "us-east-1"
	if _, err := s.UpsertFinding(ctx, uuid, otherRegion); err != nil {
		t.Fatalf("UpsertFinding(別リージョン): %v", err)
	}

	// 今回のスキャンで見えたのは sg-alive だけ。残り 2 件は消えた。
	closed, err := s.ResolveMissingFindings(ctx, uuid, checkID, region, []string{"sg-alive"})
	if err != nil {
		t.Fatalf("ResolveMissingFindings: %v", err)
	}
	if closed != 2 {
		t.Fatalf("閉じた件数 = %d, want 2", closed)
	}

	openIDs := openResourceIDs(t, db.Pool(), uuid, checkID, region)
	if len(openIDs) != 1 || openIDs[0] != "sg-alive" {
		t.Errorf("open のまま残るべきは sg-alive だけ: %v", openIDs)
	}

	// 波及していないこと。
	if n := countFindings(t, db.Pool(), uuid, "open"); n != 3 {
		t.Errorf("account 全体の open = %d, want 3 (別チェック・別リージョンを巻き込んでいる)", n)
	}

	// 2 回目は冪等 (既に resolved なので閉じるものが無い)。
	closed, err = s.ResolveMissingFindings(ctx, uuid, checkID, region, []string{"sg-alive"})
	if err != nil {
		t.Fatalf("ResolveMissingFindings(2 回目): %v", err)
	}
	if closed != 0 {
		t.Errorf("2 回目に %d 件閉じた, want 0", closed)
	}

	// 資源が 1 つも無くなった場合は全部閉じる。完走した上で 0 件なら
	// 所見も 0 件が正しい。
	closed, err = s.ResolveMissingFindings(ctx, uuid, checkID, region, nil)
	if err != nil {
		t.Fatalf("ResolveMissingFindings(空): %v", err)
	}
	if closed != 1 {
		t.Errorf("空の資源一覧で %d 件閉じた, want 1", closed)
	}
	if got := openResourceIDs(t, db.Pool(), uuid, checkID, region); len(got) != 0 {
		t.Errorf("空の資源一覧なのに open が残っている: %v", got)
	}
}

// TestCSPMClaimNextScan は定期スキャンの占有。
//
// api は複数レプリカで動く (helm の replicaCount は 2)。占有が効かないと
// 全レプリカが同じアカウントを同時にスキャンし、AWS API の呼び出しが
// 台数倍になるうえ、Persist が並行して所見が点滅する。
// leader election の仕組みが無いので、この 1 文の UPDATE が唯一の防御。
func TestCSPMClaimNextScan(t *testing.T) {
	db := cspmTestDB(t)
	s := store.NewCSPMStore(db.Pool())
	ctx := context.Background()

	const roleARN = "arn:aws:iam::123456789012:role/KizashiCSPMReadOnly"
	target := cspmTestAccount(t, db.Pool(), s)
	if err := s.SetCredentials(ctx, target, roleARN, "ext-target", []string{"ap-northeast-1"}); err != nil {
		t.Fatalf("SetCredentials: %v", err)
	}

	// 引受情報が無いアカウントは対象にならない。スキャンしようが無いのに
	// 掴むと、毎周回 'error' に落として無駄にログを埋める。
	noCreds := cspmTestAccount(t, db.Pool(), s)

	// 無効化されたアカウントも対象にならない。
	disabled := cspmTestAccount(t, db.Pool(), s)
	if err := s.SetCredentials(ctx, disabled, roleARN, "ext-disabled", nil); err != nil {
		t.Fatalf("SetCredentials(disabled): %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE cspm_accounts SET enabled = false WHERE id = $1::uuid`, disabled); err != nil {
		t.Fatalf("無効化: %v", err)
	}

	// 対象を掴み切る。DB は他のテストと共有なので、自分の行が出てくることと
	// 重複が出ないことで判定する。
	claimAll := func() map[string]bool {
		t.Helper()
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			got, err := s.ClaimNextScan(ctx, time.Hour, 30*time.Minute)
			if err != nil {
				t.Fatalf("ClaimNextScan: %v", err)
			}
			if got == nil {
				return seen
			}
			if seen[got.AccountUUID] {
				t.Fatalf("同じアカウントを 2 回掴んだ: %s", got.AccountUUID)
			}
			seen[got.AccountUUID] = true
		}
		t.Fatal("占有が解放され続けている (50 回掴んでも尽きない)")
		return nil
	}

	first := claimAll()
	if !first[target] {
		t.Error("引受情報のあるアカウントが対象にならなかった")
	}
	if first[noCreds] {
		t.Error("引受情報の無いアカウントを掴んだ")
	}
	if first[disabled] {
		t.Error("無効化されたアカウントを掴んだ")
	}

	// ここが本題。すべて 'scanning' になったので、2 台目のレプリカに
	// 相当する 2 回目の掃引では 1 件も掴めない。
	if again, err := s.ClaimNextScan(ctx, time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("ClaimNextScan(2 回目): %v", err)
	} else if again != nil {
		t.Errorf("占有済みのアカウントを別レプリカが掴めてしまう: %s", again.AccountUUID)
	}

	// 掴んだ側は引受情報を受け取れていること。ここが欠けると
	// スキャナが起動できない。
	claimed, err := s.Credentials(ctx, target)
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if claimed.RoleARN != roleARN || claimed.ExternalID != "ext-target" {
		t.Errorf("引受情報が取れていない: %+v", claimed)
	}

	// プロセスが検査中に落ちると scan_status は 'scanning' で残る。
	// 解放されないと、そのアカウントは二度とスキャンされない。
	// 落ちたことは画面にも出ないので、最も気づきにくい止まり方になる。
	if _, err := db.Pool().Exec(ctx, `
		UPDATE cspm_accounts SET last_scan_started_at = NOW() - INTERVAL '2 hours'
		 WHERE id = $1::uuid`, target); err != nil {
		t.Fatalf("古い占有の作成: %v", err)
	}
	stale, err := s.ClaimNextScan(ctx, time.Hour, 30*time.Minute)
	if err != nil {
		t.Fatalf("ClaimNextScan(stale): %v", err)
	}
	if stale == nil || stale.AccountUUID != target {
		t.Fatalf("放置された占有が解放されない (got %v)", stale)
	}

	// 直近にスキャン済みのアカウントは、間隔が空くまで対象にしない。
	if err := s.SetScanStatus(ctx, target, "completed", nil); err != nil {
		t.Fatalf("SetScanStatus: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE cspm_accounts SET last_scanned_at = NOW() WHERE id = $1::uuid`, target); err != nil {
		t.Fatalf("last_scanned_at の更新: %v", err)
	}
	if got, err := s.ClaimNextScan(ctx, time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("ClaimNextScan(間隔内): %v", err)
	} else if got != nil && got.AccountUUID == target {
		t.Error("スキャン直後のアカウントを再び掴んだ (間隔が効いていない)")
	}
}

func openResourceIDs(t *testing.T, pool *pgxpool.Pool, accountUUID, checkID, region string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT resource_id FROM cspm_findings
		 WHERE account_id = $1::uuid AND check_id = $2 AND COALESCE(region, '') = $3
		   AND status = 'open' ORDER BY resource_id`, accountUUID, checkID, region)
	if err != nil {
		t.Fatalf("open 所見の取得: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func countFindings(t *testing.T, pool *pgxpool.Pool, accountUUID, status string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM cspm_findings
		 WHERE account_id = $1::uuid AND status = $2`, accountUUID, status).Scan(&n); err != nil {
		t.Fatalf("所見の件数取得: %v", err)
	}
	return n
}
