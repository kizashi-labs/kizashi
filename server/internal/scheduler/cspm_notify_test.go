package scheduler

// 定期スキャンの通知。
//
// ここで一番守りたいのは 2 つ。
//
//  1. 異常が無い回は送らない。毎日「異常なし」が届くと数日で読み飛ばされ、
//     本当に伝えたい回が埋もれる。沈黙が「異常なし」の意味を持つ。
//  2. 逆に、**測れなかった回は必ず送る**。未計測は所見にならないので、
//     送らなければ画面上は「問題なし」と区別が付かない。権限が外れたまま
//     何ヶ月も気づかれない状態になる。
//
// 1 の都合で 2 を落とすのが最も危ない。「静かにする」方向の変更を入れた
// ときに、未計測まで一緒に黙らないことをテストで縛る。

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/cspm/awsscan"
	"github.com/edr-platform/server/internal/notification"
)

var testNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func build(out awsscan.Outcome) *notificationForTest {
	n := buildCSPMNotification("acct-uuid", "https://edr.example.com", out, testNow)
	if n == nil {
		return nil
	}
	return &notificationForTest{Title: n.Title, Body: n.Summary, Severity: n.Severity, Link: n.DashboardURL}
}

type notificationForTest struct {
	Title    string
	Body     string
	Severity int
	Link     string
}

func okOutcome() awsscan.Outcome {
	return awsscan.Outcome{
		AWSAccountID: "103958286651",
		Regions:      1,
		Duration:     7 * time.Second,
		Persisted:    awsscan.PersistResult{Upserted: 62, Resolved: 1},
	}
}

// 異常なしの回は送らない。
func TestNoNotificationWhenNothingChanged(t *testing.T) {
	if got := build(okOutcome()); got != nil {
		t.Errorf("異常が無い回に通知が出ている: %+v", got)
	}
}

// 未計測は必ず送る。所見にならないので、送らなければ画面上「問題なし」と
// 区別が付かない。
func TestUnmeasuredAlwaysNotifies(t *testing.T) {
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{
		{CheckID: "aws-iam-user-mfa", Region: "ap-northeast-1",
			Message: "AccessDenied: not authorized to perform: iam:GetCredentialReport"},
	}

	got := build(out)
	if got == nil {
		t.Fatal("未計測があるのに通知が出ていない")
	}
	if got.Severity != sevUnmeasured {
		t.Errorf("severity = %d, want %d", got.Severity, sevUnmeasured)
	}
	// 何が測れなかったのか、なぜかが本文から分かること。件数だけだと
	// 受け取った側は調査から始めることになる。
	for _, want := range []string{"aws-iam-user-mfa", "iam:GetCredentialReport", "測れていない"} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("本文に %q が無い:\n%s", want, got.Body)
		}
	}
}

// 未計測は、新しい high の所見より重く扱う。所見は「見つかった 1 件」だが、
// 未計測は「何件あるか分からない」状態のため。
func TestUnmeasuredOutranksNewHighFinding(t *testing.T) {
	if sevUnmeasured <= sevNewHigh {
		t.Errorf("未計測 (%d) が新規 high (%d) 以下になっている", sevUnmeasured, sevNewHigh)
	}
}

// スキャンそのものが失敗した回。1 項目も測れていないので、画面の所見が
// 現状を表していないことまで伝える。
func TestScanFailureNotifies(t *testing.T) {
	got := build(awsscan.Outcome{
		AWSAccountID: "103958286651",
		Err:          errScanFailed{},
	})
	if got == nil {
		t.Fatal("スキャン失敗で通知が出ていない")
	}
	if got.Severity != sevScanFailed {
		t.Errorf("severity = %d, want %d", got.Severity, sevScanFailed)
	}
	for _, want := range []string{"1 項目も測れていません", "前回の結果のまま", "AssumeRole に失敗"} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("本文に %q が無い:\n%s", want, got.Body)
		}
	}
}

type errScanFailed struct{}

func (errScanFailed) Error() string { return "AssumeRole に失敗しました: AccessDenied" }

// 引受情報が不正な場合もスキャン失敗として通知される。この経路は
// RunAndPersist を通らないので、通知が抜けやすい。
func TestInvalidCredentialsNotifies(t *testing.T) {
	got := build(awsscan.Outcome{AWSAccountID: "103958286651", Err: errScanFailed{}})
	if got == nil {
		t.Fatal("引受情報が不正な場合に通知が出ていない")
	}
	if !strings.Contains(got.Title, "失敗") {
		t.Errorf("題名から失敗と分からない: %s", got.Title)
	}
}

// 新しい所見の重大度は、最も重いものに合わせる。平均や件数で決めると
// critical 1 件が medium 20 件に薄められる。
func TestNewFindingSeverityUsesWorst(t *testing.T) {
	out := okOutcome()
	out.Persisted.New = []awsscan.NewFinding{
		{CheckID: "a", CheckName: "medium のもの", Severity: awsscan.SeverityMedium, ResourceName: "r1", Region: "ap-northeast-1"},
		{CheckID: "b", CheckName: "critical のもの", Severity: awsscan.SeverityCritical, ResourceName: "r2", Region: "ap-northeast-1"},
		{CheckID: "c", CheckName: "low のもの", Severity: awsscan.SeverityLow, ResourceName: "r3", Region: "ap-northeast-1"},
	}

	got := build(out)
	if got == nil {
		t.Fatal("新しい所見があるのに通知が出ていない")
	}
	if got.Severity != sevNewCritical {
		t.Errorf("severity = %d, want %d (critical が 1 件ある)", got.Severity, sevNewCritical)
	}
	if !strings.Contains(got.Body, "critical のもの") || !strings.Contains(got.Body, "r2") {
		t.Errorf("どの所見が出たか本文から分からない:\n%s", got.Body)
	}
}

// 未計測と新しい所見が同じ回に出たら、1 通にまとめる。別々に送ると
// 1 回のスキャンで 2 通届き、どちらも読まれにくくなる。
func TestUnmeasuredAndNewFindingsShareOneNotification(t *testing.T) {
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "aws-efs-encrypted", Region: "ap-northeast-1", Message: "AccessDenied"}}
	out.Persisted.New = []awsscan.NewFinding{
		{CheckID: "aws-s3-public", CheckName: "S3 が公開されている", Severity: awsscan.SeverityCritical, ResourceName: "my-bucket", Region: "ap-northeast-1"},
	}

	got := build(out)
	if got == nil {
		t.Fatal("通知が出ていない")
	}
	// 未計測が理由で選ばれた題名でも、本文には新しい所見も入っていること。
	if !strings.Contains(got.Body, "aws-efs-encrypted") {
		t.Errorf("未計測が本文から落ちている:\n%s", got.Body)
	}
	if !strings.Contains(got.Body, "my-bucket") {
		t.Errorf("新しい所見が本文から落ちている:\n%s", got.Body)
	}
	// 重い方に合わせる (critical 9 > 未計測 8)。
	if got.Severity != sevNewCritical {
		t.Errorf("severity = %d, want %d", got.Severity, sevNewCritical)
	}
}

// スキャン失敗の回は所見の集計を載せない。測れていないので、
// 「所見 0 件」と書くと最も誤解を招く。
func TestScanFailureDoesNotReportCounts(t *testing.T) {
	got := build(awsscan.Outcome{AWSAccountID: "103958286651", Err: errScanFailed{}})
	if strings.Contains(got.Body, "所見 0 件") {
		t.Errorf("測れていない回に件数を出している:\n%s", got.Body)
	}
}

// 一覧は打ち切る。全部並べると Slack で折りたたまれて先頭しか読まれない。
func TestListsAreTruncated(t *testing.T) {
	out := okOutcome()
	for i := 0; i < notifyListLimit+3; i++ {
		out.Unmeasured = append(out.Unmeasured,
			awsscan.ScanError{CheckID: "check", Region: "ap-northeast-1", Message: "AccessDenied"})
	}

	got := build(out)
	if !strings.Contains(got.Body, "他 3 件") {
		t.Errorf("打ち切りの表示が無い:\n%s", got.Body)
	}
}

// リンク先は CSPM の画面。既定の /alerts/<id> は対応する画面が無いので、
// そのまま送ると存在しないページを踏ませる。
//
// 最初 "/cspm" と書いていたが、そんな画面は無かった。所見を表示して
// いるのは frontend/app/cloud-security/。存在しないページへのリンクを
// 避けるために上書き可能にしたのに、差し替え先を確認していなかった。
// 実在するパスであることは frontend 側と突き合わせて確認すること
// (ここで固定しているのは「既定のままではない」ことだけ)。
func TestLinksToCSPMScreen(t *testing.T) {
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "m"}}

	got := build(out)
	if got.Link != "https://edr.example.com/cloud-security" {
		t.Errorf("リンク先 = %q, want https://edr.example.com/cloud-security", got.Link)
	}
	if strings.Contains(got.Link, "/alerts/") {
		t.Errorf("既定のアラート画面のままになっている: %s", got.Link)
	}
}

// AWS アカウント ID が取れていない場合 (引受前に失敗した等) でも、
// どのアカウントの話か分かること。
func TestFallsBackToUUIDWhenAccountIDUnknown(t *testing.T) {
	got := build(awsscan.Outcome{Err: errScanFailed{}})
	if !strings.Contains(got.Title, "acct-uuid") {
		t.Errorf("題名からアカウントが分からない: %s", got.Title)
	}
}

// 送信先が 0 件のときは送らずに警告だけ出す。Dispatcher は 0 件でも
// 静かに何もしないので、ここで止めないと「通知したつもり」になる。
type fakeNotifier struct {
	channels int
	failed   int
	sent     int

	// result は Notify が返す送信結果。既定 (ゼロ値) のままだと
	// Eligible = 0 になるので、送信を試行した体にしたいテストは
	// 明示的に埋める。
	result notification.NotifyResult
}

func (f *fakeNotifier) EnabledChannels() int { return f.channels }
func (f *fakeNotifier) FailedChannels() int  { return f.failed }
func (f *fakeNotifier) Notify(context.Context, *notification.AlertNotification) notification.NotifyResult {
	f.sent++
	return f.result
}

func TestNoChannelsMeansNoSend(t *testing.T) {
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "AccessDenied"}}

	f := &fakeNotifier{channels: 0}
	s := NewCSPMScanner(nil, time.Minute, time.Hour).WithNotifier(f, "https://edr.example.com")
	s.notifyCSPM(context.Background(), "acct-uuid", out)
	if f.sent != 0 {
		t.Errorf("送信先が無いのに送っている (sent=%d)", f.sent)
	}

	f.channels = 1
	s.notifyCSPM(context.Background(), "acct-uuid", out)
	if f.sent != 1 {
		t.Errorf("送信先があるのに送っていない (sent=%d)", f.sent)
	}
}

// 通知先が未設定でも定期スキャン自体は動く。通知は付加機能であって、
// 検査を止める理由にはならない。
func TestNilNotifierIsSafe(t *testing.T) {
	s := NewCSPMScanner(nil, time.Minute, time.Hour)
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "m"}}
	s.notifyCSPM(context.Background(), "acct-uuid", out) // panic しないこと
}

// 未計測がある回の件数は「今回測れた範囲」でしかない。読めなかった項目の
// 所見は open のまま残っているので、総数ではない。
//
// これを素の「所見 N 件」として出すと、前回の件数を知っている担当者には
// 減った = 改善したと読める。実際に権限を 1 つ外した検証で、62 件抱えた
// アカウントの通知に「所見 30 件」と出た (未計測 3 項目分の 32 件が
// 今回のスキャンで生成されなかったため)。unknown を pass に寄せない
// 設計にしておきながら、最後の 1 行で安心できる嘘を出していた。
func TestCountsAreScopedWhenUnmeasured(t *testing.T) {
	out := okOutcome()
	out.Persisted.Upserted = 30 // 62 件のうち 32 件は測れなかった
	out.Unmeasured = []awsscan.ScanError{
		{CheckID: "aws-iam-user-mfa", Region: "ap-northeast-1", Message: "AccessDenied"},
	}

	got := build(out)
	if !strings.Contains(got.Body, "測れた範囲の所見 30 件") {
		t.Errorf("件数の範囲が明示されていない:\n%s", got.Body)
	}
	if !strings.Contains(got.Body, "前回と比較できません") {
		t.Errorf("前回と比較できない旨が無い:\n%s", got.Body)
	}
	if !strings.Contains(got.Body, "閉じずに残しています") {
		t.Errorf("所見が残っていることが書かれていない:\n%s", got.Body)
	}
}

// 全項目測れた回は、断り書きを付けない。毎回付けると意味を失う。
func TestCountsArePlainWhenFullyMeasured(t *testing.T) {
	out := okOutcome()
	out.Persisted.New = []awsscan.NewFinding{
		{CheckID: "a", CheckName: "何か", Severity: awsscan.SeverityLow, ResourceName: "r", Region: "ap-northeast-1"},
	}

	got := build(out)
	if !strings.Contains(got.Body, "所見 62 件") || strings.Contains(got.Body, "測れた範囲の所見") {
		t.Errorf("全項目測れた回に範囲の断りが付いている:\n%s", got.Body)
	}
	if strings.Contains(got.Body, "前回と比較できません") {
		t.Errorf("全項目測れた回に比較不可の断りが付いている:\n%s", got.Body)
	}
}

// 一部のチャンネルだけ落ちている場合でも送信自体は続ける。生きている
// 送信先には届けたい。ただし黙って続けない (notifyCSPM が警告を出す)。
//
// 実際に webhook_generic が Dispatcher 側で認識されず、email だけ生きて
// いる環境が発生した。EnabledChannels は 1 を返すので、これだけを見て
// いると「送信先はある」と判断してしまう。
func TestPartialChannelFailureStillSends(t *testing.T) {
	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "AccessDenied"}}

	f := &fakeNotifier{channels: 1, failed: 1}
	s := NewCSPMScanner(nil, time.Minute, time.Hour).WithNotifier(f, "https://edr.example.com")
	s.notifyCSPM(context.Background(), "acct-uuid", out)
	if f.sent != 1 {
		t.Errorf("生きている送信先があるのに送っていない (sent=%d)", f.sent)
	}
}

// captureLogs は既定のロガーを差し替えて出力を集める。
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// 重大度が全チャンネルの下限に届かず 1 件も送信されなかった回を言うこと。
//
// **これは Dispatcher 側では言えない。** 送信を 1 件も試行していないので
// あちらから見れば失敗 0 件で、notification_delivery は何も記録しない。
// EnabledChannels も 0 にならない (チャンネルは生きている)。
// 定期実行は人が見ていないので、ここで言わなければ誰も気づかない。
func TestNothingSentBecauseOfSeverityFloorIsReported(t *testing.T) {
	logs := captureLogs(t)

	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "AccessDenied"}}

	// チャンネルは有効で、センダーも作れている。しかし MinSeverity で
	// 全部ふるい落とされて Eligible = 0 になった状態。
	f := &fakeNotifier{channels: 2, result: notification.NotifyResult{}}
	s := NewCSPMScanner(nil, time.Minute, time.Hour).WithNotifier(f, "https://edr.example.com")
	s.notifyCSPM(context.Background(), "acct-uuid", out)

	if f.sent != 1 {
		t.Fatalf("送信が試行されていない (sent=%d)", f.sent)
	}
	if !strings.Contains(logs.String(), "どこにも送られませんでした") {
		t.Errorf("1 件も送られなかったのに警告が出ていない:\n%s", logs.String())
	}
}

// 逆に、届いた回に警告を出さないこと。毎回警告が出ると読まれなくなり、
// 本当に届かなかった回が埋もれる ---この機能が防ごうとしているものと
// 同じ失敗をここで作ることになる。
func TestSuccessfulDeliveryIsQuiet(t *testing.T) {
	logs := captureLogs(t)

	out := okOutcome()
	out.Unmeasured = []awsscan.ScanError{{CheckID: "c", Region: "r", Message: "AccessDenied"}}

	f := &fakeNotifier{channels: 2, result: notification.NotifyResult{Eligible: 2, Sent: 2}}
	s := NewCSPMScanner(nil, time.Minute, time.Hour).WithNotifier(f, "https://edr.example.com")
	s.notifyCSPM(context.Background(), "acct-uuid", out)

	if strings.Contains(logs.String(), "どこにも送られませんでした") {
		t.Errorf("届いた回に警告が出ている:\n%s", logs.String())
	}
}
