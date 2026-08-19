package response

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 隔離したファイルは、サーバに記録が届いてはじめて `/quarantine` の
// 一覧に出ます。**一覧に出ないファイルは、画面から復元できません。**
//
// 以前 reportQuarantineToServer は、JSON 生成・リクエスト生成・送信・
// HTTP 4xx/5xx のどれで失敗しても slog.Warn を1行出して黙って戻り、
// その下の ackSuccess が無条件に成功を返していました。サーバ側には
// 「隔離成功」だけが残ります —— **ファイルは端末から消えていて、
// 一覧には無く、復元ボタンも出ません。**
//
// ここで留めるのは2つです:
//
//   1. 記録が届かなかったことが、ack に**出る**こと
//   2. それでも ack は**成功のまま**であること
//
// 2 を落とすと逆の間違いになります。隔離そのものは成功しているのに
// 「隔離に失敗しました」と画面に出れば、担当者はもう一度隔離を試み、
// すでに移動済みのパスに対して失敗し続けます。**失敗しているのは
// 「一覧に出ること」で、それは別の事実です。**

const testQuarantineID = "quar-report-001"

// newQuarantineExecutor は隔離が必ず成功する Executor を、指定の
// サーバ宛先で作ります。
func newQuarantineExecutor(server string, ack *mockAckSender) *Executor {
	return NewExecutor(
		&mockIsolationManager{},
		&mockProcessManager{},
		&mockFileQuarantine{quarantineID: testQuarantineID},
		"agent-001",
		server,
		ack,
	)
}

func runQuarantine(exec *Executor) {
	exec.QuarantineFile(context.Background(), QuarantineFileCmd{
		CommandID: "qf-report",
		Path:      "/tmp/evil.exe",
		Reason:    "report path under test",
		AlertID:   "alert-111",
	})
}

// assertReportFailureIsSurfaced は「隔離は成功、記録は届かなかった」が
// ack から読み取れることを確かめます。
func assertReportFailureIsSurfaced(t *testing.T, ack *mockAckSender) {
	t.Helper()
	if ack.calls != 1 {
		t.Fatalf("ack 回数 = %d, want 1", ack.calls)
	}
	if !ack.success {
		t.Error("ack が失敗になっています。**隔離そのものは成功しています** —— " +
			"失敗として返すと、担当者は移動済みのファイルに隔離を再試行します")
	}
	got := string(ack.result)
	if got == testQuarantineID {
		t.Fatal("記録が届かなかったのに、ack の中身が全部通ったときと同じです。" +
			"**サーバには「隔離成功」だけが残り、/quarantine の一覧には出ません** —— " +
			"隔離されたファイルが画面から復元できなくなります")
	}
	if !strings.Contains(got, testQuarantineID) {
		t.Errorf("ack の中身 = %q。隔離ID が消えています —— "+
			"一覧に出ない以上、この ID だけが端末側の隔離を指す手掛かりです", got)
	}
}

// TestQuarantineRecordRejectedIsSurfaced — サーバが受け取ったが拒否した場合。
// **2xx でないのは、届いていないのと同じです。**
func TestQuarantineRecordRejectedIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ack := &mockAckSender{}
	runQuarantine(newQuarantineExecutor(srv.URL, ack))
	assertReportFailureIsSurfaced(t, ack)
}

// TestQuarantineRecordUnreachableIsSurfaced — サーバに届かなかった場合。
// 停止済みの httptest の宛先を使うので、接続は即座に拒否されます。
func TestQuarantineRecordUnreachableIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	ack := &mockAckSender{}
	runQuarantine(newQuarantineExecutor(dead, ack))
	assertReportFailureIsSurfaced(t, ack)
}

// TestQuarantineWithNoServerIsNotAFailure — 宛先そのものが構成されて
// いない場合。**記録先が無いことは、記録が落ちたことではありません。**
// ここまで「未記録」を出すと、宛先を持たない構成で毎回警告が出ます。
func TestQuarantineWithNoServerIsNotAFailure(t *testing.T) {
	ack := &mockAckSender{}
	runQuarantine(newQuarantineExecutor("", ack))

	if !ack.success {
		t.Fatal("宛先の無い構成で ack が失敗になっています")
	}
	if string(ack.result) != testQuarantineID {
		t.Errorf("ack の中身 = %q, want %q", ack.result, testQuarantineID)
	}
}

// TestQuarantineRecordCarriesWhatTheListNeeds — 届いた記録に、一覧と
// 復元に要るものが載っていること。
//
// **ID が欠けた記録は、届いても復元できません。** サーバはこの
// quarantine_id を復元コマンドで端末に送り返します。
func TestQuarantineRecordCarriesWhatTheListNeeds(t *testing.T) {
	var got map[string]interface{}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ack := &mockAckSender{}
	runQuarantine(newQuarantineExecutor(srv.URL, ack))

	if want := "/api/v1/agents/agent-001/quarantine-result"; gotPath != want {
		t.Errorf("宛先のパス = %q, want %q", gotPath, want)
	}
	if got["quarantine_id"] != testQuarantineID {
		t.Errorf("quarantine_id = %v, want %q。**これが無いと、"+
			"一覧に出ても復元コマンドが端末側の隔離を指せません**",
			got["quarantine_id"], testQuarantineID)
	}
	if got["path"] != "/tmp/evil.exe" {
		t.Errorf("path = %v, want /tmp/evil.exe", got["path"])
	}
	if got["alert_id"] != "alert-111" {
		t.Errorf("alert_id = %v, want alert-111", got["alert_id"])
	}
}
