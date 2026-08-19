package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 到達できなかったスキャンは失敗であって「脆弱性0件」ではありません。
//
// 以前 runOWASPScan は接続できなくても (findings, 0) を返し、呼び出し側は
// それを status='completed', vulns_found=0 として記録していました。
// 診断のために走らせる機能が、失敗を最良の結果として報告します。
func TestAnUnreachableTargetIsAFailureNotACleanScan(t *testing.T) {
	// 起動してすぐ閉じたサーバの URL。ポートは誰も listen していません。
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	findings, endpoints, err := runOWASPScan(context.Background(), url)
	if err == nil {
		t.Fatalf("接続できないURLがエラーになりません: findings=%d endpoints=%d", len(findings), endpoints)
	}
	if findings != nil {
		t.Errorf("失敗時に所見を返しています: %v", findings)
	}
	if endpoints != 0 {
		t.Errorf("失敗時に endpoints=%d を返しています", endpoints)
	}
	if !strings.Contains(err.Error(), "接続できませんでした") {
		t.Errorf("理由が読み取れません: %v", err)
	}
}

// 無効なURLは「調べた結果」です。到達失敗と同じ扱いにすると、指定ミスを
// 伝える所見まで消えます。
func TestAnInvalidTargetIsStillAFinding(t *testing.T) {
	findings, _, err := runOWASPScan(context.Background(), "not a url at all")
	if err != nil {
		t.Fatalf("無効なURLはエラーではなく所見です: %v", err)
	}
	if len(findings) != 1 || findings[0].VulnType != "invalid_target" {
		t.Fatalf("invalid_target の所見が返りません: %+v", findings)
	}
}

// 到達できたときは所見の有無にかかわらずエラーではありません。ヘッダを
// すべて備えた相手に対して「スキャン失敗」と言い出さないこと。
func TestAReachableTargetIsNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, endpoints, err := runOWASPScan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("到達できた相手でエラーになりました: %v", err)
	}
	if endpoints == 0 {
		t.Error("到達したのに endpoints=0 です")
	}
	// httptest はセキュリティヘッダを何も付けないので、所見は出るはずです。
	// ここが0件なら、走査そのものが動いていません。
	if len(findings) == 0 {
		t.Error("ヘッダ無しの相手に所見が1件も出ていません。走査が動いていません")
	}
}

// 走らなかったスキャンが 'completed' として記録されないこと。
//
// この検査を書く前は、UPDATE の 'failed' を 'completed' に書き換える変異が
// 生き残りました。判断が呼び出し側の SQL 文字列の中にあり、どのテストも
// 触っていなかったためです。
func TestAFailedScanIsNotRecordedAsCompleted(t *testing.T) {
	for _, c := range []struct {
		name       string
		err        error
		wantStatus string
		wantReason string
	}{
		{"到達できなかった", errors.New("接続できませんでした"), "failed", "接続できませんでした"},
		{"走り切った", nil, "completed", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, reason := scanOutcome(c.err)
			if status != c.wantStatus {
				t.Errorf("status = %q, want %q", status, c.wantStatus)
			}
			if reason != c.wantReason {
				t.Errorf("reason = %q, want %q", reason, c.wantReason)
			}
		})
	}
}

// 読めない ?from で CSV を書き出さないこと。
//
// 400 は Store に触る前に返るので、ここでは Store を持たないハンドラで
// 確かめられます。逆に言うと、判定が外れていれば nil の Store に届いて
// panic するので、素通りは見逃されません。
func TestTheCSVExportRefusesAnUnreadableBound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, q := range []string{"from=2026-03-17", "to=not-a-date", "from=01/01/2026"} {
		t.Run(q, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/alerts/export?"+q, nil)

			(&AlertHandler{}).Export(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400 (全期間の1万件を書き出しています)", q, w.Code)
			}
		})
	}
}

// 読める範囲は 400 にしないこと。上の検査だけだと「常に400」で通ります。
func TestAReadableBoundIsNotRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet,
		"/alerts?from="+url.QueryEscape("2026-03-17T10:00:00Z"), nil)

	from, to, ok := timeRangeParams(c)
	if !ok {
		t.Fatalf("読める値を拒否しました: %d", w.Code)
	}
	if from == nil {
		t.Error("from が読めていません")
	}
	if to != nil {
		t.Error("指定していない to に値が入っています")
	}
}
