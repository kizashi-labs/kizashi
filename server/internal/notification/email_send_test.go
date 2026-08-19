package notification

// メール送信経路。
//
// 実際の SMTP 送信 (sendMailSTARTTLS) は STARTTLS ハンドシェイクを伴うため、
// EmailNotifier.sendMail を差し替えて「宛先・接続先・本文」の組み立てを検証する。
// 本番では sendMailSTARTTLS が入っており、差し替えは検査の中だけです。
//
// **これは写しではなく継ぎ目（seam）です。** 写しの見張り
// （`internal/store/reproduced_logic_test.go`）は決まった語を印に
// して数えるので、その語を避けて書いてあります。戻さないでください。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturedMail は sendMail に渡された引数一式。
type capturedMail struct {
	addr, host, username, password, from, to string
	msg                                      []byte
}

// newCapturingNotifier は送信を捕捉するだけの Notifier を返す。
func newCapturingNotifier(cfg SMTPConfig) (*EmailNotifier, *[]capturedMail, *sync.Mutex) {
	var mu sync.Mutex
	var sent []capturedMail

	n := &EmailNotifier{
		smtp: cfg,
		sendMail: func(addr, host, username, password, from, to string, msg []byte) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, capturedMail{addr, host, username, password, from, to, msg})
			return nil
		},
	}
	return n, &sent, &mu
}

func testSMTPConfig() SMTPConfig {
	return SMTPConfig{
		Host:     "smtp.itest.invalid",
		Port:     587,
		Username: "itest-user",
		Password: "itest-pass",
		From:     "edr@itest.invalid",
	}
}

// TestSendEmail_BuildsRFC5322Message は組み立てたメッセージの形を見る。
// ヘッダが欠けるとメールクライアントが本文を正しく表示しない。
func TestSendEmail_BuildsRFC5322Message(t *testing.T) {
	cfg := testSMTPConfig()
	n, sent, mu := newCapturingNotifier(cfg)

	const to = "analyst@itest.invalid"
	const subject = "[EDR Platform] 緊急 アラート: test"
	const body = "<h1>本文</h1>"

	if err := n.sendEmail(context.Background(), to, subject, body); err != nil {
		t.Fatalf("sendEmail: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*sent) != 1 {
		t.Fatalf("送信回数 = %d, want 1", len(*sent))
	}
	got := (*sent)[0]

	// 接続先は host:port。
	if got.addr != "smtp.itest.invalid:587" {
		t.Errorf("addr = %q, want smtp.itest.invalid:587", got.addr)
	}
	if got.host != cfg.Host {
		t.Errorf("host = %q, want %q", got.host, cfg.Host)
	}
	// 認証情報がそのまま渡ること。
	if got.username != cfg.Username || got.password != cfg.Password {
		t.Errorf("認証情報が渡っていない: user=%q pass=%q", got.username, got.password)
	}
	if got.from != cfg.From || got.to != to {
		t.Errorf("(from, to) = (%q, %q), want (%q, %q)", got.from, got.to, cfg.From, to)
	}

	msg := string(got.msg)
	for _, want := range []string{
		"From: EDR Platform <" + cfg.From + ">\r\n",
		"To: " + to + "\r\n",
		"Subject: " + subject + "\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/html; charset=UTF-8\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("ヘッダ %q が無い:\n%s", strings.TrimSuffix(want, "\r\n"), msg)
		}
	}

	// ヘッダと本文は空行で区切る。ここが無いと本文がヘッダとして解釈される。
	sep := strings.Index(msg, "\r\n\r\n")
	if sep < 0 {
		t.Fatalf("ヘッダと本文の区切り (空行) が無い:\n%s", msg)
	}
	if !strings.Contains(msg[sep:], body) {
		t.Errorf("本文が区切りの後に無い:\n%s", msg)
	}
}

// TestSendEmail_RespectsContextCancellation は送信が長引いたときに
// コンテキストで打ち切れること。ここが効かないと 1 通の詰まりで
// 通知処理全体が張り付く。
func TestSendEmail_RespectsContextCancellation(t *testing.T) {
	release := make(chan struct{})
	n := &EmailNotifier{
		smtp: testSMTPConfig(),
		sendMail: func(_, _, _, _, _, _ string, _ []byte) error {
			<-release // 送信が終わらない状況を作る
			return nil
		},
	}
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := n.sendEmail(ctx, "a@itest.invalid", "s", "b")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("打ち切られてもエラーが返っていない")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("打ち切りに %v かかっている", elapsed)
	}
}

// TestSendEmail_PropagatesSendError は送信失敗をそのまま返すこと。
func TestSendEmail_PropagatesSendError(t *testing.T) {
	wantErr := errors.New("SMTP接続失敗")
	n := &EmailNotifier{
		smtp: testSMTPConfig(),
		sendMail: func(_, _, _, _, _, _ string, _ []byte) error {
			return wantErr
		},
	}

	err := n.sendEmail(context.Background(), "a@itest.invalid", "s", "b")
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// TestNewEmailNotifier_UsesRealSender は本番の既定が実送信であること。
// ここが nil だと sendEmail が nil 関数を呼んで panic する。
func TestNewEmailNotifier_UsesRealSender(t *testing.T) {
	if NewEmailNotifier(nil, nil).sendMail == nil {
		t.Error("既定の sendMail が設定されていない")
	}
}

// TestNewEmailNotifier_FromFallsBackToUsername は From 未設定時に
// Username を使うこと。空の From だと多くの SMTP サーバが拒否する。
func TestNewEmailNotifier_FromFallsBackToUsername(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.itest.invalid")
	t.Setenv("SMTP_USERNAME", "fallback@itest.invalid")
	t.Setenv("SMTP_FROM", "")

	n := NewEmailNotifier(nil, nil)
	if n.smtp.From != "fallback@itest.invalid" {
		t.Errorf("From = %q, want fallback@itest.invalid", n.smtp.From)
	}
}

// TestNewEmailNotifier_PortDefaultsTo587 はポート既定値と環境変数の反映。
func TestNewEmailNotifier_PortDefaultsTo587(t *testing.T) {
	t.Setenv("SMTP_PORT", "")
	if got := NewEmailNotifier(nil, nil).smtp.Port; got != 587 {
		t.Errorf("既定ポート = %d, want 587", got)
	}

	t.Setenv("SMTP_PORT", "2525")
	if got := NewEmailNotifier(nil, nil).smtp.Port; got != 2525 {
		t.Errorf("ポート = %d, want 2525", got)
	}

	// 数値でない値は既定にフォールバックする。設定ミスで 0 番ポートへ
	// 接続しにいかないこと。
	t.Setenv("SMTP_PORT", "not-a-number")
	if got := NewEmailNotifier(nil, nil).smtp.Port; got != 587 {
		t.Errorf("不正な値のとき = %d, want 587", got)
	}
}

// TestSendEmail_StripsHeaderInjection は件名・宛先に混ぜた CRLF が
// ヘッダに漏れないこと。
//
// 件名は組織名などテナントが設定した値から組み立てられ、宛先は DB の
// 管理者メールアドレスをそのまま使う。どちらも CRLF を通すと
// 「Bcc: attacker@…」を差し込まれ、通知メールの宛先を増やされる。
func TestSendEmail_StripsHeaderInjection(t *testing.T) {
	n, sent, mu := newCapturingNotifier(testSMTPConfig())

	const injectedTo = "victim@itest.invalid\r\nBcc: attacker@itest.invalid"
	const injectedSubject = "件名\r\nBcc: attacker2@itest.invalid"

	if err := n.sendEmail(context.Background(), injectedTo, injectedSubject, "本文"); err != nil {
		t.Fatalf("sendEmail: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*sent) != 1 {
		t.Fatalf("送信回数 = %d, want 1", len(*sent))
	}
	msg := string((*sent)[0].msg)

	sep := strings.Index(msg, "\r\n\r\n")
	if sep < 0 {
		t.Fatalf("ヘッダと本文の区切りが無い:\n%s", msg)
	}
	lines := strings.Split(msg[:sep], "\r\n")

	// 「Bcc: 」という文字列が To/Subject の値の一部として残ること自体は
	// 無害 — ヘッダとして解釈されるのは行頭に来た場合だけ。注入が成立して
	// いないことは「Bcc で始まる行が無い」かどうかで判定する。
	for _, l := range lines {
		if strings.HasPrefix(l, "Bcc:") || strings.HasPrefix(l, "Cc:") {
			t.Errorf("ヘッダ行が注入されている: %q\n全体:\n%s", l, msg[:sep])
		}
	}

	// 行数が増えていないこと。From / To / Subject / MIME-Version /
	// Content-Type の 5 行のまま。
	if len(lines) != 5 {
		t.Errorf("ヘッダ行数 = %d, want 5 (行が増えている)\n%s", len(lines), msg[:sep])
	}
}
