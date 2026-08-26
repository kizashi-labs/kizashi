// Package notification handles alert notifications via multiple channels.
package notification

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/metrics"
)

// Channel types
const (
	ChannelEmail   = "email"
	ChannelSlack   = "slack"
	ChannelWebhook = "webhook"
	ChannelTeams   = "teams"
)

// AlertNotification is the payload sent to notification channels.
type AlertNotification struct {
	AlertID      string
	Title        string
	Severity     int
	Status       string
	Hostname     string
	OS           string
	RuleName     string
	Summary      string // AI-generated Japanese summary (if available)
	AIIsThreat   *bool
	DashboardURL string
	CreatedAt    time.Time
}

// ChannelConfig defines a notification channel.
type ChannelConfig struct {
	ID          string
	Name        string
	Type        string
	Config      map[string]string // channel-specific config
	Enabled     bool
	MinSeverity int
}

// Sender is implemented by each channel type.
type Sender interface {
	Send(ctx context.Context, n *AlertNotification) error
	Type() string
}

// Dispatcher fans out alert notifications to all configured channels.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []ChannelConfig
	senders  map[string]Sender
	baseURL  string
}

func NewDispatcher(baseURL string) *Dispatcher {
	return &Dispatcher{
		senders: make(map[string]Sender),
		baseURL: baseURL,
	}
}

// LoadChannels replaces the current channel configuration.
//
// センダーの表は毎回作り直します。以前は既存の表に上書きしていたため、
// 設定を壊したチャネル（newSender が拒否したチャネル）については
// 古いセンダーが残り、旧い webhook URL に送信し続けていました。
// 「設定を直したのに反映されない」ではなく「設定を壊したのに動き続ける」
// 側の挙動なので、運用中は気づけません。
func (d *Dispatcher) LoadChannels(channels []ChannelConfig) {
	senders := make(map[string]Sender, len(channels))
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		sender, err := newSender(ch)
		if err != nil {
			metrics.BackgroundFailed("notification_channels", err, "通知チャンネルの初期化に失敗しました",
				"channel", ch.Name,
				"type", ch.Type,
				"error", err)
			continue
		}
		senders[ch.ID] = sender
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = channels
	d.senders = senders
}

// NotifyResult reports what one fan-out actually achieved.
//
// Notify's callers (the alert path) fire and forget: a failed send is logged
// and counted, and the alert is in the console regardless. NotifyText's caller
// is a playbook action, and there "the notification went out" is the entire
// result being reported to the operator — so it needs to know whether anything
// was sent, not merely that the attempt was made.
//
// **EnabledChannels / FailedChannels ではこれの代わりにならない。** あちらは
// センダーを作れたかどうか、つまり設定の話しかしていない。センダーが作れた
// チャンネルが送信時に落ちる (webhook が 405、SMTP が 535 を返す) 場合、
// FailedChannels は 0 のままで、EnabledChannels は落ちたチャンネルまで
// 数え込む。有効 3 件のうち 1 件しか届いていない状態が
// EnabledChannels()=3 / FailedChannels()=0 と表示された実例がある。
// 「送ろうとした数」ではなく「届いた数」を知るには、送信のあとに出る
// これを見るしかない。
type NotifyResult struct {
	Eligible int // channels enabled and above their severity floor
	Sent     int
	Failed   int
	// FailedNames は送信時に落ちたチャンネル名。件数だけだと、どれが
	// 落ちたのかを探すのに起動時ログまで遡ることになる。
	FailedNames []string
}

// Notify sends an alert notification to all eligible channels concurrently,
// and reports how many of them it actually reached.
//
// 戻り値を無視しても構わない (アラート経路は握り潰してよい)。ただし人が
// 見ていない定期実行から呼ぶ場合は、必ず Sent / Failed を確認すること。
func (d *Dispatcher) Notify(ctx context.Context, alert *AlertNotification) NotifyResult {
	d.mu.RLock()
	channels := make([]ChannelConfig, len(d.channels))
	copy(channels, d.channels)
	d.mu.RUnlock()

	// 呼び出し側がリンク先を決めていればそれを使う。アラート以外
	// (CSPM の定期スキャン等) は /alerts/<id> に対応する画面が無く、
	// 既定のまま送ると存在しないページへのリンクを踏ませることになる。
	if alert.DashboardURL == "" {
		alert.DashboardURL = fmt.Sprintf("%s/alerts/%s", d.baseURL, alert.AlertID)
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		result NotifyResult
	)
	for _, ch := range channels {
		if !ch.Enabled || alert.Severity < ch.MinSeverity {
			continue
		}

		d.mu.RLock()
		sender, ok := d.senders[ch.ID]
		d.mu.RUnlock()
		if !ok {
			continue
		}

		result.Eligible++
		wg.Add(1)
		go func(s Sender, c ChannelConfig) {
			defer wg.Done()
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			err := s.Send(sendCtx, alert)
			mu.Lock()
			if err != nil {
				result.Failed++
				result.FailedNames = append(result.FailedNames, c.Name)
			} else {
				result.Sent++
			}
			mu.Unlock()

			if err != nil {
				metrics.NotifsError.Add(1)
				slog.Warn("通知の送信に失敗しました",
					"channel", c.Name,
					"type", c.Type,
					"alert", alert.AlertID,
					"error", err,
				)
			} else {
				metrics.NotifsSent.Add(1)
				slog.Debug("通知を送信しました",
					"channel", c.Name,
					"alert", alert.AlertID,
				)
			}
		}(sender, ch)
	}
	wg.Wait()
	// 送信は並行なので FailedNames の順序は毎回変わる。ログとして読む側にも
	// テストにも順序が安定していたほうが都合がよいので、ここで揃える。
	sort.Strings(result.FailedNames)

	// ファンアウト 1 回分の結末をここで 1 度だけ数える。
	//
	// **送信ごとの NotifsError では「一部だけ死んでいる」が見えない。**
	// あれは失敗の総数なので、3 チャンネル中 1 つが毎回落ちている状態と、
	// たまたま 1 回だけ落ちた状態が同じ増え方をする。監視を貼るなら
	// 「その通知はどこにも届かなかった」「届かない送信先が混じっている」
	// という結末の単位が要る。LoadChannels の失敗 (notification_channels)
	// とも分けてある ---あちらは設定の誤り、こちらは送信先の側の問題で、
	// 直す相手が違う。
	switch {
	case result.Eligible == 0:
		// 送信先が 0 件なのは設定の話で、送信の失敗ではない。呼び出し側が
		// 判断する (アラート経路では正常、定期実行では警告に値する)。
	case result.Sent == 0:
		metrics.BackgroundFailed("notification_delivery",
			fmt.Errorf("%d件すべて失敗 (%v)", result.Failed, result.FailedNames),
			"通知がどこにも届きませんでした",
			"alert", alert.AlertID, "title", alert.Title, "failed", result.Failed)
	case result.Failed > 0:
		metrics.BackgroundFailed("notification_delivery",
			fmt.Errorf("%d件失敗 (%v)", result.Failed, result.FailedNames),
			"一部のチャンネルに通知が届きませんでした",
			"alert", alert.AlertID, "sent", result.Sent, "failed", result.Failed)
	}
	return result
}

// EnabledChannels は実際に送信できるチャンネルの数。
//
// Notify は送信先が 0 件でも静かに何もしない。呼び出し側が「送った」と
// 思い込むのを防ぐために公開している。定期実行のように人が見ていない
// 経路では、届かなかったことに気づく手段がこれしかない。
//
// 同じ問題に対する答えが、この型には2つある。**どちらも要る**:
// 送信先が 0 件でも黙っている `Notify` を使う側は、呼ぶ前にこれで
// 数えるしかない。一方 `NotifyText` は自分で error を返せるので、
// 数えさせるのではなく下のように答える。
func (d *Dispatcher) EnabledChannels() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	n := 0
	for _, ch := range d.channels {
		if !ch.Enabled {
			continue
		}
		if _, ok := d.senders[ch.ID]; ok {
			n++
		}
	}
	return n
}

// FailedChannels は「有効なのに送信実装を作れなかった」チャンネルの数。
//
// LoadChannels は失敗を Warn 1 行に残すだけで、そのチャンネルは以後
// 存在しないものとして扱われる。他に生きたチャンネルが 1 つでもあれば
// EnabledChannels は 0 にならないので、片方だけ黙って落ちている状態は
// 素通りする。実際に webhook_generic が落ちて email だけ生きている環境で
// 起きた。人が見ていない経路では、これを呼んで気づくしかない。
func (d *Dispatcher) FailedChannels() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	n := 0
	for _, ch := range d.channels {
		if !ch.Enabled {
			continue
		}
		if _, ok := d.senders[ch.ID]; !ok {
			n++
		}
	}
	return n
}

// NotifyText sends a plain-text message through all channels (used by
// playbooks), and reports whether it reached anything.
//
// これは以前 nil を返していました。設定済みのチャネルが1つも無い場合も、
// 全チャネルの送信が失敗した場合も「成功」です。呼び出し元はプレイブックの
// notify アクションで、実行ログには成功として残り、コンソールには
// 「通知しました」と表示されます。SOC が失うのは通知そのものではなく
// 「通知は飛んでいる」という確信で、送信ごとの警告ログはその確信を揺るがしません。
func (d *Dispatcher) NotifyText(ctx context.Context, message string, severity int) error {
	n := &AlertNotification{
		AlertID:   "playbook",
		Title:     "[プレイブック] " + message,
		Severity:  severity,
		Status:    "open",
		RuleName:  "プレイブック自動通知",
		Summary:   message,
		CreatedAt: time.Now(),
	}
	r := d.Notify(ctx, n)
	switch {
	case r.Eligible == 0:
		return fmt.Errorf("通知の送信先がありません (重大度 %d 以上で有効なチャンネルが0件)", severity)
	case r.Sent == 0:
		return fmt.Errorf("通知の送信が%d件すべて失敗しました", r.Failed)
	}
	return nil
}

// TestChannel sends a test notification to a single channel.
func (d *Dispatcher) TestChannel(ctx context.Context, channelID string) error {
	d.mu.RLock()
	sender, ok := d.senders[channelID]
	d.mu.RUnlock()

	if !ok {
		return fmt.Errorf("チャンネルが見つかりません: %s", channelID)
	}

	test := &AlertNotification{
		AlertID:      "test-alert-id",
		Title:        "[テスト] EDR Platform 通知テスト",
		Severity:     7,
		Status:       "open",
		Hostname:     "test-endpoint",
		OS:           "windows",
		RuleName:     "Test Rule",
		Summary:      "これはEDR Platformからのテスト通知です。",
		DashboardURL: fmt.Sprintf("%s/alerts/test", d.baseURL),
		CreatedAt:    time.Now(),
	}

	return sender.Send(ctx, test)
}

// newSender builds the sender for one channel, or reports why it cannot.
//
// **「届かない」には別々の原因が2つあり、どちらもここで塞ぐ。**
//
// 1つめは種別の語彙が 2 つあること。notification_channels テーブルは 1 つだが、
// 書く側と読む側で名前が揃っていない。
//
//	API / 画面が保存する値 : webhook_slack, webhook_teams, webhook_generic, email
//	notify.Notifier が読む値: 同上 (一致している)
//	ここ (Dispatcher) の定数: slack, teams, webhook, email
//
// このため webhook_* で保存されたチャンネルは Dispatcher 側で
// 「不明なチャンネルタイプ」となり、**送信先に一切載らなかった**。
// 行は存在して enabled = true なのに、Notify は静かに何もしない。
// 起動時の Warn 1 行以外に手がかりが無く、「設定したのに届かない」に見える。
// 語彙を片方に寄せる移行はデータの書き換えを伴うので、まず両方を受ける。
// 設定キーも同様で、API は webhook_url に入れるがここは url を読んでいた。
//
// 2つめは宛先が空でもセンダーが作れてしまうこと。作ってしまうと、そのチャネルは
// d.senders に登録されて「設定済み」に見え、アラートが来るたびに送信が失敗して
// ログとメトリクスを埋めます。SOC にとっての実害は「Slack に通知が飛んでいる
// つもりだった」という状態そのものなので、宛先の欠落はここで一度だけ報告して
// 登録しない方が、毎回失敗するより見つけやすくなります。
//
// **別名を受けることと、宛先の欠落を弾くことは両立する。** 別名を受ける側だけを
// 採ると、URL が空のまま登録される状態に戻る —— 種別が読めるようになった分、
// かえって「設定済みに見えて毎回失敗する」行が増える。`required` が複数キーを
// 順に見るので、webhook_url → url の優先順位はそのまま欠落検出に載る。
func newSender(ch ChannelConfig) (Sender, error) {
	required := func(keys ...string) (string, error) {
		for _, k := range keys {
			if v := ch.Config[k]; v != "" {
				return v, nil
			}
		}
		return "", fmt.Errorf("チャンネル %q (%s) に %v が設定されていません", ch.Name, ch.Type, keys)
	}

	switch ch.Type {
	case ChannelSlack, "webhook_slack":
		url, err := required("webhook_url", "url")
		if err != nil {
			return nil, err
		}
		return NewSlackSender(url), nil
	case ChannelEmail:
		// Support both field naming conventions (frontend: smtp_username/from_address/to_address, legacy: username/from/recipients)
		username := ch.Config["smtp_username"]
		if username == "" {
			username = ch.Config["username"]
		}
		password := ch.Config["smtp_password"]
		if password == "" {
			password = ch.Config["password"]
		}
		from := ch.Config["from_address"]
		if from == "" {
			from = ch.Config["from"]
		}
		recipients, err := required("to_address", "recipients")
		if err != nil {
			return nil, err
		}
		if _, err := required("smtp_host"); err != nil {
			return nil, err
		}
		return NewEmailSender(EmailConfig{
			SMTPHost:      ch.Config["smtp_host"],
			SMTPPort:      ch.Config["smtp_port"],
			Username:      username,
			Password:      password,
			From:          from,
			Recipients:    splitComma(recipients),
			SenderName:    ch.Config["sender_name"],
			SubjectPrefix: ch.Config["subject_prefix"],
		}), nil
	case ChannelWebhook, "webhook_generic":
		url, err := required("webhook_url", "url")
		if err != nil {
			return nil, err
		}
		return NewWebhookSender(url, ch.Config["secret"]), nil
	case ChannelTeams, "webhook_teams":
		url, err := required("webhook_url", "url")
		if err != nil {
			return nil, err
		}
		return NewTeamsSender(url), nil
	default:
		return nil, fmt.Errorf("不明なチャンネルタイプ: %s", ch.Type)
	}
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trimSpace(s[start:i])
			if part != "" {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
