// Package notification handles alert notifications via multiple channels.
package notification

import (
	"context"
	"fmt"
	"log/slog"
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
func (d *Dispatcher) LoadChannels(channels []ChannelConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.channels = channels

	// Build senders
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		sender, err := newSender(ch)
		if err != nil {
			slog.Warn("通知チャンネルの初期化に失敗しました",
				"channel", ch.Name,
				"type", ch.Type,
				"error", err,
			)
			continue
		}
		d.senders[ch.ID] = sender
	}
}

// Notify sends an alert notification to all eligible channels concurrently.
func (d *Dispatcher) Notify(ctx context.Context, alert *AlertNotification) {
	d.mu.RLock()
	channels := make([]ChannelConfig, len(d.channels))
	copy(channels, d.channels)
	d.mu.RUnlock()

	alert.DashboardURL = fmt.Sprintf("%s/alerts/%s", d.baseURL, alert.AlertID)

	var wg sync.WaitGroup
	for _, ch := range channels {
		if !ch.Enabled || alert.Severity < ch.MinSeverity {
			continue
		}

		sender, ok := d.senders[ch.ID]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(s Sender, c ChannelConfig) {
			defer wg.Done()
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			if err := s.Send(sendCtx, alert); err != nil {
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
}

// NotifyText sends a plain-text message through all channels (used by playbooks).
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
	d.Notify(ctx, n)
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

func newSender(ch ChannelConfig) (Sender, error) {
	switch ch.Type {
	case ChannelSlack:
		return NewSlackSender(ch.Config["webhook_url"]), nil
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
		recipients := ch.Config["to_address"]
		if recipients == "" {
			recipients = ch.Config["recipients"]
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
	case ChannelWebhook:
		return NewWebhookSender(ch.Config["url"], ch.Config["secret"]), nil
	case ChannelTeams:
		return NewTeamsSender(ch.Config["webhook_url"]), nil
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
