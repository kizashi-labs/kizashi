package notification

import (
	"strings"
	"testing"
)

// newSender built a sender out of whatever was in ch.Config, including nothing.
// An empty map produced a Slack sender with an empty webhook URL, a webhook
// sender pointed at "", an email sender with no host and no recipients — and
// the dispatcher then registered it, so the channel looked configured and every
// alert failed to send.
//
// Two things fed that empty map. store.ListChannels discarded the error from
// json.Unmarshal on the stored config, so a malformed blob became an empty
// Config with no complaint; and newSender never checked that the destination it
// needed was actually there.
//
// The damage is not the failed send — those are logged and counted. It is that
// the console shows the channel as enabled and healthy, so the belief "our
// Slack alerts are going out" survives. For a SOC that belief is the whole
// point of the channel, and a per-alert error in a log nobody is reading does
// not disturb it. Reporting once, at load, and refusing to register the channel
// does.

// The headline: a channel with no destination is refused rather than built.
func TestAChannelWithNoDestinationIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		ch   ChannelConfig
	}{
		{"slack with no webhook", ChannelConfig{
			Name: "c", Type: ChannelSlack, Config: map[string]string{}}},
		{"slack with an empty webhook", ChannelConfig{
			Name: "c", Type: ChannelSlack, Config: map[string]string{"webhook_url": ""}}},
		{"teams with no webhook", ChannelConfig{
			Name: "c", Type: ChannelTeams, Config: map[string]string{}}},
		{"webhook with no url", ChannelConfig{
			Name: "c", Type: ChannelWebhook, Config: map[string]string{"secret": "s"}}},
		{"email with no recipients", ChannelConfig{
			Name: "c", Type: ChannelEmail, Config: map[string]string{"smtp_host": "smtp.example.invalid"}}},
		{"email with no host", ChannelConfig{
			Name: "c", Type: ChannelEmail, Config: map[string]string{"to_address": "soc@example.invalid"}}},
		{"config is nil", ChannelConfig{
			Name: "c", Type: ChannelSlack}},
	} {
		s, err := newSender(tc.ch)
		if err == nil {
			t.Errorf("%s: 宛先が無いのにセンダーを作りました (%T)。"+
				"作ってしまうと dispatcher に登録され、"+
				"コンソール上は設定済みに見えたままアラートごとに送信が失敗します",
				tc.name, s)
		}
		if s != nil {
			t.Errorf("%s: エラーと同時にセンダーを返しています", tc.name)
		}
	}
}

// And a properly configured channel of each type still builds, or the check
// above is just "everything is refused".
func TestAConfiguredChannelStillBuilds(t *testing.T) {
	for _, tc := range []struct {
		name string
		ch   ChannelConfig
	}{
		{"slack", ChannelConfig{Name: "c", Type: ChannelSlack,
			Config: map[string]string{"webhook_url": "https://hooks.example.invalid/x"}}},
		{"teams", ChannelConfig{Name: "c", Type: ChannelTeams,
			Config: map[string]string{"webhook_url": "https://teams.example.invalid/x"}}},
		{"webhook", ChannelConfig{Name: "c", Type: ChannelWebhook,
			Config: map[string]string{"url": "https://example.invalid/hook", "secret": "s"}}},
		{"email, frontend field names", ChannelConfig{Name: "c", Type: ChannelEmail,
			Config: map[string]string{
				"smtp_host": "smtp.example.invalid", "smtp_port": "587",
				"to_address": "soc@example.invalid", "from_address": "edr@example.invalid",
				"smtp_username": "u", "smtp_password": "p",
			}}},
		{"email, legacy field names", ChannelConfig{Name: "c", Type: ChannelEmail,
			Config: map[string]string{
				"smtp_host": "smtp.example.invalid", "smtp_port": "587",
				"recipients": "soc@example.invalid", "from": "edr@example.invalid",
				"username": "u", "password": "p",
			}}},
	} {
		s, err := newSender(tc.ch)
		if err != nil {
			t.Errorf("%s: 正しく設定されたチャネルが拒否されました: %v", tc.name, err)
		}
		if s == nil {
			t.Errorf("%s: センダーが nil です", tc.name)
		}
	}
}

// The two field-naming conventions must both keep working. The email branch
// falls back from the console's names to the legacy ones, and a validation that
// only knew one set would reject half the configured channels — turning a
// silent-failure fix into an outage.
func TestBothEmailFieldNamingConventionsAreAccepted(t *testing.T) {
	modern := ChannelConfig{Name: "c", Type: ChannelEmail, Config: map[string]string{
		"smtp_host": "h", "to_address": "a@example.invalid"}}
	legacy := ChannelConfig{Name: "c", Type: ChannelEmail, Config: map[string]string{
		"smtp_host": "h", "recipients": "a@example.invalid"}}

	for name, ch := range map[string]ChannelConfig{"to_address": modern, "recipients": legacy} {
		if _, err := newSender(ch); err != nil {
			t.Errorf("%s 形式の宛先が拒否されました: %v", name, err)
		}
	}
}

// The rejection has to name the channel, or an operator with a dozen channels
// learns only that "a channel" is broken.
func TestTheRejectionNamesTheChannel(t *testing.T) {
	_, err := newSender(ChannelConfig{
		Name: "SOC-Slack-Primary", Type: ChannelSlack, Config: map[string]string{}})
	if err == nil {
		t.Fatal("宛先が無いチャネルが拒否されていません")
	}
	if !strings.Contains(err.Error(), "SOC-Slack-Primary") {
		t.Errorf("エラーにチャネル名がありません: %v", err)
	}
	if !strings.Contains(err.Error(), "webhook_url") {
		t.Errorf("エラーに不足しているキーがありません: %v", err)
	}
}

// An unknown channel type must still be refused. This is the branch that was
// already right, and it is the shape the others now match.
func TestAnUnknownChannelTypeIsRefused(t *testing.T) {
	if _, err := newSender(ChannelConfig{
		Name: "c", Type: "carrier-pigeon", Config: map[string]string{"url": "x"}}); err == nil {
		t.Error("未知のチャネルタイプが受け入れられました")
	}
}
