package store

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

// ListChannels ran the stored config through `_ = json.Unmarshal` and returned
// the channel either way. A blob that would not decode into map[string]string
// therefore became a channel with an empty Config — and the dispatcher built a
// sender from it, registered it, and reported the channel as enabled while
// every alert notification failed to send.
//
// config is jsonb, so the failure is never malformed JSON. It is valid JSON of
// the wrong shape: an array where an object is expected, or an object whose
// values are numbers rather than strings. Both are what a hand-edited row or an
// older schema leaves behind, and neither is visible from the console.

func channelStore(t *testing.T) (*NotificationStore, *DB) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	db, err := Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return NewNotificationStore(db), db
}

// seedChannel inserts one enabled channel with the given raw jsonb config.
func seedChannel(t *testing.T, db *DB, name, chType, config string) {
	t.Helper()
	if _, err := db.Pool().Exec(context.Background(), `
		INSERT INTO notification_channels (name, type, config, enabled, min_severity)
		VALUES ($1, $2, $3::jsonb, true, 1)`, name, chType, config); err != nil {
		t.Fatalf("seed channel %q: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(),
			`DELETE FROM notification_channels WHERE name=$1`, name)
	})
}

// The headline: a channel whose config cannot be read is not returned as a
// usable channel.
func TestAChannelWithAnUnreadableConfigIsNotReturned(t *testing.T) {
	store, db := channelStore(t)
	ctx := context.Background()

	marker := uuid.NewString()[:8]
	good := "notif-good-" + marker
	arrayShape := "notif-array-" + marker
	numericValues := "notif-numeric-" + marker

	seedChannel(t, db, good, "slack", `{"webhook_url":"https://hooks.example.invalid/x"}`)
	// Valid jsonb, wrong shape for map[string]string.
	seedChannel(t, db, arrayShape, "slack", `["webhook_url","https://hooks.example.invalid/x"]`)
	seedChannel(t, db, numericValues, "slack", `{"webhook_url":123,"retries":5}`)

	channels, err := store.ListChannels(ctx)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}

	byName := map[string]*NotifChannelRow{}
	for _, c := range channels {
		byName[c.Name] = c
	}

	if byName[good] == nil {
		t.Fatalf("正常なチャネルが返っていません: %d件", len(channels))
	}
	if got := byName[good].Config["webhook_url"]; got != "https://hooks.example.invalid/x" {
		t.Errorf("正常なチャネルの設定が読めていません: %q", got)
	}

	for _, name := range []string{arrayShape, numericValues} {
		if c := byName[name]; c != nil {
			t.Errorf("設定を読めないチャネル %q が返っています (Config=%v)。"+
				"空の Config から宛先の無いセンダーが作られ、"+
				"コンソールでは有効に見えたまま通知が飛びません", name, c.Config)
		}
	}
}

// And the loader must not go back to discarding it. There is no symptom at the
// point the error happens — the channel simply arrives empty.
func TestTheChannelLoaderDoesNotDiscardItsUnmarshalError(t *testing.T) {
	b, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	if contains(string(b), "_ = json.Unmarshal(configJSON") {
		t.Error("チャネル設定の解釈エラーを捨てています。" +
			"空の Config のまま返ると、宛先の無いセンダーが" +
			"「設定済みのチャネル」として登録されます")
	}
}

func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
