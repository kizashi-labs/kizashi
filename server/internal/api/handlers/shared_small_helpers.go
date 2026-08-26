// shared_small_helpers.go — 除外側のハンドラから切り出した小さな共有ヘルパ。
//
// 定義元のファイルは公開版が同梱しない側（EXCLUDE §20.2）だが、kept 側の
// ハンドラも参照するためここに置く。
package handlers

import "time"

// nilIfEmpty returns nil if the string is empty, otherwise returns a pointer to it.
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// buildGenericTestPayload returns a generic JSON test payload.
func buildGenericTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"event":     "test",
		"message":   "EDR Platform テスト通知",
		"source":    "edr-platform",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// buildSlackTestPayload returns a Slack-compatible test message payload.
func buildSlackTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color":  "#0099FF",
			"title":  "[LOW] EDR Platform テスト通知",
			"text":   "これはEDR Platformからのテスト通知です。",
			"footer": "EDR Platform",
			"ts":     time.Now().Unix(),
		}},
	}
}

// buildTeamsTestPayload returns a Microsoft Teams MessageCard test payload.
func buildTeamsTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    "EDR Platform テスト通知",
		"themeColor": "0099FF",
		"title":      "EDR Platform テスト通知",
		"sections": []map[string]interface{}{{
			"facts": []map[string]string{
				{"name": "種別", "value": "テスト"},
				{"name": "送信日時", "value": time.Now().Format(time.RFC3339)},
			},
		}},
	}
}
