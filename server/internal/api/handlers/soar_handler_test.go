package handlers

import (
	"encoding/json"
	"testing"
)

// maskConfig のユニットテスト
func TestMaskConfig(t *testing.T) {
	t.Run("機密キーがマスクされること", func(t *testing.T) {
		raw := json.RawMessage(`{
			"url": "https://jira.example.com",
			"api_token": "secret-token-value",
			"project_key": "EDR"
		}`)
		result := maskConfig(raw)

		// api_token はマスクされる
		if result["api_token"] != "***" {
			t.Errorf("api_token should be masked, got: %v", result["api_token"])
		}
		// 非機密フィールドはそのまま残る
		if result["url"] != "https://jira.example.com" {
			t.Errorf("url should be preserved, got: %v", result["url"])
		}
		if result["project_key"] != "EDR" {
			t.Errorf("project_key should be preserved, got: %v", result["project_key"])
		}
	})

	t.Run("passwordフィールドがマスクされること", func(t *testing.T) {
		raw := json.RawMessage(`{"username": "admin", "password": "mysecretpass"}`)
		result := maskConfig(raw)

		if result["password"] != "***" {
			t.Errorf("password should be masked, got: %v", result["password"])
		}
		if result["username"] != "admin" {
			t.Errorf("username should be preserved, got: %v", result["username"])
		}
	})

	t.Run("tokenとsecretフィールドがマスクされること", func(t *testing.T) {
		raw := json.RawMessage(`{"token": "tok123", "secret": "sec456", "name": "test"}`)
		result := maskConfig(raw)

		if result["token"] != "***" {
			t.Errorf("token should be masked, got: %v", result["token"])
		}
		if result["secret"] != "***" {
			t.Errorf("secret should be masked, got: %v", result["secret"])
		}
		if result["name"] != "test" {
			t.Errorf("name should be preserved, got: %v", result["name"])
		}
	})

	t.Run("機密キーなしの設定はそのまま返す", func(t *testing.T) {
		raw := json.RawMessage(`{"host": "localhost", "port": 8080, "project": "EDR"}`)
		result := maskConfig(raw)

		if result["host"] != "localhost" {
			t.Errorf("host should be preserved, got: %v", result["host"])
		}
	})

	// 以前は「不正なJSONは空mapを返す」でした。空の設定は「この連携は未設定」
	// と読めます。設定済みの連携が未設定に見えると、入れ直そうとした人が
	// 既にある接続先を上書きします。読めなかったと書いて返します。
	t.Run("不正なJSONは読めなかったと書いて返す", func(t *testing.T) {
		raw := json.RawMessage(`not valid json`)
		result := maskConfig(raw)

		if result["_unreadable"] != true {
			t.Errorf("読めなかったことが示されていません: %v", result)
		}
		if result["_error"] == nil || result["_error"] == "" {
			t.Errorf("理由がありません: %v", result)
		}
	})

	t.Run("空のJSONオブジェクトは空mapを返す", func(t *testing.T) {
		raw := json.RawMessage(`{}`)
		result := maskConfig(raw)

		if len(result) != 0 {
			t.Errorf("empty JSON should return empty map, got: %v", result)
		}
	})

	t.Run("複数の機密キーがすべてマスクされること", func(t *testing.T) {
		raw := json.RawMessage(`{
			"api_token": "tok1",
			"password":  "pass1",
			"token":     "tok2",
			"secret":    "sec1",
			"safe_key":  "value"
		}`)
		result := maskConfig(raw)

		sensitiveKeys := []string{"api_token", "password", "token", "secret"}
		for _, k := range sensitiveKeys {
			if result[k] != "***" {
				t.Errorf("key %q should be masked, got: %v", k, result[k])
			}
		}
		if result["safe_key"] != "value" {
			t.Errorf("safe_key should be preserved, got: %v", result["safe_key"])
		}
	})
}
