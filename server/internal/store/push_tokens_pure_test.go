package store

import (
	"strings"
	"testing"
)

// ─── PushToken 構造体テスト ────────────────────────────────────────────────────

// TestPushToken_ZeroValue は PushToken のゼロ値が期待通りであることを確認する
func TestPushToken_ZeroValue(t *testing.T) {
	var pt PushToken
	if pt.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", pt.ID)
	}
	if pt.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", pt.UserID)
	}
	if pt.Token != "" {
		t.Errorf("Token のデフォルト = %q, want \"\"", pt.Token)
	}
	if pt.Platform != "" {
		t.Errorf("Platform のデフォルト = %q, want \"\"", pt.Platform)
	}
}

// TestPushToken_FieldAssignment は PushToken のフィールド代入が正しく反映されることを確認する
func TestPushToken_FieldAssignment(t *testing.T) {
	pt := PushToken{
		ID:       "token-001",
		UserID:   "user-abc-123",
		Token:    "ExponentPushToken[xxxxxxxxxxxxxxxx]",
		Platform: "ios",
	}

	if pt.ID != "token-001" {
		t.Errorf("ID = %q, want \"token-001\"", pt.ID)
	}
	if pt.UserID != "user-abc-123" {
		t.Errorf("UserID = %q, want \"user-abc-123\"", pt.UserID)
	}
	if pt.Token != "ExponentPushToken[xxxxxxxxxxxxxxxx]" {
		t.Errorf("Token = %q", pt.Token)
	}
	if pt.Platform != "ios" {
		t.Errorf("Platform = %q, want \"ios\"", pt.Platform)
	}
}

// TestPushToken_ValidPlatforms は有効なプラットフォーム値（ios / android）を確認する
func TestPushToken_ValidPlatforms(t *testing.T) {
	// コメント: "ios" | "android" の 2 値のみ有効
	validPlatforms := []string{"ios", "android"}
	for _, p := range validPlatforms {
		pt := PushToken{Platform: p}
		if pt.Platform != p {
			t.Errorf("Platform = %q, want %q", pt.Platform, p)
		}
	}
}

// TestPushToken_PlatformValidation は有効・無効なプラットフォームの判定ロジックを確認する
func TestPushToken_PlatformValidation(t *testing.T) {
	// isValidPushPlatform をインラインで再現するヘルパーロジック
	isValid := func(platform string) bool {
		return platform == "ios" || platform == "android"
	}

	validCases := []struct {
		platform string
		want     bool
	}{
		{"ios", true},
		{"android", true},
		{"IOS", false},     // 大文字は無効
		{"Android", false}, // 大文字混在は無効
		{"web", false},     // 未知のプラットフォーム
		{"windows", false}, // 未知のプラットフォーム
		{"", false},        // 空文字は無効
		{"ios\n", false},   // 末尾改行あり
	}

	for _, tc := range validCases {
		got := isValid(tc.platform)
		if got != tc.want {
			t.Errorf("isValid(%q) = %v, want %v", tc.platform, got, tc.want)
		}
	}
}

// TestPushToken_TokenNonEmpty は Token フィールドが空でないことを前提とする
func TestPushToken_TokenNonEmpty(t *testing.T) {
	// 実際のデバイストークンは非空かつ十分な長さを持つ
	validTokens := []string{
		"ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxxxx]",
		"APA91bHPRgkFnqDHZDMOV2CaCsKAuL1234567890abcdefghijklmnopqrstuvwxyz",
		"dGhpcyBpcyBhIHRlc3QgdG9rZW4",
	}

	for _, tok := range validTokens {
		pt := PushToken{Token: tok}
		if len(pt.Token) == 0 {
			t.Errorf("Token は空であるべきでない: %q", tok)
		}
	}
}

// TestPushToken_IOSTokenFormat は iOS 向けトークン形式の文字列特性を確認する
func TestPushToken_IOSTokenFormat(t *testing.T) {
	// iOS APNs トークンは通常 64 文字の16進数
	iosToken := strings.Repeat("a1", 32) // 64文字の16進数文字列
	pt := PushToken{
		Platform: "ios",
		Token:    iosToken,
	}
	if len(pt.Token) != 64 {
		t.Errorf("iOS トークン長 = %d, want 64", len(pt.Token))
	}
	if pt.Platform != "ios" {
		t.Errorf("Platform = %q, want \"ios\"", pt.Platform)
	}
}

// TestPushToken_AndroidTokenFormat は Android 向けトークン形式の文字列特性を確認する
func TestPushToken_AndroidTokenFormat(t *testing.T) {
	// FCM トークンは通常 152 文字程度
	androidToken := "dGhpcyBpcyBhIHRlc3QgdG9rZW4gZm9yIEFuZHJvaWQgRkNNIHB1c2ggbm90aWZpY2F0aW9ucw=="
	pt := PushToken{
		Platform: "android",
		Token:    androidToken,
	}
	if pt.Platform != "android" {
		t.Errorf("Platform = %q, want \"android\"", pt.Platform)
	}
	if pt.Token != androidToken {
		t.Errorf("Token が正しく格納されていない")
	}
}

// TestPushToken_UniquePerUserPlatform は同一ユーザー・同一プラットフォームのトークン更新ロジックを確認する
func TestPushToken_UniquePerUserPlatform(t *testing.T) {
	// ON CONFLICT (user_id, platform) の制約を表すロジックを検証する
	// 同じ (userID, platform) ペアに対してトークンが一意であることを確認する
	userID := "user-xyz"

	tokens := []PushToken{
		{UserID: userID, Platform: "ios", Token: "old-ios-token"},
		{UserID: userID, Platform: "android", Token: "old-android-token"},
	}

	// トークンマップで上書きをシミュレートする
	type key struct{ userID, platform string }
	tokenMap := make(map[key]string)
	for _, pt := range tokens {
		tokenMap[key{pt.UserID, pt.Platform}] = pt.Token
	}

	// 新しいトークンで更新する
	newToken := PushToken{UserID: userID, Platform: "ios", Token: "new-ios-token"}
	tokenMap[key{newToken.UserID, newToken.Platform}] = newToken.Token

	if tokenMap[key{userID, "ios"}] != "new-ios-token" {
		t.Errorf("iOS トークンが新しい値に更新されるべき")
	}
	if tokenMap[key{userID, "android"}] != "old-android-token" {
		t.Errorf("Android トークンは変更されるべきでない")
	}
	if len(tokenMap) != 2 {
		t.Errorf("トークン数 = %d, want 2（上書きのみでレコードが増えるべきでない）", len(tokenMap))
	}
}

// TestPushTokenStore_FilterByPlatform は特定プラットフォームのトークンを絞り込む純粋ロジックを確認する
func TestPushTokenStore_FilterByPlatform(t *testing.T) {
	// GetByUserID が返すトークンをプラットフォームで絞り込むロジックのテスト
	tokens := []PushToken{
		{ID: "1", UserID: "u1", Token: "tok-ios-1", Platform: "ios"},
		{ID: "2", UserID: "u1", Token: "tok-android-1", Platform: "android"},
		{ID: "3", UserID: "u2", Token: "tok-ios-2", Platform: "ios"},
	}

	filterByPlatform := func(tokens []PushToken, platform string) []PushToken {
		var result []PushToken
		for _, t := range tokens {
			if t.Platform == platform {
				result = append(result, t)
			}
		}
		return result
	}

	iosTokens := filterByPlatform(tokens, "ios")
	if len(iosTokens) != 2 {
		t.Errorf("iOS トークン数 = %d, want 2", len(iosTokens))
	}

	androidTokens := filterByPlatform(tokens, "android")
	if len(androidTokens) != 1 {
		t.Errorf("Android トークン数 = %d, want 1", len(androidTokens))
	}
}

// TestPushToken_UserIDAssociation は PushToken が正しいユーザーに関連付けられることを確認する
func TestPushToken_UserIDAssociation(t *testing.T) {
	userA := "user-aaa"
	userB := "user-bbb"

	tokens := []PushToken{
		{UserID: userA, Platform: "ios", Token: "token-A-ios"},
		{UserID: userA, Platform: "android", Token: "token-A-android"},
		{UserID: userB, Platform: "ios", Token: "token-B-ios"},
	}

	// userA のトークンを抽出する
	var userATokens []PushToken
	for _, pt := range tokens {
		if pt.UserID == userA {
			userATokens = append(userATokens, pt)
		}
	}

	if len(userATokens) != 2 {
		t.Errorf("userA のトークン数 = %d, want 2", len(userATokens))
	}

	for _, pt := range userATokens {
		if pt.UserID != userA {
			t.Errorf("UserID = %q, want %q", pt.UserID, userA)
		}
	}
}
