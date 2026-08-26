package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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

// プラットフォームの検証は **Go にありません。** `mobile_push_tokens` の
// `platform` 列に CHECK 制約があり、そこが唯一の関門です:
//
//	platform TEXT NOT NULL CHECK (platform IN ('ios', 'android'))
//
// 検査ファイルには `isValidPushPlatform` という Go の判定を**検査の中で
// 定義して**、それを試すものが置いてありました。**製品を1行も通りません。**
//
// 制約の方を留めます。緩められたら落ちて、通知の送り先を見直す番だと
// 分かります。
func TestOnlyKnownPushPlatformsCanBeStored(t *testing.T) {
	db := covTestDBLocal(t)
	ctx := context.Background()

	var def string
	err := db.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'mobile_push_tokens'::regclass AND contype = 'c'
		  AND pg_get_constraintdef(oid) LIKE '%platform%'`).Scan(&def)
	if err != nil {
		t.Fatalf("platform の制約が見つかりません: %v。**知らない値が入ると、"+
			"通知の送り先として使われます**", err)
	}
	for _, want := range []string{"ios", "android"} {
		if !strings.Contains(def, "'"+want+"'") {
			t.Errorf("制約に %q がありません: %s", want, def)
		}
	}

	// 第三の値が入れられないこと。
	_, err = db.Exec(ctx, `
		INSERT INTO mobile_push_tokens (user_id, platform, token)
		VALUES ('55555555-5555-5555-5555-555555555555'::uuid, 'web', 'probe')`)
	if err == nil {
		_, _ = db.Exec(ctx, "DELETE FROM mobile_push_tokens WHERE token = 'probe'")
		t.Error("'web' が入りました。**制約が唯一の関門です**")
	}
}

// covTestDBLocal opens the shared migrated database, or skips.
func covTestDBLocal(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB constraint test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
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
