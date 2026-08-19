package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// 設定していない利用者に、既定が返ること。**本物を呼びます。**
//
// **`MinSeverity` の既定は `critical` です。** 緩いと設定していない
// 利用者に通知が溢れ、厳しいと届くはずのものが届きません。どちらも
// 「設定を変えたつもりが効いていない」と見分けが付きません。
//
// 切り出した `defaultNotificationPrefs` を `GetByUserID` が通っている
// ことを確かめます —— **切り出しただけでは何も保証されません。**
func TestGetByUserIDReturnsTheSharedDefaults(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const userID = "66666666-6666-6666-6666-666666666666"

	// 行が無い状態にします。
	_, _ = db.Pool().Exec(ctx,
		"DELETE FROM notification_preferences WHERE user_id = $1::uuid", userID)

	got, err := store.NewNotificationPrefStore(db).GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if got.MinSeverity != "critical" {
		t.Errorf("MinSeverity = %q, want \"critical\"。"+
			"**GetByUserID が既定を通っていません**", got.MinSeverity)
	}
	if got.UserID != userID {
		t.Errorf("UserID = %q, want %q", got.UserID, userID)
	}
	// **行が無いことは、ID が空で表されます。** 空でないと、呼び出し側は
	// 保存済みの設定だと思います。
	if got.ID != "" {
		t.Errorf("ID = %q, want 空", got.ID)
	}
}
