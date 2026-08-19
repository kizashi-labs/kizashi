package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// Upsert が、切り出した既定値を本当に通っていること。
//
// **切り出しただけでは何も保証されません。** `applyPreferenceDefaults` を
// 直しても、`Upsert` がそれを呼んでいなければ、画面に出る既定値は前の
// ままです。検査は緑で、値だけが違います。

func TestUpsertAppliesTheSharedDefaults(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const userID = "33333333-3333-3333-3333-333333333333"

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO users (id, email, role) VALUES ($1::uuid, $2, 'analyst')
	      ON CONFLICT (id) DO NOTHING`, userID, "prefs-probe@example.test")
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(ctx, "DELETE FROM user_preferences WHERE user_id=$1::uuid", userID)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1::uuid", userID)
	})

	s := store.NewUserPreferencesStore(db.Pool())
	// **何も指定せずに保存します。** 既定値が入るはずです。
	got, err := s.Upsert(ctx, userID, store.UserPreferences{})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	want := store.UserPreferences{
		Theme: "dark", Language: "ja", Timezone: "Asia/Tokyo", ItemsPerPage: 20,
	}
	if got.Theme != want.Theme {
		t.Errorf("Theme = %q, want %q。**Upsert が既定値を通っていません**",
			got.Theme, want.Theme)
	}
	if got.Language != want.Language {
		t.Errorf("Language = %q, want %q", got.Language, want.Language)
	}
	if got.Timezone != want.Timezone {
		t.Errorf("Timezone = %q, want %q", got.Timezone, want.Timezone)
	}
	if got.ItemsPerPage != want.ItemsPerPage {
		t.Errorf("ItemsPerPage = %d, want %d", got.ItemsPerPage, want.ItemsPerPage)
	}
	if len(got.Notifications) == 0 {
		t.Error("Notifications が空です。既定の JSON が入っていません")
	}
	if len(got.DashboardPrefs) == 0 {
		t.Error("DashboardPrefs が空です")
	}

	// 指定した値は、既定で上書きされないこと。
	got, err = s.Upsert(ctx, userID, store.UserPreferences{
		Theme: "light", Language: "en", ItemsPerPage: 100,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got.Theme != "light" || got.Language != "en" || got.ItemsPerPage != 100 {
		t.Errorf("指定した値が既定で潰されています: %+v", got)
	}
}
