package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type FavoriteItem struct {
	Href  string `json:"href"`
	Label string `json:"label"`
}

type UserPreferences struct {
	UserID           string          `json:"user_id"`
	Theme            string          `json:"theme"`
	Language         string          `json:"language"`
	Timezone         string          `json:"timezone"`
	Notifications    json.RawMessage `json:"notifications"`
	DashboardPrefs   json.RawMessage `json:"dashboard_prefs"`
	SidebarCollapsed bool            `json:"sidebar_collapsed"`
	ItemsPerPage     int             `json:"items_per_page"`
	Favorites        json.RawMessage `json:"favorites"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type UserPreferencesStore struct {
	pool *pgxpool.Pool
}

func NewUserPreferencesStore(pool *pgxpool.Pool) *UserPreferencesStore {
	return &UserPreferencesStore{pool: pool}
}

var defaultPrefs = UserPreferences{
	Theme:          "dark",
	Language:       "ja",
	Timezone:       "Asia/Tokyo",
	Notifications:  json.RawMessage(`{"email":true,"browser":true,"digest":false}`),
	DashboardPrefs: json.RawMessage(`{}`),
	ItemsPerPage:   20,
}

func (s *UserPreferencesStore) Get(ctx context.Context, userID string) (UserPreferences, error) {
	var p UserPreferences
	err := s.pool.QueryRow(ctx,
		`SELECT user_id::TEXT, theme, language, timezone, notifications, dashboard_prefs, sidebar_collapsed, items_per_page, created_at, updated_at
         FROM user_preferences WHERE user_id=$1::UUID`, userID,
	).Scan(&p.UserID, &p.Theme, &p.Language, &p.Timezone, &p.Notifications, &p.DashboardPrefs, &p.SidebarCollapsed, &p.ItemsPerPage, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// まだ設定していない。既定値で返します。
		prefs := defaultPrefs
		prefs.UserID = userID
		prefs.CreatedAt = time.Now()
		prefs.UpdatedAt = time.Now()
		return prefs, nil
	}
	if err != nil {
		// 以前はどんな失敗も既定値でした。利用者が変えた表示設定が、
		// 読めなかっただけで既定に戻ったように見えます。
		return UserPreferences{}, fmt.Errorf("表示設定を読めませんでした: %w", err)
	}
	return p, nil
}

// applyPreferenceDefaults fills the unset fields of a preferences record.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。** 以前この
// 6つの既定値は `Upsert` の中にだけあり、DB が要るので検査から呼べません
// でした。検査ファイルには `applyPrefsDefaults` という**同じ既定値の写し**が
// 置いてあり、そちらだけが試されていました —— 製品側の "dark" を "light" に
// 変えても、落ちる検査はありません。
//
// 埋めるのは「指定が無かった」場合だけです。**`SidebarCollapsed` は
// ここにありません** —— false が既定であり、同時に利用者の選択でもあるので、
// 「指定が無い」と「たたんでいない」を区別できません。
func applyPreferenceDefaults(prefs UserPreferences) UserPreferences {
	if prefs.Theme == "" {
		prefs.Theme = "dark"
	}
	if prefs.Language == "" {
		prefs.Language = "ja"
	}
	if prefs.Timezone == "" {
		prefs.Timezone = "Asia/Tokyo"
	}
	if prefs.ItemsPerPage <= 0 {
		prefs.ItemsPerPage = 20
	}
	if prefs.Notifications == nil {
		prefs.Notifications = json.RawMessage(`{"email":true,"browser":true,"digest":false}`)
	}
	if prefs.DashboardPrefs == nil {
		prefs.DashboardPrefs = json.RawMessage(`{}`)
	}
	return prefs
}

func (s *UserPreferencesStore) Upsert(ctx context.Context, userID string, prefs UserPreferences) (UserPreferences, error) {
	prefs = applyPreferenceDefaults(prefs)

	var result UserPreferences
	err := s.pool.QueryRow(ctx,
		`INSERT INTO user_preferences (user_id, theme, language, timezone, notifications, dashboard_prefs, sidebar_collapsed, items_per_page)
         VALUES ($1::UUID,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (user_id) DO UPDATE SET
             theme=$2, language=$3, timezone=$4, notifications=$5, dashboard_prefs=$6,
             sidebar_collapsed=$7, items_per_page=$8, updated_at=NOW()
         RETURNING user_id::TEXT, theme, language, timezone, notifications, dashboard_prefs, sidebar_collapsed, items_per_page, created_at, updated_at`,
		userID, prefs.Theme, prefs.Language, prefs.Timezone,
		prefs.Notifications, prefs.DashboardPrefs, prefs.SidebarCollapsed, prefs.ItemsPerPage,
	).Scan(&result.UserID, &result.Theme, &result.Language, &result.Timezone,
		&result.Notifications, &result.DashboardPrefs, &result.SidebarCollapsed, &result.ItemsPerPage,
		&result.CreatedAt, &result.UpdatedAt)
	return result, err
}

const maxFavorites = 20

func (s *UserPreferencesStore) GetFavorites(ctx context.Context, userID string) ([]FavoriteItem, error) {
	var raw json.RawMessage
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(favorites, '[]'::jsonb) FROM user_preferences WHERE user_id=$1::UUID`, userID,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return []FavoriteItem{}, nil // まだ何も登録していない
	}
	if err != nil {
		return nil, fmt.Errorf("お気に入りを読めませんでした: %w", err)
	}
	var items []FavoriteItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("お気に入りの内容を読めませんでした: %w", err)
	}
	return items, nil
}

func (s *UserPreferencesStore) SetFavorites(ctx context.Context, userID string, items []FavoriteItem) ([]FavoriteItem, error) {
	if len(items) > maxFavorites {
		items = items[:maxFavorites]
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO user_preferences
           (user_id, theme, language, timezone, notifications, dashboard_prefs, sidebar_collapsed, items_per_page, favorites)
         VALUES
           ($1::UUID, 'dark', 'ja', 'Asia/Tokyo',
            '{"email":true,"browser":true,"digest":false}'::jsonb, '{}'::jsonb, false, 20, $2::jsonb)
         ON CONFLICT (user_id) DO UPDATE SET favorites=$2::jsonb, updated_at=NOW()`,
		userID, raw,
	)
	if err != nil {
		return nil, err
	}
	return items, nil
}
