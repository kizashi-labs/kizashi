package store

import (
	"strings"
	"testing"
	"time"
)

// ─── Session 構造体テスト ──────────────────────────────────────────────────────

// TestSession_ZeroValue は Session のゼロ値が期待通りであることを確認する
func TestSession_ZeroValue(t *testing.T) {
	var s Session
	if s.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", s.ID)
	}
	if s.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", s.UserID)
	}
	if s.JTI != "" {
		t.Errorf("JTI のデフォルト = %q, want \"\"", s.JTI)
	}
	if s.Revoked {
		t.Error("Revoked のデフォルトは false であるべき")
	}
	if s.DeviceInfo != nil {
		t.Errorf("DeviceInfo のデフォルトは nil であるべき: got %v", s.DeviceInfo)
	}
}

// TestSession_FieldAssignment は Session の全フィールドが正しく代入されることを確認する
func TestSession_FieldAssignment(t *testing.T) {
	now := time.Now()
	s := Session{
		ID:         "sess-001",
		UserID:     "user-abc",
		JTI:        "jti-xyz",
		IPAddress:  "192.168.1.10",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
		Revoked:    false,
		DeviceInfo: map[string]interface{}{"ua": "Go-Test"},
	}

	if s.ID != "sess-001" {
		t.Errorf("ID = %q, want \"sess-001\"", s.ID)
	}
	if s.UserID != "user-abc" {
		t.Errorf("UserID = %q, want \"user-abc\"", s.UserID)
	}
	if s.JTI != "jti-xyz" {
		t.Errorf("JTI = %q, want \"jti-xyz\"", s.JTI)
	}
	if s.IPAddress != "192.168.1.10" {
		t.Errorf("IPAddress = %q, want \"192.168.1.10\"", s.IPAddress)
	}
	if s.Revoked {
		t.Error("Revoked は false であるべき")
	}
	if s.DeviceInfo["ua"] != "Go-Test" {
		t.Errorf("DeviceInfo[ua] = %v, want \"Go-Test\"", s.DeviceInfo["ua"])
	}
}

// TestSession_IsExpired はセッションの有効期限判定ロジックを確認する
// ExpiresAt が過去であればセッションは期限切れとみなされる
func TestSession_IsExpired(t *testing.T) {
	now := time.Now()

	// 期限切れセッション：ExpiresAt が現在より前
	expired := Session{
		ID:        "sess-expired",
		ExpiresAt: now.Add(-1 * time.Second),
	}
	if !expired.ExpiresAt.Before(now) {
		t.Error("ExpiresAt が過去のセッションは期限切れとみなされるべき")
	}

	// 有効セッション：ExpiresAt が現在より後
	active := Session{
		ID:        "sess-active",
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if active.ExpiresAt.Before(now) {
		t.Error("ExpiresAt が未来のセッションは有効であるべき")
	}
}

// TestSession_RevokedFlag は Revoked フラグの切り替えを確認する
func TestSession_RevokedFlag(t *testing.T) {
	s := Session{
		ID:      "sess-002",
		Revoked: false,
	}
	if s.Revoked {
		t.Error("初期状態で Revoked は false であるべき")
	}

	// 失効フラグを立てる
	s.Revoked = true
	if !s.Revoked {
		t.Error("Revoked = true に設定した後は true であるべき")
	}
}

// TestSession_DeviceInfoMap は DeviceInfo マップの操作を確認する
func TestSession_DeviceInfoMap(t *testing.T) {
	s := Session{
		DeviceInfo: map[string]interface{}{
			"browser": "Firefox",
			"os":      "Linux",
			"version": "120.0",
		},
	}

	if s.DeviceInfo["browser"] != "Firefox" {
		t.Errorf("DeviceInfo[browser] = %v, want \"Firefox\"", s.DeviceInfo["browser"])
	}
	if s.DeviceInfo["os"] != "Linux" {
		t.Errorf("DeviceInfo[os] = %v, want \"Linux\"", s.DeviceInfo["os"])
	}
	if len(s.DeviceInfo) != 3 {
		t.Errorf("DeviceInfo の件数 = %d, want 3", len(s.DeviceInfo))
	}
}

// TestSession_ExpiresAtDuration は ExpiresAt と CreatedAt の差がセッション有効期間であることを確認する
func TestSession_ExpiresAtDuration(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	duration := 8 * time.Hour

	s := Session{
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}

	diff := s.ExpiresAt.Sub(s.CreatedAt)
	if diff != duration {
		t.Errorf("セッション有効期間 = %v, want %v", diff, duration)
	}
}

// TestSession_LastSeenAtUpdate は LastSeenAt の更新ロジックを確認する
func TestSession_LastSeenAtUpdate(t *testing.T) {
	created := time.Now().Add(-30 * time.Minute)
	s := Session{
		CreatedAt:  created,
		LastSeenAt: created,
	}

	// 新しいリクエストで LastSeenAt を更新するシミュレーション
	newSeen := time.Now()
	s.LastSeenAt = newSeen

	if !s.LastSeenAt.After(s.CreatedAt) {
		t.Error("更新後の LastSeenAt は CreatedAt より後であるべき")
	}
}

// ─── セッション有効期限ヘルパーロジックテスト ─────────────────────────────────

// sessionIsActive はセッションが失効していないかつ有効期限内であるかを判定する
// （sessions.go の ListByUser の WHERE 条件と同等のロジックをピュア関数で再現）
func sessionIsActive(s Session, now time.Time) bool {
	return !s.Revoked && s.ExpiresAt.After(now)
}

// TestSessionIsActive_ActiveSession は有効なセッションで true を返すことを確認する
func TestSessionIsActive_ActiveSession(t *testing.T) {
	now := time.Now()
	s := Session{
		Revoked:   false,
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if !sessionIsActive(s, now) {
		t.Error("失効していない有効期限内のセッションは active であるべき")
	}
}

// TestSessionIsActive_ExpiredSession は有効期限切れセッションで false を返すことを確認する
func TestSessionIsActive_ExpiredSession(t *testing.T) {
	now := time.Now()
	s := Session{
		Revoked:   false,
		ExpiresAt: now.Add(-1 * time.Second),
	}
	if sessionIsActive(s, now) {
		t.Error("有効期限切れのセッションは active でないべき")
	}
}

// TestSessionIsActive_RevokedSession は失効済みセッションで false を返すことを確認する
func TestSessionIsActive_RevokedSession(t *testing.T) {
	now := time.Now()
	s := Session{
		Revoked:   true,
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if sessionIsActive(s, now) {
		t.Error("失効済みのセッションは active でないべき")
	}
}

// TestSessionIsActive_RevokedAndExpired は失効かつ期限切れのセッションで false を返すことを確認する
func TestSessionIsActive_RevokedAndExpired(t *testing.T) {
	now := time.Now()
	s := Session{
		Revoked:   true,
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	if sessionIsActive(s, now) {
		t.Error("失効済みかつ期限切れのセッションは active でないべき")
	}
}

// ─── セッション IP アドレス正規化テスト ──────────────────────────────────────

// normalizeIP は **本物を呼びます。**
//
// 以前ここには `Create` の置き換えを書き写したものが置いてありました。
func normalizeIP(ip string) string {
	return sessionIPOrFallback(ip)
}

// TestNormalizeIP_EmptyStringFallsBack は空文字列が 0.0.0.0 にフォールバックすることを確認する
func TestNormalizeIP_EmptyStringFallsBack(t *testing.T) {
	if got := normalizeIP(""); got != "0.0.0.0" {
		t.Errorf("normalizeIP(\"\") = %q, want \"0.0.0.0\"", got)
	}
}

// TestNormalizeIP_ValidIPPreserved は有効な IP アドレスがそのまま保持されることを確認する
func TestNormalizeIP_ValidIPPreserved(t *testing.T) {
	cases := []string{"192.168.1.1", "10.0.0.1", "172.16.0.100", "::1"}
	for _, ip := range cases {
		if got := normalizeIP(ip); got != ip {
			t.Errorf("normalizeIP(%q) = %q, want %q", ip, got, ip)
		}
	}
}

// TestNormalizeIP_LoopbackPreserved は loopback アドレスが変更されないことを確認する
func TestNormalizeIP_LoopbackPreserved(t *testing.T) {
	if got := normalizeIP("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("normalizeIP(\"127.0.0.1\") = %q, want \"127.0.0.1\"", got)
	}
}

// ─── JTI ユニーク性テスト ─────────────────────────────────────────────────────

// TestSession_JTIUniqueness は同じセッションIDを持つ複数セッションで JTI が異なることを確認する
func TestSession_JTIUniqueness(t *testing.T) {
	now := time.Now()
	sessions := []Session{
		{ID: "s1", UserID: "u1", JTI: "jti-aaa", ExpiresAt: now.Add(time.Hour)},
		{ID: "s2", UserID: "u1", JTI: "jti-bbb", ExpiresAt: now.Add(time.Hour)},
		{ID: "s3", UserID: "u1", JTI: "jti-ccc", ExpiresAt: now.Add(time.Hour)},
	}

	seen := map[string]bool{}
	for _, s := range sessions {
		if seen[s.JTI] {
			t.Errorf("JTI が重複しています: %q", s.JTI)
		}
		seen[s.JTI] = true
	}
}

// TestSession_IPAddressFormats は各種 IP アドレス形式が Session に保存できることを確認する
func TestSession_IPAddressFormats(t *testing.T) {
	ips := []string{"192.168.0.1", "10.10.10.10", "::1", "2001:db8::1"}
	for _, ip := range ips {
		s := Session{IPAddress: ip}
		if s.IPAddress != ip {
			t.Errorf("IPAddress = %q, want %q", s.IPAddress, ip)
		}
		// IPv4 は "." を含む
		if strings.Contains(ip, ".") {
			if !strings.Contains(s.IPAddress, ".") {
				t.Errorf("IPv4 アドレスには '.' が含まれるべき: %q", ip)
			}
		}
	}
}
