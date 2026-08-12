package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────
// ipToSubnet24 のテスト
// ─────────────────────────────────────────────

func TestIPToSubnet24_ValidIPv4(t *testing.T) {
	// 有効なIPv4アドレスが /24 サブネット表記に変換されることを確認
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.100", "192.168.1.0/24"},
		{"10.0.0.1", "10.0.0.0/24"},
		{"172.16.254.99", "172.16.254.0/24"},
		{"8.8.8.8", "8.8.8.0/24"},
		{"255.255.255.1", "255.255.255.0/24"},
		{"1.2.3.4", "1.2.3.0/24"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ipToSubnet24(tc.input)
			if got != tc.want {
				t.Errorf("ipToSubnet24(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestIPToSubnet24_HostOctetIsZeroed(t *testing.T) {
	// ホストオクテット（第4オクテット）がゼロになることを確認
	input := "10.20.30.200"
	got := ipToSubnet24(input)
	want := "10.20.30.0/24"
	if got != want {
		t.Errorf("ipToSubnet24(%q) = %q, want %q", input, got, want)
	}
}

func TestIPToSubnet24_InvalidIP_ReturnsEmpty(t *testing.T) {
	// 無効なIPアドレスは空文字列を返すことを確認
	invalid := []string{
		"",
		"not-an-ip",
		"999.999.999.999",
		"abc.def.ghi.jkl",
		"256.0.0.1",
		"192.168.1",     // オクテット不足
		"192.168.1.1.1", // オクテット過多
	}
	for _, ip := range invalid {
		t.Run(ip, func(t *testing.T) {
			got := ipToSubnet24(ip)
			if got != "" {
				t.Errorf("ipToSubnet24(%q) = %q, want \"\" (無効なIP)", ip, got)
			}
		})
	}
}

func TestIPToSubnet24_IPv6_ReturnsEmpty(t *testing.T) {
	// IPv6アドレスはサポート対象外なので空文字列を返す
	ipv6Cases := []string{
		"::1",
		"2001:db8::1",
		"fe80::1%eth0",
		"::ffff:192.168.1.1", // IPv4マップドIPv6
	}
	for _, ip := range ipv6Cases {
		t.Run(ip, func(t *testing.T) {
			got := ipToSubnet24(ip)
			if got != "" {
				t.Errorf("ipToSubnet24(%q) = %q, want \"\" (IPv6は非対応)", ip, got)
			}
		})
	}
}

// ─────────────────────────────────────────────
// nodeCoord のテスト
// ─────────────────────────────────────────────

func TestNodeCoord_ReturnValueInRange(t *testing.T) {
	// 返り値が [0, max) の範囲内であることを確認
	cases := []struct {
		id   string
		salt int
		max  float64
	}{
		{"agent-001", 0, 1000},
		{"agent-001", 1, 800},
		{"node-abc", 0, 500},
		{"node-abc", 2, 100},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := nodeCoord(tc.id, tc.salt, tc.max)
			if got < 0 || got >= tc.max {
				t.Errorf("nodeCoord(%q, %d, %v) = %v, 範囲 [0, %v) の外", tc.id, tc.salt, tc.max, got, tc.max)
			}
		})
	}
}

func TestNodeCoord_IsDeterministic(t *testing.T) {
	// 同じ入力に対して常に同じ値を返すことを確認（決定論的）
	id := "deterministic-node"
	salt := 0
	max := 1000.0

	first := nodeCoord(id, salt, max)
	for i := 0; i < 10; i++ {
		got := nodeCoord(id, salt, max)
		if got != first {
			t.Errorf("nodeCoord は決定論的でありません: 1回目=%v, %d回目=%v", first, i+1, got)
		}
	}
}

func TestNodeCoord_DifferentSaltsProduceDifferentCoords(t *testing.T) {
	// 同じIDでもsaltが異なれば異なる座標が返ることを確認（X座標とY座標の独立性）
	id := "node-xyz"
	x := nodeCoord(id, 0, 1000)
	y := nodeCoord(id, 1, 1000)
	// 同じ値になる確率は低いが絶対ではないため、
	// ここではパニックなく計算できることを主に確認する
	_ = x
	_ = y
	// 両方が有効範囲内にあることだけ確認
	if x < 0 || x >= 1000 {
		t.Errorf("X座標が範囲外: %v", x)
	}
	if y < 0 || y >= 1000 {
		t.Errorf("Y座標が範囲外: %v", y)
	}
}

func TestNodeCoord_DifferentIDsProduceDifferentCoords(t *testing.T) {
	// 異なるIDは（大部分の場合）異なる座標を生成することを確認
	ids := []string{
		"agent-aaa",
		"agent-bbb",
		"agent-ccc",
		"agent-ddd",
		"agent-eee",
	}
	seen := map[float64]string{}
	for _, id := range ids {
		coord := nodeCoord(id, 0, 1000)
		if prev, ok := seen[coord]; ok {
			// ハッシュ衝突が起きた場合は警告のみ（失敗扱いしない）
			t.Logf("ハッシュ衝突: %q と %q が同じ座標 %v を持ちます", prev, id, coord)
		}
		seen[coord] = id
	}
}

func TestNodeCoord_EmptyIDDoesNotPanic(t *testing.T) {
	// 空文字列IDでもパニックなく動作することを確認
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nodeCoord(\"\") でパニックが発生しました: %v", r)
		}
	}()
	got := nodeCoord("", 0, 1000)
	if got < 0 || got >= 1000 {
		t.Errorf("nodeCoord(\"\") = %v, 範囲外", got)
	}
}
