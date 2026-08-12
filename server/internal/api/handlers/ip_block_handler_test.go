package handlers

import "testing"

// TestIsValidIPOrCIDR_ValidIPv4 は有効な IPv4 アドレスを受理することを確認する
func TestIsValidIPOrCIDR_ValidIPv4(t *testing.T) {
	for _, v := range []string{"192.168.1.100", "10.0.0.1", "8.8.8.8"} {
		if !isValidIPOrCIDR(v) {
			t.Errorf("isValidIPOrCIDR(%q) = false, want true", v)
		}
	}
}

// TestIsValidIPOrCIDR_ValidCIDR は有効な CIDR 範囲を受理することを確認する
func TestIsValidIPOrCIDR_ValidCIDR(t *testing.T) {
	for _, v := range []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"} {
		if !isValidIPOrCIDR(v) {
			t.Errorf("isValidIPOrCIDR(%q) = false, want true", v)
		}
	}
}

// TestIsValidIPOrCIDR_ValidIPv6 は有効な IPv6 アドレスを受理することを確認する
func TestIsValidIPOrCIDR_ValidIPv6(t *testing.T) {
	if !isValidIPOrCIDR("2001:db8::1") {
		t.Error("isValidIPOrCIDR(IPv6) = false, want true")
	}
}

// TestIsValidIPOrCIDR_Invalid は不正な値を拒否することを確認する
func TestIsValidIPOrCIDR_Invalid(t *testing.T) {
	for _, v := range []string{"", "not-an-ip", "999.999.999.999", "10.0.0.0/99", "example.com"} {
		if isValidIPOrCIDR(v) {
			t.Errorf("isValidIPOrCIDR(%q) = true, want false", v)
		}
	}
}
