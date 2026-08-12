package handlers

import (
	"net"
	"testing"
)

// ─── isPrivateIP ─────────────────────────────────────────────────────────────

func TestIsPrivateIP_Nil_ReturnsFalse(t *testing.T) {
	if isPrivateIP(nil) {
		t.Error("isPrivateIP(nil): expected false")
	}
}

func TestIsPrivateIP_Loopback_ReturnsTrue(t *testing.T) {
	if !isPrivateIP(net.ParseIP("127.0.0.1")) {
		t.Error("isPrivateIP(127.0.0.1): expected true")
	}
}

func TestIsPrivateIP_RFC1918_Class10_ReturnsTrue(t *testing.T) {
	if !isPrivateIP(net.ParseIP("10.0.0.1")) {
		t.Error("isPrivateIP(10.0.0.1): expected true")
	}
}

func TestIsPrivateIP_RFC1918_Class172_ReturnsTrue(t *testing.T) {
	if !isPrivateIP(net.ParseIP("172.16.0.1")) {
		t.Error("isPrivateIP(172.16.0.1): expected true")
	}
}

func TestIsPrivateIP_RFC1918_Class192_ReturnsTrue(t *testing.T) {
	if !isPrivateIP(net.ParseIP("192.168.1.1")) {
		t.Error("isPrivateIP(192.168.1.1): expected true")
	}
}

func TestIsPrivateIP_PublicIP_ReturnsFalse(t *testing.T) {
	if isPrivateIP(net.ParseIP("8.8.8.8")) {
		t.Error("isPrivateIP(8.8.8.8): expected false (public IP)")
	}
}

func TestIsPrivateIP_RFC5737_TestAddr_ReturnsFalse(t *testing.T) {
	// 192.0.2.0/24 is documentation range, not private
	if isPrivateIP(net.ParseIP("192.0.2.1")) {
		t.Error("isPrivateIP(192.0.2.1): expected false (doc range, not private)")
	}
}

func TestIsPrivateIP_LinkLocal_ReturnsTrue(t *testing.T) {
	if !isPrivateIP(net.ParseIP("169.254.1.1")) {
		t.Error("isPrivateIP(169.254.1.1): expected true (link-local)")
	}
}
