//go:build linux

// Package linux — DNS・ネットワークヘルパー ユニットテスト
// syscallやソケット操作を行わず、純粋なパケット解析・変換関数のみをテストする。
package linux

import (
	"encoding/binary"
	"testing"
)

// ─── dnsQTypeString ───────────────────────────────────────────

// TestDNSQTypeString_KnownTypes は既知のDNSクエリタイプが正しい文字列に変換されることを確認する。
func TestDNSQTypeString_KnownTypes(t *testing.T) {
	tests := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"Aレコード", 1, "A"},
		{"NSレコード", 2, "NS"},
		{"CNAMEレコード", 5, "CNAME"},
		{"MXレコード", 15, "MX"},
		{"TXTレコード", 16, "TXT"},
		{"AAAAレコード", 28, "AAAA"},
		{"SRVレコード", 33, "SRV"},
		{"ANYクエリ", 255, "ANY"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsQTypeString(tc.qtype)
			if got != tc.want {
				t.Errorf("dnsQTypeString(%d) = %q, want %q", tc.qtype, got, tc.want)
			}
		})
	}
}

// TestDNSQTypeString_UnknownType は未知のタイプ番号がTYPE<N>形式で返ることを確認する。
func TestDNSQTypeString_UnknownType(t *testing.T) {
	tests := []struct {
		qtype uint16
		want  string
	}{
		{0, "TYPE0"},
		{100, "TYPE100"},
		{999, "TYPE999"},
		{65535, "TYPE65535"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := dnsQTypeString(tc.qtype)
			if got != tc.want {
				t.Errorf("dnsQTypeString(%d) = %q, want %q", tc.qtype, got, tc.want)
			}
		})
	}
}

// ─── parseDNSQuestion ─────────────────────────────────────────

// TestParseDNSQuestion_SingleLabel は単一ラベルのDNSクエリを解析できることを確認する。
func TestParseDNSQuestion_SingleLabel(t *testing.T) {
	// "example" という単一ラベルのDNSクエリデータを手動構築する。
	// 形式: <len><label><0x00><qtype (2bytes)><qclass (2bytes)>
	data := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // ラベル "example"
		0,    // ラベル終端
		0, 1, // QTYPE = A (1)
		0, 1, // QCLASS = IN (1)
	}

	domain, qtype, ok := parseDNSQuestion(data)
	if !ok {
		t.Fatal("parseDNSQuestion が false を返した")
	}
	if domain != "example" {
		t.Errorf("domain = %q, want \"example\"", domain)
	}
	if qtype != "A" {
		t.Errorf("qtype = %q, want \"A\"", qtype)
	}
}

// TestParseDNSQuestion_MultiLabel は複数ラベルのFQDNを正しく結合することを確認する。
func TestParseDNSQuestion_MultiLabel(t *testing.T) {
	// "www.example.com" のDNSクエリ（Aレコード）を手動構築する。
	data := []byte{
		3, 'w', 'w', 'w', // ラベル "www"
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // ラベル "example"
		3, 'c', 'o', 'm', // ラベル "com"
		0,    // ラベル終端
		0, 1, // QTYPE = A (1)
		0, 1, // QCLASS = IN
	}

	domain, qtype, ok := parseDNSQuestion(data)
	if !ok {
		t.Fatal("parseDNSQuestion が false を返した")
	}
	if domain != "www.example.com" {
		t.Errorf("domain = %q, want \"www.example.com\"", domain)
	}
	if qtype != "A" {
		t.Errorf("qtype = %q, want \"A\"", qtype)
	}
}

// TestParseDNSQuestion_AAAARecord はAAAAレコードのクエリタイプを正しく識別することを確認する。
func TestParseDNSQuestion_AAAARecord(t *testing.T) {
	data := []byte{
		4, 'i', 'p', 'v', '6', // ラベル "ipv6"
		4, 't', 'e', 's', 't', // ラベル "test"
		0,     // ラベル終端
		0, 28, // QTYPE = AAAA (28)
		0, 1, // QCLASS = IN
	}

	domain, qtype, ok := parseDNSQuestion(data)
	if !ok {
		t.Fatal("parseDNSQuestion が false を返した")
	}
	if domain != "ipv6.test" {
		t.Errorf("domain = %q, want \"ipv6.test\"", domain)
	}
	if qtype != "AAAA" {
		t.Errorf("qtype = %q, want \"AAAA\"", qtype)
	}
}

// TestParseDNSQuestion_MXRecord はMXレコードのクエリタイプを正しく識別することを確認する。
func TestParseDNSQuestion_MXRecord(t *testing.T) {
	data := []byte{
		4, 'm', 'a', 'i', 'l', // ラベル "mail"
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // ラベル "example"
		3, 'c', 'o', 'm', // ラベル "com"
		0,     // ラベル終端
		0, 15, // QTYPE = MX (15)
		0, 1, // QCLASS = IN
	}

	domain, qtype, ok := parseDNSQuestion(data)
	if !ok {
		t.Fatal("parseDNSQuestion が false を返した")
	}
	if domain != "mail.example.com" {
		t.Errorf("domain = %q, want \"mail.example.com\"", domain)
	}
	if qtype != "MX" {
		t.Errorf("qtype = %q, want \"MX\"", qtype)
	}
}

// ─── parseHexAddr ─────────────────────────────────────────────

// TestParseHexAddr_IPv4Loopback はループバックアドレスのIPv4解析を確認する。
func TestParseHexAddr_IPv4Loopback(t *testing.T) {
	// 127.0.0.1:80 — /proc/net/tcp形式のリトルエンディアンhex
	// 127.0.0.1 → バイト列 [0x7f, 0x00, 0x00, 0x01] → LE32 → 0x0100007F
	ip, port, err := parseHexAddr("0100007F:0050", false)
	if err != nil {
		t.Fatalf("parseHexAddr失敗: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("IP = %q, want \"127.0.0.1\"", ip)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

// TestParseHexAddr_IPv4HighPort は大きなポート番号のIPv4解析を確認する。
func TestParseHexAddr_IPv4HighPort(t *testing.T) {
	// 10.0.0.1:443 — 0x000000A = 10.0.0.0 の表現ではなく
	// 10.0.0.1 → [0x0a, 0x00, 0x00, 0x01] → LE32 → 0x0100000A
	// ポート 443 (0x01BB)
	ip, port, err := parseHexAddr("0100000A:01BB", false)
	if err != nil {
		t.Fatalf("parseHexAddr失敗: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("IP = %q, want \"10.0.0.1\"", ip)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

// TestParseHexAddr_InvalidFormat は不正な形式でエラーを返すことを確認する。
func TestParseHexAddr_InvalidFormat(t *testing.T) {
	invalidInputs := []string{
		"",              // 空文字列
		"NOCOLON",       // コロンなし
		"GGGGGGGG:0050", // 無効な16進数（IP部）
		"0100007F:ZZZZ", // 無効な16進数（ポート部）
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, _, err := parseHexAddr(input, false)
			if err == nil {
				t.Errorf("不正な入力%qでエラーが返されなかった", input)
			}
		})
	}
}

// ─── parseDNSPacket ───────────────────────────────────────────

// TestParseDNSPacket_TooShort は短すぎるパケットが拒否されることを確認する。
func TestParseDNSPacket_TooShort(t *testing.T) {
	_, ok := parseDNSPacket([]byte{0x00, 0x01})
	if ok {
		t.Error("短すぎるパケットがtrue（ok）を返した")
	}
}

// TestParseDNSPacket_NonUDP はUDP以外のプロトコルが拒否されることを確認する。
func TestParseDNSPacket_NonUDP(t *testing.T) {
	// TCPパケット（protocol=6）を構築する
	pkt := make([]byte, 60)
	pkt[0] = 0x45 // IPv4, IHL=20
	pkt[9] = 6    // IPPROTO_TCP（UDPは17）
	_, ok := parseDNSPacket(pkt)
	if ok {
		t.Error("TCPパケット（protocol=6）がtrue（ok）を返した")
	}
}

// TestParseDNSPacket_NonDNSPort はポート53以外のUDPパケットが拒否されることを確認する。
func TestParseDNSPacket_NonDNSPort(t *testing.T) {
	// 宛先ポートが8080のUDPパケットを構築する
	pkt := make([]byte, 60)
	pkt[0] = 0x45                                // IPv4, IHL=20
	pkt[9] = 17                                  // IPPROTO_UDP
	binary.BigEndian.PutUint16(pkt[22:24], 8080) // 宛先ポート = 8080
	_, ok := parseDNSPacket(pkt)
	if ok {
		t.Error("ポート8080のUDPパケットがtrue（ok）を返した")
	}
}

// TestParseDNSPacket_DNSResponse はDNSレスポンス（QRビット=1）が拒否されることを確認する。
func TestParseDNSPacket_DNSResponse(t *testing.T) {
	// DNSレスポンスパケットを構築する（QRビット=1はレスポンスを意味する）
	pkt := make([]byte, 80)
	pkt[0] = 0x45                              // IPv4, IHL=20
	pkt[9] = 17                                // IPPROTO_UDP
	binary.BigEndian.PutUint16(pkt[22:24], 53) // 宛先ポート = 53

	// DNSヘッダー（オフセット = IHL(20) + UDP(8) = 28）
	// flags = 0x8000（QRビット=1 → レスポンス）
	binary.BigEndian.PutUint16(pkt[30:32], 0x8000)
	// qdcount = 1
	binary.BigEndian.PutUint16(pkt[32:34], 1)

	_, ok := parseDNSPacket(pkt)
	if ok {
		t.Error("DNSレスポンスパケット（QR=1）がtrue（ok）を返した")
	}
}
