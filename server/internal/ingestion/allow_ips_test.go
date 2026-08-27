package ingestion

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAllowIPs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          string
		wantAccepted []string
		wantRejected int
	}{
		{name: "空", raw: "", wantAccepted: nil},
		{name: "空白のみ", raw: "  ,  , ", wantAccepted: nil},
		{
			name:         "単一アドレスと CIDR",
			raw:          "10.0.0.5, 192.168.1.0/24",
			wantAccepted: []string{"10.0.0.5", "192.168.1.0/24"},
		},
		{
			name:         "前後の空白を落とす",
			raw:          "  10.0.0.5  ",
			wantAccepted: []string{"10.0.0.5"},
		},
		{
			// **ここで弾くのが要点。** 通してしまうと、気づくのは端末が
			// 隔離されたあと ——「除外したはずのセグメントが遮断されている」
			// という形で、しかも隔離は外から取り消せない。
			name:         "壊れた項目は落とし、正しい項目は残す",
			raw:          "10.0.0.5, not-an-ip, 10.0.0.0/33, 256.1.2.3",
			wantAccepted: []string{"10.0.0.5"},
			wantRejected: 3,
		},
		{
			// agent 側のブロック範囲計算は uint32 で IPv6 を載せられない。
			// ここで通すと、agent まで運ばれてから捨てられる。
			name:         "IPv6 は対象外",
			raw:          "2001:db8::1, 2001:db8::/32, 10.0.0.5",
			wantAccepted: []string{"10.0.0.5"},
			wantRejected: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accepted, rejected := ParseAllowIPs(tc.raw)
			if strings.Join(accepted, ",") != strings.Join(tc.wantAccepted, ",") {
				t.Errorf("accepted: %v を期待、得たのは %v", tc.wantAccepted, accepted)
			}
			if len(rejected) != tc.wantRejected {
				t.Errorf("rejected: %d 件を期待、得たのは %d 件 %v",
					tc.wantRejected, len(rejected), rejected)
			}
		})
	}
}

// 弾いた項目には理由が付くこと。件数だけでは、運用側は何を直せばよいか分からない。
func TestParseAllowIPs_RejectionCarriesReason(t *testing.T) {
	_, rejected := ParseAllowIPs("not-an-ip")
	if len(rejected) != 1 {
		t.Fatalf("1 件を期待、得たのは %v", rejected)
	}
	if !strings.Contains(rejected[0], "not-an-ip") {
		t.Errorf("どの項目が弾かれたのか分かりません: %q", rejected[0])
	}
	if !strings.Contains(rejected[0], "(") {
		t.Errorf("理由が付いていません: %q", rejected[0])
	}
}

// 許可リストが隔離コマンドに載ること。
//
// **proto の allow_ips は最初からあったのに、サーバが一度も詰めていなかった。**
// 隔離された端末から届くのは EDR サーバとループバックだけで、踏み台や DC を
// 残す手段が運用側に無かった。
func TestCommandToProto_IsolateCarriesAllowIPs(t *testing.T) {
	allow := []string{"10.0.0.5", "192.168.1.0/24"}
	got := commandToProto(&Command{
		ID:      "cmd-iso",
		Type:    "isolate",
		Payload: json.RawMessage(`{"reason":"test","alert_id":"a-1"}`),
	}, allow)
	if got == nil {
		t.Fatal("隔離コマンドが組み立てられていません")
	}
	iso := got.GetIsolate()
	if iso == nil {
		t.Fatal("Isolate が入っていません")
	}
	if strings.Join(iso.GetAllowIps(), ",") != strings.Join(allow, ",") {
		t.Errorf("allow_ips: %v を期待、得たのは %v", allow, iso.GetAllowIps())
	}
	// 既存の項目を壊していないこと。
	if iso.GetReason() != "test" || iso.GetAlertId() != "a-1" {
		t.Errorf("reason/alert_id が壊れています: %+v", iso)
	}
}

// 未設定なら従来どおり空で送ること（EDR サーバとループバックのみ）。
func TestCommandToProto_IsolateWithoutAllowIPs(t *testing.T) {
	got := commandToProto(&Command{
		ID:      "cmd-iso",
		Type:    "isolate",
		Payload: json.RawMessage(`{"reason":"test","alert_id":"a-1"}`),
	}, nil)
	if got == nil {
		t.Fatal("隔離コマンドが組み立てられていません")
	}
	if n := len(got.GetIsolate().GetAllowIps()); n != 0 {
		t.Errorf("未設定なら空であるべきです。得たのは %d 件", n)
	}
}

// 許可リストは隔離コマンドにだけ載ること。他の種別に混ぜない。
func TestCommandToProto_AllowIPsOnlyOnIsolate(t *testing.T) {
	got := commandToProto(&Command{
		ID:      "cmd-un",
		Type:    "unisolate",
		Payload: json.RawMessage(`{"reason":"test"}`),
	}, []string{"10.0.0.5"})
	if got == nil {
		t.Fatal("解除コマンドが組み立てられていません")
	}
	if got.GetUnisolate() == nil {
		t.Fatal("Unisolate が入っていません")
	}
	if got.GetIsolate() != nil {
		t.Error("解除コマンドに Isolate が混ざっています")
	}
}
