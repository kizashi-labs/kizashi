package ingestion

// 壊れたコマンドペイロードをそのままエージェントへ送っていた件の再発防止。
//
// commandToProto は各コマンド種別のペイロードを json.Unmarshal でほどくが、
// 戻り値を捨てていた。パースに失敗すると構造体はゼロ値のままで、その値で
// proto を組み立てて送信していた。害が具体的なのは:
//
//	kill_process    → PID 0 のプロセス終了コマンドが端末に届く
//	quarantine_file → 空パスの隔離コマンドが届く
//	isolate         → 理由なしの隔離コマンドが届く
//
// 呼び出し側 (Dequeue のループ) は nil を読み飛ばすので、壊れていたら
// 送らないのが安全側。

import (
	"encoding/json"
	"testing"
)

func TestCommandToProto_DropsMalformedPayload(t *testing.T) {
	// どれも JSON として壊れている。ゼロ値で送られると実害があるものを選ぶ。
	for _, tc := range []struct {
		name    string
		cmdType string
		payload string
	}{
		{"kill_process/壊れたJSON", "kill_process", `{"pid": }`},
		{"kill_process/配列", "kill_process", `[1,2,3]`},
		{"quarantine_file/壊れたJSON", "quarantine_file", `{"path":`},
		{"isolate/壊れたJSON", "isolate", `not json at all`},
		{"unisolate/壊れたJSON", "unisolate", `{`},
		{"restore_file/壊れたJSON", "restore_file", `{"quarantine_id"}`},
		{"scan/壊れたJSON", "scan", `{{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := commandToProto(&Command{
				ID:      "cmd-1",
				Type:    tc.cmdType,
				Payload: json.RawMessage(tc.payload),
			}, nil)
			if got != nil {
				t.Fatalf("壊れたペイロードなのに送信対象が組み立てられている: %+v", got)
			}
		})
	}
}

func TestCommandToProto_KeepsValidPayload(t *testing.T) {
	cmd := &Command{
		ID:      "cmd-2",
		Type:    "kill_process",
		Payload: json.RawMessage(`{"pid": 4242, "reason": "ransomware"}`),
	}
	got := commandToProto(cmd, nil)
	if got == nil {
		t.Fatal("正しいペイロードが落とされている")
	}
	kp := got.GetKillProcess()
	if kp == nil {
		t.Fatalf("KillProcess が入っていない: %+v", got)
	}
	if kp.Pid != 4242 {
		t.Errorf("Pid = %d, want 4242", kp.Pid)
	}
	if kp.Reason != "ransomware" {
		t.Errorf("Reason = %q, want ransomware", kp.Reason)
	}
	if got.CommandId != "cmd-2" {
		t.Errorf("CommandId = %q, want cmd-2", got.CommandId)
	}
}

// ペイロードを JSON としてほどかない種別 (apply_policy / cert_renew /
// live_response_start / reload_config) は、壊れた JSON でも素通しでよい。
// 中身の解釈はエージェント側が行うため、ここで落とすと正常系まで止まる。
func TestCommandToProto_PassthroughTypesUnaffected(t *testing.T) {
	for _, cmdType := range []string{"apply_policy", "cert_renew", "reload_config"} {
		t.Run(cmdType, func(t *testing.T) {
			got := commandToProto(&Command{
				ID:      "cmd-3",
				Type:    cmdType,
				Payload: json.RawMessage(`{"type":"` + cmdType + `"}`),
			}, nil)
			if got == nil {
				t.Fatalf("%s が落とされている", cmdType)
			}
		})
	}
}
