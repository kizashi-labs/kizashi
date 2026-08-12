package timeline

import (
	"strings"
	"testing"
)

// ─── strData ─────────────────────────────────────────────────────────────────

func TestStrData_FirstKeyFound(t *testing.T) {
	data := map[string]interface{}{"process_name": "cmd.exe", "image": "cmd.exe"}
	got := strData(data, "process_name", "image")
	if got != "cmd.exe" {
		t.Errorf("strData: got %q, want cmd.exe", got)
	}
}

func TestStrData_FallbackToSecondKey(t *testing.T) {
	data := map[string]interface{}{"image": "notepad.exe"}
	got := strData(data, "process_name", "image")
	if got != "notepad.exe" {
		t.Errorf("strData フォールバック: got %q, want notepad.exe", got)
	}
}

func TestStrData_NoneFound_ReturnsEmpty(t *testing.T) {
	data := map[string]interface{}{"other": "value"}
	got := strData(data, "process_name", "image")
	if got != "" {
		t.Errorf("キーなし: got %q, want empty", got)
	}
}

func TestStrData_NilMap_ReturnsEmpty(t *testing.T) {
	got := strData(nil, "key1")
	if got != "" {
		t.Errorf("nilマップ: got %q, want empty", got)
	}
}

func TestStrData_NonStringValue_Skipped(t *testing.T) {
	data := map[string]interface{}{"pid": 1234, "name": "proc.exe"}
	got := strData(data, "pid", "name")
	// int型はスキップされ "name" にフォールバック
	if got != "proc.exe" {
		t.Errorf("非文字列値スキップ: got %q, want proc.exe", got)
	}
}

// ─── categoryFromEventType ────────────────────────────────────────────────────

func TestCategoryFromEventType_Process_Default(t *testing.T) {
	cat := categoryFromEventType("process", map[string]interface{}{
		"process_name": "calc.exe",
	})
	if cat != "execution" {
		t.Errorf("通常プロセス: got %q, want execution", cat)
	}
}

func TestCategoryFromEventType_Process_Persistence(t *testing.T) {
	cat := categoryFromEventType("process", map[string]interface{}{
		"cmdline": "schtasks /create /tn malware",
	})
	if cat != "persistence" {
		t.Errorf("schtasks: got %q, want persistence", cat)
	}
}

func TestCategoryFromEventType_Process_Discovery(t *testing.T) {
	cat := categoryFromEventType("process", map[string]interface{}{
		"process_name": "whoami.exe",
	})
	if cat != "discovery" {
		t.Errorf("whoami.exe: got %q, want discovery", cat)
	}
}

func TestCategoryFromEventType_Network_C2_HTTPS(t *testing.T) {
	cat := categoryFromEventType("network", map[string]interface{}{
		"dst_port": "443",
	})
	if cat != "c2" {
		t.Errorf("port 443: got %q, want c2", cat)
	}
}

func TestCategoryFromEventType_Network_LateralMovement(t *testing.T) {
	cat := categoryFromEventType("network", map[string]interface{}{
		"dst_port": "445",
	})
	if cat != "lateral_movement" {
		t.Errorf("port 445: got %q, want lateral_movement", cat)
	}
}

func TestCategoryFromEventType_File_Write_Persistence(t *testing.T) {
	cat := categoryFromEventType("file", map[string]interface{}{
		"operation": "write",
	})
	if cat != "persistence" {
		t.Errorf("file write: got %q, want persistence", cat)
	}
}

func TestCategoryFromEventType_Registry_Persistence(t *testing.T) {
	cat := categoryFromEventType("registry", nil)
	if cat != "persistence" {
		t.Errorf("registry: got %q, want persistence", cat)
	}
}

func TestCategoryFromEventType_DNS_C2(t *testing.T) {
	cat := categoryFromEventType("dns", nil)
	if cat != "c2" {
		t.Errorf("dns: got %q, want c2", cat)
	}
}

func TestCategoryFromEventType_Auth_LateralMovement(t *testing.T) {
	cat := categoryFromEventType("auth", nil)
	if cat != "lateral_movement" {
		t.Errorf("auth: got %q, want lateral_movement", cat)
	}
}

func TestCategoryFromEventType_Unknown_Execution(t *testing.T) {
	cat := categoryFromEventType("unknown_type", nil)
	if cat != "execution" {
		t.Errorf("unknown type: got %q, want execution", cat)
	}
}

// ─── titleFromEvent ───────────────────────────────────────────────────────────

func TestTitleFromEvent_Process_WithName(t *testing.T) {
	title := titleFromEvent("process", map[string]interface{}{
		"process_name": "cmd.exe",
	})
	if !strings.Contains(title, "cmd.exe") {
		t.Errorf("プロセスタイトル: got %q, want contains cmd.exe", title)
	}
}

func TestTitleFromEvent_Process_UnknownFallback(t *testing.T) {
	title := titleFromEvent("process", map[string]interface{}{})
	if !strings.Contains(title, "Unknown Process") {
		t.Errorf("プロセス名なし: got %q, want contains Unknown Process", title)
	}
}

func TestTitleFromEvent_Network_WithIP(t *testing.T) {
	title := titleFromEvent("network", map[string]interface{}{
		"dst_ip": "8.8.8.8", "dst_port": "53",
	})
	if !strings.Contains(title, "8.8.8.8") {
		t.Errorf("ネットワークタイトル: got %q, want contains 8.8.8.8", title)
	}
}

func TestTitleFromEvent_File_WithPath(t *testing.T) {
	title := titleFromEvent("file", map[string]interface{}{
		"file_path": "C:\\temp\\evil.exe", "operation": "write",
	})
	if !strings.Contains(title, "evil.exe") {
		t.Errorf("ファイルタイトル: got %q, want contains evil.exe", title)
	}
}

func TestTitleFromEvent_DNS(t *testing.T) {
	title := titleFromEvent("dns", map[string]interface{}{
		"query": "malware.example.com",
	})
	if !strings.Contains(title, "malware.example.com") {
		t.Errorf("DNSタイトル: got %q, want contains malware.example.com", title)
	}
}

// ─── descriptionFromEvent ─────────────────────────────────────────────────────

func TestDescriptionFromEvent_Process_WithCmdline(t *testing.T) {
	desc := descriptionFromEvent("process", map[string]interface{}{
		"cmdline": "powershell.exe -enc SGVsbG8=",
	})
	if !strings.Contains(desc, "Cmdline:") {
		t.Errorf("プロセス説明: got %q, want contains Cmdline:", desc)
	}
}

func TestDescriptionFromEvent_Process_LongCmdlineTruncated(t *testing.T) {
	long := strings.Repeat("A", 200)
	desc := descriptionFromEvent("process", map[string]interface{}{
		"cmdline": long,
	})
	// 120文字 + "..." にトリムされるはず
	if len(desc) > 140 {
		t.Errorf("長いcmdlineはトリムされるべきです: len=%d", len(desc))
	}
	if !strings.HasSuffix(desc, "...") {
		t.Error("トリムされた説明は ... で終わるべきです")
	}
}

func TestDescriptionFromEvent_Network_Protocol(t *testing.T) {
	desc := descriptionFromEvent("network", map[string]interface{}{
		"protocol": "TCP",
	})
	if !strings.Contains(desc, "TCP") {
		t.Errorf("ネットワーク説明: got %q, want contains TCP", desc)
	}
}

func TestDescriptionFromEvent_Unknown_EmptyString(t *testing.T) {
	desc := descriptionFromEvent("unknown", nil)
	if desc != "" {
		t.Errorf("未知タイプの説明は空であるべきです: got %q", desc)
	}
}
