package scanner

import (
	"testing"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// ─── helpers ─────────────────────────────────────────────────

func makeProcessEvent(name, imagePath, cmdLine string) collector.ProcessEvent {
	return collector.ProcessEvent{
		ID:          "test-pid-001",
		Timestamp:   time.Now(),
		PID:         1234,
		PPID:        1,
		ProcessName: name,
		CommandLine: cmdLine,
		ImagePath:   imagePath,
		Username:    "testuser",
	}
}

func makeNetworkEvent(processName string, dstPort uint16, direction string, bytesSent uint64) collector.NetworkEvent {
	return collector.NetworkEvent{
		ID:          "net-001",
		Timestamp:   time.Now(),
		ProcessName: processName,
		DstPort:     dstPort,
		Direction:   direction,
		BytesSent:   bytesSent,
	}
}

func makeFileEvent(path, action string) collector.FileEvent {
	return collector.FileEvent{
		ID:        "file-001",
		Timestamp: time.Now(),
		Path:      path,
		Action:    action,
	}
}

// ─── NewLocalAnomalyDetector ─────────────────────────────────

func TestNewLocalAnomalyDetector_NotNil(t *testing.T) {
	d := NewLocalAnomalyDetector()
	if d == nil {
		t.Fatal("NewLocalAnomalyDetector returned nil")
	}
	if d.baseline == nil {
		t.Error("baseline should not be nil")
	}
}

// ─── normalizeProcessName ─────────────────────────────────────

func TestNormalizeProcessName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SVCHOST.EXE", "svchost.exe"},
		{`C:\Windows\System32\svchost.exe`, "svchost.exe"},
		{"/usr/bin/bash", "bash"},
		{"bash", "bash"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeProcessName(tc.input)
			if got != tc.want {
				t.Errorf("normalizeProcessName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── toLower ─────────────────────────────────────────────────

func TestToLower(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"HELLO", "hello"},
		{"Hello World", "hello world"},
		{"already lower", "already lower"},
		{"", ""},
		{"ABCXYZ", "abcxyz"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := toLower(tc.input)
			if got != tc.want {
				t.Errorf("toLower(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── contains ────────────────────────────────────────────────

func TestContains(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"hello world", "hello world", true},
		{"abc", "abcdef", false},
		{"", "x", false},
		{"abc", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.s+"/"+tc.substr, func(t *testing.T) {
			got := contains(tc.s, tc.substr)
			if got != tc.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tc.s, tc.substr, got, tc.want)
			}
		})
	}
}

// ─── hasSuffix ───────────────────────────────────────────────

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		s      string
		suffix string
		want   bool
	}{
		{"file.exe", ".exe", true},
		{"file.dll", ".exe", false},
		{"file.ps1", ".ps1", true},
		{"file.sh", ".sh", true},
		{"", ".exe", false},
		{"exe", ".exe", false},
		{"a.exe", "a.exe", true},
	}

	for _, tc := range tests {
		t.Run(tc.s, func(t *testing.T) {
			got := hasSuffix(tc.s, tc.suffix)
			if got != tc.want {
				t.Errorf("hasSuffix(%q, %q) = %v, want %v", tc.s, tc.suffix, got, tc.want)
			}
		})
	}
}

// ─── ScoreProcess ─────────────────────────────────────────────

func TestScoreProcess_CleanProcess(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeProcessEvent("nginx", "/usr/sbin/nginx", "nginx -g daemon off;")
	score := d.ScoreProcess(evt)

	// A normal process should have a low score.
	if score.Score >= 0.6 {
		t.Errorf("clean process score = %.2f, want < 0.6; reasons: %v", score.Score, score.Reasons)
	}
	if score.SendToCloud {
		t.Error("clean process should not trigger cloud analysis")
	}
}

func TestScoreProcess_SuspiciousPath(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeProcessEvent("evil.exe", `C:\Users\user\Downloads\evil.exe`, "evil.exe")
	score := d.ScoreProcess(evt)

	if score.Score <= 0 {
		t.Errorf("process in suspicious path should have score > 0, got %.2f", score.Score)
	}
	if len(score.Reasons) == 0 {
		t.Error("expected at least one reason for suspicious path")
	}
}

func TestScoreProcess_SuspiciousCommandLine(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{"encoded command", "powershell.exe -enc SQBFAFgA"},
		{"iex invocation", "powershell -iex (New-Object Net.WebClient).DownloadString()"},
		{"bypass flag", "powershell -bypass -nop script.ps1"},
	}

	d := NewLocalAnomalyDetector()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := makeProcessEvent("powershell.exe", `C:\Windows\System32\powershell.exe`, tc.cmd)
			score := d.ScoreProcess(evt)
			if score.Score <= 0 {
				t.Errorf("suspicious cmd %q should have score > 0, got %.2f", tc.cmd, score.Score)
			}
		})
	}
}

func TestScoreProcess_Masquerading(t *testing.T) {
	d := NewLocalAnomalyDetector()
	// svchost.exe running from a non-system32 path is masquerading.
	evt := makeProcessEvent("svchost.exe", `C:\Users\attacker\svchost.exe`, "svchost.exe")
	score := d.ScoreProcess(evt)

	if score.Score < 0.6 {
		t.Errorf("masquerading process score = %.2f, want >= 0.6; reasons: %v", score.Score, score.Reasons)
	}
	if !score.SendToCloud {
		t.Error("masquerading process should trigger cloud analysis")
	}
}

func TestScoreProcess_ScoreIsClamped(t *testing.T) {
	d := NewLocalAnomalyDetector()
	// Craft a worst-case event: masquerading + suspicious path + suspicious args.
	evt := makeProcessEvent(
		"svchost.exe",
		`C:\Users\bob\Downloads\svchost.exe`,
		"svchost.exe -enc SQBFAFgA -bypass",
	)
	score := d.ScoreProcess(evt)

	if score.Score > 1.0 {
		t.Errorf("score = %.2f, must not exceed 1.0", score.Score)
	}
	if score.Score < 0 {
		t.Errorf("score = %.2f, must not be negative", score.Score)
	}
}

func TestScoreProcess_UpdatesBaseline(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeProcessEvent("chrome.exe", `C:\Program Files\Google\Chrome\chrome.exe`, "chrome.exe")

	// Score the same process twice — the second call should not panic.
	d.ScoreProcess(evt)
	d.ScoreProcess(evt)

	d.mu.Lock()
	stats := d.baseline.processes["chrome.exe"]
	d.mu.Unlock()

	if stats == nil {
		t.Fatal("baseline was not updated")
	}
	if stats.SeenCount < 2 {
		t.Errorf("SeenCount = %d, want >= 2", stats.SeenCount)
	}
}

// ─── ScoreNetwork ─────────────────────────────────────────────

func TestScoreNetwork_CleanConnection(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeNetworkEvent("chrome.exe", 443, "outbound", 1024)
	score := d.ScoreNetwork(evt)

	if score.Score >= 0.6 {
		t.Errorf("normal HTTPS connection score = %.2f, want < 0.6", score.Score)
	}
}

func TestScoreNetwork_SuspiciousPort(t *testing.T) {
	tests := []struct {
		name    string
		port    uint16
		wantMin float64
	}{
		{"metasploit default 4444", 4444, 0.7},
		{"leet port 1337", 1337, 0.5},
		{"elite port 31337", 31337, 0.6},
	}

	d := NewLocalAnomalyDetector()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := makeNetworkEvent("evil.exe", tc.port, "outbound", 0)
			score := d.ScoreNetwork(evt)
			if score.Score < tc.wantMin {
				t.Errorf("port %d score = %.2f, want >= %.2f; reasons: %v",
					tc.port, score.Score, tc.wantMin, score.Reasons)
			}
		})
	}
}

func TestScoreNetwork_SystemProcessOutbound(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeNetworkEvent("lsass.exe", 80, "outbound", 0)
	score := d.ScoreNetwork(evt)

	if score.Score <= 0 {
		t.Error("lsass.exe making outbound connection should score > 0")
	}
}

func TestScoreNetwork_LargeOutboundTransfer(t *testing.T) {
	d := NewLocalAnomalyDetector()
	// 15MB outbound — potential exfiltration.
	evt := makeNetworkEvent("notepad.exe", 443, "outbound", 15*1024*1024)
	score := d.ScoreNetwork(evt)

	if score.Score <= 0 {
		t.Errorf("large outbound transfer should score > 0, got %.2f", score.Score)
	}
}

func TestScoreNetwork_ScoreIsClamped(t *testing.T) {
	d := NewLocalAnomalyDetector()
	// Worst case: system process, suspicious port, large transfer.
	evt := makeNetworkEvent("lsass.exe", 4444, "outbound", 20*1024*1024)
	score := d.ScoreNetwork(evt)

	if score.Score > 1.0 {
		t.Errorf("score = %.2f, must not exceed 1.0", score.Score)
	}
}

// ─── ScoreFile ────────────────────────────────────────────────

func TestScoreFile_NormalFile(t *testing.T) {
	d := NewLocalAnomalyDetector()
	evt := makeFileEvent("/home/user/document.txt", "modify")
	score := d.ScoreFile(evt)

	if score.Score >= 0.5 {
		t.Errorf("normal file modification score = %.2f, want < 0.5", score.Score)
	}
}

func TestScoreFile_SensitiveFile(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"linux passwd", "/etc/passwd"},
		{"linux shadow", "/etc/shadow"},
		{"linux sudoers", "/etc/sudoers"},
		{"windows hosts", `c:\windows\system32\drivers\etc\hosts`},
	}

	d := NewLocalAnomalyDetector()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := makeFileEvent(tc.path, "modify")
			score := d.ScoreFile(evt)
			if score.Score <= 0 {
				t.Errorf("sensitive file %q score = %.2f, want > 0", tc.path, score.Score)
			}
			if len(score.Reasons) == 0 {
				t.Error("expected at least one reason for sensitive file modification")
			}
		})
	}
}

func TestScoreFile_ExecutableInTempDir(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"exe in windows temp", `C:\Users\user\AppData\Local\Temp\evil.exe`},
		{"dll in windows temp", `C:\Windows\Temp\payload.dll`},
		{"script in linux tmp", "/tmp/evil.sh"},
		{"ps1 in downloads", `C:\Users\user\Downloads\script.ps1`},
	}

	d := NewLocalAnomalyDetector()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := makeFileEvent(tc.path, "create")
			score := d.ScoreFile(evt)
			if score.Score <= 0 {
				t.Errorf("executable in temp dir %q score = %.2f, want > 0", tc.path, score.Score)
			}
		})
	}
}

func TestScoreFile_ScoreIsClamped(t *testing.T) {
	d := NewLocalAnomalyDetector()
	// Both a sensitive path and an executable created in temp.
	evt := makeFileEvent(`C:\Windows\Temp\lsass.exe`, "create")
	score := d.ScoreFile(evt)

	if score.Score > 1.0 {
		t.Errorf("score = %.2f, must not exceed 1.0", score.Score)
	}
	if score.Score < 0 {
		t.Errorf("score = %.2f, must not be negative", score.Score)
	}
}

func TestScoreFile_SendToCloud_Threshold(t *testing.T) {
	d := NewLocalAnomalyDetector()

	// High score file → SendToCloud
	evt := makeFileEvent("/etc/shadow", "modify")
	score := d.ScoreFile(evt)
	if score.Score >= 0.6 && !score.SendToCloud {
		t.Errorf("score %.2f >= 0.6 but SendToCloud = false", score.Score)
	}

	// Low score file → not SendToCloud
	evt2 := makeFileEvent("/home/user/notes.txt", "modify")
	score2 := d.ScoreFile(evt2)
	if score2.Score < 0.6 && score2.SendToCloud {
		t.Errorf("score %.2f < 0.6 but SendToCloud = true", score2.Score)
	}
}

// ─── AnomalyScore struct ─────────────────────────────────────

func TestAnomalyScore_ZeroValue(t *testing.T) {
	var s AnomalyScore
	if s.Score != 0 {
		t.Errorf("zero Score = %v, want 0", s.Score)
	}
	if s.SendToCloud {
		t.Error("zero SendToCloud should be false")
	}
	if s.Reasons != nil {
		t.Error("zero Reasons should be nil")
	}
}

// ─── LocalAlert 判定 ──────────────────────────────────────────────────────────
//
// LocalAlert はエンドポイント単独で発報してよい水準に達したことを表す。
// 呼び出し側 (cmd/agent) はこれを見てバッチ間隔を待たずに送信するため、
// 判定がずれると「アラートなのに数秒遅れて届く」か「全イベントが即時送信」の
// どちらかになる。

// TestNewAnomalyScore_ThresholdBoundaries は 2 つの閾値の境界を押さえる。
// 境界は「以上」であること (0.6 ちょうどはクラウド送り、0.85 ちょうどはアラート)。
func TestNewAnomalyScore_ThresholdBoundaries(t *testing.T) {
	tests := []struct {
		raw            float64
		wantCloud      bool
		wantLocalAlert bool
	}{
		{0.0, false, false},
		{0.59, false, false},
		{0.6, true, false}, // クラウド閾値ちょうど
		{0.84, true, false},
		{0.85, true, true}, // ローカルアラート閾値ちょうど
		{0.99, true, true},
		{1.0, true, true},
	}
	for _, tc := range tests {
		got := newAnomalyScore(tc.raw, nil)
		if got.SendToCloud != tc.wantCloud {
			t.Errorf("raw=%v: SendToCloud = %v, want %v", tc.raw, got.SendToCloud, tc.wantCloud)
		}
		if got.LocalAlert != tc.wantLocalAlert {
			t.Errorf("raw=%v: LocalAlert = %v, want %v", tc.raw, got.LocalAlert, tc.wantLocalAlert)
		}
	}
}

// TestNewAnomalyScore_ClampsAboveOne は 1.0 を超える素点が丸められること。
// 丸めずに返すと、外部に出るスコアが仕様 (0.0-1.0) から外れる。
func TestNewAnomalyScore_ClampsAboveOne(t *testing.T) {
	got := newAnomalyScore(2.5, nil)
	if got.Score != 1.0 {
		t.Errorf("Score = %v, want 1.0", got.Score)
	}
	if !got.LocalAlert {
		t.Error("丸めた結果 1.0 なのに LocalAlert が立っていない")
	}
}

// TestScoreProcess_MasqueradingRaisesLocalAlert は実際の検知パターンで
// LocalAlert が立つこと。システムプロセスが想定外パス (0.6) かつ一時ディレクトリ
// (0.3) から起動 = 0.9 で、エンドポイント単独で発報してよい典型例。
func TestScoreProcess_MasqueradingRaisesLocalAlert(t *testing.T) {
	d := NewLocalAnomalyDetector()
	got := d.ScoreProcess(collector.ProcessEvent{
		ProcessName: "svchost.exe",
		ImagePath:   `c:\users\victim\appdata\local\temp\svchost.exe`,
	})
	if !got.LocalAlert {
		t.Errorf("LocalAlert = false (score=%v, reasons=%v), want true", got.Score, got.Reasons)
	}
}

// TestScoreProcess_CleanProcessHasNoLocalAlert は正常なプロセスで
// アラートが立たないこと。ここが緩むと即時送信が常時発火する。
func TestScoreProcess_CleanProcessHasNoLocalAlert(t *testing.T) {
	d := NewLocalAnomalyDetector()
	got := d.ScoreProcess(collector.ProcessEvent{
		ProcessName: "nginx",
		ImagePath:   "/usr/sbin/nginx",
		CommandLine: "nginx -g daemon off;",
	})
	if got.LocalAlert {
		t.Errorf("正常なプロセスで LocalAlert = true (score=%v, reasons=%v)", got.Score, got.Reasons)
	}
}

// TestScoreNetwork_LocalAlertOnC2Port は network 経路でも LocalAlert が
// 立つこと。以前はスコアリング自体が process にしか繋がっておらず、
// network/file の Score* は呼ばれてすらいなかった。
func TestScoreNetwork_LocalAlertOnC2Port(t *testing.T) {
	d := NewLocalAnomalyDetector()
	got := d.ScoreNetwork(collector.NetworkEvent{
		ProcessName: "lsass.exe",
		DstPort:     4444,
		Direction:   "outbound",
	})
	if !got.LocalAlert {
		t.Errorf("LocalAlert = false (score=%v, reasons=%v), want true", got.Score, got.Reasons)
	}
}

// ─── コスト計測 ──────────────────────────────────────────────────────────────
//
// ScoreFile / ScoreNetwork は以前は呼ばれておらず、ローカルアラート配線で
// 全 file/network イベントごとに走るようになった。イベント 1 件あたりの
// 追加コストがどの程度かを残しておく (protobuf マーシャルに比べて無視できる
// 水準であることの根拠)。

func BenchmarkScoreFile(b *testing.B) {
	d := NewLocalAnomalyDetector()
	evt := collector.FileEvent{
		Path:        "/var/lib/app/data/records-2026-08.tmp",
		Action:      "modify",
		ProcessName: "app",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.ScoreFile(evt)
	}
}

func BenchmarkScoreNetwork(b *testing.B) {
	d := NewLocalAnomalyDetector()
	evt := collector.NetworkEvent{
		ProcessName: "app",
		DstPort:     443,
		Direction:   "outbound",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.ScoreNetwork(evt)
	}
}
