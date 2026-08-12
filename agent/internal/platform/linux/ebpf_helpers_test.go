//go:build linux && ebpf

// Package linux — eBPFローダーのGo側ヘルパー ユニットテスト
// eBPFプログラムのロード・カーネル呼び出しは一切行わず、
// 純粋なGo関数（nullTerminated, splitLines, splitColon, byteReader）のみをテストする。
package linux

import (
	"testing"
	"unsafe"
)

// ─── nullTerminated ───────────────────────────────────────────

// TestNullTerminated_NullInMiddle はNULLバイトより前の文字列だけが返ることを確認する。
func TestNullTerminated_NullInMiddle(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "中間NULLバイト",
			input: []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'},
			want:  "hello",
		},
		{
			name:  "先頭NULLバイト",
			input: []byte{0, 'a', 'b', 'c'},
			want:  "",
		},
		{
			name:  "NULLバイトなし（全データを返す）",
			input: []byte{'a', 'b', 'c'},
			want:  "abc",
		},
		{
			name:  "末尾NULLバイト",
			input: []byte{'t', 'e', 's', 't', 0},
			want:  "test",
		},
		{
			name:  "空バイトスライス",
			input: []byte{},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nullTerminated(tc.input)
			if got != tc.want {
				t.Errorf("nullTerminated(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestNullTerminated_CommField はeBPF comm フィールド（16バイト固定長）の変換を確認する。
func TestNullTerminated_CommField(t *testing.T) {
	// カーネルが埋める comm フィールドのシミュレーション（15文字 + NULL）
	var comm [16]byte
	copy(comm[:], "systemd-journald")
	// 16文字ぴったりなのでNULLなし → 全部返る
	got := nullTerminated(comm[:])
	if got != "systemd-journald" {
		t.Errorf("nullTerminated(16バイトfull) = %q, want \"systemd-journald\"", got)
	}

	// 短いプロセス名（bash\0）
	var comm2 [16]byte
	copy(comm2[:], "bash")
	got2 := nullTerminated(comm2[:])
	if got2 != "bash" {
		t.Errorf("nullTerminated(\"bash\" + zeros) = %q, want \"bash\"", got2)
	}
}

// TestNullTerminated_FilenameField はFilenameフィールド（256バイト）の変換を確認する。
func TestNullTerminated_FilenameField(t *testing.T) {
	var filename [256]byte
	path := "/usr/bin/python3"
	copy(filename[:], path)

	got := nullTerminated(filename[:])
	if got != path {
		t.Errorf("nullTerminated(filename) = %q, want %q", got, path)
	}
}

// ─── splitLines ───────────────────────────────────────────────

// TestSplitLines_Basic は改行で正しく分割されることを確認する。
func TestSplitLines_Basic(t *testing.T) {
	input := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	lines := splitLines(input)

	if len(lines) != 2 {
		t.Errorf("行数 = %d, want 2", len(lines))
	}
	if lines[0] != "root:x:0:0:root:/root:/bin/bash" {
		t.Errorf("lines[0] = %q, 期待値と異なる", lines[0])
	}
	if lines[1] != "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" {
		t.Errorf("lines[1] = %q, 期待値と異なる", lines[1])
	}
}

// TestSplitLines_EmptyInput は空文字列で空スライスを返すことを確認する。
func TestSplitLines_EmptyInput(t *testing.T) {
	// nil スライスの len() は 0 と定義されているので、nil 判定は要らない。
	lines := splitLines("")
	if len(lines) != 0 {
		t.Errorf("空文字列のsplitLines = %v, want []", lines)
	}
}

// TestSplitLines_NoNewline は改行なし文字列でスライスが空になることを確認する（末尾のみ）。
func TestSplitLines_NoNewline(t *testing.T) {
	// splitLines は '\n' だけで分割し、残りは追加しない
	lines := splitLines("no newline here")
	if len(lines) != 0 {
		t.Errorf("改行なし文字列のsplitLines = %d行, want 0", len(lines))
	}
}

// TestSplitLines_MultipleLines は複数行の/etc/passwdライクなデータを分割できることを確認する。
func TestSplitLines_MultipleLines(t *testing.T) {
	input := "line1\nline2\nline3\n"
	lines := splitLines(input)

	if len(lines) != 3 {
		t.Fatalf("行数 = %d, want 3", len(lines))
	}
	for i, want := range []string{"line1", "line2", "line3"} {
		if lines[i] != want {
			t.Errorf("lines[%d] = %q, want %q", i, lines[i], want)
		}
	}
}

// ─── splitColon ───────────────────────────────────────────────

// TestSplitColon_PasswdEntry は/etc/passwdの典型的な行を正しく分割することを確認する。
func TestSplitColon_PasswdEntry(t *testing.T) {
	line := "root:x:0:0:root:/root:/bin/bash"
	parts := splitColon(line)

	if len(parts) != 7 {
		t.Fatalf("フィールド数 = %d, want 7", len(parts))
	}
	if parts[0] != "root" {
		t.Errorf("parts[0] = %q, want \"root\"", parts[0])
	}
	if parts[2] != "0" {
		t.Errorf("parts[2] = %q, want \"0\"（UID）", parts[2])
	}
	if parts[6] != "/bin/bash" {
		t.Errorf("parts[6] = %q, want \"/bin/bash\"", parts[6])
	}
}

// TestSplitColon_NoColon はコロンを含まない文字列が単一要素スライスを返すことを確認する。
func TestSplitColon_NoColon(t *testing.T) {
	parts := splitColon("noColon")
	if len(parts) != 1 {
		t.Fatalf("フィールド数 = %d, want 1", len(parts))
	}
	if parts[0] != "noColon" {
		t.Errorf("parts[0] = %q, want \"noColon\"", parts[0])
	}
}

// TestSplitColon_ConsecutiveColons は連続したコロンが空フィールドを生成することを確認する。
func TestSplitColon_ConsecutiveColons(t *testing.T) {
	// "a::b" → ["a", "", "b"]
	parts := splitColon("a::b")
	if len(parts) != 3 {
		t.Fatalf("フィールド数 = %d, want 3", len(parts))
	}
	if parts[1] != "" {
		t.Errorf("parts[1] = %q, want \"\"（空フィールド）", parts[1])
	}
}

// ─── byteReader ───────────────────────────────────────────────

// TestByteReader_SequentialRead は順次読み出しが正しく動作することを確認する。
func TestByteReader_SequentialRead(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := unsafeReader(data)

	buf1 := make([]byte, 2)
	n1, err1 := r.Read(buf1)
	if err1 != nil {
		t.Fatalf("1回目Read失敗: %v", err1)
	}
	if n1 != 2 || buf1[0] != 0x01 || buf1[1] != 0x02 {
		t.Errorf("1回目Read = %v (n=%d), want [0x01 0x02]", buf1[:n1], n1)
	}

	buf2 := make([]byte, 3)
	n2, err2 := r.Read(buf2)
	if err2 != nil {
		t.Fatalf("2回目Read失敗: %v", err2)
	}
	if n2 != 3 || buf2[0] != 0x03 {
		t.Errorf("2回目Read = %v (n=%d), want [0x03 0x04 0x05]", buf2[:n2], n2)
	}
}

// TestByteReader_EmptyData は空データからのReadがエラーを返すことを確認する。
func TestByteReader_EmptyData(t *testing.T) {
	r := unsafeReader([]byte{})
	buf := make([]byte, 4)
	_, err := r.Read(buf)
	if err == nil {
		t.Error("空データからのReadがエラーを返さなかった")
	}
}

// ─── ebpfProcessEventFull 構造体サイズ ───────────────────────

// TestEBPFProcessEventFull_Size は構造体のサイズがC側 (ebpf/process_monitor.bpf.c
// の struct process_event) のメモリレイアウトと一致することを確認する。
// リングバッファから受け取った生バイト列をこの構造体で解釈するため、サイズ不一致は
// パース破損を意味する。
func TestEBPFProcessEventFull_Size(t *testing.T) {
	var e ebpfProcessEventFull
	got := int(unsafe.Sizeof(e))

	// TimestampNs(8) + Pid(4) + Ppid(4) + Uid(4) + Gid(4) + Action(4) + ExitCode(4)
	// + Comm(16) + Filename(256) + Args(512) = 816、末尾に ArgsLen(4) = 820。
	// 構造体は __u64/uint64 を含むためアライメント 8 で末尾に 4 バイトの
	// パディングが入り、最終サイズは 824 バイトになる (C 側の struct process_event
	// も同じ 824 バイト)。
	const wantSize = 824
	if got != wantSize {
		t.Errorf("sizeof(ebpfProcessEventFull) = %d, want %d", got, wantSize)
	}
}

// TestEBPFProcessEventFull_ActionValues はActionフィールドの期待値を確認する。
// C定義: 1=exec, 2=exit, 3=fork
func TestEBPFProcessEventFull_ActionValues(t *testing.T) {
	const (
		actionExec = uint32(1)
		actionExit = uint32(2)
		actionFork = uint32(3)
	)

	e := ebpfProcessEventFull{Action: actionExec}
	if e.Action != 1 {
		t.Errorf("Action exec = %d, want 1", e.Action)
	}

	e.Action = actionExit
	action := "create"
	if e.Action == 2 {
		action = "terminate"
	}
	if action != "terminate" {
		t.Errorf("Action=2 の変換結果 = %q, want \"terminate\"", action)
	}

	e.Action = actionFork
	if e.Action != actionFork {
		t.Errorf("Action fork = %d, want %d", e.Action, actionFork)
	}
}
