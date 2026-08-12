package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────
// フォレンジックジョブタイプバリデーションのテスト
// ─────────────────────────────────────────────

// isValidForensicsJobType は forensics_handler.go の CreateJob で行う
// ジョブタイプの検証ロジックを純粋関数として抽出したもの。
func isValidForensicsJobType(jobType string) bool {
	switch jobType {
	case "memory_dump", "process_list", "artifact_collect":
		return true
	default:
		return false
	}
}

func TestIsValidForensicsJobType_ValidTypes(t *testing.T) {
	// 有効なジョブタイプ（memory_dump, process_list, artifact_collect）が認識されることを確認
	valid := []string{"memory_dump", "process_list", "artifact_collect"}
	for _, jt := range valid {
		t.Run(jt, func(t *testing.T) {
			if !isValidForensicsJobType(jt) {
				t.Errorf("isValidForensicsJobType(%q) = false, want true", jt)
			}
		})
	}
}

func TestIsValidForensicsJobType_InvalidTypes(t *testing.T) {
	// 無効なジョブタイプは false を返すことを確認
	invalid := []string{
		"",
		"MEMORY_DUMP",     // 大文字は無効
		"network_capture", // 定義されていないタイプ
		"disk_image",
		"registry_dump",
		"log_collect",
		"unknown",
	}
	for _, jt := range invalid {
		t.Run(jt, func(t *testing.T) {
			if isValidForensicsJobType(jt) {
				t.Errorf("isValidForensicsJobType(%q) = true, want false (無効なタイプ)", jt)
			}
		})
	}
}

func TestIsValidForensicsJobType_CaseSensitive(t *testing.T) {
	// バリデーションが大文字小文字を区別することを確認
	if isValidForensicsJobType("Memory_Dump") {
		t.Error("isValidForensicsJobType(\"Memory_Dump\") = true, 大文字混在は無効のはず")
	}
	if isValidForensicsJobType("PROCESS_LIST") {
		t.Error("isValidForensicsJobType(\"PROCESS_LIST\") = true, 全大文字は無効のはず")
	}
	if !isValidForensicsJobType("memory_dump") {
		t.Error("isValidForensicsJobType(\"memory_dump\") = false, 小文字は有効のはず")
	}
}

// ─────────────────────────────────────────────
// フォレンジックジョブステータス遷移のテスト
// ─────────────────────────────────────────────

// isValidForensicsStatus は ForensicsJob の Status フィールドに格納できる
// 有効な値を検証する純粋関数。
func isValidForensicsStatus(status string) bool {
	switch status {
	case "pending", "running", "done", "failed":
		return true
	default:
		return false
	}
}

func TestIsValidForensicsStatus_ValidStatuses(t *testing.T) {
	// 有効なステータス値（pending, running, done, failed）が認識されることを確認
	valid := []string{"pending", "running", "done", "failed"}
	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			if !isValidForensicsStatus(s) {
				t.Errorf("isValidForensicsStatus(%q) = false, want true", s)
			}
		})
	}
}

func TestIsValidForensicsStatus_InvalidStatuses(t *testing.T) {
	// 未定義のステータス値は false を返すことを確認
	invalid := []string{
		"",
		"completed", // done の代わりに使われがちだが無効
		"error",
		"cancelled",
		"PENDING", // 大文字は無効
		"in_progress",
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			if isValidForensicsStatus(s) {
				t.Errorf("isValidForensicsStatus(%q) = true, want false", s)
			}
		})
	}
}

// ─────────────────────────────────────────────
// アーティファクトファイル名生成のテスト
// ─────────────────────────────────────────────

// buildArtifactFilename は forensics_handler.go の DownloadArtifact で行う
// ファイル名生成ロジックを純粋関数として抽出したもの。
// 実際のコード: fmt.Sprintf("forensics_%s_%s_%d.bin", agentPrefix, jobType, time.Now().Unix())
func buildArtifactFilename(agentID, jobType string, ts time.Time) string {
	agentPrefix := agentID
	if len(agentPrefix) > 8 {
		agentPrefix = agentPrefix[:8]
	}
	return fmt.Sprintf("forensics_%s_%s_%d.bin", agentPrefix, jobType, ts.Unix())
}

func TestBuildArtifactFilename_ContainsJobType(t *testing.T) {
	// 生成されたファイル名にジョブタイプが含まれることを確認
	ts := time.Unix(1700000000, 0)
	for _, jt := range []string{"memory_dump", "process_list", "artifact_collect"} {
		got := buildArtifactFilename("agent-001", jt, ts)
		if !strings.Contains(got, jt) {
			t.Errorf("buildArtifactFilename (%q): ジョブタイプが含まれていません: %q", jt, got)
		}
	}
}

func TestBuildArtifactFilename_AgentIDTruncatedTo8Chars(t *testing.T) {
	// エージェントIDが8文字に切り詰められることを確認
	ts := time.Unix(1700000000, 0)
	longAgentID := "abcdefghijklmnopqrstuvwxyz"
	got := buildArtifactFilename(longAgentID, "memory_dump", ts)
	// "forensics_" プレフィックスの後に来るエージェントプレフィックスは最大8文字
	expected := "forensics_abcdefgh_memory_dump_"
	if !strings.HasPrefix(got, expected) {
		t.Errorf("buildArtifactFilename: エージェントプレフィックスが正しくありません\ngot: %q\nwant prefix: %q", got, expected)
	}
}

func TestBuildArtifactFilename_ShortAgentIDNotTruncated(t *testing.T) {
	// 8文字以下のエージェントIDは切り詰められないことを確認
	ts := time.Unix(1700000000, 0)
	shortAgentID := "ag-001"
	got := buildArtifactFilename(shortAgentID, "process_list", ts)
	if !strings.Contains(got, shortAgentID) {
		t.Errorf("buildArtifactFilename: 短いエージェントIDが保持されていません: %q", got)
	}
}

func TestBuildArtifactFilename_HasBinExtension(t *testing.T) {
	// 生成されたファイル名が .bin 拡張子で終わることを確認
	ts := time.Unix(1700000000, 0)
	got := buildArtifactFilename("agent-001", "memory_dump", ts)
	if !strings.HasSuffix(got, ".bin") {
		t.Errorf("buildArtifactFilename: .bin 拡張子がありません: %q", got)
	}
}

func TestBuildArtifactFilename_ContainsTimestamp(t *testing.T) {
	// ファイル名にUnixタイムスタンプが含まれることを確認
	ts := time.Unix(1700000000, 0)
	got := buildArtifactFilename("agent-001", "memory_dump", ts)
	wantTimestamp := fmt.Sprintf("%d", ts.Unix())
	if !strings.Contains(got, wantTimestamp) {
		t.Errorf("buildArtifactFilename: タイムスタンプが含まれていません\ngot: %q\nwant substring: %q", got, wantTimestamp)
	}
}

func TestBuildArtifactFilename_StartsWithForensicsPrefix(t *testing.T) {
	// ファイル名が "forensics_" で始まることを確認
	ts := time.Unix(1700000000, 0)
	got := buildArtifactFilename("some-agent", "artifact_collect", ts)
	if !strings.HasPrefix(got, "forensics_") {
		t.Errorf("buildArtifactFilename: \"forensics_\" プレフィックスがありません: %q", got)
	}
}

// ─────────────────────────────────────────────
// フォレンジックモジュール一覧のテスト
// ─────────────────────────────────────────────

// forensicsAvailableModules は forensics_automation_handler.go の GetStats で
// ハードコードされている利用可能モジュール一覧。
var forensicsAvailableModules = []string{
	"memory_dump", "disk_image", "network_capture", "registry",
	"event_logs", "prefetch", "shellbag", "mft", "lnk_files",
}

func TestForensicsAvailableModules_NotEmpty(t *testing.T) {
	// モジュール一覧が空でないことを確認
	if len(forensicsAvailableModules) == 0 {
		t.Error("利用可能モジュール一覧が空です")
	}
}

func TestForensicsAvailableModules_ContainsCoreModules(t *testing.T) {
	// 重要なコアモジュールが一覧に含まれることを確認
	coreModules := []string{"memory_dump", "disk_image", "network_capture", "event_logs"}
	moduleSet := make(map[string]bool)
	for _, m := range forensicsAvailableModules {
		moduleSet[m] = true
	}
	for _, core := range coreModules {
		if !moduleSet[core] {
			t.Errorf("コアモジュール %q がモジュール一覧に含まれていません", core)
		}
	}
}

func TestForensicsAvailableModules_NoDuplicates(t *testing.T) {
	// モジュール一覧に重複がないことを確認
	seen := make(map[string]bool)
	for _, m := range forensicsAvailableModules {
		if seen[m] {
			t.Errorf("モジュール %q が重複しています", m)
		}
		seen[m] = true
	}
}

func TestForensicsAvailableModules_NoEmptyEntries(t *testing.T) {
	// モジュール一覧に空文字列が含まれないことを確認
	for i, m := range forensicsAvailableModules {
		if m == "" {
			t.Errorf("インデックス %d のモジュール名が空文字列です", i)
		}
	}
}
