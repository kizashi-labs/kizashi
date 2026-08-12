package store

import (
	"strings"
	"testing"
)

// ─── タグ名バリデーションヘルパー（テスト専用）────────────────────────────────
// agent_tag_store.go にはDB依存のメソッドしか存在しないため、
// タグ文字列の性質に関するロジックをテスト内ヘルパーとして再現する。

// isValidTagName はタグ名の基本的な妥当性を検証する
// ・空文字列は無効
// ・先頭・末尾のスペースが含まれる場合は無効
// ・255文字を超える場合は無効
func isValidTagName(tag string) bool {
	if tag == "" {
		return false
	}
	if strings.TrimSpace(tag) != tag {
		return false
	}
	if len(tag) > 255 {
		return false
	}
	return true
}

// normalizeTag はタグ名を正規化する（小文字化・前後スペース除去）
func normalizeTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

// containsTag はタグスライス内に指定タグが含まれるかを確認する
func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

// deduplicateTags はタグスライスから重複を除去する（順序保持）
func deduplicateTags(tags []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	if result == nil {
		return []string{}
	}
	return result
}

// ─── isValidTagName テスト ────────────────────────────────────────────────────

// TestTagName_EmptyStringIsInvalid は空文字列が無効なタグ名であることを確認する
func TestTagName_EmptyStringIsInvalid(t *testing.T) {
	if isValidTagName("") {
		t.Error("空文字列は無効なタグ名であるべき")
	}
}

// TestTagName_PlainStringIsValid は通常の文字列が有効であることを確認する
func TestTagName_PlainStringIsValid(t *testing.T) {
	validTags := []string{"production", "critical", "web-server", "dc-01", "region:us-east"}
	for _, tag := range validTags {
		if !isValidTagName(tag) {
			t.Errorf("isValidTagName(%q) = false, want true", tag)
		}
	}
}

// TestTagName_LeadingSpaceIsInvalid は先頭スペースが無効であることを確認する
func TestTagName_LeadingSpaceIsInvalid(t *testing.T) {
	if isValidTagName(" production") {
		t.Error("先頭にスペースがあるタグは無効であるべき")
	}
}

// TestTagName_TrailingSpaceIsInvalid は末尾スペースが無効であることを確認する
func TestTagName_TrailingSpaceIsInvalid(t *testing.T) {
	if isValidTagName("production ") {
		t.Error("末尾にスペースがあるタグは無効であるべき")
	}
}

// TestTagName_TooLongIsInvalid は255文字を超えるタグが無効であることを確認する
func TestTagName_TooLongIsInvalid(t *testing.T) {
	longTag := strings.Repeat("a", 256)
	if isValidTagName(longTag) {
		t.Errorf("256文字のタグは無効であるべき: len=%d", len(longTag))
	}
}

// TestTagName_ExactlyMaxLengthIsValid は255文字ちょうどが有効であることを確認する
func TestTagName_ExactlyMaxLengthIsValid(t *testing.T) {
	maxTag := strings.Repeat("x", 255)
	if !isValidTagName(maxTag) {
		t.Errorf("255文字のタグは有効であるべき: len=%d", len(maxTag))
	}
}

// ─── normalizeTag テスト ──────────────────────────────────────────────────────

// TestNormalizeTag_ConvertsToLowercase は大文字が小文字に変換されることを確認する
func TestNormalizeTag_ConvertsToLowercase(t *testing.T) {
	got := normalizeTag("Production")
	if got != "production" {
		t.Errorf("normalizeTag(\"Production\") = %q, want \"production\"", got)
	}
}

// TestNormalizeTag_TrimsSpaces は前後スペースが除去されることを確認する
func TestNormalizeTag_TrimsSpaces(t *testing.T) {
	got := normalizeTag("  critical  ")
	if got != "critical" {
		t.Errorf("normalizeTag(\"  critical  \") = %q, want \"critical\"", got)
	}
}

// TestNormalizeTag_EmptyStringRemainsEmpty は空文字列が空のままであることを確認する
func TestNormalizeTag_EmptyStringRemainsEmpty(t *testing.T) {
	got := normalizeTag("")
	if got != "" {
		t.Errorf("normalizeTag(\"\") = %q, want \"\"", got)
	}
}

// ─── containsTag テスト ───────────────────────────────────────────────────────

// TestContainsTag_FoundInSlice はスライス内に存在するタグを見つけることを確認する
func TestContainsTag_FoundInSlice(t *testing.T) {
	tags := []string{"production", "critical", "web"}
	if !containsTag(tags, "critical") {
		t.Error("\"critical\" はスライスに含まれるべき")
	}
}

// TestContainsTag_NotFoundInSlice はスライスに存在しないタグが false を返すことを確認する
func TestContainsTag_NotFoundInSlice(t *testing.T) {
	tags := []string{"production", "critical"}
	if containsTag(tags, "staging") {
		t.Error("\"staging\" はスライスに含まれないべき")
	}
}

// TestContainsTag_EmptySliceReturnsFalse は空スライスが常に false を返すことを確認する
func TestContainsTag_EmptySliceReturnsFalse(t *testing.T) {
	if containsTag([]string{}, "any") {
		t.Error("空スライスは常に false を返すべき")
	}
}

// ─── deduplicateTags テスト ───────────────────────────────────────────────────

// TestDeduplicateTags_RemovesDuplicates は重複タグが除去されることを確認する
func TestDeduplicateTags_RemovesDuplicates(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	result := deduplicateTags(input)
	if len(result) != 3 {
		t.Errorf("重複除去後の長さ = %d, want 3: %v", len(result), result)
	}
}

// TestDeduplicateTags_PreservesOrder は順序が保持されることを確認する
func TestDeduplicateTags_PreservesOrder(t *testing.T) {
	input := []string{"z", "a", "m", "a", "z"}
	result := deduplicateTags(input)
	if len(result) != 3 {
		t.Fatalf("重複除去後の長さ = %d, want 3", len(result))
	}
	if result[0] != "z" || result[1] != "a" || result[2] != "m" {
		t.Errorf("順序が正しくない: %v", result)
	}
}

// TestDeduplicateTags_EmptySliceReturnsEmpty は空スライスが空スライスを返すことを確認する
func TestDeduplicateTags_EmptySliceReturnsEmpty(t *testing.T) {
	result := deduplicateTags([]string{})
	if len(result) != 0 {
		t.Errorf("空スライスの重複除去結果は空のはず: %v", result)
	}
}

// TestDeduplicateTags_NilSliceReturnsEmpty は nil スライスが空スライスを返すことを確認する
func TestDeduplicateTags_NilSliceReturnsEmpty(t *testing.T) {
	result := deduplicateTags(nil)
	if result == nil {
		t.Error("nil スライスの結果は nil でないべき（空スライスを返すべき）")
	}
	if len(result) != 0 {
		t.Errorf("nil スライスの重複除去結果の長さ = %d, want 0", len(result))
	}
}

// TestDeduplicateTags_AllUniquePreservesAll は全要素がユニークなら全て保持されることを確認する
func TestDeduplicateTags_AllUniquePreservesAll(t *testing.T) {
	input := []string{"alpha", "beta", "gamma"}
	result := deduplicateTags(input)
	if len(result) != 3 {
		t.Errorf("全ユニーク要素の重複除去後の長さ = %d, want 3", len(result))
	}
}
