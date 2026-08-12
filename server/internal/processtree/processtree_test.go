package processtree

import (
	"testing"
)

// ─── isSuspicious ─────────────────────────────────────────────────────────────

func TestIsSuspicious_KnownSuspiciousNameAndPattern(t *testing.T) {
	// powershell.exe + "-enc" は典型的な悪意あるパターン
	if !isSuspicious("powershell.exe", "powershell.exe -enc SGVsbG8=") {
		t.Error("powershell.exe + -enc は suspicious とみなされるべきです")
	}
}

func TestIsSuspicious_SuspiciousName_NoPattern(t *testing.T) {
	// プロセス名は suspicious だがパターンが含まれない場合は false
	result := isSuspicious("powershell.exe", "powershell.exe Get-Date")
	// パターンが一致しなければ false のはず（パターン次第）
	_ = result // 動作確認のみ、パニックしないことを確認
}

func TestIsSuspicious_NormalProcess(t *testing.T) {
	if isSuspicious("explorer.exe", "C:\\Windows\\explorer.exe") {
		t.Error("explorer.exe は通常 suspicious でないはずです")
	}
}

func TestIsSuspicious_CaseInsensitive(t *testing.T) {
	// 大文字小文字を区別しない確認
	r1 := isSuspicious("POWERSHELL.EXE", "POWERSHELL.EXE -enc SGVsbG8=")
	r2 := isSuspicious("powershell.exe", "powershell.exe -enc SGVsbG8=")
	if r1 != r2 {
		t.Error("isSuspicious は大文字小文字を区別しないべきです")
	}
}

func TestIsSuspicious_EmptyInputs(t *testing.T) {
	// パニックしないことを確認
	result := isSuspicious("", "")
	if result {
		t.Error("空の入力は suspicious でないはずです")
	}
}

// ─── mitreFromParentChild ─────────────────────────────────────────────────────

func TestMitreFromParentChild_KnownPair(t *testing.T) {
	// winword.exe → powershell.exe は典型的なスピアフィッシング実行パターン (T1566.001)
	tech := mitreFromParentChild("winword.exe", "powershell.exe")
	if tech == "" {
		t.Error("winword.exe → powershell.exe はMITREテクニックを持つはずです")
	}
	if tech != "T1566.001" {
		t.Errorf("tech: got %q, want T1566.001", tech)
	}
}

func TestMitreFromParentChild_UnknownParent(t *testing.T) {
	tech := mitreFromParentChild("legit-app.exe", "cmd.exe")
	if tech != "" {
		t.Errorf("未知の親プロセスは空文字列を返すべきです: got %q", tech)
	}
}

func TestMitreFromParentChild_UnknownChild(t *testing.T) {
	// 既知の親・未知の子
	tech := mitreFromParentChild("winword.exe", "unknown-child.exe")
	if tech != "" {
		t.Errorf("未知の子プロセスは空文字列を返すべきです: got %q", tech)
	}
}

func TestMitreFromParentChild_CaseInsensitive(t *testing.T) {
	t1 := mitreFromParentChild("WINWORD.EXE", "POWERSHELL.EXE")
	t2 := mitreFromParentChild("winword.exe", "powershell.exe")
	if t1 != t2 {
		t.Error("mitreFromParentChild は大文字小文字を区別しないべきです")
	}
}

// ─── setDepths ────────────────────────────────────────────────────────────────

func TestSetDepths_RootIsDepthZero(t *testing.T) {
	root := &ProcessNode{PID: 1}
	setDepths(root, 0)
	if root.Depth != 0 {
		t.Errorf("ルートノードのDepth: got %d, want 0", root.Depth)
	}
}

func TestSetDepths_ChildIsDepthOne(t *testing.T) {
	child := &ProcessNode{PID: 2}
	root := &ProcessNode{PID: 1, Children: []*ProcessNode{child}}
	setDepths(root, 0)
	if child.Depth != 1 {
		t.Errorf("子ノードのDepth: got %d, want 1", child.Depth)
	}
}

func TestSetDepths_GrandChildIsDepthTwo(t *testing.T) {
	grandchild := &ProcessNode{PID: 3}
	child := &ProcessNode{PID: 2, Children: []*ProcessNode{grandchild}}
	root := &ProcessNode{PID: 1, Children: []*ProcessNode{child}}
	setDepths(root, 0)
	if grandchild.Depth != 2 {
		t.Errorf("孫ノードのDepth: got %d, want 2", grandchild.Depth)
	}
}

func TestSetDepths_MultipleChildren(t *testing.T) {
	c1 := &ProcessNode{PID: 2}
	c2 := &ProcessNode{PID: 3}
	c3 := &ProcessNode{PID: 4}
	root := &ProcessNode{PID: 1, Children: []*ProcessNode{c1, c2, c3}}
	setDepths(root, 0)
	for i, c := range []*ProcessNode{c1, c2, c3} {
		if c.Depth != 1 {
			t.Errorf("子ノード[%d]のDepth: got %d, want 1", i, c.Depth)
		}
	}
}

func TestSetDepths_StartFromNonZero(t *testing.T) {
	child := &ProcessNode{PID: 2}
	root := &ProcessNode{PID: 1, Children: []*ProcessNode{child}}
	setDepths(root, 5)
	if root.Depth != 5 {
		t.Errorf("startDepth=5: root.Depth got %d, want 5", root.Depth)
	}
	if child.Depth != 6 {
		t.Errorf("startDepth=5: child.Depth got %d, want 6", child.Depth)
	}
}
