package detection

import (
	"fmt"
	"testing"
	"time"
)

func TestFileBurst_FiresOnMassModify(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	for i := 0; i < fileBurstMinFiles; i++ {
		path := fmt.Sprintf(`C:\Users\victim\Documents\file%d.docx`, i)
		m := d.Observe("agent1", "evil.exe", path, "modify", base.Add(time.Duration(i)*time.Millisecond*100))
		fired += len(m)
		if len(m) > 0 {
			if m[0].MITRETags[0] != "T1486" {
				t.Errorf("ransomware burst should tag T1486, got %v", m[0].MITRETags)
			}
			if m[0].Severity < 8 {
				t.Errorf("ransomware burst severity should be high, got %d", m[0].Severity)
			}
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 ransomware alert after %d files, got %d", fileBurstMinFiles, fired)
	}
}

func TestFileBurst_NonDestructiveIgnored(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	// Many plain creates/reads (a compiler emitting objects, an installer) must
	// NOT trip the detector.
	for i := 0; i < fileBurstMinFiles*2; i++ {
		path := fmt.Sprintf(`/build/out/obj%d.o`, i)
		if m := d.Observe("agent1", "cc1.exe", path, "create", base.Add(time.Duration(i)*time.Millisecond)); len(m) > 0 {
			t.Fatalf("non-destructive create must not alert (iter %d)", i)
		}
		if m := d.Observe("agent1", "cc1.exe", path, "read", base.Add(time.Duration(i)*time.Millisecond)); len(m) > 0 {
			t.Fatalf("read must not alert (iter %d)", i)
		}
	}
}

func TestFileBurst_DistinctPathsRequired(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	// Rewriting the SAME file many times (e.g., a log/db file) is one path, not a
	// mass-encryption fan-out.
	for i := 0; i < fileBurstMinFiles*2; i++ {
		if m := d.Observe("agent1", "app.exe", `/var/lib/app/state.db`, "write", base.Add(time.Duration(i)*time.Millisecond)); len(m) > 0 {
			t.Fatalf("repeated writes to one file must not alert (iter %d)", i)
		}
	}
}

func TestFileBurst_PerProcessKeying(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	// The same total file count split across TWO processes stays under threshold
	// for each — a burst is per-process, not per-host.
	half := fileBurstMinFiles - 1
	for i := 0; i < half; i++ {
		p := fmt.Sprintf(`/data/f%d`, i)
		if m := d.Observe("agent1", "procA", p, "modify", base.Add(time.Duration(i)*time.Millisecond)); len(m) > 0 {
			t.Fatalf("procA under threshold must not alert")
		}
		if m := d.Observe("agent1", "procB", p, "modify", base.Add(time.Duration(i)*time.Millisecond)); len(m) > 0 {
			t.Fatalf("procB under threshold must not alert")
		}
	}
}

// TestFileActionEnumForm guards the production reachability of the ransomware
// detector: ingestion flattens a FileEvent's action via proto's Enum.String(),
// which yields "FILE_ACTION_MODIFY"/"FILE_ACTION_DELETE"/… (see
// proto/agent/v1/events.proto FileAction). isDestructiveFileAction must classify
// those real telemetry values, not just the lowercase demo forms. A regression
// here means the detector silently counts nothing in production.
func TestFileActionEnumForm(t *testing.T) {
	destructive := []string{"FILE_ACTION_MODIFY", "FILE_ACTION_DELETE", "FILE_ACTION_RENAME"}
	for _, a := range destructive {
		if !isDestructiveFileAction(a) {
			t.Errorf("proto enum form %q must be classified destructive", a)
		}
	}
	nondestructive := []string{"FILE_ACTION_CREATE", "FILE_ACTION_EXECUTE", "FILE_ACTION_UNSPECIFIED"}
	for _, a := range nondestructive {
		if isDestructiveFileAction(a) {
			t.Errorf("proto enum form %q must NOT be classified destructive", a)
		}
	}
}

func TestFileBurst_FiresOnProtoEnumActions(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	// Feed the exact enum-string form ingestion produces for the "operation" field.
	for i := 0; i < fileBurstMinFiles; i++ {
		path := fmt.Sprintf(`C:\victim\f%d.docx`, i)
		fired += len(d.Observe("agent1", "locker.exe", path, "FILE_ACTION_MODIFY", base.Add(time.Duration(i)*time.Millisecond*50)))
	}
	if fired != 1 {
		t.Fatalf("ransomware detector must fire on the real FILE_ACTION_* form, got %d", fired)
	}
}

func TestIsDestructiveFileAction(t *testing.T) {
	destructive := []string{"modify", "modified", "write", "WriteFile", "overwrite", "rename", "renamed", "delete", "unlink", "truncate", "encrypt"}
	for _, a := range destructive {
		if !isDestructiveFileAction(a) {
			t.Errorf("%q should be destructive", a)
		}
	}
	for _, a := range []string{"create", "created", "read", "open", "access", ""} {
		if isDestructiveFileAction(a) {
			t.Errorf("%q should NOT be destructive", a)
		}
	}
}

// ─── 実エンドポイント検証(2026-07-26, WIN-ENDPOINT-01)で判明した退化への回帰 ───
//
// 本番ではどのプラットフォームの file collector も FileEvent.ProcessName/PID を
// 埋めない(Linux inotify / macOS FSEvents / Windows ReadDirectoryChangesW はいずれも
// 実行主体を報告しない)。よって procName は常に空で、この検知器はホスト単位に退化する。
// 実機 Windows ではその結果、(a) 背景チャーンが閾値を越えて24時間で34件の誤検知を出し、
// (b) その発火で張られた5分クールダウンが、直後に来た本物の140ファイル暗号化バーストを
// 抑制した。以下はその両方を固定する。

// 背景チャーンのように「30秒かけて」60ファイルに触れる動きは、プロセス特定不可の
// ホスト単位モードでは発火してはならない(レート集中で本物と切り分ける)。
func TestFileBurst_HostScoped_SlowChurnDoesNotFire(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	// 60ファイルを30秒かけて(=5秒窓には最大約10件しか入らない)
	for i := 0; i < fileBurstMinFiles; i++ {
		path := fmt.Sprintf(`C:\Windows\SoftwareDistribution\bg%d.tmp`, i)
		fired += len(d.Observe("agentW", "", path, "FILE_ACTION_MODIFY",
			base.Add(time.Duration(i)*500*time.Millisecond)))
	}
	if fired != 0 {
		t.Fatalf("プロセス特定不可の緩やかな背景チャーンで発火してはならない: %d件発火", fired)
	}
}

// 一方、同じ60ファイルでも暗号化のように数秒に凝縮していれば発火する。
func TestFileBurst_HostScoped_FastBurstFires(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	for i := 0; i < fileBurstMinFiles; i++ {
		path := fmt.Sprintf(`C:\Users\victim\Documents\f%d.docx`, i)
		fired += len(d.Observe("agentW", "", path, "FILE_ACTION_MODIFY",
			base.Add(time.Duration(i)*10*time.Millisecond)))
	}
	if fired != 1 {
		t.Fatalf("プロセス特定不可でも高レートバーストは発火すべき: %d件", fired)
	}
}

// 実機で起きた見逃しの核心: 先行する小さい発火のクールダウンが、直後の
// 遥かに大きい本物のバーストを黙らせてはならない(エスカレーション)。
func TestFileBurst_LargerBurstEscalatesThroughDedup(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)

	var first int
	for i := 0; i < fileBurstMinFiles; i++ {
		first += len(d.Observe("agentW", "", fmt.Sprintf(`C:\noise\n%d.tmp`, i),
			"FILE_ACTION_MODIFY", base.Add(time.Duration(i)*10*time.Millisecond)))
	}
	if first != 1 {
		t.Fatalf("前提: 最初のバーストで1件発火するはず: %d件", first)
	}

	// クールダウン(5分)の内側で、2倍以上の規模の本物バーストが来る
	later := base.Add(90 * time.Second)
	var second int
	for i := 0; i < fileBurstMinFiles*2; i++ {
		second += len(d.Observe("agentW", "", fmt.Sprintf(`C:\Users\victim\Documents\real%d.docx`, i),
			"FILE_ACTION_MODIFY", later.Add(time.Duration(i)*10*time.Millisecond)))
	}
	if second == 0 {
		t.Fatal("クールダウン中でも、規模が倍増した本物のバーストは発火すべき(実機で見逃した挙動)")
	}
}

// プロセス名が取れている場合は従来どおり30秒窓・プロセス単位で発火する(非退行)。
func TestFileBurst_KnownProcessKeepsWiderWindow(t *testing.T) {
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	for i := 0; i < fileBurstMinFiles; i++ {
		fired += len(d.Observe("agent1", "cryptor.exe", fmt.Sprintf(`C:\d\f%d.docx`, i),
			"modify", base.Add(time.Duration(i)*400*time.Millisecond))) // 24秒に分散
	}
	if fired != 1 {
		t.Fatalf("プロセス特定済みなら30秒窓で発火すべき: %d件", fired)
	}
}
