package collector

import (
	"os"
	"testing"
)

// ppid on its own was never an answer, and every consumer that wanted the
// parent invented its own and got nothing. The server read
// raw_data->>'parent_name' / ->>'parent_image', which the proto did not carry,
// so the parent was empty on every row ever written and the whole
// parent/child MITRE technique table could not match. These pin the endpoint
// resolution that replaces it.

// The headline: a process the agent watched start can be named as somebody's
// parent afterwards — including after it has exited, which is the case a
// live-process lookup cannot cover and the one that matters.
func TestAParentTheAgentSawIsNamedAfterItExits(t *testing.T) {
	r := NewParentResolver()
	r.Observe(4242, "winword.exe", `C:\Program Files\Microsoft Office\winword.exe`)

	child := &ProcessEvent{PID: 4243, PPID: 4242, ProcessName: "powershell.exe"}
	r.Fill(child)

	if child.ParentName != "winword.exe" {
		t.Errorf("親プロセス名 = %q, want winword.exe。"+
			"Office からのシェル起動は親子関係で判定するため、"+
			"親が空だと T1566 系のテクニックが一切一致しません", child.ParentName)
	}
	if child.ParentImage == "" {
		t.Error("親のフルパスが空です")
	}
}

// A child observed after its parent must be nameable, which is the ordinary
// case: Fill records the process before resolving, so a parent that arrived
// through the same channel one event earlier is already in the cache.
func TestFillRecordsTheProcessSoItsChildrenCanNameIt(t *testing.T) {
	r := NewParentResolver()

	parent := &ProcessEvent{PID: 900, PPID: 1, ProcessName: "bash", ImagePath: "/bin/bash"}
	r.Fill(parent)

	child := &ProcessEvent{PID: 901, PPID: 900, ProcessName: "curl"}
	r.Fill(child)

	if child.ParentName != "bash" {
		t.Errorf("親プロセス名 = %q, want bash", child.ParentName)
	}
	if child.ParentImage != "/bin/bash" {
		t.Errorf("親のイメージパス = %q, want /bin/bash", child.ParentImage)
	}
}

// An unknown parent is reported as empty, not guessed. An invented parent is
// worse than none: it would make the technique table match the wrong thing.
func TestAnUnknownParentIsEmptyNotInvented(t *testing.T) {
	r := NewParentResolver()

	// A pid that cannot exist, so neither the cache nor the OS can name it.
	child := &ProcessEvent{PID: 2, PPID: 0x7FFFFFFF, ProcessName: "sh"}
	r.Fill(child)

	if child.ParentName != "" || child.ParentImage != "" {
		t.Errorf("不明な親に値を入れています: name=%q image=%q。"+
			"誤った親は空の親より有害です", child.ParentName, child.ParentImage)
	}
}

// pid 0 is not a process. Nothing may be recorded under it, or every process
// whose ppid is 0 — the whole first generation, and anything reparented to
// init — would be given whatever happened to be stored there.
func TestPidZeroIsNeverRecorded(t *testing.T) {
	r := NewParentResolver()
	r.Observe(0, "kernel", "/kernel")

	r.mu.RLock()
	_, present := r.cache[0]
	r.mu.RUnlock()
	if present {
		t.Error("pid 0 をキャッシュに入れています。" +
			"ppid 0 のプロセスすべてに誤った親が付きます")
	}

	child := &ProcessEvent{PID: 1, PPID: 0, ProcessName: "init"}
	r.Fill(child)
	if child.ParentName != "" {
		t.Errorf("ppid 0 に親を割り当てています: %q", child.ParentName)
	}
}

// A collector that already knows the parent keeps its answer. A lookup can
// only be less accurate than the kernel's own report.
func TestACollectorSuppliedParentIsNotOverwritten(t *testing.T) {
	r := NewParentResolver()
	r.Observe(500, "wrong.exe", "/wrong.exe")

	child := &ProcessEvent{
		PID: 501, PPID: 500, ProcessName: "sh",
		ParentName: "right.exe", ParentImage: "/right.exe",
	}
	r.Fill(child)

	if child.ParentName != "right.exe" || child.ParentImage != "/right.exe" {
		t.Errorf("コレクタが設定した親を上書きしました: name=%q image=%q",
			child.ParentName, child.ParentImage)
	}
}

// The cache is bounded. A long-lived agent on a busy host creates processes
// indefinitely; an unbounded map would be a slow leak for the life of the
// process.
func TestTheParentCacheIsBounded(t *testing.T) {
	r := NewParentResolver()
	r.max = 8

	for pid := uint32(1000); pid < 1100; pid++ {
		r.Observe(pid, "p", "/p")
	}

	r.mu.RLock()
	size, order := len(r.cache), len(r.order)
	r.mu.RUnlock()

	if size > 8 {
		t.Errorf("キャッシュに %d 件残っています (上限 8)。"+
			"長時間稼働するエージェントでの緩やかなリークになります", size)
	}
	if order > 8 {
		t.Errorf("挿入順リストが %d 件です (上限 8)", order)
	}
	// The most recent entries are the ones kept — they are the live processes.
	if _, ok := r.cache[1099]; !ok {
		t.Error("最新のエントリが破棄されています")
	}
}

// Re-observing a pid must not grow the order list, or a process reported
// repeatedly (create then terminate) would evict live entries.
func TestReObservingAPidDoesNotGrowTheCache(t *testing.T) {
	r := NewParentResolver()
	for i := 0; i < 50; i++ {
		r.Observe(777, "same", "/same")
	}
	r.mu.RLock()
	order := len(r.order)
	r.mu.RUnlock()
	if order != 1 {
		t.Errorf("同一 pid の再観測で挿入順リストが %d 件に増えました", order)
	}
}

// And the OS lookup works, so a parent that predates the agent is still named.
// Uses this test process's own pid, which is certainly live.
func TestTheOSLookupNamesALiveProcess(t *testing.T) {
	r := NewParentResolver()

	self := uint32(os.Getpid())
	name, image := r.Resolve(self)
	if name == "" && image == "" {
		t.Skip("この環境ではプロセス情報を参照できません")
	}
	if name == "" {
		t.Errorf("プロセス名が空です (image=%q)", image)
	}
}

// Concurrent use must be safe: the resolver is touched from the batching loop
// while collectors keep producing.
func TestTheResolverIsSafeUnderConcurrency(t *testing.T) {
	r := NewParentResolver()
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func(base uint32) {
			for i := uint32(0); i < 500; i++ {
				r.Observe(base+i, "p", "/p")
				_, _ = r.Resolve(base + i)
			}
			done <- struct{}{}
		}(uint32(w) * 1000)
	}
	for w := 0; w < 4; w++ {
		<-done
	}
}
