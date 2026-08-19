package collector

import (
	"path/filepath"
	"sync"
)

// ParentResolver names the parent of an observed process.
//
// ppid on its own is not an answer. It is a number that the kernel reuses, and
// by the time anything downstream asks "what spawned this?" the parent has
// usually exited. Every consumer that wanted the parent invented its own way of
// getting it and none of them worked:
//
//   - The server read raw_data->>'parent_name' / ->>'parent_image'. The proto
//     carried neither, so the value was empty on every row ever written, and
//     mitreFromParentChild() — the Office-spawns-a-shell, browser-spawns-
//     PowerShell technique table — was called with an empty parent every time.
//     It could not match, ever.
//   - detection's parentResolver looks ppid up against recent events. That only
//     works while the parent is still inside the correlation window, and the
//     answer never leaves that process's memory.
//
// The endpoint is the one place where the question is cheap and the answer is
// right: the agent is notified of the create while the parent is still alive,
// and /proc — or QueryFullProcessImageName, or ps — is immediately to hand.
//
// Two sources, in order:
//
//  1. the cache — every process this agent has seen created, so a parent that
//     the agent watched start is named even after it exits;
//  2. an OS lookup — for parents that predate the agent, or that the agent
//     missed.
//
// Neither can name a parent that exited before the child was observed. That
// leaves the field empty, which is honest and uncommon, as against the previous
// behaviour of empty always.
type ParentResolver struct {
	mu    sync.RWMutex
	cache map[uint32]parentEntry
	// order records insertion order so the cache can be trimmed without
	// scanning. A long-lived agent on a busy host would otherwise accumulate one
	// entry per process created for the life of the process.
	order []uint32
	max   int
	// containerOf reads a process's containment. A field rather than a direct
	// call to containerContextOf so the join between "enrich a process event"
	// and "read /proc" can be tested: the parsing has its own tests and the call
	// site has its own, but with a direct call nothing covers the wire between
	// them, and deleting it passes every other test.
	containerOf func(pid uint32) ContainerContext
}

type parentEntry struct {
	name  string
	image string
}

// defaultParentCacheSize bounds the pid cache. Sized for a busy host's working
// set of live processes with room for recently-exited ones, which is what a
// parent lookup actually needs.
const defaultParentCacheSize = 4096

func NewParentResolver() *ParentResolver {
	return &ParentResolver{
		cache:       make(map[uint32]parentEntry, defaultParentCacheSize),
		max:         defaultParentCacheSize,
		containerOf: containerContextOf,
	}
}

// Observe records a process so it can later be named as somebody's parent.
// Called for every process-create the agent sees.
func (r *ParentResolver) Observe(pid uint32, name, image string) {
	if r == nil || pid == 0 || (name == "" && image == "") {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cache[pid]; !exists {
		r.order = append(r.order, pid)
		// Trim oldest-first once over the bound.
		for len(r.order) > r.max {
			oldest := r.order[0]
			r.order = r.order[1:]
			delete(r.cache, oldest)
		}
	}
	r.cache[pid] = parentEntry{name: name, image: image}
}

// Resolve names the process with the given pid. Returns ("", "") when it cannot
// be determined — an empty parent is reported as empty, never guessed.
func (r *ParentResolver) Resolve(pid uint32) (name, image string) {
	if r == nil || pid == 0 {
		return "", ""
	}

	r.mu.RLock()
	e, ok := r.cache[pid]
	r.mu.RUnlock()
	if ok {
		return e.name, e.image
	}

	// Not seen by this agent: ask the OS. lookupProcess is per-platform
	// (parent_linux.go / parent_windows.go / parent_darwin.go).
	name, image = lookupProcess(pid)
	if name == "" && image == "" {
		return "", ""
	}
	if name == "" && image != "" {
		name = filepath.Base(image)
	}
	// Cache it: a parent asked about once is usually asked about again, and the
	// OS lookup is the expensive path.
	r.Observe(pid, name, image)
	return name, image
}

// Fill records evt's own identity and populates its parent fields. It is the
// single place a process event acquires a parent, so every platform collector
// gets the same behaviour without repeating it twelve times.
func (r *ParentResolver) Fill(evt *ProcessEvent) {
	if r == nil || evt == nil {
		return
	}
	// Record first: a process that spawns a child immediately is then already
	// nameable when that child arrives.
	r.Observe(evt.PID, evt.ProcessName, evt.ImagePath)

	if evt.ParentName != "" || evt.ParentImage != "" {
		// A collector that already knows the parent is left alone. None does
		// today — the macOS ESF callback passes ppid only — but a sensor that
		// gets the parent from the kernel alongside the child should not have
		// it overwritten by a lookup that can only be less accurate.
		return
	}
	evt.ParentName, evt.ParentImage = r.Resolve(evt.PPID)
}

// EnrichProcess fills everything the endpoint can determine about a process
// event that the collectors do not already know: its parent, and its
// containment. One call site rather than twelve, so a new sensor gets both
// without having to remember either.
func (r *ParentResolver) EnrichProcess(evt *ProcessEvent) {
	if evt == nil {
		return
	}
	r.Fill(evt)
	if evt.Container.ID == "" && r.containerOf != nil {
		evt.Container = r.containerOf(evt.PID)
	}
}
