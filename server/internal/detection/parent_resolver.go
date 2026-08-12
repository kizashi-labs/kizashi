// Package detection — parent_resolver.go resolves a process's parent image name
// from its PPID so that Sigma ParentImage rules can fire.
//
// The agent telemetry carries pid/ppid but not the parent image name (the proto
// ProcessEvent has no parent field). Without resolution, ParentImage-based rules
// (e.g. "WMI Spawning Command Shell", Office-spawns-script) silently never match.
// This lightweight per-agent pid→name cache reconstructs the parent name from the
// PPID of recently-seen processes and injects it as "parent_process", which the
// pipeline's Sigma alias layer maps to ParentImage.
package detection

import (
	"strconv"
	"sync"
	"time"
)

// parentResolverTTL bounds how long a pid→name mapping is retained.
const parentResolverTTL = 30 * time.Minute

type parentEntry struct {
	image string // full image path (or basename when only that is available)
	ts    time.Time
}

// parentResolver maintains a per-agent pid→name cache. All methods are
// safe for concurrent use.
type parentResolver struct {
	mu     sync.Mutex
	agents map[string]map[uint64]parentEntry
	ttl    time.Duration
}

func newParentResolver() *parentResolver {
	return &parentResolver{
		agents: make(map[string]map[uint64]parentEntry),
		ttl:    parentResolverTTL,
	}
}

// enrich records this process event's pid→name and, when the event is a process
// event with a known parent, injects the resolved parent image name as
// "parent_process" (unless the event already carries a parent field). It is a
// no-op for non-process events and when the parent pid is not yet known.
func (r *parentResolver) enrich(event map[string]any) {
	// Cache the FULL image path (not the basename): SigmaHQ ParentImage rules match
	// path patterns (ParentImage|endswith '/nginx', ParentImage|startswith '/tmp/'),
	// which a bare basename cannot satisfy. Prefer the full-path fields and fall back
	// to the process name only when no path is available.
	image := firstNonEmpty(event, "Image", "image_path", "imagePath", "processName", "process_name")
	pid, okPid := eventUint(event, "pid")
	ppid, okPpid := eventUint(event, "ppid")
	agentID, _ := event["agent_id"].(string)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.evict(agentID)

	if okPid && image != "" {
		cache := r.agents[agentID]
		if cache == nil {
			cache = make(map[uint64]parentEntry)
			r.agents[agentID] = cache
		}
		cache[pid] = parentEntry{image: image, ts: time.Now()}
	}

	// Inject the parent image path only if the event does not already carry one.
	if !hasParent(event) && okPpid {
		if cache, ok := r.agents[agentID]; ok {
			if pe, ok := cache[ppid]; ok && pe.image != "" {
				event["parent_process"] = pe.image
			}
		}
	}
}

// record caches a process's pid → full image path. Used by callers (the detection
// engine) that resolve and inject the parent field themselves rather than via enrich.
func (r *parentResolver) record(agentID string, pid uint64, imagePath string) {
	if pid == 0 || imagePath == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evict(agentID)
	cache := r.agents[agentID]
	if cache == nil {
		cache = make(map[uint64]parentEntry)
		r.agents[agentID] = cache
	}
	cache[pid] = parentEntry{image: imagePath, ts: time.Now()}
}

// lookup returns the cached full image path for the given pid on this agent, or "".
func (r *parentResolver) lookup(agentID string, pid uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cache, ok := r.agents[agentID]; ok {
		if pe, ok := cache[pid]; ok {
			return pe.image
		}
	}
	return ""
}

func hasParent(event map[string]any) bool {
	for _, k := range []string{"parent_process", "parentImagePath", "parent_image_path", "ParentImage"} {
		if s, _ := event[k].(string); s != "" {
			return true
		}
	}
	return false
}

// evict drops entries older than the TTL for the given agent.
func (r *parentResolver) evict(agentID string) {
	cache := r.agents[agentID]
	if cache == nil {
		return
	}
	cutoff := time.Now().Add(-r.ttl)
	for pid, e := range cache {
		if e.ts.Before(cutoff) {
			delete(cache, pid)
		}
	}
}

// firstNonEmpty returns the first non-empty string value among the given keys.
func firstNonEmpty(event map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := event[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// eventUint coerces a pid/ppid field (which may arrive as float64 from JSON,
// or various int kinds, or a numeric string) to uint64.
func eventUint(event map[string]any, key string) (uint64, bool) {
	switch v := event[key].(type) {
	case float64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case string:
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}
