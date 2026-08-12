package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// captureSender records every event batch it is asked to send.
type captureSender struct {
	mu      sync.Mutex
	batches []*v1.EventBatch
}

func (c *captureSender) SendEvents(_ context.Context, batch *v1.EventBatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, batch)
	return nil
}

// fimPaths returns the fim_change payload paths seen across all captured batches.
func (c *captureSender) fimPaths() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{} // path -> change_type
	for _, b := range c.batches {
		for _, e := range b.GetEvents() {
			id := e.GetId()
			if !strings.HasPrefix(id, "fim_change:") {
				continue
			}
			parts := strings.SplitN(id, ":", 3)
			if len(parts) != 3 {
				continue
			}
			var p fimChangePayload
			if json.Unmarshal([]byte(parts[2]), &p) == nil {
				out[p.Path] = p.ChangeType
			}
		}
	}
	return out
}

func newTestFIM(sender EventSender, rules []FIMRule) *FIMCollector {
	return &FIMCollector{
		sender:   sender,
		agentID:  "test-agent",
		rules:    rules,
		interval: time.Hour,
		hashes:   make(map[string]string),
	}
}

// A glob rule ("/home/*/.ssh") must expand to every user's authorized_keys, so
// per-user SSH persistence is watched without hard-coding usernames — the gap
// the 2026-07-06 Linux measurement found (only /root/.ssh was covered).
func TestFIM_GlobExpandsPerUserSSH(t *testing.T) {
	root := t.TempDir()
	for _, u := range []string{"alice", "bob"} {
		dir := filepath.Join(root, u, ".ssh")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte("ssh-rsa AAAA original\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	f := newTestFIM(&captureSender{}, []FIMRule{{Path: filepath.Join(root, "*", ".ssh"), Recursive: false}})
	paths := f.expandRules()

	for _, u := range []string{"alice", "bob"} {
		want := filepath.Join(root, u, ".ssh", "authorized_keys")
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("glob rule should watch %s, got %v", want, paths)
		}
	}
}

// Modifying a watched authorized_keys must emit a fim_change "modified" event.
func TestFIM_DetectsAuthorizedKeysModification(t *testing.T) {
	root := t.TempDir()
	ak := filepath.Join(root, "victim", ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(ak), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ak, []byte("ssh-rsa AAAA legit\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: filepath.Join(root, "*", ".ssh"), Recursive: false}})
	f.seedHashes() // baseline, no events

	// Attacker appends a backdoor key.
	if err := os.WriteFile(ak, []byte("ssh-rsa AAAA legit\nssh-rsa BBBB attacker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	if ct := sender.fimPaths()[ak]; ct != "modified" {
		t.Fatalf("expected 'modified' fim_change for %s, got %q (all: %v)", ak, ct, sender.fimPaths())
	}
}

// An authorized_keys that does not exist at seed time but is created later (the
// attacker planting a fresh backdoor) must be picked up as "created" — the glob
// is re-evaluated every scan.
func TestFIM_DetectsAuthorizedKeysCreation(t *testing.T) {
	root := t.TempDir()
	// Seed with an existing user dir but no authorized_keys yet.
	if err := os.MkdirAll(filepath.Join(root, "victim", ".ssh"), 0o755); err != nil {
		t.Fatal(err)
	}

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: filepath.Join(root, "*", ".ssh"), Recursive: false}})
	f.seedHashes()

	ak := filepath.Join(root, "victim", ".ssh", "authorized_keys")
	if err := os.WriteFile(ak, []byte("ssh-rsa BBBB attacker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	if ct := sender.fimPaths()[ak]; ct != "created" {
		t.Fatalf("expected 'created' fim_change for %s, got %q (all: %v)", ak, ct, sender.fimPaths())
	}
}

// A literal (non-glob) rule path must still resolve unchanged.
func TestFIM_ExpandGlobLiteralPassthrough(t *testing.T) {
	if got := expandGlob("/etc/passwd"); len(got) != 1 || got[0] != "/etc/passwd" {
		t.Fatalf("literal path should pass through, got %v", got)
	}
	if got := expandGlob("/no/such/glob/*/x"); got != nil {
		t.Fatalf("non-matching glob should return nil, got %v", got)
	}
}
