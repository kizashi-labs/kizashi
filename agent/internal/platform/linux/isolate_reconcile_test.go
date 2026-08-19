//go:build linux

package linux

import (
	"errors"
	"strings"
	"testing"
)

// recorder captures the argv of every firewall command the isolator would run,
// so a test can assert on what is (and is not) executed without touching the
// host's real firewall.
type recorder struct {
	calls [][]string
	// fail reports whether the given call should return an error. It stands in
	// for iptables' -C / nft's list, whose exit status is the presence check.
	fail func(argv []string) bool
	out  string
}

func (r *recorder) record(name string, args ...string) []string {
	argv := append([]string{name}, args...)
	r.calls = append(r.calls, argv)
	return argv
}

func (r *recorder) run(name string, args ...string) error {
	argv := r.record(name, args...)
	if r.fail != nil && r.fail(argv) {
		return errors.New("exit status 1")
	}
	return nil
}

func (r *recorder) runOut(name string, args ...string) ([]byte, error) {
	argv := r.record(name, args...)
	if r.fail != nil && r.fail(argv) {
		return nil, errors.New("exit status 1")
	}
	return []byte(r.out), nil
}

func (r *recorder) joined() []string {
	var out []string
	for _, c := range r.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func (r *recorder) ran(want string) bool {
	for _, c := range r.joined() {
		if c == want {
			return true
		}
	}
	return false
}

func newTestIsolator(r *recorder, allowSSH, useNFT bool) *IPTablesIsolationManager {
	return &IPTablesIsolationManager{
		edrServerIP: "10.0.0.1",
		allowSSH:    allowSSH,
		useNFTables: useNFT,
		run:         r.run,
		runOut:      r.runOut,
	}
}

// A host that never asked for SSH access during isolation must not have its
// isolation chain widened behind its back.
func TestReconcileSSHAccessNoopWhenNotAllowed(t *testing.T) {
	r := &recorder{}
	newTestIsolator(r, false, false).reconcileSSHAccess()

	if len(r.calls) != 0 {
		t.Fatalf("allowSSH=false でファイアウォールを操作した: %v", r.joined())
	}
}

// The lockout this guards against: isolation was applied while SSH was blocked,
// the operator then set EDR_ISOLATION_ALLOW_SSH=true and restarted the agent.
// The accept must be inserted at position 1 — appending would land it after the
// chain's trailing DROP, where it can never match.
func TestReconcileSSHAccessInsertsAheadOfDrop(t *testing.T) {
	r := &recorder{fail: func(argv []string) bool { return argv[1] == "-C" }}
	newTestIsolator(r, true, false).reconcileSSHAccess()

	want := "iptables -I EDR_ISOLATE 1 -p tcp --dport 22 -j ACCEPT"
	if !r.ran(want) {
		t.Fatalf("SSH許可ルールが先頭に挿入されていない\n want: %s\n  got: %v", want, r.joined())
	}
	for _, c := range r.joined() {
		if strings.HasPrefix(c, "iptables -A ") {
			t.Errorf("-A は末尾のDROPより後ろに積まれるため使ってはならない: %s", c)
		}
	}
}

// Restarting the agent repeatedly must not stack duplicate accepts.
func TestReconcileSSHAccessIdempotent(t *testing.T) {
	r := &recorder{} // -C succeeds ⇒ the rule is already there
	newTestIsolator(r, true, false).reconcileSSHAccess()

	if len(r.calls) != 1 || r.calls[0][1] != "-C" {
		t.Fatalf("既存ルールがあるのに追加操作を行った: %v", r.joined())
	}
}

func TestReconcileSSHAccessNFTables(t *testing.T) {
	t.Run("インストール済みなら何もしない", func(t *testing.T) {
		r := &recorder{out: "chain input {\n  tcp dport 22 accept\n}"}
		newTestIsolator(r, true, true).reconcileSSHAccess()

		if len(r.calls) != 1 {
			t.Fatalf("既存ルールがあるのに追加操作を行った: %v", r.joined())
		}
	})

	t.Run("未インストールなら挿入する", func(t *testing.T) {
		r := &recorder{out: "chain input {\n  ct state established,related accept\n}"}
		newTestIsolator(r, true, true).reconcileSSHAccess()

		want := "nft insert rule inet edr_isolate input tcp dport 22 accept"
		if !r.ran(want) {
			t.Fatalf("SSH許可ルールが挿入されていない\n want: %s\n  got: %v", want, r.joined())
		}
	})
}

// Nothing in the repair path may touch the isolation itself — no flush, no
// delete of the chain or its jumps, no policy change. Repairing SSH access must
// not become a way to lift isolation.
func TestReconcileSSHAccessNeverWeakensIsolation(t *testing.T) {
	for _, nft := range []bool{false, true} {
		r := &recorder{fail: func(argv []string) bool { return argv[1] == "-C" }}
		newTestIsolator(r, true, nft).reconcileSSHAccess()

		for _, c := range r.joined() {
			for _, banned := range []string{
				"iptables -F", "iptables -X", "iptables -P", "iptables -D",
				"nft delete", "nft flush",
			} {
				if strings.HasPrefix(c, banned) {
					t.Errorf("useNFTables=%v: 隔離を解除する操作を実行した: %s", nft, c)
				}
			}
		}
	}
}
