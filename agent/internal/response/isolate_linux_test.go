package response

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// recorder captures the argv of every firewall command the isolator would run,
// and lets a test decide which ones "fail" (iptables signals both real errors
// and ordinary conditions like "chain exists" / "rule not present" that way).
type recorder struct {
	calls []string
	fail  func(name string, args []string) bool
}

func (r *recorder) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if r.fail != nil && r.fail(name, args) {
		return []byte(""), fmt.Errorf("exit status 1")
	}
	return nil, nil
}

func (r *recorder) ran(substr string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (r *recorder) count(substr string) int {
	n := 0
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// destructive reports commands that operate on the host's whole filter table
// rather than on the EDR chain: a bare flush, a bare delete-chain, or a policy
// change. Isolation must never issue one of these.
func destructive(call string) bool {
	f := strings.Fields(call)
	if len(f) < 2 || f[0] != "iptables" {
		return false
	}
	switch f[1] {
	case "-F", "-X":
		// Scoped to the EDR chain is fine; bare (whole table) is not.
		return len(f) == 2 || f[2] != edrQuarantineChain
	case "-P":
		return true
	}
	return false
}

// This is the regression this file exists for. isolateLinux used to begin with
// `iptables -F` and `-X`, wiping every rule and user chain on the host — on a
// container host that deletes Docker's DOCKER/DOCKER-USER chains and all
// published-port rules, which release could not restore. A single severity-9
// false positive was therefore enough to require manual recovery of the host.
func TestIsolateLinuxNeverFlushesTheHostFirewall(t *testing.T) {
	// -N succeeds (fresh chain), -C fails (jump not yet present).
	r := &recorder{fail: func(_ string, args []string) bool {
		return len(args) > 0 && args[0] == "-C"
	}}
	n := &NetworkIsolator{exec: r.exec}

	if err := n.isolateLinux(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("isolateLinux: %v", err)
	}
	for _, c := range r.calls {
		if destructive(c) {
			t.Errorf("ホスト全体のファイアウォールを壊すコマンドが発行されました: %q", c)
		}
	}
	if r.ran("nft") {
		t.Error("iptables が成功しているのに nftables にフォールバックしました")
	}

	// The isolation itself must still be in place.
	for _, want := range []string{
		"-N " + edrQuarantineChain,
		"-A " + edrQuarantineChain + " -i lo -j ACCEPT",
		"-A " + edrQuarantineChain + " -s 10.0.0.1 -j ACCEPT",
		"-A " + edrQuarantineChain + " -j DROP",
		"-I INPUT 1 -j " + edrQuarantineChain,
		"-I OUTPUT 1 -j " + edrQuarantineChain,
		"-I FORWARD 1 -j " + edrQuarantineChain,
	} {
		if !r.ran(want) {
			t.Errorf("必要なコマンドが発行されていません: %q\n発行: %v", want, r.calls)
		}
	}
}

func TestReleaseLinuxOnlyRemovesWhatIsolateAdded(t *testing.T) {
	// One jump present per built-in chain: the first -C succeeds, the second fails.
	seen := map[string]int{}
	r := &recorder{}
	r.fail = func(_ string, args []string) bool {
		if len(args) > 0 && args[0] == "-C" {
			key := strings.Join(args, " ")
			seen[key]++
			return seen[key] > 1 // only the first check finds a jump
		}
		return false
	}
	n := &NetworkIsolator{exec: r.exec}

	if err := n.releaseLinux(context.Background()); err != nil {
		t.Fatalf("releaseLinux: %v", err)
	}
	for _, c := range r.calls {
		if destructive(c) {
			t.Errorf("解除がホスト全体のファイアウォールを触りました: %q", c)
		}
	}
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		want := "-D " + builtin + " -j " + edrQuarantineChain
		if got := r.count(want); got != 1 {
			t.Errorf("%q が %d 回発行されました, want 1\n発行: %v", want, got, r.calls)
		}
	}
	if !r.ran("-X " + edrQuarantineChain) {
		t.Error("隔離チェーンが削除されていません")
	}
}

// A chain that was never created must not turn release into an error: the
// server retries release, and a permanently-failing release would look like a
// host stuck in quarantine.
func TestReleaseLinuxIsCleanWhenNothingWasIsolated(t *testing.T) {
	r := &recorder{fail: func(name string, args []string) bool {
		if name == "nft" {
			return false
		}
		return len(args) > 0 && (args[0] == "-C" || args[0] == "-F" || args[0] == "-X")
	}}
	// iptables reports a missing chain with this exact text.
	execWithMsg := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := r.exec(ctx, name, args...)
		if err != nil && name == "iptables" && (args[0] == "-F" || args[0] == "-X") {
			return []byte("iptables: No chain/target/match by that name.\n"), err
		}
		return out, err
	}
	n := &NetworkIsolator{exec: execWithMsg}

	if err := n.releaseLinux(context.Background()); err != nil {
		t.Errorf("隔離されていないホストの解除がエラーになりました: %v", err)
	}
}

// Re-isolating an already-isolated host must not stack a second jump, or
// release would leave one behind and the host would stay cut off.
func TestIsolateLinuxIsIdempotent(t *testing.T) {
	r := &recorder{fail: func(_ string, args []string) bool {
		return len(args) > 0 && args[0] == "-N" // chain already exists
	}}
	n := &NetworkIsolator{exec: r.exec}

	if err := n.isolateLinux(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("isolateLinux: %v", err)
	}
	if !r.ran("-F " + edrQuarantineChain) {
		t.Error("既存チェーンが再利用時にクリアされていません")
	}
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if got := r.count("-I " + builtin); got != 0 {
			t.Errorf("既にジャンプがあるのに %s へ %d 回挿入しました", builtin, got)
		}
	}
}
