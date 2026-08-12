package detection

import "testing"

// TestAuthorizedKeysFileEventFires locks in the routing that the /home FIM
// sensor expansion (agent #423) depends on: a FILE event carrying a `path` must
// reach the built-in file_event Sigma rule via the path→TargetFilename alias and
// match. If this regresses, every file_event rule (authorized_keys plus the
// migration-311 shell-init/ld.so.preload/rc.local/cron rules) goes silent.
func TestAuthorizedKeysFileEventFires(t *testing.T) {
	// A regular user's authorized_keys — now emitted because the FIM collector
	// watches /home/*/.ssh, not only /root/.ssh and /etc.
	evt := map[string]interface{}{
		"type":        "file",
		"path":        "/home/victim/.ssh/authorized_keys",
		"change_type": "modified",
	}
	f := EvaluateEnvelope("file", evt)
	if len(f) == 0 {
		t.Fatal("authorized_keys file_event should fire the T1098.004 built-in rule; got no findings")
	}
}

// TestBenignFileEventNoFire guards the alias/routing against over-matching: an
// ordinary file change under a monitored directory that no rule targets must not
// produce a finding.
func TestBenignFileEventNoFire(t *testing.T) {
	evt := map[string]interface{}{
		"type":        "file",
		"path":        "/etc/hosts",
		"change_type": "modified",
	}
	if f := EvaluateEnvelope("file", evt); len(f) != 0 {
		t.Errorf("benign /etc/hosts change should not fire a file_event rule; got %d findings", len(f))
	}
}
