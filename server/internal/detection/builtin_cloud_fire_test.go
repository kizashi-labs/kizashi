package detection

import "testing"

// TestCloudAttackRulesFire verifies the cloud-attack builtin rules (IMDS credential
// theft, cloud CLI discovery, Kubernetes SA-token theft) fire on representative
// telemetry through the real flatten+alias+evaluate path, and that near-miss benign
// commands do not. These close a genuine gap: the pre-existing set had container
// escape but no cloud-credential / cloud-recon coverage (T1552.005 / T1526 / T1552.007).
func TestCloudAttackRulesFire(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	fires := func(title string, event map[string]interface{}) bool {
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	proc := func(image, cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "image_path": image, "command_line": cmd}
	}

	// ── Positive cases ────────────────────────────────────────────────────
	pos := []struct {
		title, image, cmd string
	}{
		{
			"Cloud Instance Metadata Service (IMDS) Credential Access",
			"/usr/bin/curl",
			"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role",
		},
		{
			// GCP metadata hostname + computeMetadata path.
			"Cloud Instance Metadata Service (IMDS) Credential Access",
			"/usr/bin/curl",
			`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`,
		},
		{
			"Cloud Service Discovery or Secret Enumeration via CLI",
			"/usr/local/bin/aws",
			"aws sts get-caller-identity",
		},
		{
			"Cloud Service Discovery or Secret Enumeration via CLI",
			"/usr/local/bin/aws",
			"aws secretsmanager get-secret-value --secret-id prod/db",
		},
		{
			"Kubernetes Service Account Token Access",
			"/bin/cat",
			"cat /var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on: %s", tc.title, tc.cmd)
		}
	}

	// ── Negative cases (near-miss benign) ─────────────────────────────────
	neg := []struct {
		title, image, cmd string
	}{
		{
			// Reaching IMDS IP but without a credential/metadata intent path.
			"Cloud Instance Metadata Service (IMDS) Credential Access",
			"/usr/bin/ping",
			"ping -c1 169.254.169.254",
		},
		{
			// Benign aws usage that is not caller-identity / enumeration.
			"Cloud Service Discovery or Secret Enumeration via CLI",
			"/usr/local/bin/aws",
			"aws s3 cp file.txt s3://bucket/",
		},
		{
			// Reading an unrelated file, not the SA token path.
			"Kubernetes Service Account Token Access",
			"/bin/cat",
			"cat /etc/hostname",
		},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on benign: %s", tc.title, tc.cmd)
		}
	}
}
