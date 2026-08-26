package detection

import "testing"

// TestCloudPersistenceFire covers cloud backdoor account creation (new IAM user/service
// principal) and persistence via scheduled event trigger (EventBridge → Lambda/SSM, or
// GCP Cloud Scheduler), each with benign negatives.
func TestCloudPersistenceFire(t *testing.T) {
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

	pos := []struct{ title, image, cmd string }{
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)",
			`/usr/local/bin/aws`, `aws iam create-user --user-name backdoor-svc`},
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)",
			`/usr/bin/gcloud`, `gcloud iam service-accounts create backdoor-sa`},
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)",
			`/usr/bin/gcloud`, `gcloud iam service-accounts keys create key.json --iam-account=backdoor-sa@proj.iam.gserviceaccount.com`},
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)",
			`/usr/bin/az`, `az ad sp create-for-rbac --role Owner --scopes /subscriptions/abc`},
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)",
			`/usr/local/bin/aws`, `aws events put-targets --rule persist-rule --targets Id=1,Arn=arn:aws:lambda:us-east-1:1234:function:backdoor`},
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)",
			`/usr/local/bin/aws`, `aws events put-targets --rule persist-rule --targets Id=1,Arn=arn:aws:ssm:us-east-1:1234:document/evil-doc`},
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)",
			`/usr/bin/gcloud`, `gcloud scheduler jobs create http persist-job --uri=https://evil.example/hook --schedule="*/5 * * * *"`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on %q", tc.title, tc.cmd)
		}
	}

	neg := []struct{ title, image, cmd string }{
		// Read-only IAM listing → no fire.
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)", `/usr/local/bin/aws`, `aws iam list-users`},
		// Listing service accounts (no creation) → no fire.
		{"Cloud Backdoor Account Creation (IAM User / Service Principal)", `/usr/bin/gcloud`, `gcloud iam service-accounts list`},
		// Creating an EventBridge rule that targets an SNS topic, not compute → no fire.
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)",
			`/usr/local/bin/aws`, `aws events put-targets --rule notify-rule --targets Id=1,Arn=arn:aws:sns:us-east-1:1234:alerts`},
		// Just creating the rule shell, no target wiring yet → no fire.
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)",
			`/usr/local/bin/aws`, `aws events put-rule --name persist-rule --schedule-expression "rate(5 minutes)"`},
		// Listing scheduler jobs → no fire.
		{"Cloud Persistence via Scheduled Event Trigger (EventBridge/Cloud Scheduler)", `/usr/bin/gcloud`, `gcloud scheduler jobs list`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on %q", tc.title, tc.cmd)
		}
	}
}
