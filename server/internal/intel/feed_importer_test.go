package intel

import (
	"strings"
	"testing"
)

// ─── parseOTXReputation ───────────────────────────────────────────────────────

func TestParseOTXReputation_NormalLine_ReturnsIPEntry(t *testing.T) {
	input := "1.2.3.4 some_tag malicious\n"
	entries, err := parseOTXReputation(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseOTXReputation: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Value != "1.2.3.4" {
		t.Errorf("Value: got %q, want 1.2.3.4", entries[0].Value)
	}
	if entries[0].Type != "ip" {
		t.Errorf("Type: got %q, want ip", entries[0].Type)
	}
	if entries[0].Threat != "malicious" {
		t.Errorf("Threat: got %q, want malicious", entries[0].Threat)
	}
	if entries[0].Source != "otx" {
		t.Errorf("Source: got %q, want otx", entries[0].Source)
	}
}

func TestParseOTXReputation_DefaultThreat_WhenFewFields(t *testing.T) {
	// 3番目のフィールドがない場合はデフォルト "malicious"
	input := "5.6.7.8\n"
	entries, _ := parseOTXReputation(strings.NewReader(input))
	if len(entries) != 1 || entries[0].Threat != "malicious" {
		t.Errorf("デフォルトThreat: got %q, want malicious", entries[0].Threat)
	}
}

func TestParseOTXReputation_CommentLine_Skipped(t *testing.T) {
	input := "# this is a comment\n1.2.3.4\n"
	entries, _ := parseOTXReputation(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("コメント行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseOTXReputation_EmptyLine_Skipped(t *testing.T) {
	input := "\n1.2.3.4\n\n"
	entries, _ := parseOTXReputation(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("空行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseOTXReputation_EmptyInput_ReturnsEmpty(t *testing.T) {
	entries, err := parseOTXReputation(strings.NewReader(""))
	if err != nil {
		t.Fatalf("空入力: 予期しないエラー: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("空入力: got %d entries, want 0", len(entries))
	}
}

func TestParseOTXReputation_MultipleLines(t *testing.T) {
	input := "# header\n1.1.1.1\n2.2.2.2 tag threat\n3.3.3.3\n"
	entries, _ := parseOTXReputation(strings.NewReader(input))
	if len(entries) != 3 {
		t.Errorf("複数行: got %d entries, want 3", len(entries))
	}
}

// ─── parseURLhausCSV ──────────────────────────────────────────────────────────

func TestParseURLhausCSV_ValidCSV_ReturnsURLEntry(t *testing.T) {
	// id, dateadded, url, url_status, ...
	input := "1,2024-01-01,http://evil.example.com/payload,active\n"
	entries, err := parseURLhausCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseURLhausCSV: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Value != "http://evil.example.com/payload" {
		t.Errorf("Value: got %q", entries[0].Value)
	}
	if entries[0].Type != "url" {
		t.Errorf("Type: got %q, want url", entries[0].Type)
	}
	if entries[0].Source != "urlhaus" {
		t.Errorf("Source: got %q, want urlhaus", entries[0].Source)
	}
}

func TestParseURLhausCSV_HeaderRow_Skipped(t *testing.T) {
	// url フィールドが "url" のヘッダー行はスキップ
	input := "id,dateadded,url,url_status\n1,2024-01-01,http://evil.example.com,active\n"
	entries, _ := parseURLhausCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("ヘッダー行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseURLhausCSV_CommentLine_Skipped(t *testing.T) {
	input := "# comment\n1,2024-01-01,http://evil.example.com,active\n"
	entries, _ := parseURLhausCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("コメント行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseURLhausCSV_EmptyInput_ReturnsEmpty(t *testing.T) {
	entries, _ := parseURLhausCSV(strings.NewReader(""))
	if len(entries) != 0 {
		t.Errorf("空入力: got %d entries, want 0", len(entries))
	}
}

// ─── parseMalwareBazaarCSV ────────────────────────────────────────────────────

// The live abuse.ch exports quote every field and put a space after each comma;
// these regression tests pin the real-world formats that were silently yielding
// zero IOCs.

func TestParseOTXReputation_HashDelimited(t *testing.T) {
	// AlienVault reputation.data: IP#reliability#risk#type#country#city#lat,lon#...
	body := "49.143.32.6#4#2#Malicious Host#KR##37.51,126.97#3\n" +
		"222.77.181.28#4#2#Scanning Host#CN##24.47,118.08#3\n"
	entries, err := parseOTXReputation(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].Value != "49.143.32.6" || entries[0].Type != "ip" {
		t.Errorf("entry0 = %+v, want ip 49.143.32.6", entries[0])
	}
	if entries[0].Threat != "Malicious Host" {
		t.Errorf("entry0 threat = %q, want 'Malicious Host'", entries[0].Threat)
	}
}

func TestParseMalwareBazaarCSV_QuotedSpacedRow(t *testing.T) {
	// Recent-CSV export is `"date", "sha256", "md5", ...` with a space after each
	// comma — TrimLeadingSpace must recover the 64-char hash.
	sha := "5b9eba1a7822d95af75c31f05d9d4483bb72394f9101d36a6f0a1e01c5a02f8f"
	body := `"2026-07-06 02:19:45", "` + sha + `", "8a65f22dbdb86335dd4146eddbf8c243", "7be9dba16496068589173e868a9473d7aded8fbe", "abuse_ch", "file", "exe"`
	entries, err := parseMalwareBazaarCSV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Value != sha || entries[0].Type != "hash" {
		t.Errorf("entry = %+v, want hash %s", entries[0], sha)
	}
}

func TestParseMalwareBazaarCSV_ValidHash_ReturnsEntry(t *testing.T) {
	// first_seen, sha256_hash(64文字)
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	input := "2024-01-01," + sha256 + ",md5hash,sha1hash\n"
	entries, err := parseMalwareBazaarCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseMalwareBazaarCSV: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Value != sha256 {
		t.Errorf("Value: got %q", entries[0].Value)
	}
	if entries[0].Type != "hash" {
		t.Errorf("Type: got %q, want hash", entries[0].Type)
	}
	if entries[0].Source != "malwarebazaar" {
		t.Errorf("Source: got %q, want malwarebazaar", entries[0].Source)
	}
}

func TestParseMalwareBazaarCSV_HeaderRow_Skipped(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	input := "first_seen,sha256_hash,md5_hash\n2024-01-01," + sha256 + ",md5\n"
	entries, _ := parseMalwareBazaarCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("ヘッダー行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseMalwareBazaarCSV_ShortHash_Skipped(t *testing.T) {
	// 64文字未満のハッシュはスキップ
	input := "2024-01-01,abc123,md5,sha1\n"
	entries, _ := parseMalwareBazaarCSV(strings.NewReader(input))
	if len(entries) != 0 {
		t.Errorf("短いハッシュはスキップ: got %d entries, want 0", len(entries))
	}
}

// ─── parseFeodoCSV ────────────────────────────────────────────────────────────

func TestParseFeodoCSV_ValidIP_ReturnsEntry(t *testing.T) {
	// something, ip_address, ...
	input := "2024-01-01,185.220.101.1,port,country\n"
	entries, err := parseFeodoCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseFeodoCSV: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Value != "185.220.101.1" {
		t.Errorf("Value: got %q", entries[0].Value)
	}
	if entries[0].Type != "ip" {
		t.Errorf("Type: got %q, want ip", entries[0].Type)
	}
	if entries[0].Threat != "c2" {
		t.Errorf("Threat: got %q, want c2", entries[0].Threat)
	}
	if entries[0].Source != "feodo" {
		t.Errorf("Source: got %q, want feodo", entries[0].Source)
	}
}

func TestParseFeodoCSV_HeaderRow_Skipped(t *testing.T) {
	input := "first_seen,ip_address,port,country\n2024-01-01,185.220.101.1,443,DE\n"
	entries, _ := parseFeodoCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("ヘッダー行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParseFeodoCSV_CommentLine_Skipped(t *testing.T) {
	input := "# Feodo C2\n2024-01-01,185.220.101.1,443,DE\n"
	entries, _ := parseFeodoCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Errorf("コメント行スキップ: got %d entries, want 1", len(entries))
	}
}

// ─── parseThreatFoxCSV ────────────────────────────────────────────────────────

func TestParseThreatFoxCSV_IPPort_StripsPortAndReturnsIP(t *testing.T) {
	// first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, alias, printable
	input := `"2024-01-01","123","1.2.3.4:443","ip:port","botnet_cc","win.redline","","RedLine Stealer"` + "\n"
	entries, err := parseThreatFoxCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseThreatFoxCSV: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Type != "ip" {
		t.Errorf("Type: got %q, want ip", entries[0].Type)
	}
	if entries[0].Value != "1.2.3.4" {
		t.Errorf("Value: got %q, want 1.2.3.4 (ポート除去)", entries[0].Value)
	}
	if entries[0].Threat != "RedLine Stealer" {
		t.Errorf("Threat: got %q, want RedLine Stealer (malware_printable優先)", entries[0].Threat)
	}
	if entries[0].Source != "threatfox" {
		t.Errorf("Source: got %q, want threatfox", entries[0].Source)
	}
}

func TestParseThreatFoxCSV_Domain_ReturnsDomain(t *testing.T) {
	input := `"2024-01-01","124","evil.example.com","domain","payload_delivery","win.agent","",""` + "\n"
	entries, _ := parseThreatFoxCSV(strings.NewReader(input))
	if len(entries) != 1 || entries[0].Type != "domain" || entries[0].Value != "evil.example.com" {
		t.Errorf("domainエントリ: got %+v", entries)
	}
	// malware_printable が空なので threat_type にフォールバック
	if len(entries) == 1 && entries[0].Threat != "payload_delivery" {
		t.Errorf("Threat フォールバック: got %q, want payload_delivery", entries[0].Threat)
	}
}

func TestParseThreatFoxCSV_URLAndHash(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	input := `"2024-01-01","125","http://evil.example.com/p","url","payload_delivery","win.x","",""` + "\n" +
		`"2024-01-01","126","` + sha256 + `","sha256_hash","payload","win.y","",""` + "\n"
	entries, _ := parseThreatFoxCSV(strings.NewReader(input))
	if len(entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(entries))
	}
	if entries[0].Type != "url" {
		t.Errorf("Type[0]: got %q, want url", entries[0].Type)
	}
	if entries[1].Type != "hash" || entries[1].Value != sha256 {
		t.Errorf("Type[1]/Value[1]: got %q/%q, want hash/%s", entries[1].Type, entries[1].Value, sha256)
	}
}

func TestParseThreatFoxCSV_UnknownType_Skipped(t *testing.T) {
	input := `"2024-01-01","127","something","email","spam","win.z","",""` + "\n"
	entries, _ := parseThreatFoxCSV(strings.NewReader(input))
	if len(entries) != 0 {
		t.Errorf("未知 ioc_type はスキップ: got %d entries, want 0", len(entries))
	}
}

func TestParseThreatFoxCSV_CommentAndHeader_Skipped(t *testing.T) {
	input := "# ThreatFox export legend\n" +
		`"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type"` + "\n" +
		`"2024-01-01","128","9.9.9.9:80","ip:port","botnet_cc","win.a","","Agent"` + "\n"
	entries, _ := parseThreatFoxCSV(strings.NewReader(input))
	// コメント('#')はスキップ、ヘッダー行は ioc_value=="ioc_value" でスキップ → 1件のみ
	if len(entries) != 1 {
		t.Errorf("コメント/ヘッダースキップ: got %d entries, want 1", len(entries))
	}
}

// ─── parseMISPJSON ────────────────────────────────────────────────────────────

func TestParseMISPJSON_IPAttribute_ReturnsIPEntry(t *testing.T) {
	input := `{"Event":{"Attribute":[{"type":"ip-dst","value":"1.2.3.4"}]}}`
	entries, err := parseMISPJSON(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseMISPJSON: 予期しないエラー: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}
	if entries[0].Type != "ip" {
		t.Errorf("Type: got %q, want ip", entries[0].Type)
	}
	if entries[0].Value != "1.2.3.4" {
		t.Errorf("Value: got %q, want 1.2.3.4", entries[0].Value)
	}
	if entries[0].Source != "misp" {
		t.Errorf("Source: got %q, want misp", entries[0].Source)
	}
}

func TestParseMISPJSON_DomainAttribute_ReturnsDomainEntry(t *testing.T) {
	input := `{"Event":{"Attribute":[{"type":"domain","value":"evil.example.com"}]}}`
	entries, _ := parseMISPJSON(strings.NewReader(input))
	if len(entries) != 1 || entries[0].Type != "domain" {
		t.Errorf("domainエントリ: got type %q", entries[0].Type)
	}
}

func TestParseMISPJSON_SHA256Attribute_ReturnsHashEntry(t *testing.T) {
	input := `{"Event":{"Attribute":[{"type":"sha256","value":"abc123"}]}}`
	entries, _ := parseMISPJSON(strings.NewReader(input))
	if len(entries) != 1 || entries[0].Type != "hash" {
		t.Errorf("hashエントリ: got type %q", entries[0].Type)
	}
}

func TestParseMISPJSON_UnknownAttributeType_Skipped(t *testing.T) {
	input := `{"Event":{"Attribute":[{"type":"unknown-type","value":"somevalue"}]}}`
	entries, _ := parseMISPJSON(strings.NewReader(input))
	if len(entries) != 0 {
		t.Errorf("未知タイプはスキップ: got %d entries, want 0", len(entries))
	}
}

func TestParseMISPJSON_PipeValue_TakesFirstPart(t *testing.T) {
	// ip-dst|port 形式: "1.2.3.4|443" → "1.2.3.4"
	input := `{"Event":{"Attribute":[{"type":"ip-dst|port","value":"1.2.3.4|443"}]}}`
	entries, _ := parseMISPJSON(strings.NewReader(input))
	if len(entries) != 1 || entries[0].Value != "1.2.3.4" {
		t.Errorf("パイプ値: got %q, want 1.2.3.4", entries[0].Value)
	}
}

func TestParseMISPJSON_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := parseMISPJSON(strings.NewReader("{invalid json"))
	if err == nil {
		t.Error("不正 JSON はエラーを返すべきです")
	}
}

func TestParseMISPJSON_MultipleAttributes(t *testing.T) {
	input := `{"Event":{"Attribute":[
		{"type":"ip-dst","value":"1.2.3.4"},
		{"type":"domain","value":"evil.com"},
		{"type":"url","value":"http://evil.com/payload"}
	]}}`
	entries, _ := parseMISPJSON(strings.NewReader(input))
	if len(entries) != 3 {
		t.Errorf("複数属性: got %d entries, want 3", len(entries))
	}
}

// ─── parsePlainList ───────────────────────────────────────────────────────────

func TestParsePlainList_DefaultFormat_ReturnsIPEntry(t *testing.T) {
	entries, _ := parsePlainList(strings.NewReader("1.2.3.4\n5.6.7.8\n"), "ip_list")
	if len(entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(entries))
	}
	if entries[0].Type != "ip" {
		t.Errorf("Type: got %q, want ip", entries[0].Type)
	}
}

func TestParsePlainList_DomainFormat_ReturnsDomainEntry(t *testing.T) {
	entries, _ := parsePlainList(strings.NewReader("evil.example.com\n"), "domain_list")
	if len(entries) != 1 || entries[0].Type != "domain" {
		t.Errorf("domain format: got type %q, want domain", entries[0].Type)
	}
}

func TestParsePlainList_URLFormat_ReturnsURLEntry(t *testing.T) {
	entries, _ := parsePlainList(strings.NewReader("http://evil.example.com\n"), "url_blocklist")
	if len(entries) != 1 || entries[0].Type != "url" {
		t.Errorf("url format: got type %q, want url", entries[0].Type)
	}
}

func TestParsePlainList_HashFormat_ReturnsHashEntry(t *testing.T) {
	entries, _ := parsePlainList(strings.NewReader("abc123def456\n"), "hash_list")
	if len(entries) != 1 || entries[0].Type != "hash" {
		t.Errorf("hash format: got type %q, want hash", entries[0].Type)
	}
}

func TestParsePlainList_CommentLines_Skipped(t *testing.T) {
	input := "# comment\n// also comment\n1.2.3.4\n"
	entries, _ := parsePlainList(strings.NewReader(input), "ip")
	if len(entries) != 1 {
		t.Errorf("コメント行スキップ: got %d entries, want 1", len(entries))
	}
}

func TestParsePlainList_EmptyLines_Skipped(t *testing.T) {
	input := "\n1.2.3.4\n\n5.6.7.8\n"
	entries, _ := parsePlainList(strings.NewReader(input), "ip")
	if len(entries) != 2 {
		t.Errorf("空行スキップ: got %d entries, want 2", len(entries))
	}
}

func TestParsePlainList_Source_IsCustom(t *testing.T) {
	entries, _ := parsePlainList(strings.NewReader("1.2.3.4\n"), "ip")
	if entries[0].Source != "custom" {
		t.Errorf("Source: got %q, want custom", entries[0].Source)
	}
}
