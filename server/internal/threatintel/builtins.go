package threatintel

import "time"

// LoadBuiltinIOCs は起動時に静的IOCをロードする関数です。
//
// ここには RFC 5737 テストアドレス (192.0.2.0/24) と *.example ドメインのみを含みます。
// これらは実トラフィックに一致しない安全なセンチネル値であり、
// システムの動作確認（ユニットテスト・統合テスト）に使用されます。
//
// 実際のIOCは以下の公開脅威インテルフィードから自動同期されます:
//   - Abuse.ch URLhaus  (マルウェアURL)
//   - Abuse.ch ThreatFox (IOC)
//   - Emerging Threats (ルールセット)
//   - AlienVault OTX (パルス)
//
// フィード同期は ScheduledSync() または手動で
// POST /api/v1/admin/threat-intel/sync を呼び出すことで実行できます。
func LoadBuiltinIOCs(m *FeedManager) {
	now := time.Now().UTC()
	// RFC 5737 TEST-NET-1 sentinel — never appears in real traffic
	m.AddIOC(&IOC{
		Type:       "ip",
		Value:      "192.0.2.10",
		Confidence: 90,
		Severity:   8,
		Source:     "builtin",
		Tags:       []string{"c2", "sentinel"},
		CreatedAt:  now,
	})
	// Reserved .example domain sentinel — never resolves in real DNS
	m.AddIOC(&IOC{
		Type:       "domain",
		Value:      "malware-c2.example",
		Confidence: 90,
		Severity:   8,
		Source:     "builtin",
		Tags:       []string{"c2", "sentinel"},
		CreatedAt:  now,
	})
}
