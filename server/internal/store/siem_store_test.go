package store

import (
	"strings"
	"testing"
	"time"
)

// ─── SIEMフォーマット・プロトコル検証ヘルパー ────────────────────────────────

// validSIEMTypes は有効な SIEM ターゲットタイプの一覧を返す
func validSIEMTypes() []string {
	return []string{"splunk", "elasticsearch", "qradar", "sentinel", "syslog", "generic_http"}
}

// isValidSIEMType は SIEM タイプが有効かどうかを判定する
func isValidSIEMType(siemType string) bool {
	for _, v := range validSIEMTypes() {
		if v == siemType {
			return true
		}
	}
	return false
}

// validSIEMProtocols は有効なプロトコルの一覧を返す
func validSIEMProtocols() []string {
	return []string{"tcp", "udp", "https", "http"}
}

// isValidSIEMProtocol はプロトコルが有効かどうかを判定する
func isValidSIEMProtocol(protocol string) bool {
	for _, v := range validSIEMProtocols() {
		if v == protocol {
			return true
		}
	}
	return false
}

// isValidSIEMPort はポート番号が 1〜65535 の範囲にあるか確認する
func isValidSIEMPort(port int) bool {
	return port >= 1 && port <= 65535
}

// isValidMinSeverity は最低重大度が 0〜10 の範囲にあるか確認する（0 は全アラート転送）
func isValidSIEMMinSeverity(minSeverity int) bool {
	return minSeverity >= 0 && minSeverity <= 10
}

// siemTargetRequiresTLS はターゲットが TLS を必要とするかどうかを判定する
// HTTPS プロトコルまたは Splunk/Sentinel タイプは TLS を推奨する
func siemTargetRequiresTLS(t *SIEMTarget) bool {
	if t.Protocol == "https" {
		return true
	}
	if t.Type == "splunk" || t.Type == "sentinel" {
		return true
	}
	return false
}

// siemTargetHasRequiredFields は SIEM ターゲットが最低限必要なフィールドを持つか確認する
func siemTargetHasRequiredFields(t *SIEMTarget) bool {
	return t.Name != "" && t.Type != "" && t.Host != "" && t.Protocol != ""
}

// filterEnabledSIEMTargets は有効な SIEM ターゲットのみを返す
func filterEnabledSIEMTargets(targets []*SIEMTarget) []*SIEMTarget {
	var result []*SIEMTarget
	for _, t := range targets {
		if t.Enabled {
			result = append(result, t)
		}
	}
	if result == nil {
		result = []*SIEMTarget{}
	}
	return result
}

// filterSIEMTargetsBySeverity は指定のアラート重大度を転送対象とする SIEM ターゲットを返す
func filterSIEMTargetsBySeverity(targets []*SIEMTarget, alertSeverity int) []*SIEMTarget {
	var result []*SIEMTarget
	for _, t := range targets {
		if t.MinSeverity <= alertSeverity {
			result = append(result, t)
		}
	}
	if result == nil {
		result = []*SIEMTarget{}
	}
	return result
}

// siemTargetNeedsToken はトークン認証が必要なタイプかどうかを判定する
func siemTargetNeedsToken(t *SIEMTarget) bool {
	return t.Type == "splunk" || t.Type == "elasticsearch" || t.Type == "sentinel"
}

// ─── SIEMTarget 構造体テスト ──────────────────────────────────────────────────

// TestSIEMTarget_ZeroValue は SIEMTarget のゼロ値フィールドを確認する
func TestSIEMTarget_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルト値を確認する
	var st SIEMTarget
	if st.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", st.ID)
	}
	if st.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", st.Name)
	}
	if st.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", st.Type)
	}
	if st.Host != "" {
		t.Errorf("Host のデフォルト = %q, want \"\"", st.Host)
	}
	if st.Port != 0 {
		t.Errorf("Port のデフォルト = %d, want 0", st.Port)
	}
	if st.TLSEnabled {
		t.Error("TLSEnabled のデフォルトは false であるべき")
	}
	if st.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if st.MinSeverity != 0 {
		t.Errorf("MinSeverity のデフォルト = %d, want 0", st.MinSeverity)
	}
}

// TestSIEMTarget_FieldAssignment は SIEMTarget フィールド代入を確認する
func TestSIEMTarget_FieldAssignment(t *testing.T) {
	// 全フィールドへの代入が正しく反映されるか確認する
	now := time.Now()
	st := SIEMTarget{
		ID:          "siem-001",
		Name:        "本番Splunkサーバー",
		Type:        "splunk",
		Host:        "splunk.example.com",
		Port:        8088,
		Protocol:    "https",
		Token:       "Bearer eyJhbGci...",
		TLSEnabled:  true,
		IndexName:   "edr_alerts",
		Enabled:     true,
		MinSeverity: 5,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if st.ID != "siem-001" {
		t.Errorf("ID = %q, want \"siem-001\"", st.ID)
	}
	if st.Type != "splunk" {
		t.Errorf("Type = %q, want \"splunk\"", st.Type)
	}
	if st.Port != 8088 {
		t.Errorf("Port = %d, want 8088", st.Port)
	}
	if !st.TLSEnabled {
		t.Error("TLSEnabled は true であるべき")
	}
	if st.IndexName != "edr_alerts" {
		t.Errorf("IndexName = %q, want \"edr_alerts\"", st.IndexName)
	}
	if st.MinSeverity != 5 {
		t.Errorf("MinSeverity = %d, want 5", st.MinSeverity)
	}
}

// TestIsValidSIEMType_KnownTypes は既知のタイプが全て有効と判定されることを確認する
func TestIsValidSIEMType_KnownTypes(t *testing.T) {
	// 定義済みの全 SIEM タイプが有効と判定されるか確認する
	for _, st := range validSIEMTypes() {
		if !isValidSIEMType(st) {
			t.Errorf("有効な SIEM タイプ %q が無効と判定された", st)
		}
	}
}

// TestIsValidSIEMType_UnknownTypes は未知のタイプが拒否されることを確認する
func TestIsValidSIEMType_UnknownTypes(t *testing.T) {
	// 定義されていないタイプは拒否される
	unknownTypes := []string{"Splunk", "ELASTICSEARCH", "logstash", "", "arcsight"}
	for _, st := range unknownTypes {
		if isValidSIEMType(st) {
			t.Errorf("未知の SIEM タイプ %q が有効と判定された", st)
		}
	}
}

// TestIsValidSIEMProtocol_ValidProtocols は有効なプロトコルを確認する
func TestIsValidSIEMProtocol_ValidProtocols(t *testing.T) {
	// 定義済みの全プロトコルが有効と判定されるか確認する
	for _, p := range validSIEMProtocols() {
		if !isValidSIEMProtocol(p) {
			t.Errorf("有効なプロトコル %q が無効と判定された", p)
		}
	}
}

// TestIsValidSIEMProtocol_InvalidProtocols は無効なプロトコルが拒否されることを確認する
func TestIsValidSIEMProtocol_InvalidProtocols(t *testing.T) {
	// 未定義のプロトコルは拒否される
	invalidProtocols := []string{"TCP", "HTTP", "tls", "ssl", "", "ftp", "grpc"}
	for _, p := range invalidProtocols {
		if isValidSIEMProtocol(p) {
			t.Errorf("無効なプロトコル %q が有効と判定された", p)
		}
	}
}

// TestIsValidSIEMPort_BoundaryValues はポート番号の境界値を確認する
func TestIsValidSIEMPort_BoundaryValues(t *testing.T) {
	// 1 から 65535 の境界値を確認する
	validPorts := []int{1, 80, 443, 514, 8088, 9200, 65535}
	for _, port := range validPorts {
		if !isValidSIEMPort(port) {
			t.Errorf("ポート %d は有効であるべき", port)
		}
	}

	// 0 以下と 65536 以上は無効
	invalidPorts := []int{0, -1, 65536, 100000}
	for _, port := range invalidPorts {
		if isValidSIEMPort(port) {
			t.Errorf("ポート %d は無効であるべき", port)
		}
	}
}

// TestIsValidSIEMMinSeverity_ValidRange は最低重大度の有効範囲を確認する
func TestIsValidSIEMMinSeverity_ValidRange(t *testing.T) {
	// 0（全転送）から 10 まで全て有効
	for sev := 0; sev <= 10; sev++ {
		if !isValidSIEMMinSeverity(sev) {
			t.Errorf("最低重大度 %d は有効であるべき", sev)
		}
	}
}

// TestIsValidSIEMMinSeverity_OutOfRange は範囲外の最低重大度が無効と判定されることを確認する
func TestIsValidSIEMMinSeverity_OutOfRange(t *testing.T) {
	// 負の値と 11 以上は無効
	invalidCases := []int{-1, 11, 100}
	for _, sev := range invalidCases {
		if isValidSIEMMinSeverity(sev) {
			t.Errorf("最低重大度 %d は無効であるべき", sev)
		}
	}
}

// TestSIEMTargetRequiresTLS_HTTPSProtocol は HTTPS プロトコルで TLS が必要と判定されることを確認する
func TestSIEMTargetRequiresTLS_HTTPSProtocol(t *testing.T) {
	// HTTPS プロトコルは TLS を必要とする
	st := &SIEMTarget{Type: "generic_http", Protocol: "https"}
	if !siemTargetRequiresTLS(st) {
		t.Error("HTTPS プロトコルは TLS が必要と判定されるべき")
	}
}

// TestSIEMTargetRequiresTLS_SplunkType は Splunk タイプで TLS が推奨されることを確認する
func TestSIEMTargetRequiresTLS_SplunkType(t *testing.T) {
	// Splunk は TLS が必要
	st := &SIEMTarget{Type: "splunk", Protocol: "tcp"}
	if !siemTargetRequiresTLS(st) {
		t.Error("Splunk タイプは TLS が必要と判定されるべき")
	}
}

// TestSIEMTargetRequiresTLS_SentinelType は Sentinel タイプで TLS が推奨されることを確認する
func TestSIEMTargetRequiresTLS_SentinelType(t *testing.T) {
	// Azure Sentinel は TLS が必要
	st := &SIEMTarget{Type: "sentinel", Protocol: "tcp"}
	if !siemTargetRequiresTLS(st) {
		t.Error("Sentinel タイプは TLS が必要と判定されるべき")
	}
}

// TestSIEMTargetRequiresTLS_PlainTCP は平文 TCP で TLS が不要と判定されることを確認する
func TestSIEMTargetRequiresTLS_PlainTCP(t *testing.T) {
	// syslog over TCP は TLS を強制しない
	st := &SIEMTarget{Type: "syslog", Protocol: "tcp"}
	if siemTargetRequiresTLS(st) {
		t.Error("syslog over tcp は TLS 不要と判定されるべき")
	}
}

// TestSIEMTargetHasRequiredFields_Complete は必須フィールドが揃っている場合を確認する
func TestSIEMTargetHasRequiredFields_Complete(t *testing.T) {
	// Name, Type, Host, Protocol が全て設定されていれば有効
	st := &SIEMTarget{
		Name:     "テストSIEM",
		Type:     "syslog",
		Host:     "siem.internal",
		Protocol: "tcp",
	}
	if !siemTargetHasRequiredFields(st) {
		t.Error("必須フィールドが揃っている SIEM ターゲットは有効と判定されるべき")
	}
}

// TestSIEMTargetHasRequiredFields_MissingHost は Host が空の場合を確認する
func TestSIEMTargetHasRequiredFields_MissingHost(t *testing.T) {
	// Host が空のターゲットは無効
	st := &SIEMTarget{
		Name:     "テストSIEM",
		Type:     "syslog",
		Host:     "",
		Protocol: "tcp",
	}
	if siemTargetHasRequiredFields(st) {
		t.Error("Host が空の SIEM ターゲットは無効と判定されるべき")
	}
}

// TestFilterEnabledSIEMTargets_FiltersCorrectly は有効な SIEM ターゲットのフィルタリングを確認する
func TestFilterEnabledSIEMTargets_FiltersCorrectly(t *testing.T) {
	// 有効・無効が混在するリストから有効のみ抽出されるか確認する
	targets := []*SIEMTarget{
		{ID: "s1", Enabled: true},
		{ID: "s2", Enabled: false},
		{ID: "s3", Enabled: true},
		{ID: "s4", Enabled: false},
		{ID: "s5", Enabled: true},
	}
	enabled := filterEnabledSIEMTargets(targets)
	if len(enabled) != 3 {
		t.Errorf("有効な SIEM ターゲット数 = %d, want 3", len(enabled))
	}
	for _, st := range enabled {
		if !st.Enabled {
			t.Errorf("無効なターゲット %q がフィルタ結果に含まれている", st.ID)
		}
	}
}

// TestFilterEnabledSIEMTargets_EmptyInput は空入力が空スライスを返すことを確認する
func TestFilterEnabledSIEMTargets_EmptyInput(t *testing.T) {
	// 空スライス入力は空スライスを返す
	result := filterEnabledSIEMTargets([]*SIEMTarget{})
	if len(result) != 0 {
		t.Errorf("空入力から空出力のはず: got %d items", len(result))
	}
}

// TestFilterSIEMTargetsBySeverity_MatchingTargets は重大度に合致するターゲットを確認する
func TestFilterSIEMTargetsBySeverity_MatchingTargets(t *testing.T) {
	// MinSeverity <= alertSeverity のターゲットのみが転送対象
	targets := []*SIEMTarget{
		{ID: "s1", MinSeverity: 1},
		{ID: "s2", MinSeverity: 5},
		{ID: "s3", MinSeverity: 8},
		{ID: "s4", MinSeverity: 10},
	}
	// alertSeverity 6: MinSeverity <= 6 のターゲットは s1(1), s2(5)
	result := filterSIEMTargetsBySeverity(targets, 6)
	if len(result) != 2 {
		t.Errorf("重大度 6 の転送対象数 = %d, want 2", len(result))
	}
	for _, st := range result {
		if st.MinSeverity > 6 {
			t.Errorf("MinSeverity %d > 6 のターゲット %q が含まれている", st.MinSeverity, st.ID)
		}
	}
}

// TestFilterSIEMTargetsBySeverity_MinSeverityZero は MinSeverity 0 が全アラートを転送することを確認する
func TestFilterSIEMTargetsBySeverity_MinSeverityZero(t *testing.T) {
	// MinSeverity 0 は全重大度が対象
	targets := []*SIEMTarget{
		{ID: "s1", MinSeverity: 0},
	}
	for alertSev := 1; alertSev <= 10; alertSev++ {
		result := filterSIEMTargetsBySeverity(targets, alertSev)
		if len(result) != 1 {
			t.Errorf("MinSeverity 0 のターゲットは重大度 %d でも対象であるべき", alertSev)
		}
	}
}

// TestSIEMTargetNeedsToken_TokenRequiredTypes はトークン認証が必要なタイプを確認する
func TestSIEMTargetNeedsToken_TokenRequiredTypes(t *testing.T) {
	// splunk, elasticsearch, sentinel はトークンが必要
	tokenTypes := []string{"splunk", "elasticsearch", "sentinel"}
	for _, tt := range tokenTypes {
		st := &SIEMTarget{Type: tt}
		if !siemTargetNeedsToken(st) {
			t.Errorf("SIEM タイプ %q はトークンが必要と判定されるべき", tt)
		}
	}
}

// TestSIEMTargetNeedsToken_TokenNotRequired はトークン不要なタイプを確認する
func TestSIEMTargetNeedsToken_TokenNotRequired(t *testing.T) {
	// syslog と qradar はトークン不要（別の認証方式）
	nonTokenTypes := []string{"syslog", "qradar", "generic_http"}
	for _, tt := range nonTokenTypes {
		st := &SIEMTarget{Type: tt}
		if siemTargetNeedsToken(st) {
			t.Errorf("SIEM タイプ %q はトークン不要と判定されるべき", tt)
		}
	}
}

// TestSIEMTarget_IndexNameOptional は IndexName が省略可能であることを確認する
func TestSIEMTarget_IndexNameOptional(t *testing.T) {
	// IndexName が空でも SIEM ターゲットは有効（syslog 等では不要）
	st := &SIEMTarget{
		Name:     "SyslogSIEM",
		Type:     "syslog",
		Host:     "siem.internal",
		Protocol: "udp",
		Port:     514,
		// IndexName は空
	}
	if !siemTargetHasRequiredFields(st) {
		t.Error("IndexName が空でも必須フィールドが揃っていれば有効であるべき")
	}
	if st.IndexName != "" {
		t.Errorf("IndexName のデフォルト = %q, want \"\"", st.IndexName)
	}
}

// TestSIEMTarget_WellKnownPorts はよく知られたポートの有効性を確認する
func TestSIEMTarget_WellKnownPorts(t *testing.T) {
	// SIEM でよく使われるポートが有効かどうかを確認する
	wellKnownPorts := map[string]int{
		"syslog_udp":    514,
		"syslog_tls":    6514,
		"splunk_hec":    8088,
		"elasticsearch": 9200,
		"https":         443,
	}
	for name, port := range wellKnownPorts {
		if !isValidSIEMPort(port) {
			t.Errorf("%s のポート %d は有効であるべき", name, port)
		}
	}
}

// TestSIEMTarget_TimestampFieldsAreTimeType は CreatedAt と UpdatedAt が time.Time 型であることを確認する
func TestSIEMTarget_TimestampFieldsAreTimeType(t *testing.T) {
	// タイムスタンプフィールドが time.Time 型として正しく設定されるか確認する
	now := time.Now()
	st := SIEMTarget{
		CreatedAt: now,
		UpdatedAt: now,
	}
	if !st.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt が期待値と一致しない")
	}
	if !st.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt が期待値と一致しない")
	}
	// ゼロ値の確認
	var zeroTarget SIEMTarget
	if !zeroTarget.CreatedAt.IsZero() {
		t.Error("CreatedAt のゼロ値は zero time であるべき")
	}
}

// TestSIEMTarget_TLSAndProtocolConsistency は TLS と HTTPS プロトコルの整合性を確認する
func TestSIEMTarget_TLSAndProtocolConsistency(t *testing.T) {
	// HTTPS プロトコルを使う場合は TLSEnabled=true が自然
	st := SIEMTarget{
		Protocol:   "https",
		TLSEnabled: true,
	}
	if st.Protocol != "https" {
		t.Errorf("Protocol = %q, want \"https\"", st.Protocol)
	}
	if !st.TLSEnabled {
		t.Error("HTTPS プロトコルでは TLSEnabled=true が期待される")
	}

	// TCP プロトコルでは TLS は任意
	stTCP := SIEMTarget{
		Protocol:   "tcp",
		TLSEnabled: false,
	}
	if strings.ToUpper(stTCP.Protocol) != "TCP" {
		t.Errorf("Protocol の大文字変換 = %q, want \"TCP\"", strings.ToUpper(stTCP.Protocol))
	}
}
