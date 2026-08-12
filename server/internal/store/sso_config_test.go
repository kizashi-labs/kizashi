package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── SSOプロバイダータイプ検証ヘルパー ────────────────────────────────────────

// validSSOProviders は有効な SSO プロバイダータイプの一覧を返す
func validSSOProviders() []string {
	return []string{"saml", "oidc"}
}

// isValidSSOProvider は SSO プロバイダータイプが有効かどうかを判定する
func isValidSSOProvider(provider string) bool {
	for _, v := range validSSOProviders() {
		if v == provider {
			return true
		}
	}
	return false
}

// validSSODefaultRoles は有効なデフォルトロールの一覧を返す
func validSSODefaultRoles() []string {
	return []string{"admin", "analyst", "viewer", "readonly"}
}

// isValidSSODefaultRole は SSO デフォルトロールが有効かどうかを判定する
func isValidSSODefaultRole(role string) bool {
	for _, v := range validSSODefaultRoles() {
		if v == role {
			return true
		}
	}
	return false
}

// ssoConfigIsSAML は SSO 設定が SAML プロバイダーかどうかを確認する
func ssoConfigIsSAML(c *SSOConfig) bool {
	return c.Provider == "saml"
}

// ssoConfigIsOIDC は SSO 設定が OIDC プロバイダーかどうかを確認する
func ssoConfigIsOIDC(c *SSOConfig) bool {
	return c.Provider == "oidc"
}

// samlConfigHasRequiredFields は SAML 設定が必須フィールドを持つか確認する
func samlConfigHasRequiredFields(c *SSOConfig) bool {
	return c.IDPEntityID != "" && c.IDPSSOUrl != "" && c.IDPCertificate != "" && c.SPEntityID != ""
}

// oidcConfigHasRequiredFields は OIDC 設定が必須フィールドを持つか確認する
func oidcConfigHasRequiredFields(c *SSOConfig) bool {
	return c.ClientID != "" && c.DiscoveryURL != ""
}

// ssoConfigHasRequiredBaseFields は SSO 設定の基本的な必須フィールドを確認する
func ssoConfigHasRequiredBaseFields(c *SSOConfig) bool {
	return c.Provider != "" && c.Name != ""
}

// isValidDiscoveryURL は OIDC ディスカバリー URL が .well-known/openid-configuration を含むか確認する
func isValidDiscoveryURL(url string) bool {
	return strings.Contains(url, ".well-known/openid-configuration")
}

// filterEnabledSSOConfigs は有効な SSO 設定のみを返す
func filterEnabledSSOConfigs(configs []SSOConfig) []SSOConfig {
	var result []SSOConfig
	for _, c := range configs {
		if c.Enabled {
			result = append(result, c)
		}
	}
	if result == nil {
		result = []SSOConfig{}
	}
	return result
}

// filterSSOConfigsByProvider は指定プロバイダータイプの設定のみを返す
func filterSSOConfigsByProvider(configs []SSOConfig, provider string) []SSOConfig {
	var result []SSOConfig
	for _, c := range configs {
		if c.Provider == provider {
			result = append(result, c)
		}
	}
	if result == nil {
		result = []SSOConfig{}
	}
	return result
}

// ssoConfigToPublicProvider は SSOConfig を SSOPublicProvider に変換する純粋関数
func ssoConfigToPublicProvider(c SSOConfig) SSOPublicProvider {
	return SSOPublicProvider{ID: c.ID, Name: c.Name}
}

// ─── SSOConfig 構造体テスト ───────────────────────────────────────────────────

// TestSSOConfig_ZeroValue は SSOConfig のゼロ値フィールドを確認する
func TestSSOConfig_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルト値を確認する
	var c SSOConfig
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.Provider != "" {
		t.Errorf("Provider のデフォルト = %q, want \"\"", c.Provider)
	}
	if c.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", c.Name)
	}
	if c.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if c.IDPEntityID != "" {
		t.Errorf("IDPEntityID のデフォルト = %q, want \"\"", c.IDPEntityID)
	}
	if c.ClientID != "" {
		t.Errorf("ClientID のデフォルト = %q, want \"\"", c.ClientID)
	}
	if c.ClientSecret != "" {
		t.Errorf("ClientSecret のデフォルト = %q, want \"\"", c.ClientSecret)
	}
	if c.DefaultRole != "" {
		t.Errorf("DefaultRole のデフォルト = %q, want \"\"", c.DefaultRole)
	}
}

// TestSSOConfig_SAMLFieldAssignment は SAML プロバイダーのフィールド代入を確認する
func TestSSOConfig_SAMLFieldAssignment(t *testing.T) {
	// SAML 設定の全フィールドへの代入を確認する
	now := time.Now()
	attrMapping := json.RawMessage(`{"email":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress","name":"displayName","role":"role"}`)
	c := SSOConfig{
		ID:               "sso-001",
		Provider:         "saml",
		Name:             "Okta SAML",
		IDPEntityID:      "http://www.okta.com/exk123abc",
		IDPSSOUrl:        "https://company.okta.com/app/saml/exk123/sso/saml",
		IDPCertificate:   "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		SPEntityID:       "https://edr.example.com/sso/saml/acs",
		Enabled:          true,
		AttributeMapping: attrMapping,
		DefaultRole:      "analyst",
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if c.Provider != "saml" {
		t.Errorf("Provider = %q, want \"saml\"", c.Provider)
	}
	if c.IDPEntityID != "http://www.okta.com/exk123abc" {
		t.Errorf("IDPEntityID が期待値と一致しない: %q", c.IDPEntityID)
	}
	if c.IDPSSOUrl == "" {
		t.Error("IDPSSOUrl が空であるべきでない")
	}
	if !strings.Contains(c.IDPCertificate, "BEGIN CERTIFICATE") {
		t.Error("IDPCertificate に BEGIN CERTIFICATE が含まれるべき")
	}
	if c.DefaultRole != "analyst" {
		t.Errorf("DefaultRole = %q, want \"analyst\"", c.DefaultRole)
	}
}

// TestSSOConfig_OIDCFieldAssignment は OIDC プロバイダーのフィールド代入を確認する
func TestSSOConfig_OIDCFieldAssignment(t *testing.T) {
	// OIDC 設定の全フィールドへの代入を確認する
	c := SSOConfig{
		ID:           "sso-002",
		Provider:     "oidc",
		Name:         "Azure AD OIDC",
		ClientID:     "client-id-azure-12345",
		ClientSecret: "secret-value-xyz",
		DiscoveryURL: "https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration",
		Enabled:      true,
		DefaultRole:  "viewer",
	}

	if c.Provider != "oidc" {
		t.Errorf("Provider = %q, want \"oidc\"", c.Provider)
	}
	if c.ClientID != "client-id-azure-12345" {
		t.Errorf("ClientID = %q, want \"client-id-azure-12345\"", c.ClientID)
	}
	if c.ClientSecret != "secret-value-xyz" {
		t.Errorf("ClientSecret が期待値と一致しない")
	}
	if !isValidDiscoveryURL(c.DiscoveryURL) {
		t.Errorf("DiscoveryURL が .well-known/openid-configuration を含まない: %q", c.DiscoveryURL)
	}
}

// TestIsValidSSOProvider_ValidProviders は有効なプロバイダータイプを確認する
func TestIsValidSSOProvider_ValidProviders(t *testing.T) {
	// saml と oidc が有効と判定されるか確認する
	for _, p := range validSSOProviders() {
		if !isValidSSOProvider(p) {
			t.Errorf("有効な SSO プロバイダー %q が無効と判定された", p)
		}
	}
}

// TestIsValidSSOProvider_InvalidProviders は無効なプロバイダータイプが拒否されることを確認する
func TestIsValidSSOProvider_InvalidProviders(t *testing.T) {
	// 定義外のプロバイダータイプは拒否される
	invalidProviders := []string{"SAML", "OIDC", "oauth2", "ldap", "", "kerberos", "cas"}
	for _, p := range invalidProviders {
		if isValidSSOProvider(p) {
			t.Errorf("無効な SSO プロバイダー %q が有効と判定された", p)
		}
	}
}

// TestIsValidSSODefaultRole_ValidRoles は有効なデフォルトロールを確認する
func TestIsValidSSODefaultRole_ValidRoles(t *testing.T) {
	// 定義済みの全ロールが有効と判定されるか確認する
	for _, role := range validSSODefaultRoles() {
		if !isValidSSODefaultRole(role) {
			t.Errorf("有効なデフォルトロール %q が無効と判定された", role)
		}
	}
}

// TestIsValidSSODefaultRole_InvalidRoles は無効なデフォルトロールが拒否されることを確認する
func TestIsValidSSODefaultRole_InvalidRoles(t *testing.T) {
	// 定義外のロールは拒否される
	invalidRoles := []string{"superadmin", "root", "ADMIN", "", "user", "operator"}
	for _, role := range invalidRoles {
		if isValidSSODefaultRole(role) {
			t.Errorf("無効なデフォルトロール %q が有効と判定された", role)
		}
	}
}

// TestSSOConfigIsSAML_SAMLProvider は SAML プロバイダーの判定を確認する
func TestSSOConfigIsSAML_SAMLProvider(t *testing.T) {
	// Provider が "saml" の場合は SAML と判定される
	c := &SSOConfig{Provider: "saml"}
	if !ssoConfigIsSAML(c) {
		t.Error("Provider が 'saml' の設定は SAML と判定されるべき")
	}
}

// TestSSOConfigIsSAML_OIDCProvider は OIDC プロバイダーが SAML でないことを確認する
func TestSSOConfigIsSAML_OIDCProvider(t *testing.T) {
	// Provider が "oidc" の場合は SAML でない
	c := &SSOConfig{Provider: "oidc"}
	if ssoConfigIsSAML(c) {
		t.Error("Provider が 'oidc' の設定は SAML と判定されるべきでない")
	}
}

// TestSSOConfigIsOIDC_OIDCProvider は OIDC プロバイダーの判定を確認する
func TestSSOConfigIsOIDC_OIDCProvider(t *testing.T) {
	// Provider が "oidc" の場合は OIDC と判定される
	c := &SSOConfig{Provider: "oidc"}
	if !ssoConfigIsOIDC(c) {
		t.Error("Provider が 'oidc' の設定は OIDC と判定されるべき")
	}
}

// TestSAMLConfigHasRequiredFields_Complete は SAML 必須フィールドが揃っている場合を確認する
func TestSAMLConfigHasRequiredFields_Complete(t *testing.T) {
	// SAML の 4 つの必須フィールドが全て設定されていれば有効
	c := &SSOConfig{
		IDPEntityID:    "http://idp.example.com",
		IDPSSOUrl:      "https://idp.example.com/sso",
		IDPCertificate: "-----BEGIN CERTIFICATE-----\nMIIC...",
		SPEntityID:     "https://sp.example.com/acs",
	}
	if !samlConfigHasRequiredFields(c) {
		t.Error("SAML 必須フィールドが揃っている設定は有効と判定されるべき")
	}
}

// TestSAMLConfigHasRequiredFields_MissingCertificate は IDPCertificate が空の場合を確認する
func TestSAMLConfigHasRequiredFields_MissingCertificate(t *testing.T) {
	// IDPCertificate が空の SAML 設定は無効
	c := &SSOConfig{
		IDPEntityID:    "http://idp.example.com",
		IDPSSOUrl:      "https://idp.example.com/sso",
		IDPCertificate: "",
		SPEntityID:     "https://sp.example.com/acs",
	}
	if samlConfigHasRequiredFields(c) {
		t.Error("IDPCertificate が空の SAML 設定は無効と判定されるべき")
	}
}

// TestOIDCConfigHasRequiredFields_Complete は OIDC 必須フィールドが揃っている場合を確認する
func TestOIDCConfigHasRequiredFields_Complete(t *testing.T) {
	// ClientID と DiscoveryURL が設定されていれば有効
	c := &SSOConfig{
		ClientID:     "client-123",
		DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
	}
	if !oidcConfigHasRequiredFields(c) {
		t.Error("OIDC 必須フィールドが揃っている設定は有効と判定されるべき")
	}
}

// TestOIDCConfigHasRequiredFields_MissingDiscoveryURL は DiscoveryURL が空の場合を確認する
func TestOIDCConfigHasRequiredFields_MissingDiscoveryURL(t *testing.T) {
	// DiscoveryURL が空の OIDC 設定は無効
	c := &SSOConfig{
		ClientID:     "client-123",
		DiscoveryURL: "",
	}
	if oidcConfigHasRequiredFields(c) {
		t.Error("DiscoveryURL が空の OIDC 設定は無効と判定されるべき")
	}
}

// TestIsValidDiscoveryURL_ValidURLs は有効な OIDC ディスカバリー URL を確認する
func TestIsValidDiscoveryURL_ValidURLs(t *testing.T) {
	// .well-known/openid-configuration を含む URL が有効
	validURLs := []string{
		"https://accounts.google.com/.well-known/openid-configuration",
		"https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration",
		"https://company.okta.com/.well-known/openid-configuration",
		"https://auth0.example.com/.well-known/openid-configuration",
	}
	for _, url := range validURLs {
		if !isValidDiscoveryURL(url) {
			t.Errorf("有効なディスカバリー URL %q が無効と判定された", url)
		}
	}
}

// TestIsValidDiscoveryURL_InvalidURLs は無効な OIDC ディスカバリー URL が拒否されることを確認する
func TestIsValidDiscoveryURL_InvalidURLs(t *testing.T) {
	// .well-known/openid-configuration を含まない URL は無効
	invalidURLs := []string{
		"https://accounts.google.com/oauth/token",
		"https://login.microsoftonline.com/tenant",
		"",
		"not-a-url",
		"https://example.com/.well-known/jwks.json",
	}
	for _, url := range invalidURLs {
		if isValidDiscoveryURL(url) {
			t.Errorf("無効なディスカバリー URL %q が有効と判定された", url)
		}
	}
}

// TestFilterEnabledSSOConfigs_FiltersCorrectly は有効な SSO 設定のフィルタリングを確認する
func TestFilterEnabledSSOConfigs_FiltersCorrectly(t *testing.T) {
	// 有効・無効が混在するリストから有効のみ抽出されるか確認する
	configs := []SSOConfig{
		{ID: "sso-1", Provider: "saml", Enabled: true},
		{ID: "sso-2", Provider: "oidc", Enabled: false},
		{ID: "sso-3", Provider: "oidc", Enabled: true},
	}
	enabled := filterEnabledSSOConfigs(configs)
	if len(enabled) != 2 {
		t.Errorf("有効な SSO 設定数 = %d, want 2", len(enabled))
	}
	for _, c := range enabled {
		if !c.Enabled {
			t.Errorf("無効な設定 %q がフィルタ結果に含まれている", c.ID)
		}
	}
}

// TestFilterEnabledSSOConfigs_EmptyInput は空入力が空スライスを返すことを確認する
func TestFilterEnabledSSOConfigs_EmptyInput(t *testing.T) {
	// 空スライス入力は空スライスを返す
	result := filterEnabledSSOConfigs([]SSOConfig{})
	if len(result) != 0 {
		t.Errorf("空入力から空出力のはず: got %d items", len(result))
	}
}

// TestFilterSSOConfigsByProvider_SAMLOnly は SAML プロバイダーのフィルタリングを確認する
func TestFilterSSOConfigsByProvider_SAMLOnly(t *testing.T) {
	// "saml" のみのフィルタリング
	configs := []SSOConfig{
		{ID: "sso-1", Provider: "saml"},
		{ID: "sso-2", Provider: "oidc"},
		{ID: "sso-3", Provider: "saml"},
	}
	samlConfigs := filterSSOConfigsByProvider(configs, "saml")
	if len(samlConfigs) != 2 {
		t.Errorf("SAML 設定数 = %d, want 2", len(samlConfigs))
	}
	for _, c := range samlConfigs {
		if c.Provider != "saml" {
			t.Errorf("フィルタ結果に SAML 以外の設定 %q が含まれている", c.Provider)
		}
	}
}

// TestSSOConfigToPublicProvider_ConvertsCorrectly は SSOConfig から SSOPublicProvider への変換を確認する
func TestSSOConfigToPublicProvider_ConvertsCorrectly(t *testing.T) {
	// ID と Name のみが公開情報として変換される
	c := SSOConfig{
		ID:           "sso-001",
		Name:         "Okta SSO",
		Provider:     "saml",
		ClientSecret: "top-secret-value",
	}
	pub := ssoConfigToPublicProvider(c)
	if pub.ID != "sso-001" {
		t.Errorf("PublicProvider.ID = %q, want \"sso-001\"", pub.ID)
	}
	if pub.Name != "Okta SSO" {
		t.Errorf("PublicProvider.Name = %q, want \"Okta SSO\"", pub.Name)
	}
}

// TestSSOPublicProvider_ZeroValue は SSOPublicProvider のゼロ値を確認する
func TestSSOPublicProvider_ZeroValue(t *testing.T) {
	// ゼロ値は全フィールドが空文字
	var p SSOPublicProvider
	if p.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", p.ID)
	}
	if p.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", p.Name)
	}
}

// TestSSOPublicProvider_FieldAssignment は SSOPublicProvider フィールド代入を確認する
func TestSSOPublicProvider_FieldAssignment(t *testing.T) {
	// ID と Name が正しく設定されるか確認する
	p := SSOPublicProvider{
		ID:   "sso-abc-123",
		Name: "Google Workspace SSO",
	}
	if p.ID != "sso-abc-123" {
		t.Errorf("ID = %q, want \"sso-abc-123\"", p.ID)
	}
	if p.Name != "Google Workspace SSO" {
		t.Errorf("Name = %q, want \"Google Workspace SSO\"", p.Name)
	}
}

// TestSSOConfig_AttributeMappingDefaultJSON はデフォルトの AttributeMapping JSON が有効なことを確認する
func TestSSOConfig_AttributeMappingDefaultJSON(t *testing.T) {
	// デフォルトの属性マッピング JSON が有効かどうかを確認する
	defaultMapping := json.RawMessage(`{"email": "email", "name": "name", "role": "role"}`)
	var m map[string]string
	if err := json.Unmarshal(defaultMapping, &m); err != nil {
		t.Fatalf("デフォルトの AttributeMapping が無効な JSON: %v", err)
	}
	if m["email"] != "email" {
		t.Errorf("AttributeMapping[email] = %q, want \"email\"", m["email"])
	}
	if m["name"] != "name" {
		t.Errorf("AttributeMapping[name] = %q, want \"name\"", m["name"])
	}
	if m["role"] != "role" {
		t.Errorf("AttributeMapping[role] = %q, want \"role\"", m["role"])
	}
}

// TestSSOConfig_TimestampFields は CreatedAt と UpdatedAt が time.Time 型であることを確認する
func TestSSOConfig_TimestampFields(t *testing.T) {
	// タイムスタンプフィールドが time.Time 型として正しく設定されるか確認する
	now := time.Now()
	c := SSOConfig{
		CreatedAt: now,
		UpdatedAt: now,
	}
	if !c.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt が期待値と一致しない")
	}
	if !c.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt が期待値と一致しない")
	}
}

// TestSSOConfigHasRequiredBaseFields_MissingProvider は Provider が空の場合を確認する
func TestSSOConfigHasRequiredBaseFields_MissingProvider(t *testing.T) {
	// Provider が空の SSO 設定は基本フィールドが不完全
	c := &SSOConfig{Provider: "", Name: "My SSO"}
	if ssoConfigHasRequiredBaseFields(c) {
		t.Error("Provider が空の設定は基本フィールド不完全と判定されるべき")
	}
}

// TestSSOConfigHasRequiredBaseFields_MissingName は Name が空の場合を確認する
func TestSSOConfigHasRequiredBaseFields_MissingName(t *testing.T) {
	// Name が空の SSO 設定は基本フィールドが不完全
	c := &SSOConfig{Provider: "saml", Name: ""}
	if ssoConfigHasRequiredBaseFields(c) {
		t.Error("Name が空の設定は基本フィールド不完全と判定されるべき")
	}
}
