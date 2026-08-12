package cloud

// Azure OAuth2 client_credentials フロー実装（外部SDKなし、stdlib のみ）

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// azureTokenResponse は Azure AD トークンエンドポイントのレスポンス形式です。
type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// azureGetToken は client_credentials フローで Azure AD からアクセストークンを取得します。
// tenantID: Azure AD テナント ID
// clientID, clientSecret: サービスプリンシパル認証情報
// resource: "https://management.azure.com/"
func azureGetToken(client *http.Client, tenantID, clientID, clientSecret, resource string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("resource", resource)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("azureトークンリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("azureトークンエンドポイント呼び出し失敗: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("azureトークンレスポンス読み取り失敗: %w", err)
	}

	var tokenResp azureTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("azureトークンレスポンスのパース失敗: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("azure認証エラー: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("azureトークンが空 (HTTP %d)", resp.StatusCode)
	}

	return tokenResp.AccessToken, nil
}
