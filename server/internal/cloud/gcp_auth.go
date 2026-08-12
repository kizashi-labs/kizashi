package cloud

// GCP サービスアカウント JWT 認証実装（外部SDKなし、stdlib のみ）

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// gcpServiceAccount はサービスアカウントJSONの構造です。
type gcpServiceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// gcpTokenResponse は GCP OAuth2 トークンエンドポイントのレスポンス形式です。
type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// gcpGetToken はサービスアカウントJSONからOAuth2アクセストークンを取得します。
// scope: "https://www.googleapis.com/auth/logging.read"
func gcpGetToken(httpClient *http.Client, serviceAccountJSON string, scope string) (string, error) {
	// 1. サービスアカウントJSONをパース
	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(serviceAccountJSON), &sa); err != nil {
		return "", fmt.Errorf("サービスアカウントJSONのパース失敗: %w", err)
	}

	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", fmt.Errorf("サービスアカウントJSONにclient_emailまたはprivate_keyがありません")
	}

	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	// 2. JWTヘッダー+ペイロードを作成 (RS256)
	now := time.Now().Unix()

	headerMap := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(headerMap)
	if err != nil {
		return "", fmt.Errorf("JWTヘッダーのシリアライズ失敗: %w", err)
	}

	payloadMap := map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": scope,
		"aud":   tokenURI,
		"exp":   now + 3600,
		"iat":   now,
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return "", fmt.Errorf("JWTペイロードのシリアライズ失敗: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// 3. RSA秘密鍵をパース
	privateKey, err := parseRSAPrivateKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("RSA秘密鍵のパース失敗: %w", err)
	}

	// 4. JWTを署名
	jwt, err := signJWT(headerEncoded, payloadEncoded, privateKey)
	if err != nil {
		return "", fmt.Errorf("JWT署名失敗: %w", err)
	}

	// 5. POSTしてaccess_tokenを返す
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("GCPトークンリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GCPトークンエンドポイント呼び出し失敗: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("GCPトークンレスポンス読み取り失敗: %w", err)
	}

	var tokenResp gcpTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("GCPトークンレスポンスのパース失敗: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("GCP認証エラー: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("GCPトークンが空 (HTTP %d)", resp.StatusCode)
	}

	return tokenResp.AccessToken, nil
}

// parseRSAPrivateKey はPEM形式の文字列からRSA秘密鍵をパースします。
// PKCS#8 (BEGIN PRIVATE KEY) と PKCS#1 (BEGIN RSA PRIVATE KEY) の両形式に対応します。
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	// GCPのサービスアカウントキーは \n がリテラルで埋め込まれている場合がある
	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("PEMブロックのデコード失敗: 有効なPEMデータが見つかりません")
	}

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8秘密鍵のパース失敗: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("秘密鍵がRSA形式ではありません")
		}
		return rsaKey, nil
	case "RSA PRIVATE KEY":
		// PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1秘密鍵のパース失敗: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("未知のPEMブロックタイプ: %s", block.Type)
	}
}

// signJWT はbase64urlエンコード済みのヘッダーとペイロードをRS256で署名し、
// {header}.{payload}.{signature} 形式のJWT文字列を返します。
func signJWT(header, payload string, key *rsa.PrivateKey) (string, error) {
	signingInput := header + "." + payload

	hash := sha256.New()
	hash.Write([]byte(signingInput))
	digest := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return "", fmt.Errorf("RSA-SHA256署名失敗: %w", err)
	}

	sigEncoded := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + sigEncoded, nil
}
