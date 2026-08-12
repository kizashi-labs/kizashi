package cloud

// AWS SigV4 署名ユーティリティ（外部SDKなし、stdlib のみ）
// 用途: CloudTrail LookupEvents API 呼び出し

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// sigV4Sign はリクエストに AWS SigV4 署名ヘッダーを付与します。
func sigV4Sign(req *http.Request, body []byte, service, region, accessKey, secretKey string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// x-amz-date ヘッダーを設定
	req.Header.Set("x-amz-date", amzDate)

	// ボディの SHA256 ハッシュ
	bodyHash := sha256Hex(body)
	req.Header.Set("x-amz-content-sha256", bodyHash)

	// ---- Step 1: Canonical Request ----
	// HTTPメソッド
	method := req.Method

	// Canonical URI（パス部分）
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical Query String
	queryParams := req.URL.Query()
	queryKeys := make([]string, 0, len(queryParams))
	for k := range queryParams {
		queryKeys = append(queryKeys, k)
	}
	sort.Strings(queryKeys)
	queryParts := make([]string, 0, len(queryKeys))
	for _, k := range queryKeys {
		vals := queryParams[k]
		sort.Strings(vals)
		for _, v := range vals {
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", uriEncode(k), uriEncode(v)))
		}
	}
	canonicalQueryString := strings.Join(queryParts, "&")

	// Canonical Headers（小文字化してソート）
	headerNames := make([]string, 0)
	for k := range req.Header {
		headerNames = append(headerNames, strings.ToLower(k))
	}
	// Host ヘッダーを追加
	headerNames = append(headerNames, "host")
	sort.Strings(headerNames)
	// 重複除去
	seen := make(map[string]bool)
	dedupedHeaders := make([]string, 0)
	for _, h := range headerNames {
		if !seen[h] {
			seen[h] = true
			dedupedHeaders = append(dedupedHeaders, h)
		}
	}
	headerNames = dedupedHeaders

	canonicalHeaderParts := make([]string, 0, len(headerNames))
	for _, h := range headerNames {
		var val string
		if h == "host" {
			val = req.Host
			if val == "" {
				val = req.URL.Host
			}
		} else {
			// http.Header のキーは正規化されているので変換
			canonicalKey := http.CanonicalHeaderKey(h)
			val = strings.Join(req.Header[canonicalKey], ",")
		}
		canonicalHeaderParts = append(canonicalHeaderParts, h+":"+strings.TrimSpace(val))
	}
	canonicalHeaders := strings.Join(canonicalHeaderParts, "\n") + "\n"
	signedHeaders := strings.Join(headerNames, ";")

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	// ---- Step 2: String to Sign ----
	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// ---- Step 3: Signing Key ----
	sigKey := signingKey(secretKey, dateStamp, region, service)

	// ---- Step 4: Signature ----
	signature := hex.EncodeToString(hmacSHA256(sigKey, stringToSign))

	// ---- Step 5: Authorization Header ----
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authHeader)
}

// hmacSHA256 は HMAC-SHA256 を計算して返します。
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// sha256Hex はバイト列の SHA256 ハッシュを16進数文字列で返します。
func sha256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// signingKey は SigV4 署名キーを導出して返します。
func signingKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// uriEncode はクエリパラメータ値を RFC 3986 に従ってパーセントエンコードします。
// ただし予約文字はエンコードしません（AWS SigV4 の要件）。
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// isUnreserved は RFC 3986 の非予約文字かどうかを返します。
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '~'
}
