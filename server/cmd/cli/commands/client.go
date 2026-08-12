package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

func apiGet(path string, out interface{}) error {
	return apiRequest("GET", path, nil, out)
}

func apiPost(path string, body interface{}, out interface{}) error {
	return apiRequest("POST", path, body, out)
}

func apiPatch(path string, body interface{}, out interface{}) error {
	return apiRequest("PATCH", path, body, out)
}

func apiDelete(path string) error {
	return apiRequest("DELETE", path, nil, nil)
}

func apiRequest(method, path string, body interface{}, out interface{}) error {
	url := baseURL() + path

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("リクエストのシリアライズに失敗しました: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("リクエストの作成に失敗しました: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if tok := authToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("APIリクエストに失敗しました: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("レスポンスの読み取りに失敗しました: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("APIエラー (%d): %s", resp.StatusCode, msg)
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("レスポンスのパースに失敗しました: %w", err)
		}
	}
	return nil
}
