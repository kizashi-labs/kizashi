// Package notification provides push notification via Expo Push API.
package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const expoPushURL = "https://exp.host/--/api/v2/push/send"

type ExpoPushMessage struct {
	To       string `json:"to"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	Data     any    `json:"data,omitempty"`
	Sound    string `json:"sound,omitempty"`
	Priority string `json:"priority,omitempty"` // "default"|"normal"|"high"
	Badge    int    `json:"badge,omitempty"`
}

type ExpoClient struct {
	httpClient *http.Client
}

func NewExpoClient() *ExpoClient {
	return &ExpoClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *ExpoClient) Send(ctx context.Context, messages []ExpoPushMessage) error {
	body, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("marshal push messages: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, expoPushURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send push: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expo push API returned %d", resp.StatusCode)
	}
	return nil
}
