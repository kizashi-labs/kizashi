// Package sandbox — dynamic.go: dynamic (detonation) sandbox orchestration.
//
// A dynamic sandbox executes a sample in an isolated VM and reports its runtime
// behaviour. Standing up disposable-VM detonation infrastructure is heavy and
// dangerous to run beside production, so — like most EDRs — this integrates with an
// EXTERNAL sandbox rather than detonating in-process. It speaks the CAPE/Cuckoo
// REST API (the common self-hostable open sandbox; VMRay/Triage are similar) via a
// configurable base URL, so operators point it at their own detonation backend.
// Degrades gracefully: with no SANDBOX_URL configured it is inert and callers fall
// back to the local static analyzer (static.go).
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

// DynamicReport is the normalized result of a detonation.
type DynamicReport struct {
	JobID      string   `json:"job_id"`
	Status     string   `json:"status"`  // pending | running | completed | error
	Verdict    string   `json:"verdict"` // malicious | suspicious | clean | unknown
	Score      float64  `json:"score"`   // 0-10 (CAPE/Cuckoo scale)
	Signatures []string `json:"signatures"`
}

// DynamicClient orchestrates submissions to an external CAPE/Cuckoo-compatible
// sandbox. Construct with NewDynamicClient.
type DynamicClient struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

// NewDynamicClient reads SANDBOX_URL / SANDBOX_API_KEY from the environment. With
// no SANDBOX_URL the client is inert (Configured() == false).
func NewDynamicClient() *DynamicClient {
	return &DynamicClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: os.Getenv("SANDBOX_URL"),
		apiKey:  os.Getenv("SANDBOX_API_KEY"),
	}
}

// Configured reports whether an external sandbox backend is set.
func (c *DynamicClient) Configured() bool { return c.baseURL != "" }

func (c *DynamicClient) auth(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Token "+c.apiKey)
	}
}

// Submit uploads a file for detonation and returns the backend job/task id.
// CAPE/Cuckoo: POST {base}/tasks/create/file (multipart "file") → {"task_id": N}.
func (c *DynamicClient) Submit(ctx context.Context, name string, data []byte) (string, error) {
	if !c.Configured() {
		return "", fmt.Errorf("dynamic sandbox not configured")
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(data); err != nil {
		return "", err
	}
	_ = mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/tasks/create/file", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("sandbox submit returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		TaskID json.Number `json:"task_id"`
		ID     json.Number `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	id := out.TaskID.String()
	if id == "" || id == "0" {
		id = out.ID.String()
	}
	if id == "" || id == "0" {
		return "", fmt.Errorf("sandbox submit returned no task id")
	}
	return id, nil
}

// Report fetches and normalizes the detonation report for jobID.
// CAPE/Cuckoo: GET {base}/tasks/report/{id} → {"info":{"score":X},"signatures":[...]}.
func (c *DynamicClient) Report(ctx context.Context, jobID string) (DynamicReport, error) {
	r := DynamicReport{JobID: jobID, Status: "pending", Verdict: "unknown"}
	if !c.Configured() {
		return r, fmt.Errorf("dynamic sandbox not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/tasks/report/"+jobID, nil)
	if err != nil {
		return r, err
	}
	c.auth(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return r, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		// completed — parse below
	case http.StatusAccepted, http.StatusNoContent:
		r.Status = "running"
		return r, nil
	case http.StatusNotFound:
		r.Status = "running" // not ready yet
		return r, nil
	default:
		r.Status = "error"
		return r, fmt.Errorf("sandbox report returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Info struct {
			Score float64 `json:"score"`
		} `json:"info"`
		Signatures []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"signatures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return r, err
	}
	r.Status = "completed"
	r.Score = body.Info.Score
	for _, s := range body.Signatures {
		name := s.Name
		if name == "" {
			name = s.Description
		}
		if name != "" {
			r.Signatures = append(r.Signatures, name)
		}
	}
	r.Verdict = verdictForDynamicScore(body.Info.Score)
	return r, nil
}

// verdictForDynamicScore maps the CAPE/Cuckoo 0-10 score to a verdict.
func verdictForDynamicScore(score float64) string {
	switch {
	case score >= 6:
		return "malicious"
	case score >= 3:
		return "suspicious"
	case score > 0:
		return "clean"
	default:
		return "unknown"
	}
}
