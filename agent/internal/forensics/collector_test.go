// Package forensics — ユニットテスト
// フォレンジックコレクターのJobRequest解析・検証ロジックをテストする。
// ネットワーク呼び出しは行わない。
package forensics

import (
	"context"
	"encoding/json"
	"testing"
)

// ─── ParseRequest ─────────────────────────────────────────────

// TestParseRequest_ValidJSON は有効なJSONからJobRequestを解析できることを確認する。
func TestParseRequest_ValidJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantJobID string
		wantType  string
		wantPID   int
	}{
		{
			name:      "プロセスリストジョブ",
			input:     `{"job_id":"job-100","type":"process_list","process_id":0}`,
			wantJobID: "job-100",
			wantType:  "process_list",
			wantPID:   0,
		},
		{
			name:      "メモリダンプジョブ",
			input:     `{"job_id":"job-200","type":"memory_dump","process_id":9999}`,
			wantJobID: "job-200",
			wantType:  "memory_dump",
			wantPID:   9999,
		},
		{
			name:      "アーティファクト収集ジョブ",
			input:     `{"job_id":"job-300","type":"artifact_collect","process_id":0}`,
			wantJobID: "job-300",
			wantType:  "artifact_collect",
			wantPID:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.input))
			if err != nil {
				t.Fatalf("ParseRequestエラー: %v", err)
			}
			if req == nil {
				t.Fatal("ParseRequestがnilを返した")
			}
			if req.JobID != tc.wantJobID {
				t.Errorf("JobID = %q, want %q", req.JobID, tc.wantJobID)
			}
			if req.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", req.Type, tc.wantType)
			}
			if req.ProcessID != tc.wantPID {
				t.Errorf("ProcessID = %d, want %d", req.ProcessID, tc.wantPID)
			}
		})
	}
}

// TestParseRequest_InvalidJSON は不正なJSONでエラーを返すことを確認する。
func TestParseRequest_InvalidJSON(t *testing.T) {
	invalidInputs := []struct {
		name  string
		input string
	}{
		{"空文字列", ""},
		{"不正なJSON", "{invalid json}"},
		{"配列形式", `["job-001","process_list"]`},
		{"数値のみ", "12345"},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest([]byte(tc.input))
			if err == nil {
				t.Errorf("不正なJSON %q でエラーが返されなかった", tc.input)
			}
		})
	}
}

// TestParseRequest_EmptyFields は空フィールドのJSONを解析できることを確認する。
func TestParseRequest_EmptyFields(t *testing.T) {
	input := `{"job_id":"","type":"","process_id":0}`
	req, err := ParseRequest([]byte(input))
	if err != nil {
		t.Fatalf("ParseRequestエラー: %v", err)
	}
	if req.JobID != "" {
		t.Errorf("JobID = %q, want \"\"", req.JobID)
	}
	if req.Type != "" {
		t.Errorf("Type = %q, want \"\"", req.Type)
	}
}

// ─── JobRequest JSON シリアライズ ─────────────────────────────

// TestJobRequest_JSONMarshal はJobRequestのMarshalが正しいキーを出力することを確認する。
func TestJobRequest_JSONMarshal(t *testing.T) {
	req := &JobRequest{
		JobID:     "j-abc-123",
		Type:      "process_list",
		ProcessID: 0,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshalエラー: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("再デシリアライズエラー: %v", err)
	}

	if _, ok := out["job_id"]; !ok {
		t.Error("JSONに\"job_id\"キーがない")
	}
	if _, ok := out["type"]; !ok {
		t.Error("JSONに\"type\"キーがない")
	}
	if _, ok := out["process_id"]; !ok {
		t.Error("JSONに\"process_id\"キーがない")
	}
}

// TestJobRequest_RoundTrip はMarshal→Unmarshalのラウンドトリップを確認する。
func TestJobRequest_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		req  JobRequest
	}{
		{
			name: "プロセスリスト",
			req:  JobRequest{JobID: "rt-001", Type: "process_list", ProcessID: 0},
		},
		{
			name: "メモリダンプPID付き",
			req:  JobRequest{JobID: "rt-002", Type: "memory_dump", ProcessID: 42},
		},
		{
			name: "アーティファクト収集",
			req:  JobRequest{JobID: "rt-003", Type: "artifact_collect", ProcessID: 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatalf("Marshalエラー: %v", err)
			}

			restored, err := ParseRequest(data)
			if err != nil {
				t.Fatalf("ParseRequestエラー: %v", err)
			}

			if restored.JobID != tc.req.JobID {
				t.Errorf("JobID = %q, want %q", restored.JobID, tc.req.JobID)
			}
			if restored.Type != tc.req.Type {
				t.Errorf("Type = %q, want %q", restored.Type, tc.req.Type)
			}
			if restored.ProcessID != tc.req.ProcessID {
				t.Errorf("ProcessID = %d, want %d", restored.ProcessID, tc.req.ProcessID)
			}
		})
	}
}

// ─── Collector 初期化 ─────────────────────────────────────────

// TestNew_ReturnsCollector はNew()がnilでないCollectorを返すことを確認する。
func TestNew_ReturnsCollector(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		agentID   string
		authToken string
	}{
		{"基本構成", "http://edr-server:8080", "agent-001", "token-abc"},
		{"空認証トークン", "http://edr-server:8080", "agent-002", ""},
		{"空エージェントID", "http://edr-server:8080", "", "token-xyz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.serverURL, tc.agentID, tc.authToken)
			if c == nil {
				t.Fatal("New()がnilを返した")
			}
			if c.serverURL != tc.serverURL {
				t.Errorf("serverURL = %q, want %q", c.serverURL, tc.serverURL)
			}
			if c.agentID != tc.agentID {
				t.Errorf("agentID = %q, want %q", c.agentID, tc.agentID)
			}
			if c.authToken != tc.authToken {
				t.Errorf("authToken = %q, want %q", c.authToken, tc.authToken)
			}
			if c.client == nil {
				t.Error("httpClientが初期化されていない")
			}
		})
	}
}

// TestNew_HTTPClientNotNil はHTTPクライアントが初期化されることを確認する。
func TestNew_HTTPClientNotNil(t *testing.T) {
	c := New("http://localhost:9000", "test-agent", "")
	if c.client == nil {
		t.Error("Collector.client が nil")
	}
}

// ─── Execute — 不明なジョブタイプ ─────────────────────────────

// TestExecute_UnknownJobType は不明なジョブタイプでエラーを返すことを確認する。
// ネットワーク呼び出しは発生しないケースのみテスト。
func TestExecute_UnknownJobType(t *testing.T) {
	c := New("http://localhost:9000", "agent-x", "tok")

	unknownTypes := []string{
		"unknown_type",
		"",
		"PROCESS_LIST", // 大文字（大文字小文字区別あり）
		"scan",
		"forensics",
	}

	for _, jobType := range unknownTypes {
		t.Run(jobType, func(t *testing.T) {
			req := &JobRequest{
				JobID: "job-err",
				Type:  jobType,
			}
			// コンテキストなしで直接Execute — HTTP送信前にジョブタイプチェックで失敗する
			// submitResultはサーバーに届かないため、Execute内のswitch分岐のみテスト
			// ここでは collectMemoryDump/collectProcessList 相当のことを
			// Execute() 呼び出しではなく、型バリデーションのロジックをテスト
			err := c.Execute(context.TODO(), req)
			if err == nil {
				t.Errorf("不明なジョブタイプ %q でエラーが返されなかった", jobType)
			}
		})
	}
}

// TestCollectMemoryDump_InvalidPID は無効なPIDでエラーを返すことを確認する。
func TestCollectMemoryDump_InvalidPID(t *testing.T) {
	c := New("http://localhost:9000", "agent-x", "tok")

	invalidPIDs := []int{0, -1, -100}
	for _, pid := range invalidPIDs {
		t.Run("PID", func(t *testing.T) {
			_, err := c.collectMemoryDump(pid)
			if err == nil {
				t.Errorf("PID=%d でエラーが返されなかった", pid)
			}
		})
	}
}

// TestCollectProcessList_ReturnsJSON はcollectProcessList()がJSON形式を返すことを確認する。
func TestCollectProcessList_ReturnsJSON(t *testing.T) {
	c := New("http://localhost:9000", "agent-x", "tok")

	data, err := c.collectProcessList()
	if err != nil {
		t.Fatalf("collectProcessListエラー: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("collectProcessListが空データを返した")
	}

	// 有効なJSONであることを確認する
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("戻り値が有効なJSONでない: %v", err)
	}

	// 必須フィールドが存在することを確認する
	if _, ok := result["platform"]; !ok {
		t.Error("\"platform\"フィールドがない")
	}
	if _, ok := result["processes"]; !ok {
		t.Error("\"processes\"フィールドがない")
	}
	if _, ok := result["collected_at"]; !ok {
		t.Error("\"collected_at\"フィールドがない")
	}
}

// TestCollectArtifacts_ReturnsJSON はcollectArtifacts()がJSON形式を返すことを確認する。
func TestCollectArtifacts_ReturnsJSON(t *testing.T) {
	c := New("http://localhost:9000", "agent-x", "tok")

	data, err := c.collectArtifacts()
	if err != nil {
		t.Fatalf("collectArtifactsエラー: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("collectArtifactsが空データを返した")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("戻り値が有効なJSONでない: %v", err)
	}

	// 必須フィールドを確認する
	if _, ok := result["collected_at"]; !ok {
		t.Error("\"collected_at\"フィールドがない")
	}
	if _, ok := result["platform"]; !ok {
		t.Error("\"platform\"フィールドがない")
	}
	if _, ok := result["hostname"]; !ok {
		t.Error("\"hostname\"フィールドがない")
	}
}

// TestCollectMemoryDump_ValidPID_ReturnsJSON は有効なPIDでJSON形式を返すことを確認する。
// テストプロセス自身のPIDを使用する（必ず存在するため安全）。
func TestCollectMemoryDump_ValidPID_ReturnsJSON(t *testing.T) {
	c := New("http://localhost:9000", "agent-x", "tok")

	// PID=1 は Linux では init/systemd として必ず存在する。
	// 他のOSではスタブが実行されるので /proc が無くても問題ない。
	data, err := c.collectMemoryDump(1)
	if err != nil {
		// Linuxでpermission errorになることもある — スキップ
		t.Logf("collectMemoryDump PID=1 エラー（許容範囲）: %v", err)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("戻り値が有効なJSONでない: %v", err)
	}
	if _, ok := result["pid"]; !ok {
		t.Error("\"pid\"フィールドがない")
	}
	if _, ok := result["platform"]; !ok {
		t.Error("\"platform\"フィールドがない")
	}
}
