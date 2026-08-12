// Package transport — ユニットテスト
// ネットワーク接続不要の純粋関数・構造体のみをテストする。
package transport

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ─── extractHost ──────────────────────────────────────────────

// TestExtractHost はURLからホスト名を正しく抽出することを確認する。
func TestExtractHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"HTTPスキーム付きURL", "http://example.com:8080/path", "example.com"},
		{"HTTPSスキーム付きURL", "https://server.edr.local:443/api", "server.edr.local"},
		{"スキームなしURL", "server.edr.local:9000", "server.edr.local"},
		{"パスなしURL", "http://10.0.0.1:4317", "10.0.0.1"},
		{"ポートなしURL", "http://server.local/", "server.local"},
		{"IPアドレスのみ", "10.1.2.3", "10.1.2.3"},
		{"grpcスキーム", "grpc://edr-server:50051", "edr-server"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHost(tc.input)
			if got != tc.want {
				t.Errorf("extractHost(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── exponentialBackoff ───────────────────────────────────────

// TestExponentialBackoff_FirstAttempt は最初の試行でmin値を返すことを確認する。
func TestExponentialBackoff_FirstAttempt(t *testing.T) {
	b := &exponentialBackoff{min: 5 * time.Second, max: 5 * time.Minute}
	got := b.Next()
	if got != 5*time.Second {
		t.Errorf("初回バックオフ = %v, want 5s", got)
	}
}

// TestExponentialBackoff_Increases は試行ごとに待機時間が増加することを確認する。
func TestExponentialBackoff_Increases(t *testing.T) {
	b := &exponentialBackoff{min: 1 * time.Second, max: 10 * time.Minute}
	prev := b.Next()
	for i := 0; i < 5; i++ {
		cur := b.Next()
		if cur < prev {
			t.Errorf("試行%d: バックオフが減少した: prev=%v, cur=%v", i+1, prev, cur)
		}
		prev = cur
	}
}

// TestExponentialBackoff_CapsAtMax はmax値を超えないことを確認する。
func TestExponentialBackoff_CapsAtMax(t *testing.T) {
	b := &exponentialBackoff{min: 1 * time.Second, max: 30 * time.Second}
	for i := 0; i < 20; i++ {
		got := b.Next()
		if got > 30*time.Second {
			t.Errorf("試行%d: バックオフ=%v がmax(30s)を超えた", i, got)
		}
	}
}

// TestExponentialBackoff_Reset はリセット後に初期値に戻ることを確認する。
func TestExponentialBackoff_Reset(t *testing.T) {
	b := &exponentialBackoff{min: 5 * time.Second, max: 5 * time.Minute}
	// 数回試行して状態を進める
	b.Next()
	b.Next()
	b.Next()

	b.Reset()
	got := b.Next()
	if got != 5*time.Second {
		t.Errorf("リセット後の初回バックオフ = %v, want 5s", got)
	}
}

// TestExponentialBackoff_Formula は2の冪乗の計算式に従うことを確認する。
func TestExponentialBackoff_Formula(t *testing.T) {
	min := 2 * time.Second
	b := &exponentialBackoff{min: min, max: 10 * time.Minute}

	for attempt := 0; attempt < 4; attempt++ {
		got := b.Next()
		expected := time.Duration(float64(min) * math.Pow(2, float64(attempt)))
		if got != expected {
			t.Errorf("試行%d: got=%v, want=%v", attempt, got, expected)
		}
	}
}

// ─── ForensicsJobPayload JSON デシリアライズ ──────────────────

// TestForensicsJobPayload_Unmarshal はJSONデシリアライズが正しく動作することを確認する。
func TestForensicsJobPayload_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantType    string
		wantJobID   string
		wantJobType string
		wantPID     int
	}{
		{
			name:        "プロセスリストジョブ",
			json:        `{"type":"forensics_job","job_id":"job-001","job_type":"process_list","process_id":0}`,
			wantType:    "forensics_job",
			wantJobID:   "job-001",
			wantJobType: "process_list",
			wantPID:     0,
		},
		{
			name:        "メモリダンプジョブ",
			json:        `{"type":"forensics_job","job_id":"job-002","job_type":"memory_dump","process_id":1234}`,
			wantType:    "forensics_job",
			wantJobID:   "job-002",
			wantJobType: "memory_dump",
			wantPID:     1234,
		},
		{
			name:        "アーティファクト収集ジョブ",
			json:        `{"type":"forensics_job","job_id":"job-003","job_type":"artifact_collect","process_id":0}`,
			wantType:    "forensics_job",
			wantJobID:   "job-003",
			wantJobType: "artifact_collect",
			wantPID:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p ForensicsJobPayload
			if err := json.Unmarshal([]byte(tc.json), &p); err != nil {
				t.Fatalf("Unmarshalエラー: %v", err)
			}
			if p.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", p.Type, tc.wantType)
			}
			if p.JobID != tc.wantJobID {
				t.Errorf("JobID = %q, want %q", p.JobID, tc.wantJobID)
			}
			if p.JobType != tc.wantJobType {
				t.Errorf("JobType = %q, want %q", p.JobType, tc.wantJobType)
			}
			if p.ProcessID != tc.wantPID {
				t.Errorf("ProcessID = %d, want %d", p.ProcessID, tc.wantPID)
			}
		})
	}
}

// TestForensicsJobPayload_Marshal はシリアライズが期待フィールドを含むことを確認する。
func TestForensicsJobPayload_Marshal(t *testing.T) {
	p := ForensicsJobPayload{
		Type:      "forensics_job",
		JobID:     "test-job-99",
		JobType:   "process_list",
		ProcessID: 0,
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshalエラー: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("再デシリアライズエラー: %v", err)
	}
	if out["type"] != "forensics_job" {
		t.Errorf("typeフィールド = %v, want \"forensics_job\"", out["type"])
	}
	if out["job_id"] != "test-job-99" {
		t.Errorf("job_idフィールド = %v, want \"test-job-99\"", out["job_id"])
	}
}

// ─── CommandType 定数 ─────────────────────────────────────────

// TestCommandType_Values はコマンドタイプ定数が正しい順序で定義されていることを確認する。
func TestCommandType_Values(t *testing.T) {
	// iotaによる順序を確認する
	if CmdReloadConfig != 0 {
		t.Errorf("CmdReloadConfig = %d, want 0", CmdReloadConfig)
	}
	if CmdIsolate != 1 {
		t.Errorf("CmdIsolate = %d, want 1", CmdIsolate)
	}
	if CmdUnisolate != 2 {
		t.Errorf("CmdUnisolate = %d, want 2", CmdUnisolate)
	}
	if CmdKillProcess != 3 {
		t.Errorf("CmdKillProcess = %d, want 3", CmdKillProcess)
	}
	if CmdQuarantineFile != 4 {
		t.Errorf("CmdQuarantineFile = %d, want 4", CmdQuarantineFile)
	}
}

// TestCommandType_RestoreAndScan は後続コマンド定数の連続性を確認する。
func TestCommandType_RestoreAndScan(t *testing.T) {
	if CmdRestoreFile != 5 {
		t.Errorf("CmdRestoreFile = %d, want 5", CmdRestoreFile)
	}
	if CmdCollectArtifact != 6 {
		t.Errorf("CmdCollectArtifact = %d, want 6", CmdCollectArtifact)
	}
	if CmdScan != 7 {
		t.Errorf("CmdScan = %d, want 7", CmdScan)
	}
	if CmdUpdateAgent != 8 {
		t.Errorf("CmdUpdateAgent = %d, want 8", CmdUpdateAgent)
	}
	if CmdLiveResponseStart != 9 {
		t.Errorf("CmdLiveResponseStart = %d, want 9", CmdLiveResponseStart)
	}
	if CmdForensicsJob != 10 {
		t.Errorf("CmdForensicsJob = %d, want 10", CmdForensicsJob)
	}
}

// ─── RingBuffer — サイズ計算 ──────────────────────────────────

// TestRingBuffer_WriteAndLen は書き込み後にLen()が正しい値を返すことを確認する。
func TestRingBuffer_WriteAndLen(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 10)
	if err != nil {
		t.Fatalf("NewRingBuffer失敗: %v", err)
	}

	if rb.Len() != 0 {
		t.Errorf("初期Len = %d, want 0", rb.Len())
	}

	// 3件書き込む
	for i := 0; i < 3; i++ {
		if err := rb.Write(mustJSON(map[string]int{"i": i})); err != nil {
			t.Fatalf("Write失敗: %v", err)
		}
	}

	if rb.Len() != 3 {
		t.Errorf("3件書き込み後のLen = %d, want 3", rb.Len())
	}
}

// TestRingBuffer_ReadBatch はReadBatch()がデータを返すことを確認する。
func TestRingBuffer_ReadBatch(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 10)
	if err != nil {
		t.Fatalf("NewRingBuffer失敗: %v", err)
	}

	type testItem struct {
		Value string `json:"value"`
	}
	rb.Write(mustJSON(testItem{Value: "first"}))
	rb.Write(mustJSON(testItem{Value: "second"}))

	batch, err := rb.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch失敗: %v", err)
	}
	if len(batch) != 2 {
		t.Errorf("ReadBatchの件数 = %d, want 2", len(batch))
	}
}

// TestRingBuffer_AckReducesLen はAck後にLenが減ることを確認する。
func TestRingBuffer_AckReducesLen(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 10)
	if err != nil {
		t.Fatalf("NewRingBuffer失敗: %v", err)
	}

	rb.Write([]byte("event-a"))
	rb.Write([]byte("event-b"))
	rb.Write([]byte("event-c"))

	rb.Ack(2)
	if rb.Len() != 1 {
		t.Errorf("2件Ack後のLen = %d, want 1", rb.Len())
	}
}

// TestRingBuffer_EncryptedRoundTrip は暗号化リングバッファの読み書きを確認する。
func TestRingBuffer_EncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	rb, err := NewEncryptedRingBuffer(dir, 10, key)
	if err != nil {
		t.Fatalf("NewEncryptedRingBuffer失敗: %v", err)
	}

	type payload struct {
		Secret string `json:"secret"`
	}
	if err := rb.Write(mustJSON(payload{Secret: "classified-data"})); err != nil {
		t.Fatalf("Write失敗: %v", err)
	}

	batch, err := rb.ReadBatch(1)
	if err != nil {
		t.Fatalf("ReadBatch失敗: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("ReadBatchの件数 = %d, want 1", len(batch))
	}

	var result payload
	if err := json.Unmarshal(batch[0], &result); err != nil {
		t.Fatalf("Unmarshal失敗: %v", err)
	}
	if result.Secret != "classified-data" {
		t.Errorf("複号化後のSecret = %q, want \"classified-data\"", result.Secret)
	}
}

// TestNewEncryptedRingBuffer_WrongKeyLength は不正な鍵長でエラーを返すことを確認する。
func TestNewEncryptedRingBuffer_WrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name   string
		keyLen int
	}{
		{"16バイト鍵（不正）", 16},
		{"0バイト鍵（不正）", 0},
		{"31バイト鍵（不正）", 31},
		{"33バイト鍵（不正）", 33},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			_, err := NewEncryptedRingBuffer(dir, 10, key)
			if err == nil {
				t.Errorf("keyLen=%dでエラーが返されなかった", tc.keyLen)
			}
		})
	}
}

// ─── AES-256-GCM ヘルパー ─────────────────────────────────────

// TestEncryptDecryptGCM はAES-GCM暗号化・復号のラウンドトリップを確認する。
func TestEncryptDecryptGCM(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"空文字列", ""},
		{"短い文字列", "hello"},
		{"JSON形式", `{"event":"process_create","pid":1234}`},
		{"日本語テキスト", "テストデータ：セキュリティイベント"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := encryptGCM(key, []byte(tc.plaintext))
			if err != nil {
				t.Fatalf("encryptGCM失敗: %v", err)
			}

			pt, err := decryptGCM(key, ct)
			if err != nil {
				t.Fatalf("decryptGCM失敗: %v", err)
			}

			if string(pt) != tc.plaintext {
				t.Errorf("復号後テキスト = %q, want %q", string(pt), tc.plaintext)
			}
		})
	}
}

// TestDecryptGCM_TamperedData は改ざんされたデータでエラーを返すことを確認する。
func TestDecryptGCM_TamperedData(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}

	ct, err := encryptGCM(key, []byte("sensitive event data"))
	if err != nil {
		t.Fatalf("encryptGCM失敗: %v", err)
	}

	// 暗号文を改ざんする
	if len(ct) > 15 {
		ct[15] ^= 0xFF
	}

	_, err = decryptGCM(key, ct)
	if err == nil {
		t.Error("改ざんされた暗号文でエラーが返されなかった")
	}
}

// TestDecryptGCM_ShortCiphertext は短すぎる暗号文でエラーを返すことを確認する。
func TestDecryptGCM_ShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptGCM(key, []byte("tooshort"))
	if err == nil {
		t.Error("短い暗号文でエラーが返されなかった")
	}
}

// ─── Metrics ─────────────────────────────────────────────────

// TestRingBuffer_Metrics はMetrics()が正しい統計情報を返すことを確認する。
func TestRingBuffer_Metrics(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 10)
	if err != nil {
		t.Fatalf("NewRingBuffer失敗: %v", err)
	}

	before := time.Now()
	m := rb.Metrics()
	after := time.Now()

	if m.Buffered != 0 {
		t.Errorf("初期Buffered = %d, want 0", m.Buffered)
	}
	if m.Timestamp.Before(before) || m.Timestamp.After(after) {
		t.Errorf("Timestamp %v は%vから%vの間にない", m.Timestamp, before, after)
	}
}

// TestRingBuffer_MetricsAfterWrite は書き込み後のMetrics()を確認する。
func TestRingBuffer_MetricsAfterWrite(t *testing.T) {
	dir := t.TempDir()
	rb, err := NewRingBuffer(dir, 10)
	if err != nil {
		t.Fatalf("NewRingBuffer失敗: %v", err)
	}

	rb.Write(mustJSON(map[string]string{"key": "value"}))
	rb.Write(mustJSON(map[string]string{"key": "value2"}))

	m := rb.Metrics()
	if m.Buffered != 2 {
		t.Errorf("2件書き込み後のBuffered = %d, want 2", m.Buffered)
	}
	if m.BytesUsed <= 0 {
		t.Errorf("BytesUsed = %d, want > 0", m.BytesUsed)
	}
}
