package store

import (
	"encoding/json"
	"fmt"
)

// liveResponseSubject builds the NATS subject the agent's live-response
// start command is published on.
//
// **受け取る側は `cmd/ingestion` の `commands.*.live_response_start` です。**
// 文字列が2箇所にあり、片方だけ変えると**購読が外れます** —— ライブ
// レスポンスの開始要求が届かなくなり、画面からは「エージェントが
// 応答しない」と同じ姿になります。
//
// 検査ファイルにはこの組み立ての写しが置いてありました。写しを試しても、
// こちらは無傷のまま壊せます。
func liveResponseSubject(agentID string) string {
	return "commands." + agentID + ".live_response_start"
}

// LiveResponseStartPayload is embedded in the live_response_start command payload.
// It is sent to the agent via the collect_artifact command (type=LOGS) as a carrier,
// with the JSON encoded in the target field.
type LiveResponseStartPayload struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	Token       string `json:"token"`
	CallbackURL string `json:"callback_url"`
}

// EnqueueLiveResponseStart notifies the agent to start a live response polling loop.
// The command is published to NATS where the ingestion server picks it up and
// delivers it to the agent via gRPC using a CollectArtifactCommand(type=LOGS) carrier.
func (s *CommandStore) EnqueueLiveResponseStart(agentID, sessionID, token, callbackURL string) error {
	payload := LiveResponseStartPayload{
		Type:        "live_response",
		SessionID:   sessionID,
		Token:       token,
		CallbackURL: callbackURL,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal live_response_start: %w", err)
	}
	return s.nc.Publish(liveResponseSubject(agentID), data)
}
