package detection

import (
	"encoding/json"
	"strings"
)

// cloudPattern maps a case-insensitive substring of a cloud event type /
// operation name to its ATT&CK (Cloud) technique, a severity and a Japanese
// reason. Matching is substring-based so it works across AWS CloudTrail
// eventName, Azure operationName and GCP methodName shapes.
type cloudPattern struct {
	match     string
	technique string
	severity  int
	label     string
}

// CloudEventRule matches cloud events against suspicious patterns.
type CloudEventRule struct {
	patterns []cloudPattern
}

// CloudVerdict is the richer result of evaluating a cloud event: whether it is
// suspicious, plus the accurate ATT&CK technique and severity so the alert is
// technique-attributed (feeding the kill-chain correlator) rather than a flat
// "T1098 / severity 7" for every cloud event.
type CloudVerdict struct {
	Suspicious bool
	Reason     string
	Technique  string
	Severity   int
}

// defaultCloudPatterns covers high-signal AWS/Azure/GCP attacker operations
// across the ATT&CK Cloud matrix. Deliberately excludes noisy read/describe
// events (DescribeInstances/GetObject/ListBuckets) that dominate normal
// operations — those belong to volume/anomaly analysis, not a per-event gate.
var defaultCloudPatterns = []cloudPattern{
	// ── Defense Evasion: disable/delete cloud logging & monitoring (T1562.008) ──
	{"DeleteTrail", "T1562.008", 9, "CloudTrail 証跡の削除"},
	{"StopLogging", "T1562.008", 9, "CloudTrail ロギングの停止"},
	{"UpdateTrail", "T1562.008", 7, "CloudTrail 証跡の改変"},
	{"DeleteFlowLogs", "T1562.008", 8, "VPC フローログの削除"},
	{"DeleteDetector", "T1562.008", 9, "GuardDuty 検出器の削除"},
	{"StopMonitoringMembers", "T1562.008", 8, "GuardDuty 監視の停止"},
	{"StopConfigurationRecorder", "T1562.008", 8, "AWS Config 記録の停止"},
	{"DeleteConfigRule", "T1562.008", 7, "AWS Config ルールの削除"},
	{"DisableAlarmActions", "T1562.008", 7, "CloudWatch アラームの無効化"},
	{"diagnosticsettings/delete", "T1562.008", 8, "Azure 診断設定の削除"},
	{"logging.sinks.delete", "T1562.008", 8, "GCP ログシンクの削除"},

	// ── Credential Access: cloud secret stores (T1555.006) ──
	{"GetSecretValue", "T1555.006", 6, "Secrets Manager シークレットの取得"},
	{"BatchGetSecretValue", "T1555.006", 7, "Secrets Manager 一括シークレット取得"},
	{"keyvault/vaults/secrets/read", "T1555.006", 6, "Azure Key Vault シークレットの読取"},
	{"GetPasswordData", "T1555.006", 6, "EC2 パスワードデータの取得"},

	// ── Persistence: create cloud account / add credentials (T1136.003 / T1098.001) ──
	{"CreateUser", "T1136.003", 7, "IAM ユーザーの作成"},
	{"CreateAccessKey", "T1098.001", 8, "アクセスキーの作成(追加認証情報)"},
	{"CreateLoginProfile", "T1098", 8, "ログインプロファイルの作成"},
	{"UpdateLoginProfile", "T1098", 7, "ログインプロファイルの更新"},
	{"CreateServiceAccountKey", "T1098.001", 8, "GCP サービスアカウント鍵の作成"},

	// ── Privilege Escalation: IAM policy manipulation (T1098) ──
	{"AttachUserPolicy", "T1098", 8, "IAM ユーザーへのポリシー付与"},
	{"AttachRolePolicy", "T1098", 8, "IAM ロールへのポリシー付与"},
	{"PutUserPolicy", "T1098", 8, "IAM インラインポリシーの付与"},
	{"PutRolePolicy", "T1098", 8, "IAM ロールインラインポリシーの付与"},
	{"CreatePolicyVersion", "T1098", 7, "IAM ポリシーバージョンの作成"},
	{"AddUserToGroup", "T1098", 7, "IAM グループへのユーザー追加"},
	{"UpdateAssumeRolePolicy", "T1098", 8, "AssumeRole ポリシーの改変"},
	{"roleassignments/write", "T1098", 8, "Azure ロール割り当ての書込"},
	{"SetIamPolicy", "T1098", 8, "GCP IAM ポリシーの設定"},
	{"microsoft.security/policies/write", "T1098", 7, "Azure セキュリティポリシーの書込"},

	// ── Valid Accounts / token abuse (T1078.004 / T1550.001) ──
	{"GetFederationToken", "T1550.001", 6, "フェデレーショントークンの取得"},

	// ── Collection / Exfiltration: cloud storage exposure (T1530) ──
	{"PutBucketAcl", "T1530", 8, "S3 バケット ACL の変更(公開の恐れ)"},
	{"PutBucketPolicy", "T1530", 8, "S3 バケットポリシーの変更(公開の恐れ)"},
	{"PutBucketPublicAccessBlock", "T1530", 7, "S3 パブリックアクセスブロックの変更"},
	{"storage.setIamPermissions", "T1530", 7, "GCS バケット IAM の変更(公開の恐れ)"},

	// ── Impact: destructive cloud operations (T1485 / T1486) ──
	{"DeleteBucket", "T1485", 8, "S3 バケットの削除"},
	{"ScheduleKeyDeletion", "T1486", 9, "KMS 鍵の削除予約"},
	{"DisableKey", "T1486", 8, "KMS 鍵の無効化"},
	{"TerminateInstances", "T1485", 8, "EC2 インスタンスの終了"},
}

// DefaultCloudRules is the built-in cloud detection rule set.
var DefaultCloudRules = CloudEventRule{patterns: defaultCloudPatterns}

// Evaluate returns a CloudVerdict for the event, with the accurate ATT&CK
// technique and severity when it matches a suspicious pattern.
func (r *CloudEventRule) Evaluate(payload *CloudEventPayload) CloudVerdict {
	if payload == nil {
		return CloudVerdict{}
	}
	et := strings.ToLower(strings.TrimSpace(payload.EventType))
	if et == "" {
		return CloudVerdict{}
	}
	for _, p := range r.patterns {
		if strings.Contains(et, strings.ToLower(p.match)) {
			return CloudVerdict{
				Suspicious: true,
				Reason:     "不審なクラウド操作: " + payload.EventType + " — " + p.label,
				Technique:  p.technique,
				Severity:   p.severity,
			}
		}
	}
	return CloudVerdict{}
}

// IsSuspicious returns true and a reason string if the event matches a
// suspicious pattern. Retained for backward compatibility; new callers should
// use Evaluate to also obtain the technique and severity.
func (r *CloudEventRule) IsSuspicious(payload *CloudEventPayload) (bool, string) {
	v := r.Evaluate(payload)
	return v.Suspicious, v.Reason
}

// CloudEventPayload is the NATS message from the cloud poller.
type CloudEventPayload struct {
	ID           string                 `json:"id"`
	Provider     string                 `json:"provider"`
	EventType    string                 `json:"event_type"`
	SourceIP     string                 `json:"source_ip"`
	UserIdentity map[string]interface{} `json:"user_identity"`
	Resource     string                 `json:"resource"`
	Region       string                 `json:"region"`
	Hostname     string                 `json:"hostname"`
}

// ParseCloudEvent parses a NATS cloud event message.
func ParseCloudEvent(data []byte) (*CloudEventPayload, error) {
	var payload CloudEventPayload
	return &payload, json.Unmarshal(data, &payload)
}
