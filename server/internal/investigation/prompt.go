package investigation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// buildPrompt constructs a detailed security analysis prompt for the LLM.
// It incorporates alert metadata (severity, MITRE ATT&CK tactic/technique,
// process name/hash, hostname, OS) and a timeline of related events (process
// spawns, network connections, file operations) observed in the 10 minutes
// leading up to the alert.
func buildPrompt(alert Alert, events []Event) string {
	var sb strings.Builder

	sb.WriteString("You are a senior SOC analyst. Analyze the following security alert and produce a concise investigation summary.\n\n")

	// ── Alert metadata ────────────────────────────────────────────────────────
	sb.WriteString("## Alert Details\n")
	sb.WriteString(fmt.Sprintf("- **ID**: %s\n", alert.ID))
	sb.WriteString(fmt.Sprintf("- **Title**: %s\n", alert.Title))
	sb.WriteString(fmt.Sprintf("- **Severity**: %d / 10\n", alert.Severity))

	if alert.RuleName != "" {
		sb.WriteString(fmt.Sprintf("- **Detection Rule**: %s\n", alert.RuleName))
	}
	if alert.MITRETech != "" {
		sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK Technique**: %s\n", alert.MITRETech))
	}
	if alert.Description != "" {
		sb.WriteString(fmt.Sprintf("- **Description**: %s\n", alert.Description))
	}

	// ── Endpoint context ──────────────────────────────────────────────────────
	sb.WriteString("\n## Affected Endpoint\n")
	sb.WriteString(fmt.Sprintf("- **Hostname**: %s\n", alert.Hostname))
	sb.WriteString(fmt.Sprintf("- **OS**: %s\n", alert.OS))
	sb.WriteString(fmt.Sprintf("- **Agent ID**: %s\n", alert.AgentID))
	sb.WriteString(fmt.Sprintf("- **Alert Time (UTC)**: %s\n", alert.CreatedAt.UTC().Format("2006-01-02 15:04:05")))

	// ── Event context ─────────────────────────────────────────────────────────
	if len(events) == 0 {
		sb.WriteString("\n## Surrounding Events\nNo events found in the 10-minute window before the alert.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n## Surrounding Events (last 10 minutes, %d total)\n", len(events)))

		// Group events by type for readability.
		byType := make(map[string][]Event)
		for _, e := range events {
			byType[e.EventType] = append(byType[e.EventType], e)
		}

		for evType, evList := range byType {
			sb.WriteString(fmt.Sprintf("\n### %s events (%d)\n", cases.Title(language.English).String(evType), len(evList)))
			limit := 10
			if len(evList) < limit {
				limit = len(evList)
			}
			for i := 0; i < limit; i++ {
				e := evList[i]
				// Pretty-print the JSON payload, falling back to raw if needed.
				var m map[string]interface{}
				if json.Unmarshal(e.RawData, &m) == nil {
					// Extract the most relevant fields to keep the prompt concise.
					relevant := extractRelevantFields(evType, m)
					sb.WriteString(fmt.Sprintf("  [%s] %s\n",
						e.Timestamp.UTC().Format("15:04:05"),
						relevant,
					))
				} else {
					sb.WriteString(fmt.Sprintf("  [%s] %s\n",
						e.Timestamp.UTC().Format("15:04:05"),
						string(e.RawData),
					))
				}
			}
			if len(evList) > limit {
				sb.WriteString(fmt.Sprintf("  ... and %d more %s events\n", len(evList)-limit, evType))
			}
		}
	}

	// ── Analyst instructions ──────────────────────────────────────────────────
	sb.WriteString(`
## Instructions

Provide a structured investigation summary with the following sections:

1. **Threat Assessment** – Is this a genuine threat or likely a false positive? Explain why.
2. **Attack Narrative** – Describe the probable attack chain based on the evidence.
3. **Key IOCs** – List process names, file paths, network destinations, or hashes that are suspicious.
4. **MITRE ATT&CK Mapping** – Confirm or expand the MITRE technique/tactic mapping.
5. **Recommended Actions** – Concrete next steps for the SOC analyst (containment, eradication, evidence collection).

Keep the summary factual, concise, and actionable. Do not speculate beyond the available evidence.
`)

	return sb.String()
}

// buildAutonomousPrompt constructs a comprehensive autonomous investigation prompt.
// This mode asks the LLM to act as a full-fledged SOC analyst: produce a detailed
// investigation report in Japanese with MITRE ATT&CK mapping, IOC extraction,
// attack chain reconstruction, impact analysis, and recommended response actions.
func buildAutonomousPrompt(alert Alert, events []Event, mode *InvestigationMode) string {
	var sb strings.Builder

	// ── System-level instruction ──────────────────────────────────────────────
	lang := "Japanese"
	if mode != nil && mode.Language == "en" {
		lang = "English"
	}

	sb.WriteString(fmt.Sprintf(`あなたはエンタープライズEDRプラットフォーム「Kizashi」の自律調査エージェント（Virtual SOC Analyst）です。
提供されたアラートとコンテキスト情報を基に、人間のTier 1 SOCアナリストと同等以上の品質の調査を自律的に実施してください。

回答は%sで記述してください。

`, lang))

	// ── Alert metadata ────────────────────────────────────────────────────────
	sb.WriteString("## アラート情報\n")
	sb.WriteString(fmt.Sprintf("- **アラートID**: %s\n", alert.ID))
	sb.WriteString(fmt.Sprintf("- **タイトル**: %s\n", alert.Title))
	sb.WriteString(fmt.Sprintf("- **重大度**: %d / 10\n", alert.Severity))
	if alert.RuleName != "" {
		sb.WriteString(fmt.Sprintf("- **検知ルール**: %s\n", alert.RuleName))
	}
	if alert.MITRETech != "" {
		sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK テクニック**: %s\n", alert.MITRETech))
	}
	if alert.Description != "" {
		sb.WriteString(fmt.Sprintf("- **説明**: %s\n", alert.Description))
	}

	// ── Endpoint context ──────────────────────────────────────────────────────
	sb.WriteString("\n## 対象エンドポイント\n")
	sb.WriteString(fmt.Sprintf("- **ホスト名**: %s\n", alert.Hostname))
	sb.WriteString(fmt.Sprintf("- **OS**: %s\n", alert.OS))
	sb.WriteString(fmt.Sprintf("- **エージェントID**: %s\n", alert.AgentID))
	sb.WriteString(fmt.Sprintf("- **アラート発生時刻(UTC)**: %s\n", alert.CreatedAt.UTC().Format("2006-01-02 15:04:05")))

	// ── Event context (same as standard) ──────────────────────────────────────
	if len(events) == 0 {
		sb.WriteString("\n## 周辺イベント\nアラート前10分間のイベントは見つかりませんでした。\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n## 周辺イベント（直近10分間、%d件）\n", len(events)))
		byType := make(map[string][]Event)
		for _, e := range events {
			byType[e.EventType] = append(byType[e.EventType], e)
		}
		for evType, evList := range byType {
			sb.WriteString(fmt.Sprintf("\n### %sイベント（%d件）\n", evType, len(evList)))
			limit := 15
			if len(evList) < limit {
				limit = len(evList)
			}
			for i := 0; i < limit; i++ {
				e := evList[i]
				var m map[string]interface{}
				if json.Unmarshal(e.RawData, &m) == nil {
					relevant := extractRelevantFields(evType, m)
					sb.WriteString(fmt.Sprintf("  [%s] %s\n",
						e.Timestamp.UTC().Format("15:04:05"), relevant))
				} else {
					sb.WriteString(fmt.Sprintf("  [%s] %s\n",
						e.Timestamp.UTC().Format("15:04:05"), string(e.RawData)))
				}
			}
			if len(evList) > limit {
				sb.WriteString(fmt.Sprintf("  ... 他%d件の%sイベント\n", len(evList)-limit, evType))
			}
		}
	}

	// ── Autonomous investigation instructions ─────────────────────────────────
	sb.WriteString(`

## 調査指示

以下のセクションを含む、詳細な調査レポートを作成してください。

### 1. エグゼクティブサマリー
2〜3文で、何が起きたかの概要を記載。

### 2. 脅威判定
- **判定**: 真の脅威 / 誤検知の可能性 / 要追加調査
- **確信度**: 高 / 中 / 低
- **根拠**: 判定の根拠を具体的に記載

### 3. 攻撃チェーン分析
検出されたイベントから推測される攻撃の流れをタイムライン形式で記載。
各ステップにMITRE ATT&CKテクニックIDをマッピング。

例:
- [HH:MM:SS] 初期アクセス (T1566) — フィッシングメール経由
- [HH:MM:SS] 実行 (T1059.001) — PowerShellスクリプト実行
- [HH:MM:SS] 永続化 (T1547.001) — レジストリRunキー追加

### 4. IOC（侵害指標）
検出された疑わしい以下の情報をリストアップ:
- プロセス名 / コマンドライン
- ファイルパス / ハッシュ値
- 通信先IPアドレス / ドメイン
- レジストリキー

### 5. 影響範囲の評価
- 影響を受けたエンドポイント数（推定）
- データ漏洩の可能性
- 横展開（ラテラルムーブメント）の兆候

### 6. MITRE ATT&CK マッピング
検出されたテクニックを表形式で整理:
| テクニックID | テクニック名 | タクティック | 検出根拠 |
`)

	// ── Auto-response section (only if enabled) ───────────────────────────────
	if mode != nil && mode.AutoResponse {
		sb.WriteString(`
### 7. 推奨対応アクション
脅威の深刻度に応じて、以下のアクションの要否を判断してください:

- **エンドポイント隔離**: ネットワークからの即座の切断が必要か
- **プロセス強制終了**: 悪意のあるプロセスの停止が必要か（対象PIDがあれば記載）
- **ファイル隔離**: 疑わしいファイルの隔離が必要か（対象パスを記載）
- **追加調査**: 他のエンドポイントやログの確認が必要か

各アクションに**優先度**（即座 / 高 / 通常）と**理由**を記載してください。

⚠ 注意: エンドポイント隔離は業務への影響が大きいため、確信度が高い場合のみ推奨すること。
`)
	} else {
		sb.WriteString(`
### 7. 推奨対応アクション
SOCアナリストが取るべき次のステップを優先度順にリストアップ。
封じ込め・根絶・復旧の3段階で記載してください。
`)
	}

	return sb.String()
}

// extractRelevantFields returns a human-readable one-line summary of the most
// important fields for a given event type.
// summaryValue returns the first of keys present in m with a non-empty value.
//
// The event payloads come from internal/ingestion.normalizeEventData. Several
// of the names read here were not names it produces, and a missing key yields
// nil rather than an error, so the model was handed a summary that looked
// complete and was not: a process event summarised as "pid=4242" and nothing
// else. Listing the accepted spellings at each site is what keeps the two ends
// in step.
func summaryValue(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

// summaryTruncate shortens a value and says that it did. Silently cutting a
// command line would let the model reason about a command that appears to end
// where it does not.
func summaryTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}

// summaryDuplicateKeys are names ingestion writes purely so the Sigma alias
// layer can find a value under its Sysmon spelling. They repeat the snake_case
// key next to them, so emitting both spends one of the generic branch's slots
// restating the previous field.
var summaryDuplicateKeys = map[string]bool{
	"keyPath":   true,
	"valueName": true,
	"valueData": true,
}

// genericSummaryLimit bounds the generic branch. The prompt carries up to ten
// events per type, so an unbounded summary lets one wide event crowd the rest
// of the timeline out of the model's context.
const genericSummaryLimit = 8

// summaryValueLimit bounds a single value in the generic branch.
const summaryValueLimit = 120

func extractRelevantFields(evType string, m map[string]interface{}) string {
	str := func(keys ...string) string { return summaryValue(m, keys...) }

	switch evType {
	case "process":
		image := str("image_path", "image", "process_name")
		cmd := str("command_line", "cmdline")
		pid := str("pid")
		user := str("username", "user")
		parts := []string{}
		if image != "" {
			parts = append(parts, "image="+image)
		}
		if pid != "" {
			parts = append(parts, "pid="+pid)
		}
		if user != "" {
			parts = append(parts, "user="+user)
		}
		// Truncated, not dropped. The old guard hid any command line of 120
		// characters or more, so the more heavily encoded a command was — the
		// reason the alert exists — the more certain it was to be withheld from
		// the model.
		if cmd != "" {
			parts = append(parts, "cmd="+summaryTruncate(cmd, 300))
		}
		return strings.Join(parts, " | ")

	case "network":
		dstIP := str("dst_ip")
		dstPort := str("dst_port")
		proto := str("protocol")
		proc := str("process_name")
		parts := []string{}
		if dstIP != "" {
			conn := dstIP
			if dstPort != "" && dstPort != "0" {
				conn += ":" + dstPort
			}
			parts = append(parts, "dst="+conn)
		}
		if proto != "" {
			parts = append(parts, "proto="+proto)
		}
		if proc != "" {
			parts = append(parts, "process="+proc)
		}
		return strings.Join(parts, " | ")

	case "file":
		path := str("path", "file_path", "target_path", "old_path")
		op := str("operation", "action")
		hash := str("sha256", "sha1", "md5")
		parts := []string{}
		if op != "" {
			parts = append(parts, "op="+op)
		}
		if path != "" {
			parts = append(parts, "path="+path)
		}
		if hash != "" {
			parts = append(parts, "sha256="+hash)
		}
		return strings.Join(parts, " | ")

	case "dns":
		query := str("query", "domain")
		// Ingestion writes the resolved addresses as "answers"; nothing writes
		// "response", so the address a suspicious domain resolved to never
		// reached the model and it could not connect the lookup to the outbound
		// connection beside it in the same timeline.
		resp := str("answers", "response")
		parts := []string{}
		if query != "" {
			parts = append(parts, "query="+query)
		}
		if resp != "" {
			parts = append(parts, "answers="+resp)
		}
		return strings.Join(parts, " | ")

	default:
		// Registry, auth, image_load and script all land here. This used to take
		// five keys in Go's map order, so the same event summarised twice gave
		// different fields: measured on one registry persistence event, six calls
		// produced five distinct summaries, some without the Run key and some
		// without the payload path. Sorting makes the model's input a function of
		// the event rather than of the runtime.
		keys := make([]string, 0, len(m))
		for k := range m {
			if summaryDuplicateKeys[k] {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)

		parts := []string{}
		for _, k := range keys {
			if len(parts) >= genericSummaryLimit {
				break
			}
			v := summaryValue(m, k)
			if v == "" {
				continue
			}
			parts = append(parts, k+"="+summaryTruncate(v, summaryValueLimit))
		}
		return strings.Join(parts, " | ")
	}
}
