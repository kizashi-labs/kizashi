'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitMerge, Plus, X, AlertTriangle, Shield, ThumbsDown,
  ChevronRight, Clock, Activity, Zap, Eye, RefreshCw,
  ToggleLeft, ToggleRight, Target, Layers, TrendingUp
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type AttackChainStage = 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'defense_evasion' | 'credential_access' | 'lateral_movement' | 'collection' | 'exfiltration' | 'impact'
type CorrelationStatus = 'new' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type PatternType = 'sequence' | 'cluster' | 'threshold'

interface CorrelationGroup {
  id: string
  group_id: string
  alert_count: number
  time_span_minutes: number
  involved_hosts: string[]
  attack_chain_stage: AttackChainStage
  confidence: number
  severity: Severity
  status: CorrelationStatus
  first_seen: string
  mitre_techniques: string[]
  event_timeline: TimelineEvent[]
  recommended_response: string[]
}

interface TimelineEvent {
  id: string
  timestamp: string
  host: string
  event_type: string
  description: string
  technique?: string
}

interface CorrelationRule {
  id: string
  rule_name: string
  pattern_type: PatternType
  trigger_condition: string
  time_window_minutes: number
  match_count: number
  active: boolean
  created_at: string
}

interface EngineStatus {
  active_rules: number
  events_per_sec: number
  correlations_today: number
  detection_latency_ms: number
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ENGINE: EngineStatus = {
  active_rules: 47,
  events_per_sec: 12840,
  correlations_today: 23,
  detection_latency_ms: 142,
}

const MOCK_GROUPS: CorrelationGroup[] = [
  {
    id: 'cg-001', group_id: 'GRP-2026-0089', alert_count: 14, time_span_minutes: 47,
    involved_hosts: ['DESKTOP-A1B2', 'SERVER-DC01', 'SERVER-FILE01'], attack_chain_stage: 'lateral_movement',
    confidence: 94, severity: 'critical', status: 'investigating',
    first_seen: '2026-03-18T08:14:00Z',
    mitre_techniques: ['T1078', 'T1021', 'T1550'],
    recommended_response: ['感染端末を即時隔離', 'Active Directoryのパスワードリセット', 'ラテラルムーブメントの追跡'],
    event_timeline: [
      { id: 'e1', timestamp: '2026-03-18T08:14:00Z', host: 'DESKTOP-A1B2', event_type: 'auth_failure', description: '連続認証失敗 (32回)', technique: 'T1078' },
      { id: 'e2', timestamp: '2026-03-18T08:22:00Z', host: 'DESKTOP-A1B2', event_type: 'auth_success', description: '異常な時間帯での認証成功', technique: 'T1078' },
      { id: 'e3', timestamp: '2026-03-18T08:35:00Z', host: 'SERVER-DC01', event_type: 'lateral_movement', description: 'PsExecによるリモート実行検出', technique: 'T1021' },
      { id: 'e4', timestamp: '2026-03-18T09:01:00Z', host: 'SERVER-FILE01', event_type: 'data_access', description: '大量ファイルアクセス (1,240件)', technique: 'T1550' },
    ],
  },
  {
    id: 'cg-002', group_id: 'GRP-2026-0088', alert_count: 7, time_span_minutes: 12,
    involved_hosts: ['SERVER-WEB02'], attack_chain_stage: 'initial_access',
    confidence: 88, severity: 'high', status: 'new',
    first_seen: '2026-03-18T09:30:00Z',
    mitre_techniques: ['T1190', 'T1059'],
    recommended_response: ['Webアプリケーションの緊急パッチ適用', 'WAFルールの更新', 'アクセスログの詳細分析'],
    event_timeline: [
      { id: 'e5', timestamp: '2026-03-18T09:30:00Z', host: 'SERVER-WEB02', event_type: 'exploit', description: 'Log4Shell脆弱性悪用の試みを検出', technique: 'T1190' },
      { id: 'e6', timestamp: '2026-03-18T09:38:00Z', host: 'SERVER-WEB02', event_type: 'shell_exec', description: '不審なBashコマンド実行', technique: 'T1059' },
    ],
  },
  {
    id: 'cg-003', group_id: 'GRP-2026-0087', alert_count: 22, time_span_minutes: 180,
    involved_hosts: ['LAPTOP-MGR01', 'LAPTOP-MGR02', 'LAPTOP-HR01'], attack_chain_stage: 'credential_access',
    confidence: 76, severity: 'high', status: 'confirmed',
    first_seen: '2026-03-18T06:00:00Z',
    mitre_techniques: ['T1003', 'T1555', 'T1110'],
    recommended_response: ['MFA強制適用', '認証情報のローテーション', 'エンドポイントのEDRログ強化'],
    event_timeline: [
      { id: 'e7', timestamp: '2026-03-18T06:00:00Z', host: 'LAPTOP-MGR01', event_type: 'credential_dump', description: 'LSASS メモリダンプ試行', technique: 'T1003' },
      { id: 'e8', timestamp: '2026-03-18T07:15:00Z', host: 'LAPTOP-MGR02', event_type: 'credential_dump', description: 'ブラウザ保存パスワード抽出', technique: 'T1555' },
      { id: 'e9', timestamp: '2026-03-18T08:30:00Z', host: 'LAPTOP-HR01', event_type: 'brute_force', description: 'パスワードスプレー攻撃', technique: 'T1110' },
    ],
  },
  {
    id: 'cg-004', group_id: 'GRP-2026-0086', alert_count: 5, time_span_minutes: 8,
    involved_hosts: ['DESKTOP-DEV03'], attack_chain_stage: 'execution',
    confidence: 91, severity: 'medium', status: 'new',
    first_seen: '2026-03-18T10:05:00Z',
    mitre_techniques: ['T1204', 'T1059.001'],
    recommended_response: ['PowerShell実行ポリシーの見直し', 'ユーザー教育の実施'],
    event_timeline: [
      { id: 'e10', timestamp: '2026-03-18T10:05:00Z', host: 'DESKTOP-DEV03', event_type: 'macro_exec', description: 'Officeマクロ実行検出', technique: 'T1204' },
      { id: 'e11', timestamp: '2026-03-18T10:08:00Z', host: 'DESKTOP-DEV03', event_type: 'powershell', description: '難読化PowerShellスクリプト実行', technique: 'T1059.001' },
    ],
  },
  {
    id: 'cg-005', group_id: 'GRP-2026-0085', alert_count: 31, time_span_minutes: 420,
    involved_hosts: ['SERVER-DC01', 'SERVER-DC02'], attack_chain_stage: 'persistence',
    confidence: 85, severity: 'critical', status: 'investigating',
    first_seen: '2026-03-17T23:00:00Z',
    mitre_techniques: ['T1136', 'T1547', 'T1053'],
    recommended_response: ['新規アカウントの即時削除', '起動項目の監査', 'スケジュールタスクのレビュー'],
    event_timeline: [
      { id: 'e12', timestamp: '2026-03-17T23:00:00Z', host: 'SERVER-DC01', event_type: 'account_create', description: '不審なサービスアカウント作成', technique: 'T1136' },
      { id: 'e13', timestamp: '2026-03-17T23:30:00Z', host: 'SERVER-DC01', event_type: 'registry_mod', description: '起動キーへのエントリ追加', technique: 'T1547' },
    ],
  },
  {
    id: 'cg-006', group_id: 'GRP-2026-0084', alert_count: 9, time_span_minutes: 90,
    involved_hosts: ['DESKTOP-B3C4'], attack_chain_stage: 'exfiltration',
    confidence: 72, severity: 'high', status: 'false_positive',
    first_seen: '2026-03-17T20:00:00Z',
    mitre_techniques: ['T1041'],
    recommended_response: [],
    event_timeline: [
      { id: 'e14', timestamp: '2026-03-17T20:00:00Z', host: 'DESKTOP-B3C4', event_type: 'data_transfer', description: '大量データ外部転送検出', technique: 'T1041' },
    ],
  },
  {
    id: 'cg-007', group_id: 'GRP-2026-0083', alert_count: 18, time_span_minutes: 55,
    involved_hosts: ['SERVER-MAIL01', 'DESKTOP-A1B2', 'DESKTOP-C5D6'],
    attack_chain_stage: 'defense_evasion',
    confidence: 89, severity: 'high', status: 'investigating',
    first_seen: '2026-03-17T18:30:00Z',
    mitre_techniques: ['T1562', 'T1070', 'T1027'],
    recommended_response: ['EDRログの改ざん調査', 'ファイル復元の試行', 'セキュリティツールの整合性確認'],
    event_timeline: [
      { id: 'e15', timestamp: '2026-03-17T18:30:00Z', host: 'DESKTOP-A1B2', event_type: 'tool_disable', description: 'Windows Defenderの無効化試行', technique: 'T1562' },
      { id: 'e16', timestamp: '2026-03-17T19:00:00Z', host: 'DESKTOP-C5D6', event_type: 'log_clear', description: 'Windowsイベントログの消去', technique: 'T1070' },
    ],
  },
  {
    id: 'cg-008', group_id: 'GRP-2026-0082', alert_count: 4, time_span_minutes: 25,
    involved_hosts: ['LAPTOP-EXEC01'], attack_chain_stage: 'collection',
    confidence: 68, severity: 'medium', status: 'resolved',
    first_seen: '2026-03-17T15:00:00Z',
    mitre_techniques: ['T1560', 'T1005'],
    recommended_response: [],
    event_timeline: [
      { id: 'e17', timestamp: '2026-03-17T15:00:00Z', host: 'LAPTOP-EXEC01', event_type: 'archive_create', description: '機密フォルダのZIPアーカイブ作成', technique: 'T1560' },
    ],
  },
]

const MOCK_RULES: CorrelationRule[] = [
  { id: 'r1', rule_name: 'ブルートフォース → 認証成功', pattern_type: 'sequence', trigger_condition: '失敗10回後に成功', time_window_minutes: 15, match_count: 47, active: true, created_at: '2025-01-01' },
  { id: 'r2', rule_name: 'ラテラルムーブメント検出', pattern_type: 'sequence', trigger_condition: 'SMB接続 + リモートコード実行', time_window_minutes: 30, match_count: 12, active: true, created_at: '2025-01-15' },
  { id: 'r3', rule_name: '同一ホスト高頻度アラート', pattern_type: 'threshold', trigger_condition: '5分間に10件以上', time_window_minutes: 5, match_count: 234, active: true, created_at: '2025-02-01' },
  { id: 'r4', rule_name: 'マルウェアクラスター', pattern_type: 'cluster', trigger_condition: '同一サブネット3ホスト以上', time_window_minutes: 60, match_count: 8, active: true, created_at: '2025-02-15' },
  { id: 'r5', rule_name: 'データ流出パターン', pattern_type: 'sequence', trigger_condition: 'ファイル収集 → 圧縮 → 外部転送', time_window_minutes: 120, match_count: 3, active: true, created_at: '2025-03-01' },
  { id: 'r6', rule_name: '権限昇格チェーン', pattern_type: 'sequence', trigger_condition: 'Token窃取 → 管理者実行', time_window_minutes: 20, match_count: 19, active: true, created_at: '2025-03-10' },
  { id: 'r7', rule_name: '夜間大量アクセス', pattern_type: 'threshold', trigger_condition: '00:00-06:00に100件超', time_window_minutes: 360, match_count: 7, active: false, created_at: '2025-03-15' },
  { id: 'r8', rule_name: 'クレデンシャル収穫', pattern_type: 'cluster', trigger_condition: '複数ホストで認証情報ダンプ', time_window_minutes: 240, match_count: 5, active: true, created_at: '2025-04-01' },
  { id: 'r9', rule_name: 'C2ビーコン検出', pattern_type: 'threshold', trigger_condition: '一定間隔での外部通信', time_window_minutes: 60, match_count: 31, active: true, created_at: '2025-04-15' },
  { id: 'r10', rule_name: 'ツール無効化連鎖', pattern_type: 'sequence', trigger_condition: 'AV停止 → ログ消去', time_window_minutes: 45, match_count: 6, active: true, created_at: '2025-05-01' },
  { id: 'r11', rule_name: '水平展開スキャン', pattern_type: 'cluster', trigger_condition: '多数ポートスキャン後の接続', time_window_minutes: 30, match_count: 14, active: true, created_at: '2025-05-15' },
  { id: 'r12', rule_name: 'インサイダー異常行動', pattern_type: 'threshold', trigger_condition: '通常の5倍以上のデータアクセス', time_window_minutes: 480, match_count: 2, active: false, created_at: '2025-06-01' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const severityColor: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
}

const statusColor: Record<CorrelationStatus, string> = {
  new: 'bg-red-500/20 text-red-300 border-red-500/30',
  investigating: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  confirmed: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  false_positive: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
  resolved: 'bg-green-500/20 text-green-300 border-green-500/30',
}

const chainStageLabel: Record<AttackChainStage, string> = {
  initial_access: '初期アクセス', execution: '実行', persistence: '永続化',
  privilege_escalation: '権限昇格', defense_evasion: '防御回避',
  credential_access: '認証情報窃取', lateral_movement: '横展開',
  collection: '収集', exfiltration: '流出', impact: 'インパクト',
}

const chainStageColor: Record<AttackChainStage, string> = {
  initial_access: 'bg-red-600/20 text-red-300', execution: 'bg-orange-600/20 text-orange-300',
  persistence: 'bg-yellow-600/20 text-yellow-300', privilege_escalation: 'bg-orange-500/20 text-orange-300',
  defense_evasion: 'bg-purple-600/20 text-purple-300', credential_access: 'bg-pink-600/20 text-pink-300',
  lateral_movement: 'bg-blue-600/20 text-blue-300', collection: 'bg-cyan-600/20 text-cyan-300',
  exfiltration: 'bg-red-700/20 text-red-400', impact: 'bg-red-900/20 text-red-500',
}

const patternTypeColor: Record<PatternType, string> = {
  sequence: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  cluster: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  threshold: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${cls}`}>{text}</span>
}

function timeAgo(ts: string) {
  const m = Math.floor((Date.now() - new Date(ts).getTime()) / 60000)
  if (m < 60) return `${m}分前`
  return `${Math.floor(m / 60)}時間前`
}

// ─── Group Detail Modal ───────────────────────────────────────────────────────

function GroupDetailModal({ group, onClose, onFP }: {
  group: CorrelationGroup
  onClose: () => void
  onFP: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h3 className="text-white font-semibold">{group.group_id}</h3>
              <Badge text={severityColor[group.severity].includes('red') ? '重大' : group.severity === 'high' ? '高' : '中'} cls={severityColor[group.severity]} />
              <Badge text={chainStageLabel[group.attack_chain_stage]} cls={`border-0 ${chainStageColor[group.attack_chain_stage]}`} />
            </div>
            <p className="text-xs text-[#7d92b0]">{group.alert_count}件のアラート · {group.time_span_minutes}分間 · 信頼度 {group.confidence}%</p>
          </div>
          <div className="flex items-center gap-2">
            {group.status !== 'false_positive' && (
              <button onClick={onFP} className="flex items-center gap-1 px-3 py-1.5 text-xs border border-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] hover:border-[#e8002d]/40 rounded-lg transition-colors">
                <ThumbsDown className="w-3.5 h-3.5" /> 誤検知
              </button>
            )}
            <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
          </div>
        </div>
        <div className="p-6 space-y-5">
          {/* Timeline */}
          <div>
            <p className="text-xs text-[#7d92b0] font-medium mb-3">イベントタイムライン</p>
            <div className="space-y-0">
              {group.event_timeline.map((ev, i) => (
                <div key={ev.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-[#e8002d] mt-1.5 flex-shrink-0" />
                    {i < group.event_timeline.length - 1 && <div className="w-px flex-1 bg-[#1e2d42] my-1 min-h-[16px]" />}
                  </div>
                  <div className="flex-1 pb-3">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs text-white font-medium">{ev.host}</span>
                      <span className="text-[10px] text-[#e8002d] bg-[#e8002d]/10 px-1.5 py-0.5 rounded font-mono">{ev.technique}</span>
                      <span className="text-[10px] text-[#3d5068] ml-auto">{timeAgo(ev.timestamp)}</span>
                    </div>
                    <p className="text-xs text-[#7d92b0]">{ev.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Attack chain visualization */}
          <div>
            <p className="text-xs text-[#7d92b0] font-medium mb-3">ATT&CK チェーン</p>
            <div className="flex items-center gap-2 overflow-x-auto pb-2">
              {group.mitre_techniques.map((t, i) => (
                <div key={t} className="flex items-center gap-2 flex-shrink-0">
                  <div className="bg-[#1e2d42] border border-[#e8002d]/30 rounded-lg px-3 py-2 text-center min-w-[80px]">
                    <p className="text-xs font-mono text-[#e8002d]">{t}</p>
                    <p className="text-[10px] text-[#7d92b0]">MITRE</p>
                  </div>
                  {i < group.mitre_techniques.length - 1 && <ChevronRight className="w-4 h-4 text-[#3d5068]" />}
                </div>
              ))}
            </div>
          </div>

          {/* Involved hosts */}
          <div>
            <p className="text-xs text-[#7d92b0] font-medium mb-2">関連ホスト</p>
            <div className="flex flex-wrap gap-2">
              {group.involved_hosts.map(h => (
                <span key={h} className="text-xs bg-[#1e2d42] text-[#e2e8f4] px-2 py-1 rounded font-mono">{h}</span>
              ))}
            </div>
          </div>

          {/* Recommended actions */}
          {group.recommended_response.length > 0 && (
            <div>
              <p className="text-xs text-[#7d92b0] font-medium mb-2">推奨対応</p>
              <ul className="space-y-1">
                {group.recommended_response.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-[#e2e8f4]">
                    <ChevronRight className="w-3.5 h-3.5 text-[#e8002d] mt-0.5 flex-shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Add Rule Modal ───────────────────────────────────────────────────────────

function AddRuleModal({ onClose, onSave }: { onClose: () => void; onSave: (r: Partial<CorrelationRule>) => void }) {
  const [name, setName] = useState('')
  const [patternType, setPatternType] = useState<PatternType>('sequence')
  const [trigger, setTrigger] = useState('')
  const [window, setWindow] = useState(30)

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">相関ルール追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">ルール名</label>
            <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none"
              value={name} onChange={e => setName(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">パターンタイプ</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none"
                value={patternType} onChange={e => setPatternType(e.target.value as PatternType)}>
                <option value="sequence">シーケンス</option>
                <option value="cluster">クラスター</option>
                <option value="threshold">閾値</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">時間ウィンドウ (分)</label>
              <input type="number" className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none"
                value={window} onChange={e => setWindow(parseInt(e.target.value) || 30)} />
            </div>
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">トリガー条件</label>
            <textarea className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none resize-none"
              rows={3} placeholder="例: auth.failure.count >= 10 AND auth.success WITHIN 5m"
              value={trigger} onChange={e => setTrigger(e.target.value)} />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white">キャンセル</button>
          <button onClick={() => onSave({ rule_name: name, pattern_type: patternType, trigger_condition: trigger, time_window_minutes: window, active: true })}
            className="px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CorrelationV2Page() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'groups' | 'rules'>('groups')
  const [selectedGroup, setSelectedGroup] = useState<CorrelationGroup | null>(null)
  const [showAddRule, setShowAddRule] = useState(false)
  const [groups, setGroups] = useState<CorrelationGroup[]>(m(MOCK_GROUPS))
  const [rules, setRules] = useState<CorrelationRule[]>(m(MOCK_RULES))

  const { data: engineStatus = m(MOCK_ENGINE) } = useQuery<EngineStatus>({
    queryKey: ['correlation-engine-status'],
    queryFn: () => apiFetch('/api/v1/alerts/correlation-engine/status'),
    ...(USE_MOCK ? { initialData: MOCK_ENGINE } : {}),
    refetchInterval: 10000,
  })

  const markFP = (id: string) => {
    setGroups(prev => prev.map(g => g.id === id ? { ...g, status: 'false_positive' as CorrelationStatus } : g))
    setSelectedGroup(null)
  }

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, active: !r.active } : r))
  }

  const statusLabel: Record<CorrelationStatus, string> = {
    new: '新規', investigating: '調査中', confirmed: '確定', false_positive: '誤検知', resolved: '解決済',
  }
  const patternLabel: Record<PatternType, string> = {
    sequence: 'シーケンス', cluster: 'クラスター', threshold: '閾値',
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <GitMerge className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">高度イベント相関分析 v2</h1>
            <p className="text-xs text-[#7d92b0]">インテリジェント相関エンジン</p>
          </div>
        </div>
        {tab === 'rules' && (
          <button
            onClick={() => setShowAddRule(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" /> ルール追加
          </button>
        )}
      </div>

      {/* Engine status */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'アクティブルール', value: engineStatus.active_rules, suffix: '件', color: 'text-blue-400', icon: <Shield className="w-4 h-4" /> },
          { label: 'イベント処理速度', value: (engineStatus.events_per_sec ?? 0).toLocaleString(), suffix: '/秒', color: 'text-green-400', icon: <Zap className="w-4 h-4" /> },
          { label: '本日の相関検出', value: engineStatus.correlations_today, suffix: '件', color: 'text-orange-400', icon: <Activity className="w-4 h-4" /> },
          { label: '検出レイテンシ', value: engineStatus.detection_latency_ms, suffix: 'ms', color: 'text-purple-400', icon: <Clock className="w-4 h-4" /> },
        ].map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs text-[#7d92b0]">{s.label}</p>
              <span className={`${s.color} opacity-60`}>{s.icon}</span>
            </div>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}<span className="text-sm ml-1 font-normal text-[#7d92b0]">{s.suffix}</span></p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['groups', 'rules'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${tab === t ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {t === 'groups' ? `相関グループ (${groups.length})` : `相関ルール (${rules.length})`}
          </button>
        ))}
      </div>

      {/* Correlation Groups */}
      {tab === 'groups' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['グループID', 'アラート数', 'スパン', '関連ホスト', '攻撃チェーン', '信頼度', '重大度', 'ステータス', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {groups.map(g => (
                <tr key={g.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-[#e8002d]">{g.group_id}</td>
                  <td className="px-4 py-3 text-white font-bold">{g.alert_count}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">{g.time_span_minutes}分</td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{g.involved_hosts[0]}{g.involved_hosts.length > 1 && ` +${g.involved_hosts.length - 1}`}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-[11px] px-2 py-0.5 rounded ${chainStageColor[g.attack_chain_stage]}`}>
                      {chainStageLabel[g.attack_chain_stage]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${g.confidence >= 85 ? 'bg-[#e8002d]' : g.confidence >= 70 ? 'bg-orange-400' : 'bg-yellow-400'}`}
                          style={{ width: `${g.confidence}%` }} />
                      </div>
                      <span className="text-xs text-[#7d92b0]">{g.confidence}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3"><Badge text={g.severity === 'critical' ? '重大' : g.severity === 'high' ? '高' : g.severity === 'medium' ? '中' : '低'} cls={severityColor[g.severity]} /></td>
                  <td className="px-4 py-3"><Badge text={statusLabel[g.status]} cls={statusColor[g.status]} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setSelectedGroup(g)}
                        className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white px-2 py-1 border border-[#1e2d42] rounded transition-colors">
                        <Eye className="w-3 h-3" /> 詳細
                      </button>
                      {g.status !== 'false_positive' && (
                        <button onClick={() => markFP(g.id)}
                          className="text-xs text-[#7d92b0] hover:text-[#e8002d] px-2 py-1 border border-[#1e2d42] rounded transition-colors">
                          誤検知
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Correlation Rules */}
      {tab === 'rules' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['ルール名', 'パターン', 'トリガー条件', '時間ウィンドウ', 'マッチ数', '状態'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="px-4 py-3 text-white font-medium">{r.rule_name}</td>
                  <td className="px-4 py-3"><Badge text={patternLabel[r.pattern_type]} cls={patternTypeColor[r.pattern_type]} /></td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-xs truncate">{r.trigger_condition}</td>
                  <td className="px-4 py-3 text-[#7d92b0]">{r.time_window_minutes}分</td>
                  <td className="px-4 py-3 text-white font-bold">{r.match_count}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => toggleRule(r.id)} className="flex items-center gap-2 group">
                      {r.active
                        ? <ToggleRight className="w-5 h-5 text-green-400 group-hover:text-green-300" />
                        : <ToggleLeft className="w-5 h-5 text-[#3d5068] group-hover:text-[#7d92b0]" />
                      }
                      <span className={`text-xs ${r.active ? 'text-green-400' : 'text-[#7d92b0]'}`}>{r.active ? '有効' : '無効'}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedGroup && (
        <GroupDetailModal group={selectedGroup} onClose={() => setSelectedGroup(null)} onFP={() => markFP(selectedGroup.id)} />
      )}
      {showAddRule && (
        <AddRuleModal
          onClose={() => setShowAddRule(false)}
          onSave={r => {
            setRules(prev => [{ ...r, id: `r-${Date.now()}`, match_count: 0, created_at: new Date().toISOString() } as CorrelationRule, ...prev])
            setShowAddRule(false)
          }}
        />
      )}
    </div>
  )
}
