'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Target, Search, AlertTriangle, CheckCircle, Pause,
  Clock, ChevronDown, ChevronRight, Plus, User,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type CampaignStatus = 'planning' | 'active' | 'paused' | 'completed' | 'archived'
type Priority = 'critical' | 'high' | 'medium' | 'low'
type FindingSeverity = 'critical' | 'high' | 'medium' | 'low'
type MitreTactic =
  | 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation'
  | 'Defense Evasion' | 'Credential Access' | 'Discovery' | 'Lateral Movement'
  | 'Collection' | 'Exfiltration' | 'Command and Control'

interface HuntQuery {
  id: string
  name: string
  query: string
  hits: number
}

interface HuntFinding {
  id: string
  time: string
  description: string
  severity: FindingSeverity
}

interface Campaign {
  id: string
  name: string
  status: CampaignStatus
  priority: Priority
  tactic: MitreTactic
  techniques: string[]
  hypothesis: string
  hosts_investigated: number
  iocs_discovered: number
  days_running: number
  analysts: string[]
  queries: HuntQuery[]
  findings: HuntFinding[]
  notes: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_CAMPAIGNS: Campaign[] = [
  {
    id: 'c1',
    name: 'APT29 ラテラルムーブメント調査',
    status: 'active',
    priority: 'high',
    tactic: 'Lateral Movement',
    techniques: ['T1021.001', 'T1550.002', 'T1078'],
    hypothesis: 'APT29グループがRDPおよびPass-the-Hashを用いて内部ネットワーク内を横断移動している可能性がある。初期侵害後、認証情報を窃取し管理者権限での移動を試みていると想定。',
    hosts_investigated: 23,
    iocs_discovered: 7,
    days_running: 4,
    analysts: ['TK', 'YS', 'KN'],
    queries: [
      { id: 'q1', name: 'RDP 異常接続検出', query: 'event_id:4624 AND logon_type:10 AND NOT src_ip:10.0.0.0/8', hits: 14 },
      { id: 'q2', name: 'Pass-the-Hash パターン', query: 'event_id:4624 AND logon_type:3 AND ntlm_version:2', hits: 3 },
      { id: 'q3', name: '管理共有アクセス', query: 'event_id:5140 AND share_name:"ADMIN$" AND NOT user:SYSTEM', hits: 7 },
    ],
    findings: [
      { id: 'f1', time: '2026-03-15 14:22', description: '10.10.5.42 から 10.10.8.11 へのRDP接続（通常業務外時間）', severity: 'high' },
      { id: 'f2', time: '2026-03-16 09:05', description: 'Pass-the-Hash の痕跡 — ntds.dit アクセスログ確認', severity: 'critical' },
      { id: 'f3', time: '2026-03-17 11:30', description: '管理共有経由でのツール展開痕跡', severity: 'high' },
    ],
    notes: 'ntds.ditアクセスは特に優先して調査。DC周辺のログを重点的に確認する。',
  },
  {
    id: 'c2',
    name: 'データ窃取経路の特定',
    status: 'completed',
    priority: 'critical',
    tactic: 'Exfiltration',
    techniques: ['T1048', 'T1567.002', 'T1030'],
    hypothesis: '攻撃者がDNSトンネリングまたはHTTPS経由で機密データを外部へ送信している可能性がある。大量データ転送の異常パターンを追跡する。',
    hosts_investigated: 41,
    iocs_discovered: 12,
    days_running: 9,
    analysts: ['MO', 'TK'],
    queries: [
      { id: 'q4', name: 'DNS 異常クエリ頻度', query: 'dns_query_count > 1000 AND NOT domain:internal.corp', hits: 5 },
      { id: 'q5', name: '大量アップロード検出', query: 'bytes_out > 50000000 AND NOT dst_ip:approved_list', hits: 2 },
    ],
    findings: [
      { id: 'f4', time: '2026-03-09 23:11', description: '外部ドメインへのDNSトンネリング痕跡確認', severity: 'critical' },
      { id: 'f5', time: '2026-03-10 02:45', description: 'OneDrive 経由での 2.3GB アップロード検出', severity: 'critical' },
    ],
    notes: '最終的にC2サーバーはAS12345に帰属。IOCリストをTIチームへ共有済み。',
  },
  {
    id: 'c3',
    name: 'クレデンシャルハーベスティング検出',
    status: 'planning',
    priority: 'medium',
    tactic: 'Credential Access',
    techniques: ['T1003.001', 'T1110.003', 'T1555'],
    hypothesis: 'フィッシングメールを起点とした認証情報収集活動が進行中の可能性がある。LSASS ダンプやキーロガーの展開を調査する。',
    hosts_investigated: 0,
    iocs_discovered: 0,
    days_running: 0,
    analysts: ['YS'],
    queries: [],
    findings: [],
    notes: '',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const statusConfig: Record<CampaignStatus, { label: string; cls: string; dot: string }> = {
  planning: { label: '計画中', cls: 'bg-gray-700 text-gray-300', dot: 'bg-gray-500' },
  active: { label: 'アクティブ', cls: 'bg-blue-900 text-blue-300', dot: 'bg-blue-400' },
  paused: { label: '一時停止', cls: 'bg-yellow-900 text-yellow-300', dot: 'bg-yellow-400' },
  completed: { label: '完了', cls: 'bg-green-900 text-green-300', dot: 'bg-green-400' },
  archived: { label: 'アーカイブ', cls: 'bg-gray-800 text-gray-400', dot: 'bg-gray-600' },
}

const priorityConfig: Record<Priority, { label: string; cls: string }> = {
  critical: { label: '重大', cls: 'bg-red-900 text-red-300' },
  high: { label: '高', cls: 'bg-orange-900 text-orange-300' },
  medium: { label: '中', cls: 'bg-yellow-900 text-yellow-300' },
  low: { label: '低', cls: 'bg-gray-700 text-gray-300' },
}

const severityConfig: Record<FindingSeverity, { cls: string; label: string }> = {
  critical: { cls: 'bg-red-900 text-red-300', label: '重大' },
  high: { cls: 'bg-orange-900 text-orange-300', label: '高' },
  medium: { cls: 'bg-yellow-900 text-yellow-300', label: '中' },
  low: { cls: 'bg-gray-700 text-gray-300', label: '低' },
}

const tacticColor: Record<string, string> = {
  'Lateral Movement': 'bg-purple-900 text-purple-300',
  'Exfiltration': 'bg-red-900 text-red-300',
  'Credential Access': 'bg-orange-900 text-orange-300',
  'Initial Access': 'bg-blue-900 text-blue-300',
  'Execution': 'bg-yellow-900 text-yellow-300',
  'Persistence': 'bg-pink-900 text-pink-300',
  'Defense Evasion': 'bg-teal-900 text-teal-300',
  'Discovery': 'bg-indigo-900 text-indigo-300',
  'Collection': 'bg-cyan-900 text-cyan-300',
  'Command and Control': 'bg-rose-900 text-rose-300',
  'Privilege Escalation': 'bg-amber-900 text-amber-300',
}

function AnalystAvatar({ initials }: { initials: string }) {
  return (
    <div className="w-6 h-6 rounded-full bg-falcon-red/20 border border-falcon-red/40 flex items-center justify-center">
      <span className="text-[10px] font-bold text-falcon-red">{initials}</span>
    </div>
  )
}

// ─── Campaign Detail ──────────────────────────────────────────────────────────

function CampaignDetail({ campaign }: { campaign: Campaign }) {
  const [expandedQuery, setExpandedQuery] = useState<string | null>(null)
  const [note, setNote] = useState(campaign.notes)
  const [showNoteInput, setShowNoteInput] = useState(false)
  const st = statusConfig[campaign.status]
  const pr = priorityConfig[campaign.priority]
  const tc = tacticColor[campaign.tactic] || 'bg-gray-700 text-gray-300'

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-5 border-b border-falcon-border">
        <div className="flex items-start justify-between gap-3 mb-3">
          <h2 className="text-lg font-bold text-white leading-tight">{campaign.name}</h2>
          <div className="flex items-center gap-2 shrink-0">
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${pr.cls}`}>{pr.label}</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${st.cls}`}>{st.label}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${tc}`}>{campaign.tactic}</span>
          {campaign.techniques.map(t => (
            <span key={t} className="px-2 py-0.5 bg-[#070d19] border border-falcon-border text-falcon-muted rounded-sm text-xs font-mono">{t}</span>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Hypothesis */}
        <div>
          <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-2">仮説</div>
          <blockquote className="border-l-2 border-falcon-red pl-4 text-sm text-falcon-muted italic leading-relaxed">
            {campaign.hypothesis}
          </blockquote>
        </div>

        {/* Progress */}
        <div>
          <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-3">進捗</div>
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-white">{campaign.hosts_investigated}</div>
              <div className="text-falcon-muted text-xs mt-1">調査ホスト数</div>
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-falcon-red">{campaign.iocs_discovered}</div>
              <div className="text-falcon-muted text-xs mt-1">発見IOC</div>
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-white">{campaign.days_running}</div>
              <div className="text-falcon-muted text-xs mt-1">経過日数</div>
            </div>
          </div>
        </div>

        {/* Queries */}
        {campaign.queries.length > 0 && (
          <div>
            <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-2">ハントクエリ</div>
            <div className="space-y-2">
              {campaign.queries.map(q => (
                <div key={q.id} className="bg-[#070d19] border border-falcon-border rounded-lg overflow-hidden">
                  <button
                    onClick={() => setExpandedQuery(expandedQuery === q.id ? null : q.id)}
                    className="w-full flex items-center justify-between px-3 py-2 hover:bg-falcon-surface transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      {expandedQuery === q.id ? <ChevronDown size={12} className="text-falcon-muted" /> : <ChevronRight size={12} className="text-falcon-muted" />}
                      <span className="text-sm text-white">{q.name}</span>
                    </div>
                    <span className="text-xs text-falcon-red font-medium">{q.hits} ヒット</span>
                  </button>
                  {expandedQuery === q.id && (
                    <div className="px-3 pb-2 border-t border-falcon-border">
                      <code className="text-xs text-green-400 font-mono break-all">{q.query}</code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Findings Timeline */}
        {campaign.findings.length > 0 && (
          <div>
            <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-3">タイムライン</div>
            <div className="relative pl-4 space-y-3">
              <div className="absolute left-[7px] top-2 bottom-2 w-px bg-falcon-border" />
              {campaign.findings.map(f => {
                const sv = severityConfig[f.severity]
                return (
                  <div key={f.id} className="relative flex items-start gap-3">
                    <div className="absolute -left-4 top-1.5 w-2 h-2 rounded-full bg-falcon-red border border-[#070d19]" />
                    <div className="ml-2 flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-xs text-falcon-muted">{f.time}</span>
                        <span className={`px-1.5 py-0.5 rounded-sm text-xs font-medium ${sv.cls}`}>{sv.label}</span>
                      </div>
                      <div className="text-sm text-falcon-muted">{f.description}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Notes */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider">メモ</div>
            <button
              onClick={() => setShowNoteInput(v => !v)}
              className="flex items-center gap-1 text-xs text-falcon-muted hover:text-white"
            >
              <Plus size={11} /> メモ追加
            </button>
          </div>
          {note && (
            <div className="p-3 bg-[#070d19] border border-falcon-border rounded-lg text-sm text-falcon-muted">{note}</div>
          )}
          {showNoteInput && (
            <div className="mt-2">
              <textarea
                rows={3}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red resize-none"
                placeholder="メモを入力..."
                value={note}
                onChange={e => setNote(e.target.value)}
              />
              <div className="flex justify-end mt-1">
                <button
                  onClick={() => setShowNoteInput(false)}
                  className="px-3 py-1 bg-falcon-red text-white text-xs rounded-sm hover:bg-red-600"
                >
                  保存
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      {(campaign.status === 'active' || campaign.status === 'planning') && (
        <div className="p-4 border-t border-falcon-border flex gap-2">
          <button className="flex-1 flex items-center justify-center gap-2 py-2 bg-green-800 text-green-200 rounded-lg text-sm font-medium hover:bg-green-700 transition-colors">
            <CheckCircle size={14} />
            完了
          </button>
          <button className="flex-1 flex items-center justify-center gap-2 py-2 bg-yellow-900 text-yellow-300 rounded-lg text-sm font-medium hover:bg-yellow-800 transition-colors">
            <Pause size={14} />
            一時停止
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ThreatHuntingCampaignsPage() {
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign>(m(MOCK_CAMPAIGNS)[0])

  const { data: campaigns = m(MOCK_CAMPAIGNS) } = useQuery<Campaign[]>({
    queryKey: ['hunting-campaigns'],
    queryFn: () =>
      apiFetchList<Campaign>('/api/v1/threat-hunting/campaigns').catch(() => m(MOCK_CAMPAIGNS)),
  })

  const stats = [
    { label: '総キャンペーン', value: 18, icon: <Target size={16} className="text-falcon-red" /> },
    { label: 'アクティブ', value: 3, icon: <Search size={16} className="text-blue-400" /> },
    { label: '完了', value: 12, icon: <CheckCircle size={16} className="text-green-400" /> },
    { label: '発見IOC', value: 89, icon: <AlertTriangle size={16} className="text-yellow-400" /> },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">脅威ハンティングキャンペーン</h1>
        <p className="text-falcon-muted text-sm mt-1">Threat Hunting Campaigns</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {stats.map(s => (
          <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-3">
            <div className="p-2 bg-[#070d19] rounded-lg">{s.icon}</div>
            <div>
              <div className="text-2xl font-bold text-white">{s.value}</div>
              <div className="text-falcon-muted text-xs">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Main Layout */}
      <div className="flex gap-4" style={{ height: 'calc(100vh - 260px)' }}>
        {/* Left — Campaign List */}
        <div className="w-[35%] bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden flex flex-col">
          <div className="p-4 border-b border-falcon-border flex items-center justify-between">
            <span className="text-white font-medium">キャンペーン一覧</span>
            <button className="flex items-center gap-1 px-2.5 py-1 bg-falcon-red text-white rounded-sm text-xs hover:bg-red-600">
              <Plus size={11} />
              新規
            </button>
          </div>
          <div className="flex-1 overflow-y-auto">
            {campaigns.map(c => {
              const st = statusConfig[c.status]
              const tc = tacticColor[c.tactic] || 'bg-gray-700 text-gray-300'
              const isSelected = selectedCampaign?.id === c.id
              return (
                <div
                  key={c.id}
                  onClick={() => setSelectedCampaign(c)}
                  className={`p-4 border-b border-falcon-border cursor-pointer hover:bg-[#070d19] transition-colors ${isSelected ? 'bg-[#0a1628] border-l-2 border-l-falcon-red' : ''}`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="font-medium text-white text-sm leading-tight">{c.name}</div>
                    <div className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${st.dot}`} />
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-1.5 py-0.5 rounded-sm text-xs font-medium ${tc}`}>{c.tactic}</span>
                    <span className={`px-1.5 py-0.5 rounded-full text-xs font-medium ${st.cls}`}>{st.label}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1 text-xs text-falcon-muted">
                      <AlertTriangle size={10} className="text-falcon-red" />
                      <span>{c.iocs_discovered} IOC</span>
                    </div>
                    <div className="flex items-center -space-x-1">
                      {c.analysts.slice(0, 3).map(a => (
                        <AnalystAvatar key={a} initials={a} />
                      ))}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right — Detail */}
        <div className="flex-1 bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          {selectedCampaign
            ? <CampaignDetail campaign={selectedCampaign} />
            : (
              <div className="flex items-center justify-center h-full text-falcon-muted">
                キャンペーンを選択してください
              </div>
            )
          }
        </div>
      </div>
    </div>
  )
}
