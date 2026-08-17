'use client'

import type React from 'react'
import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  FileText, Plus, X, ChevronDown, ChevronRight, Trash2,
  ArrowUp, ArrowDown, Play, Search, BarChart2, Paperclip,
  AlertTriangle, CheckCircle, Clock, Archive, Edit2,
  Download, Share2, Users, Save, Tag, AlignLeft,
  Database, Eye, Hash, Filter
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────────

type CellType = 'query' | 'note' | 'visualization' | 'artifact' | 'finding'
type NotebookStatus = 'active' | 'completed' | 'archived'
type Verdict = 'positive_finding' | 'negative' | 'inconclusive'

interface QueryResult {
  columns: string[]
  rows: string[][]
}

interface NotebookCell {
  id: string
  type: CellType
  collapsed: boolean
  // query
  query?: string
  time_range?: string
  results?: QueryResult
  // note
  note_content?: string
  // visualization
  chart_type?: 'bar' | 'pie'
  // artifact
  artifact_hash?: string
  artifact_filename?: string
  artifact_enrichment?: string
  // finding
  finding_title?: string
  finding_severity?: 'critical' | 'high' | 'medium' | 'low'
  finding_description?: string
  finding_evidence?: string
  finding_action?: string
}

interface ThreatNotebook {
  id: string
  title: string
  description: string
  status: NotebookStatus
  tags: string[]
  created_at: string
  updated_at: string
  assigned_to: string
  hypothesis: string
  assumptions: string
  success_criteria: string
  cells: NotebookCell[]
  conclusion_summary: string
  verdict: Verdict | null
  recommendations: string[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const MOCK_NOTEBOOKS: ThreatNotebook[] = [
  {
    id: 'nb-001',
    title: 'ラテラルムーブメント調査 — 2026-03',
    description: 'SMBトラフィックの異常パターンに基づく横展開の可能性を調査する。',
    status: 'active',
    tags: ['lateral-movement', 'smb', 'internal'],
    created_at: '2026-03-10',
    updated_at: '2026-03-17',
    assigned_to: '田中 太郎',
    hypothesis: '攻撃者がSMBプロトコルを利用してネットワーク内を横展開している可能性がある。特に深夜時間帯の異常な内部SMB接続が証拠となる。',
    assumptions: '- 正常なSMBトラフィックパターンは把握済み\n- ベースラインとして過去30日のデータを使用\n- ドメインコントローラーへのアクセスログが取得可能',
    success_criteria: '- 不審なSMBセッションを3つ以上特定できた場合：Positive Finding\n- 異常なパターンが確認できない場合：Negative\n- データ不足の場合：Inconclusive',
    cells: [
      {
        id: 'c1',
        type: 'query',
        collapsed: false,
        query: 'SELECT src_ip, dst_ip, count(*) as connections\nFROM network_logs\nWHERE protocol = "SMB"\n  AND timestamp > NOW() - INTERVAL 7 DAY\n  AND hour(timestamp) BETWEEN 22 AND 6\nGROUP BY src_ip, dst_ip\nHAVING connections > 10\nORDER BY connections DESC',
        time_range: '7d',
        results: {
          columns: ['src_ip', 'dst_ip', 'connections'],
          rows: [
            ['10.0.5.42', '10.0.1.10', '47'],
            ['10.0.5.42', '10.0.1.20', '31'],
            ['10.0.3.88', '10.0.1.10', '18'],
          ],
        },
      },
      {
        id: 'c2',
        type: 'visualization',
        collapsed: false,
        chart_type: 'bar',
      },
      {
        id: 'c3',
        type: 'note',
        collapsed: false,
        note_content: '## 観察メモ\n\n10.0.5.42からDCへの深夜SMB接続が突出して多い。このエンドポイントの通常業務時間は9:00-18:00であり、深夜の接続は異常と判断できる。\n\n次のステップ：該当エンドポイントの認証ログを確認する。',
      },
      {
        id: 'c4',
        type: 'artifact',
        collapsed: false,
        artifact_hash: 'a1b2c3d4e5f6789012345678901234567890abcd',
        artifact_filename: 'suspicious_binary.exe',
        artifact_enrichment: 'VirusTotal: 23/72 検出。MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares)',
      },
      {
        id: 'c5',
        type: 'finding',
        collapsed: false,
        finding_title: '10.0.5.42からのSMBを利用した横展開の疑い',
        finding_severity: 'high',
        finding_description: '深夜時間帯に10.0.5.42から複数のサーバーへ大量のSMB接続が確認された。パターンはPass-the-Hashまたは管理共有を悪用した横展開と一致する。',
        finding_evidence: 'SMBクエリ結果（c1）、VirusTotal（c4）',
        finding_action: '10.0.5.42を即座に隔離し、EDRメモリダンプを取得する。ランサムウェア初動対応手順（rb-001）に従い対応する。',
      },
    ],
    conclusion_summary: '10.0.5.42において明確な横展開の痕跡を確認した。Pass-the-Hashを用いたSMBベースの内部侵害が高い確率で発生していると判断する。',
    verdict: 'positive_finding',
    recommendations: [
      '10.0.5.42を即座にネットワーク隔離する',
      'SMBv1を全環境で無効化する',
      'SMBセッション署名を強制する',
    ],
  },
  {
    id: 'nb-002',
    title: 'Living off the Land調査 — PowerShell',
    description: 'PowerShellを用いたLotL攻撃の痕跡調査。',
    status: 'completed',
    tags: ['lotl', 'powershell', 'fileless'],
    created_at: '2026-02-01',
    updated_at: '2026-02-28',
    assigned_to: '山田 花子',
    hypothesis: '攻撃者がPowerShellを使用してファイルレス攻撃を実施している可能性を調査する。',
    assumptions: '- PowerShellスクリプトブロックログが有効\n- Sysmonがデプロイ済み',
    success_criteria: '- エンコードされたPowerShellコマンドの証拠：Positive\n- 証拠なし：Negative',
    cells: [
      {
        id: 'c1',
        type: 'query',
        collapsed: true,
        query: 'SELECT hostname, command_line FROM process_events WHERE process_name = "powershell.exe" AND command_line LIKE "%EncodedCommand%"',
        time_range: '30d',
        results: { columns: ['hostname', 'command_line'], rows: [] },
      },
    ],
    conclusion_summary: '対象期間中、エンコードされたPowerShellコマンドの実行は確認されなかった。',
    verdict: 'negative',
    recommendations: ['PowerShell Constrained Language Modeの有効化を検討する'],
  },
  {
    id: 'nb-003',
    title: 'DNS Tunneling調査',
    description: 'DNS over HTTPSを悪用したデータ流出の可能性を調査する。',
    status: 'archived',
    tags: ['dns', 'exfiltration', 'tunneling'],
    created_at: '2026-01-05',
    updated_at: '2026-01-31',
    assigned_to: '佐藤 次郎',
    hypothesis: 'DNSクエリを使ったデータ流出が行われている可能性がある。',
    assumptions: '- DNSログが90日分保存されている',
    success_criteria: '- 異常なDNSクエリパターンの特定：Positive',
    cells: [],
    conclusion_summary: 'DNSトンネリングの証拠は確認されなかった。ただし監視継続を推奨する。',
    verdict: 'inconclusive',
    recommendations: ['DNSアナリティクスの強化', 'DoH通信のブロックを検討'],
  },
]

// ── Constants ──────────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<NotebookStatus, string> = {
  active: 'bg-green-900/40 text-green-400 border-green-800/50',
  completed: 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  archived: 'bg-falcon-border text-falcon-muted border-[#2e4060]',
}

const STATUS_LABELS: Record<NotebookStatus, string> = {
  active: 'アクティブ',
  completed: '完了',
  archived: 'アーカイブ',
}

const VERDICT_STYLES: Record<Verdict, string> = {
  positive_finding: 'bg-red-900/40 text-red-400 border-red-800/50',
  negative: 'bg-green-900/40 text-green-400 border-green-800/50',
  inconclusive: 'bg-yellow-900/40 text-yellow-400 border-yellow-800/50',
}

const VERDICT_LABELS: Record<Verdict, string> = {
  positive_finding: 'Positive Finding',
  negative: 'Negative',
  inconclusive: 'Inconclusive',
}

const CELL_TYPE_STYLES: Record<CellType, string> = {
  query: 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  note: 'bg-falcon-border text-falcon-muted border-[#2e4060]',
  visualization: 'bg-purple-900/40 text-purple-400 border-purple-800/50',
  artifact: 'bg-orange-900/40 text-orange-400 border-orange-800/50',
  finding: 'bg-red-900/40 text-red-400 border-red-800/50',
}

const CELL_TYPE_LABELS: Record<CellType, string> = {
  query: 'クエリ',
  note: 'ノート',
  visualization: '可視化',
  artifact: 'アーティファクト',
  finding: '発見事項',
}

const SEVERITY_COLORS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

// ── Mini Bar Chart ─────────────────────────────────────────────────────────────

function MiniBarChart({ data }: { data: { label: string; value: number }[] }) {
  const max = Math.max(...data.map(d => d.value), 1)
  return (
    <div className="flex items-end gap-1 h-24 pt-2">
      {data.map((d, i) => (
        <div key={i} className="flex flex-col items-center gap-1 flex-1">
          <span className="text-[10px] text-falcon-muted">{d.value}</span>
          <div
            className="w-full rounded-t bg-falcon-red/60 hover:bg-falcon-red transition-colors"
            style={{ height: `${(d.value / max) * 64}px` }}
          />
          <span className="text-[9px] text-falcon-subtle truncate w-full text-center">{d.label}</span>
        </div>
      ))}
    </div>
  )
}

function MiniPieChart({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  return (
    <div className="flex items-center gap-6">
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
          {data.reduce<{ offset: number; els: React.JSX.Element[] }>((acc, d, i) => {
            const pct = total ? (d.value / total) * 100 : 0
            acc.els.push(
              <circle
                key={i}
                cx="18" cy="18" r="15.9"
                fill="none"
                stroke={d.color}
                strokeWidth="4"
                strokeDasharray={`${pct} ${100 - pct}`}
                strokeDashoffset={-acc.offset}
              />
            )
            acc.offset += pct
            return acc
          }, { offset: 0, els: [] }).els}
        </svg>
      </div>
      <div className="space-y-1">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
            <span className="text-falcon-muted">{d.label}</span>
            <span className="text-white font-medium">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Cell Components ────────────────────────────────────────────────────────────

function QueryCell({ cell, onUpdate, onRun }: {
  cell: NotebookCell
  onUpdate: (updates: Partial<NotebookCell>) => void
  onRun: () => void
}) {
  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <textarea
          value={cell.query ?? ''}
          onChange={e => onUpdate({ query: e.target.value })}
          rows={4}
          className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-[#c8d6e8] text-xs font-mono focus:outline-hidden focus:border-falcon-red/50 resize-y"
          placeholder="SELECT * FROM events WHERE ..."
        />
        <div className="flex flex-col gap-2 shrink-0">
          <select
            value={cell.time_range ?? '24h'}
            onChange={e => onUpdate({ time_range: e.target.value })}
            className="bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-falcon-muted text-xs focus:outline-hidden"
          >
            <option value="1h">1h</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
            <option value="30d">30d</option>
          </select>
          <button
            onClick={onRun}
            className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-falcon-red text-white text-xs hover:bg-[#c00025] transition-colors"
          >
            <Play className="w-3 h-3" /> 実行
          </button>
        </div>
      </div>
      {cell.results && (
        <div className="overflow-x-auto rounded-sm border border-falcon-border">
          <table className="w-full text-xs">
            <thead className="bg-falcon-border">
              <tr>
                {cell.results.columns.map(col => (
                  <th key={col} className="px-3 py-2 text-left text-falcon-muted font-semibold">{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cell.results.rows.length === 0 ? (
                <tr><td colSpan={cell.results.columns.length} className="px-3 py-4 text-center text-falcon-subtle">結果なし</td></tr>
              ) : (
                cell.results.rows.map((row, i) => (
                  <tr key={i} className="border-t border-falcon-border hover:bg-falcon-surface">
                    {row.map((val, j) => (
                      <td key={j} className="px-3 py-2 text-[#c8d6e8] font-mono">{val}</td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function VisualizationCell({ cell, prevResults }: { cell: NotebookCell; prevResults?: QueryResult }) {
  const chartData = prevResults?.rows.map(row => ({
    label: row[0] ?? '',
    value: parseInt(row[row.length - 1] ?? '0', 10) || 0,
  })) ?? [
    { label: '10.0.5.42', value: 47, color: '#e8002d' },
    { label: '10.0.3.88', value: 18, color: '#f59e0b' },
    { label: '10.0.2.55', value: 9, color: '#3b82f6' },
  ]
  const pieData = [
    { label: 'SMB', value: 47, color: '#e8002d' },
    { label: 'RDP', value: 18, color: '#f59e0b' },
    { label: 'WMI', value: 9, color: '#3b82f6' },
  ]
  return (
    <div>
      <p className="text-xs text-falcon-muted mb-3">直前のクエリ結果を可視化</p>
      {cell.chart_type === 'pie' ? (
        <MiniPieChart data={pieData} />
      ) : (
        <MiniBarChart data={chartData} />
      )}
    </div>
  )
}

function NoteCell({ cell, onUpdate }: { cell: NotebookCell; onUpdate: (u: Partial<NotebookCell>) => void }) {
  return (
    <textarea
      value={cell.note_content ?? ''}
      onChange={e => onUpdate({ note_content: e.target.value })}
      rows={5}
      className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-[#c8d6e8] text-sm focus:outline-hidden focus:border-falcon-red/50 resize-y"
      placeholder="Markdown形式で観察・メモを記録..."
    />
  )
}

function ArtifactCell({ cell, onUpdate }: { cell: NotebookCell; onUpdate: (u: Partial<NotebookCell>) => void }) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-falcon-muted mb-1 block">ファイル名 / IOC</label>
          <input
            value={cell.artifact_filename ?? ''}
            onChange={e => onUpdate({ artifact_filename: e.target.value })}
            className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
            placeholder="filename.exe or IP/domain"
          />
        </div>
        <div>
          <label className="text-xs text-falcon-muted mb-1 block">ハッシュ (MD5/SHA256)</label>
          <input
            value={cell.artifact_hash ?? ''}
            onChange={e => onUpdate({ artifact_hash: e.target.value })}
            className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-xs font-mono text-white focus:outline-hidden focus:border-falcon-red/50"
            placeholder="a1b2c3..."
          />
        </div>
      </div>
      <div>
        <label className="text-xs text-falcon-muted mb-1 block">エンリッチメント結果</label>
        <div className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-xs text-[#c8d6e8]">
          {cell.artifact_enrichment ?? '— エンリッチメント結果がここに表示されます —'}
        </div>
      </div>
      <button
        onClick={() => onUpdate({ artifact_enrichment: 'VirusTotal: 23/72 検出。MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares)。Last seen: 2026-03-09' })}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
      >
        <Search className="w-3.5 h-3.5" /> エンリッチメント実行 (モック)
      </button>
    </div>
  )
}

function FindingCell({ cell, onUpdate }: { cell: NotebookCell; onUpdate: (u: Partial<NotebookCell>) => void }) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-falcon-muted mb-1 block">発見事項タイトル</label>
          <input
            value={cell.finding_title ?? ''}
            onChange={e => onUpdate({ finding_title: e.target.value })}
            className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
          />
        </div>
        <div>
          <label className="text-xs text-falcon-muted mb-1 block">深刻度</label>
          <select
            value={cell.finding_severity ?? 'medium'}
            onChange={e => onUpdate({ finding_severity: e.target.value as any })}
            className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>
      <div>
        <label className="text-xs text-falcon-muted mb-1 block">説明</label>
        <textarea
          value={cell.finding_description ?? ''}
          onChange={e => onUpdate({ finding_description: e.target.value })}
          rows={2}
          className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-[#c8d6e8] focus:outline-hidden focus:border-falcon-red/50 resize-none"
        />
      </div>
      <div>
        <label className="text-xs text-falcon-muted mb-1 block">証拠 (セル参照)</label>
        <input
          value={cell.finding_evidence ?? ''}
          onChange={e => onUpdate({ finding_evidence: e.target.value })}
          className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
        />
      </div>
      <div>
        <label className="text-xs text-falcon-muted mb-1 block">推奨アクション</label>
        <input
          value={cell.finding_action ?? ''}
          onChange={e => onUpdate({ finding_action: e.target.value })}
          className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
        />
      </div>
    </div>
  )
}

// ── Add Cell Bar ───────────────────────────────────────────────────────────────

function AddCellBar({ onAdd }: { onAdd: (type: CellType) => void }) {
  const types: { type: CellType; label: string; icon: any }[] = [
    { type: 'query', label: 'クエリ', icon: Database },
    { type: 'note', label: 'ノート', icon: AlignLeft },
    { type: 'visualization', label: '可視化', icon: BarChart2 },
    { type: 'artifact', label: 'アーティファクト', icon: Paperclip },
    { type: 'finding', label: '発見事項', icon: AlertTriangle },
  ]
  return (
    <div className="flex items-center gap-1 py-1 group">
      <div className="flex-1 h-px bg-falcon-border group-hover:bg-[#2e4060] transition-colors" />
      <div className="flex gap-1">
        {types.map(({ type, label, icon: Icon }) => (
          <button
            key={type}
            onClick={() => onAdd(type)}
            className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] border transition-all hover:scale-105
              opacity-0 group-hover:opacity-100 ${CELL_TYPE_STYLES[type]}`}
          >
            <Icon className="w-3 h-3" /> +{label}
          </button>
        ))}
      </div>
      <div className="flex-1 h-px bg-falcon-border group-hover:bg-[#2e4060] transition-colors" />
    </div>
  )
}

// ── New Notebook Modal ─────────────────────────────────────────────────────────

function NewNotebookModal({ onClose, onCreate }: {
  onClose: () => void
  onCreate: (data: Partial<ThreatNotebook>) => void
}) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [template, setTemplate] = useState('blank')
  const [assignedTo, setAssignedTo] = useState('')

  const TEMPLATES: Record<string, Partial<ThreatNotebook>> = {
    blank: {},
    lateral_movement: {
      hypothesis: '攻撃者がネットワーク内を横展開している可能性がある。',
      assumptions: '- ネットワークログが収集済み\n- ベースラインが設定済み',
      success_criteria: '- 異常なアクセスパターンを3件以上特定：Positive',
    },
    exfiltration: {
      hypothesis: 'データ流出が発生している可能性がある。',
      assumptions: '- DNSおよびネットワークログが収集済み',
      success_criteria: '- 外部へのデータ送信の証拠を発見：Positive',
    },
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-bold text-white">新規ノートブック</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">タイトル *</label>
            <input
              value={title}
              onChange={e => setTitle(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="調査タイトル..."
            />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">説明</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
            />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">仮説テンプレート</label>
            <select
              value={template}
              onChange={e => setTemplate(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden"
            >
              <option value="blank">空白</option>
              <option value="lateral_movement">横展開調査</option>
              <option value="exfiltration">データ流出調査</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">担当者</label>
            <input
              value={assignedTo}
              onChange={e => setAssignedTo(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="アナリスト名"
            />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button
            onClick={() => onCreate({ title, description, assigned_to: assignedTo, ...TEMPLATES[template] })}
            disabled={!title}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c00025] transition-colors disabled:opacity-40"
          >
            作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Share Modal ────────────────────────────────────────────────────────────────

function ShareModal({ onClose }: { onClose: () => void }) {
  const users = ['田中 太郎', '山田 花子', '佐藤 次郎', '鈴木 一郎', '高橋 美咲']
  const [selected, setSelected] = useState<string[]>([])
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 w-full max-w-sm shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-bold text-white">ノートブックを共有</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-2 mb-4">
          {users.map(u => (
            <label key={u} className="flex items-center gap-3 p-2 rounded-sm hover:bg-falcon-border cursor-pointer">
              <input
                type="checkbox"
                checked={selected.includes(u)}
                onChange={() => setSelected(prev => prev.includes(u) ? prev.filter(x => x !== u) : [...prev, u])}
                className="accent-falcon-red"
              />
              <div className="w-6 h-6 rounded-full bg-linear-to-br from-falcon-blue to-[#0044cc] flex items-center justify-center text-[9px] font-bold text-white">
                {u[0]}
              </div>
              <span className="text-sm text-[#c8d6e8]">{u}</span>
            </label>
          ))}
        </div>
        <button
          onClick={onClose}
          className="w-full py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c00025] transition-colors"
        >
          共有 ({selected.length}人)
        </button>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ThreatHuntingNotebookPage() {
  const queryClient = useQueryClient()
  const [selectedId, setSelectedId] = useState<string>('nb-001')
  const [showNewModal, setShowNewModal] = useState(false)
  const [showShareModal, setShowShareModal] = useState(false)

  const { data: notebooks } = useQuery<ThreatNotebook[]>({
    queryKey: ['hunt-notebooks'],
    queryFn: () => apiFetch('/api/v1/threat-hunting/notebooks'),
    staleTime: 30_000,
    ...(USE_MOCK ? { initialData: MOCK_NOTEBOOKS } : {}),
    select: d => d ?? m(MOCK_NOTEBOOKS),
  })

  const allNotebooks = notebooks ?? m(MOCK_NOTEBOOKS)
  const [localNotebooks, setLocalNotebooks] = useState<ThreatNotebook[]>(m(MOCK_NOTEBOOKS))
  const notebooks_ = allNotebooks.length > 0 ? allNotebooks : localNotebooks

  const selected = notebooks_.find(n => n.id === selectedId) ?? notebooks_[0]

  const [editingTitle, setEditingTitle] = useState(false)
  const [localTitle, setLocalTitle] = useState(selected?.title ?? '')

  const updateCell = (cellId: string, updates: Partial<NotebookCell>) => {
    setLocalNotebooks(prev => prev.map(nb => {
      if (nb.id !== selected?.id) return nb
      return { ...nb, cells: nb.cells.map(c => c.id === cellId ? { ...c, ...updates } : c) }
    }))
  }

  const addCell = (type: CellType, afterIdx?: number) => {
    const newCell: NotebookCell = {
      id: `c-${Date.now()}`,
      type,
      collapsed: false,
      ...(type === 'query' ? { query: '', time_range: '24h' } : {}),
      ...(type === 'note' ? { note_content: '' } : {}),
      ...(type === 'artifact' ? { artifact_hash: '', artifact_filename: '' } : {}),
      ...(type === 'visualization' ? { chart_type: 'bar' } : {}),
    }
    setLocalNotebooks(prev => prev.map(nb => {
      if (nb.id !== selected?.id) return nb
      const cells = [...nb.cells]
      const insertIdx = afterIdx !== undefined ? afterIdx + 1 : cells.length
      cells.splice(insertIdx, 0, newCell)
      return { ...nb, cells }
    }))
  }

  const removeCell = (cellId: string) => {
    setLocalNotebooks(prev => prev.map(nb => {
      if (nb.id !== selected?.id) return nb
      return { ...nb, cells: nb.cells.filter(c => c.id !== cellId) }
    }))
  }

  const moveCell = (cellId: string, dir: 'up' | 'down') => {
    setLocalNotebooks(prev => prev.map(nb => {
      if (nb.id !== selected?.id) return nb
      const cells = [...nb.cells]
      const idx = cells.findIndex(c => c.id === cellId)
      if (dir === 'up' && idx === 0) return nb
      if (dir === 'down' && idx === cells.length - 1) return nb
      const swap = dir === 'up' ? idx - 1 : idx + 1
      ;[cells[idx], cells[swap]] = [cells[swap], cells[idx]]
      return { ...nb, cells }
    }))
  }

  const toggleCollapse = (cellId: string) => {
    updateCell(cellId, { collapsed: !selected?.cells.find(c => c.id === cellId)?.collapsed })
  }

  const updateNotebook = (updates: Partial<ThreatNotebook>) => {
    setLocalNotebooks(prev => prev.map(nb => nb.id === selected?.id ? { ...nb, ...updates } : nb))
  }

  const deleteNotebook = (id: string) => {
    setLocalNotebooks(prev => {
      const next = prev.filter(nb => nb.id !== id)
      if (selectedId === id) setSelectedId(next[0]?.id ?? '')
      return next
    })
    apiFetch(`/api/v1/threat-hunting/notebooks/${id}`, { method: 'DELETE' }).catch(() => {})
  }

  const runQuery = (cellId: string) => {
    // Mock: set fake results
    updateCell(cellId, {
      results: {
        columns: ['src_ip', 'dst_ip', 'connections'],
        rows: [['10.0.5.42', '10.0.1.10', '47'], ['10.0.5.42', '10.0.1.20', '31']],
      },
    })
  }

  if (!selected) return (
    <div className="min-h-screen bg-[#070d19] text-white flex flex-col">
      <div className="border-b border-falcon-border px-6 py-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <FileText className="w-4 h-4 text-falcon-red" />
          </div>
          <h1 className="text-base font-bold">ハンティングノートブック</h1>
        </div>
        <button
          onClick={() => setShowNewModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-sm bg-falcon-red text-white hover:bg-[#c00025] text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> 新規ノートブック
        </button>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-16 flex flex-col items-center gap-4 text-center">
          <FileText className="w-12 h-12 text-falcon-subtle" />
          <p className="text-falcon-text font-semibold">ノートブックがありません</p>
          <p className="text-falcon-muted text-sm">「新規ノートブック」ボタンから作成してください。</p>
          <button
            onClick={() => setShowNewModal(true)}
            className="mt-2 flex items-center gap-2 px-4 py-2 rounded-sm bg-falcon-red text-white hover:bg-[#c00025] text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" /> 新規ノートブック
          </button>
        </div>
      </div>
      {showNewModal && (
        <NewNotebookModal
          onClose={() => setShowNewModal(false)}
          onCreate={data => {
            const nb: ThreatNotebook = { id: `nb-${Date.now()}`, title: data.title ?? '新しい調査', description: data.description ?? '', status: 'active', tags: [], created_at: new Date().toISOString().slice(0, 10), updated_at: new Date().toISOString().slice(0, 10), assigned_to: data.assigned_to ?? '', hypothesis: data.hypothesis ?? '', assumptions: data.assumptions ?? '', success_criteria: data.success_criteria ?? '', cells: [], conclusion_summary: '', verdict: null, recommendations: [] }
            setLocalNotebooks(prev => [nb, ...prev]); setSelectedId(nb.id); setShowNewModal(false)
          }}
        />
      )}
    </div>
  )

  return (
    <div className="min-h-screen bg-[#070d19] text-white flex flex-col">
      {/* Header */}
      <div className="border-b border-falcon-border px-6 py-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <FileText className="w-4 h-4 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">脅威ハンティングノートブック</h1>
            <p className="text-xs text-falcon-muted">Threat Hunting Notebook — 調査ワークスペース</p>
          </div>
        </div>
        <button
          onClick={() => setShowNewModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-sm bg-falcon-red text-white hover:bg-[#c00025] text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> 新規ノートブック
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar — Notebook List */}
        <aside className="w-64 shrink-0 border-r border-falcon-border overflow-y-auto">
          <div className="p-3 space-y-1.5">
            {notebooks_.map(nb => (
              <div key={nb.id} className="relative group">
                <button
                  onClick={() => setSelectedId(nb.id)}
                  className={`w-full text-left p-3 rounded border transition-colors
                    ${selectedId === nb.id ? 'bg-falcon-active border-[#2e4060]' : 'bg-falcon-surface border-falcon-border hover:border-[#2e4060]'}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-medium ${STATUS_STYLES[nb.status]}`}>
                      {STATUS_LABELS[nb.status]}
                    </span>
                    {nb.verdict && (
                      <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] ${VERDICT_STYLES[nb.verdict]}`}>
                        {VERDICT_LABELS[nb.verdict]}
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-medium text-white leading-snug mb-1 line-clamp-2 pr-5">{nb.title}</p>
                  <p className="text-[10px] text-falcon-subtle">{nb.created_at} · {displayUser(nb.assigned_to)}</p>
                </button>
                <button
                  onClick={e => {
                    e.stopPropagation()
                    if (confirm(`「${nb.title}」を削除しますか？`)) deleteNotebook(nb.id)
                  }}
                  className="absolute top-2 right-2 p-1 rounded-sm text-falcon-subtle hover:text-falcon-red hover:bg-falcon-red/10 opacity-0 group-hover:opacity-100 transition-all"
                  title="削除"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </aside>

        {/* Main Workspace */}
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-4xl mx-auto p-6 space-y-6">
            {/* Notebook Header */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
              <div className="flex items-start justify-between gap-4 mb-3">
                {editingTitle ? (
                  <input
                    value={localTitle}
                    onChange={e => setLocalTitle(e.target.value)}
                    onBlur={() => { updateNotebook({ title: localTitle }); setEditingTitle(false) }}
                    onKeyDown={e => e.key === 'Enter' && (updateNotebook({ title: localTitle }), setEditingTitle(false))}
                    autoFocus
                    className="flex-1 bg-transparent border-b border-falcon-red/50 text-white text-lg font-bold focus:outline-hidden"
                  />
                ) : (
                  <h2
                    className="flex-1 text-lg font-bold text-white cursor-text hover:text-falcon-text transition-colors"
                    onClick={() => { setLocalTitle(selected.title); setEditingTitle(true) }}
                  >
                    {selected.title}
                  </h2>
                )}
                <div className="flex gap-2">
                  <select
                    value={selected.status}
                    onChange={e => updateNotebook({ status: e.target.value as NotebookStatus })}
                    className={`px-2 py-1 rounded-sm border text-xs bg-transparent focus:outline-hidden ${STATUS_STYLES[selected.status]}`}
                  >
                    <option value="active">アクティブ</option>
                    <option value="completed">完了</option>
                    <option value="archived">アーカイブ</option>
                  </select>
                  <button
                    onClick={() => setShowShareModal(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
                  >
                    <Share2 className="w-3.5 h-3.5" /> 共有
                  </button>
                  <button
                    onClick={() => alert('エクスポート中... (モック)')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> エクスポート
                  </button>
                </div>
              </div>
              <div className="flex items-center gap-3 text-xs text-falcon-muted">
                <span>担当: {displayUser(selected.assigned_to)}</span>
                <span>更新: {selected.updated_at}</span>
              </div>
              <div className="flex flex-wrap gap-1 mt-2">
                {selected.tags.map(tag => (
                  <span key={tag} className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-[10px]">#{tag}</span>
                ))}
              </div>
            </div>

            {/* Hypothesis Section */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <span className="w-1 h-4 bg-falcon-red rounded-full" /> 仮説 / Hypothesis
              </h3>
              {[
                { field: 'hypothesis', label: '仮説 (Hypothesis)' },
                { field: 'assumptions', label: '前提条件 (Assumptions)' },
                { field: 'success_criteria', label: '成功基準 (Success Criteria)' },
              ].map(({ field, label }) => (
                <div key={field}>
                  <label className="text-xs text-falcon-muted mb-1 block">{label}</label>
                  <textarea
                    value={(selected as any)[field] ?? ''}
                    onChange={e => updateNotebook({ [field]: e.target.value })}
                    rows={3}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-[#c8d6e8] focus:outline-hidden focus:border-falcon-red/50 resize-y"
                  />
                </div>
              ))}
            </div>

            {/* Cells */}
            <AddCellBar onAdd={type => addCell(type, -1)} />
            {selected.cells.map((cell, idx) => (
              <div key={cell.id}>
                <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
                  {/* Cell header */}
                  <div className="flex items-center gap-2 px-4 py-2 border-b border-falcon-border bg-[#0a1018]">
                    <button onClick={() => toggleCollapse(cell.id)} className="text-falcon-subtle hover:text-falcon-muted">
                      {cell.collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                    <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-medium ${CELL_TYPE_STYLES[cell.type]}`}>
                      {CELL_TYPE_LABELS[cell.type]}
                    </span>
                    <span className="text-[10px] text-falcon-subtle font-mono">#{idx + 1}</span>
                    <div className="flex-1" />
                    <button onClick={() => moveCell(cell.id, 'up')} className="p-1 text-falcon-subtle hover:text-falcon-muted"><ArrowUp className="w-3.5 h-3.5" /></button>
                    <button onClick={() => moveCell(cell.id, 'down')} className="p-1 text-falcon-subtle hover:text-falcon-muted"><ArrowDown className="w-3.5 h-3.5" /></button>
                    <button onClick={() => removeCell(cell.id)} className="p-1 text-falcon-subtle hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
                  </div>
                  {/* Cell body */}
                  {!cell.collapsed && (
                    <div className="p-4">
                      {cell.type === 'query' && <QueryCell cell={cell} onUpdate={u => updateCell(cell.id, u)} onRun={() => runQuery(cell.id)} />}
                      {cell.type === 'note' && <NoteCell cell={cell} onUpdate={u => updateCell(cell.id, u)} />}
                      {cell.type === 'visualization' && (
                        <VisualizationCell
                          cell={cell}
                          prevResults={selected.cells.find((c, i) => i < idx && c.type === 'query')?.results}
                        />
                      )}
                      {cell.type === 'artifact' && <ArtifactCell cell={cell} onUpdate={u => updateCell(cell.id, u)} />}
                      {cell.type === 'finding' && <FindingCell cell={cell} onUpdate={u => updateCell(cell.id, u)} />}
                    </div>
                  )}
                </div>
                <AddCellBar onAdd={type => addCell(type, idx)} />
              </div>
            ))}

            {/* Conclusion */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <span className="w-1 h-4 bg-falcon-red rounded-full" /> 結論 / Conclusion
              </h3>
              <div>
                <label className="text-xs text-falcon-muted mb-1 block">サマリー</label>
                <textarea
                  value={selected.conclusion_summary}
                  onChange={e => updateNotebook({ conclusion_summary: e.target.value })}
                  rows={3}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-[#c8d6e8] focus:outline-hidden focus:border-falcon-red/50 resize-y"
                />
              </div>
              <div>
                <label className="text-xs text-falcon-muted mb-1 block">判定 (Verdict)</label>
                <div className="flex gap-2">
                  {(['positive_finding', 'negative', 'inconclusive'] as Verdict[]).map(v => (
                    <button
                      key={v}
                      onClick={() => updateNotebook({ verdict: v })}
                      className={`px-3 py-1.5 rounded border text-xs font-medium transition-colors
                        ${selected.verdict === v ? VERDICT_STYLES[v] : 'border-falcon-border text-falcon-subtle hover:text-falcon-muted'}`}
                    >
                      {VERDICT_LABELS[v]}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-xs text-falcon-muted mb-2 block">推奨事項</label>
                <div className="space-y-2">
                  {selected.recommendations.map((rec, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-xs text-falcon-red font-bold">{i + 1}.</span>
                      <input
                        value={rec}
                        onChange={e => {
                          const recs = [...selected.recommendations]
                          recs[i] = e.target.value
                          updateNotebook({ recommendations: recs })
                        }}
                        className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-xs text-[#c8d6e8] focus:outline-hidden focus:border-falcon-red/50"
                      />
                      <button
                        onClick={() => updateNotebook({ recommendations: selected.recommendations.filter((_, j) => j !== i) })}
                        className="p-1 text-falcon-subtle hover:text-red-400"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                  <button
                    onClick={() => updateNotebook({ recommendations: [...selected.recommendations, ''] })}
                    className="flex items-center gap-1 text-xs text-falcon-subtle hover:text-falcon-muted transition-colors"
                  >
                    <Plus className="w-3 h-3" /> 推奨事項を追加
                  </button>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      {showNewModal && (
        <NewNotebookModal
          onClose={() => setShowNewModal(false)}
          onCreate={data => {
            const nb: ThreatNotebook = {
              id: `nb-${Date.now()}`,
              title: data.title ?? '新しい調査',
              description: data.description ?? '',
              status: 'active',
              tags: [],
              created_at: new Date().toISOString().slice(0, 10),
              updated_at: new Date().toISOString().slice(0, 10),
              assigned_to: data.assigned_to ?? '',
              hypothesis: data.hypothesis ?? '',
              assumptions: data.assumptions ?? '',
              success_criteria: data.success_criteria ?? '',
              cells: [],
              conclusion_summary: '',
              verdict: null,
              recommendations: [],
            }
            setLocalNotebooks(prev => [nb, ...prev])
            setSelectedId(nb.id)
            setShowNewModal(false)
          }}
        />
      )}
      {showShareModal && <ShareModal onClose={() => setShowShareModal(false)} />}
    </div>
  )
}
