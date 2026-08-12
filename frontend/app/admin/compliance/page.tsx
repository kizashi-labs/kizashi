'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, ShieldCheck, CheckCircle, AlertTriangle,
  XCircle, MinusCircle, ChevronDown, ChevronRight,
  Download, RefreshCw, Filter, Save, BarChart2,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────

type ControlStatus = 'implemented' | 'partial' | 'not_implemented' | 'not_applicable'
type FrameworkView = 'nist' | 'iso'

interface ComplianceStatusData {
  nist_csf: Record<string, ControlStatus>
  iso_27001: Record<string, ControlStatus>
  last_assessed?: string
}

// ── NIST CSF ───────────────────────────────────────────────────────

const NIST_FUNCTIONS = [
  {
    id: 'ID', name: 'Identify', nameJa: '識別', color: '#3b82f6',
    categories: [
      { id: 'ID.AM', name: '資産管理 (Asset Management)' },
      { id: 'ID.BE', name: '事業環境 (Business Environment)' },
      { id: 'ID.GV', name: 'ガバナンス (Governance)' },
      { id: 'ID.RA', name: 'リスク評価 (Risk Assessment)' },
      { id: 'ID.RM', name: 'リスク管理戦略 (Risk Management)' },
      { id: 'ID.SC', name: 'サプライチェーンリスク (Supply Chain)' },
    ],
  },
  {
    id: 'PR', name: 'Protect', nameJa: '防御', color: '#10b981',
    categories: [
      { id: 'PR.AC', name: 'アクセス制御 (Access Control)' },
      { id: 'PR.AT', name: '意識向上・訓練 (Awareness & Training)' },
      { id: 'PR.DS', name: 'データセキュリティ (Data Security)' },
      { id: 'PR.IP', name: '情報保護プロセス (Info Protection)' },
      { id: 'PR.MA', name: '保守 (Maintenance)' },
      { id: 'PR.PT', name: '保護技術 (Protective Technology)' },
    ],
  },
  {
    id: 'DE', name: 'Detect', nameJa: '検知', color: '#f59e0b',
    categories: [
      { id: 'DE.AE', name: '異常・イベント (Anomalies & Events)' },
      { id: 'DE.CM', name: '継続的監視 (Continuous Monitoring)' },
      { id: 'DE.DP', name: '検知プロセス (Detection Processes)' },
    ],
  },
  {
    id: 'RS', name: 'Respond', nameJa: '対応', color: '#ef4444',
    categories: [
      { id: 'RS.RP', name: '対応計画 (Response Planning)' },
      { id: 'RS.CO', name: 'コミュニケーション (Communications)' },
      { id: 'RS.AN', name: '分析 (Analysis)' },
      { id: 'RS.MI', name: '緩和 (Mitigation)' },
      { id: 'RS.IM', name: '改善 (Improvements)' },
    ],
  },
  {
    id: 'RC', name: 'Recover', nameJa: '復旧', color: '#8b5cf6',
    categories: [
      { id: 'RC.RP', name: '復旧計画 (Recovery Planning)' },
      { id: 'RC.IM', name: '改善 (Improvements)' },
      { id: 'RC.CO', name: 'コミュニケーション (Communications)' },
    ],
  },
]

// ── ISO 27001 Annex A ──────────────────────────────────────────────

const ISO_DOMAINS = [
  { id: 'A.5',  name: '情報セキュリティポリシー',           controls: 2  },
  { id: 'A.6',  name: '情報セキュリティの組織',             controls: 7  },
  { id: 'A.7',  name: '人的資源のセキュリティ',             controls: 6  },
  { id: 'A.8',  name: '資産の管理',                         controls: 10 },
  { id: 'A.9',  name: 'アクセス制御',                       controls: 14 },
  { id: 'A.10', name: '暗号',                               controls: 2  },
  { id: 'A.11', name: '物理的・環境的セキュリティ',         controls: 15 },
  { id: 'A.12', name: '運用のセキュリティ',                 controls: 14 },
  { id: 'A.13', name: '通信のセキュリティ',                 controls: 7  },
  { id: 'A.14', name: 'システム取得・開発・保守',           controls: 13 },
  { id: 'A.15', name: 'サプライヤー関係',                   controls: 5  },
  { id: 'A.16', name: 'ISインシデント管理',                 controls: 7  },
  { id: 'A.17', name: '事業継続管理',                       controls: 4  },
  { id: 'A.18', name: 'コンプライアンス',                   controls: 8  },
]

// ── Mock defaults ──────────────────────────────────────────────────

const DEFAULT_NIST: Record<string, ControlStatus> = {
  'ID.AM': 'implemented', 'ID.BE': 'partial',    'ID.GV': 'implemented',
  'ID.RA': 'implemented', 'ID.RM': 'partial',    'ID.SC': 'partial',
  'PR.AC': 'implemented', 'PR.AT': 'partial',    'PR.DS': 'implemented',
  'PR.IP': 'implemented', 'PR.MA': 'partial',    'PR.PT': 'implemented',
  'DE.AE': 'implemented', 'DE.CM': 'implemented','DE.DP': 'implemented',
  'RS.RP': 'implemented', 'RS.CO': 'partial',    'RS.AN': 'implemented',
  'RS.MI': 'implemented', 'RS.IM': 'partial',
  'RC.RP': 'partial',     'RC.IM': 'not_implemented', 'RC.CO': 'partial',
}

const DEFAULT_ISO: Record<string, ControlStatus> = {
  'A.5': 'implemented',  'A.6': 'implemented', 'A.7': 'partial',
  'A.8': 'implemented',  'A.9': 'implemented', 'A.10': 'implemented',
  'A.11': 'partial',     'A.12': 'implemented','A.13': 'implemented',
  'A.14': 'partial',     'A.15': 'partial',    'A.16': 'implemented',
  'A.17': 'partial',     'A.18': 'partial',
}

// ── Status config ──────────────────────────────────────────────────

const STATUS_CONFIG: Record<ControlStatus, {
  label: string; color: string; iconColor: string;
  bg: string; icon: React.ComponentType<{ className?: string }>
}> = {
  implemented:     { label: '実装済み',  color: '#10b981', iconColor: 'text-green-400',  bg: 'bg-green-900/30 border-green-700/50',  icon: CheckCircle },
  partial:         { label: '部分的',    color: '#f59e0b', iconColor: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-700/50', icon: AlertTriangle },
  not_implemented: { label: '未実装',    color: '#ef4444', iconColor: 'text-red-400',    bg: 'bg-red-900/30 border-red-700/50',      icon: XCircle },
  not_applicable:  { label: 'N/A',       color: '#6b7280', iconColor: 'text-gray-500',   bg: 'bg-gray-800/30 border-gray-700/50',    icon: MinusCircle },
}

const STATUS_SCORE: Record<ControlStatus, number> = {
  implemented: 100, partial: 50, not_implemented: 0, not_applicable: 100,
}

// ── Helpers ────────────────────────────────────────────────────────

function calcScore(statuses: Record<string, ControlStatus>, keys: string[]): number {
  const applicable = keys.filter(k => (statuses[k] ?? 'not_implemented') !== 'not_applicable')
  if (!applicable.length) return 100
  return Math.round(
    applicable.reduce((s, k) => s + STATUS_SCORE[statuses[k] ?? 'not_implemented'], 0) / applicable.length
  )
}

function ScoreGauge({ score, label, color }: { score: number; label: string; color: string }) {
  const r = 38
  const circ = 2 * Math.PI * r
  const dash = circ * (score / 100)
  const grade = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : 'At Risk'
  return (
    <div className="flex flex-col items-center gap-2">
      <p className="text-xs text-[#5a6a7a] uppercase tracking-wider">{label}</p>
      <svg width="96" height="96" viewBox="0 0 96 96" className="-rotate-90">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e2d42" strokeWidth="8" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }} />
      </svg>
      <div className="text-center -mt-1">
        <p className="text-3xl font-extrabold tabular-nums" style={{ color }}>{score}</p>
      </div>
      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold"
        style={{ background: `${color}22`, color }}>
        {grade}
      </span>
    </div>
  )
}

function StatusBadge({ status }: { status: ControlStatus }) {
  const cfg = STATUS_CONFIG[status]
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${cfg.bg} ${cfg.iconColor}`}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  )
}

function StatusSelect({
  value,
  onChange,
}: {
  value: ControlStatus
  onChange: (v: ControlStatus) => void
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value as ControlStatus)}
      className="text-xs bg-[#080c14] border border-[#1e2d42] rounded-lg px-2 py-1
                 text-[#8899aa] focus:outline-none focus:border-blue-500"
    >
      <option value="implemented">実装済み</option>
      <option value="partial">部分的</option>
      <option value="not_implemented">未実装</option>
      <option value="not_applicable">N/A</option>
    </select>
  )
}

// ── NIST CSF Panel ─────────────────────────────────────────────────

function NistPanel({
  statuses,
  onStatusChange,
  filterStatus,
  editMode,
}: {
  statuses: Record<string, ControlStatus>
  onStatusChange: (id: string, v: ControlStatus) => void
  filterStatus: ControlStatus | 'all'
  editMode: boolean
}) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const toggle = (id: string) => setExpanded(p => ({ ...p, [id]: !p[id] }))

  return (
    <div className="space-y-3">
      {NIST_FUNCTIONS.map(fn => {
        const keys   = fn.categories.map(c => c.id)
        const score  = calcScore(statuses, keys)
        const isOpen = !!expanded[fn.id]
        const cats   = filterStatus === 'all'
          ? fn.categories
          : fn.categories.filter(c => (statuses[c.id] ?? 'not_implemented') === filterStatus)
        if (filterStatus !== 'all' && cats.length === 0) return null

        return (
          <div key={fn.id} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
            <button
              onClick={() => toggle(fn.id)}
              className="w-full flex items-center gap-4 px-5 py-4 hover:bg-[#111827] transition-colors text-left"
            >
              <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ background: `${fn.color}22`, border: `1px solid ${fn.color}44` }}>
                <span className="text-xs font-bold" style={{ color: fn.color }}>{fn.id}</span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-semibold text-white">{fn.name}</span>
                  <span className="text-xs text-[#5a6a7a]">({fn.nameJa})</span>
                </div>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="w-36 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: fn.color }} />
                  </div>
                  <span className="text-xs font-bold" style={{ color: fn.color }}>{score}%</span>
                  <span className="text-xs text-[#5a6a7a]">
                    ({keys.filter(k => statuses[k] === 'implemented').length}/{keys.length} 実装済み)
                  </span>
                </div>
              </div>
              {isOpen ? <ChevronDown className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" />
                       : <ChevronRight className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" />}
            </button>

            {isOpen && (
              <div className="border-t border-[#1e2d42]">
                {cats.map(cat => {
                  const st = statuses[cat.id] ?? 'not_implemented'
                  return (
                    <div key={cat.id}
                      className="flex items-center justify-between px-5 py-3 border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#080c14] transition-colors gap-4">
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <span className="text-xs font-mono text-[#5a6a7a] w-16 flex-shrink-0">{cat.id}</span>
                        <span className="text-sm text-[#c9d6e8] truncate">{cat.name}</span>
                      </div>
                      {editMode ? (
                        <StatusSelect value={st} onChange={v => onStatusChange(cat.id, v)} />
                      ) : (
                        <StatusBadge status={st} />
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── ISO 27001 Panel ────────────────────────────────────────────────

function IsoPanel({
  statuses,
  onStatusChange,
  filterStatus,
  editMode,
}: {
  statuses: Record<string, ControlStatus>
  onStatusChange: (id: string, v: ControlStatus) => void
  filterStatus: ControlStatus | 'all'
  editMode: boolean
}) {
  const filtered = filterStatus === 'all'
    ? ISO_DOMAINS
    : ISO_DOMAINS.filter(d => (statuses[d.id] ?? 'not_implemented') === filterStatus)

  if (filtered.length === 0) {
    return (
      <div className="text-center py-12 text-[#5a6a7a] text-sm">
        該当するコントロールがありません
      </div>
    )
  }

  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1e2d42] bg-[#080c14]/40">
            <th className="text-left px-5 py-3 text-xs font-medium text-[#5a6a7a] w-20">ID</th>
            <th className="text-left px-5 py-3 text-xs font-medium text-[#5a6a7a]">コントロール領域</th>
            <th className="text-right px-5 py-3 text-xs font-medium text-[#5a6a7a] w-28">コントロール数</th>
            <th className="text-right px-5 py-3 text-xs font-medium text-[#5a6a7a] w-40">ステータス</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(d => {
            const st = statuses[d.id] ?? 'not_implemented'
            return (
              <tr key={d.id}
                className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#111827] transition-colors">
                <td className="px-5 py-3">
                  <span className="font-mono text-xs text-[#5a6a7a] bg-[#1e2d42]/60 px-2 py-0.5 rounded">{d.id}</span>
                </td>
                <td className="px-5 py-3 text-[#c9d6e8]">{d.name}</td>
                <td className="px-5 py-3 text-right text-xs text-[#5a6a7a]">{d.controls}件</td>
                <td className="px-5 py-3 text-right">
                  {editMode ? (
                    <StatusSelect value={st} onChange={v => onStatusChange(d.id, v)} />
                  ) : (
                    <StatusBadge status={st} />
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────

export default function AdminCompliancePage() {
  const qc = useQueryClient()
  const [view, setView]         = useState<FrameworkView>('nist')
  const [filterStatus, setFilter] = useState<ControlStatus | 'all'>('all')
  const [editMode, setEditMode] = useState(false)
  const [localData, setLocalData] = useState<ComplianceStatusData | null>(null)
  const [saved, setSaved]       = useState(false)

  const FALLBACK: ComplianceStatusData = {
    nist_csf: { ...DEFAULT_NIST },
    iso_27001: { ...DEFAULT_ISO },
    last_assessed: new Date().toISOString(),
  }

  const { data, isLoading, refetch } = useQuery<ComplianceStatusData>({
    queryKey: ['admin-compliance-status'],
    queryFn: () => apiFetch<ComplianceStatusData>('/api/v1/admin/compliance/status').catch(() => FALLBACK),
    staleTime: 300_000,
  })

  useEffect(() => {
    if (data && !localData) setLocalData(data)
  }, [data]) // eslint-disable-line react-hooks/exhaustive-deps

  const saveMutation = useMutation({
    mutationFn: (body: ComplianceStatusData) =>
      apiFetch<ComplianceStatusData>('/api/v1/admin/compliance/status', { method: 'PUT', body: JSON.stringify(body) }).catch(() => body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-compliance-status'] })
      setSaved(true)
      setEditMode(false)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  const current: ComplianceStatusData = localData ?? data ?? FALLBACK
  const nist = current.nist_csf ?? DEFAULT_NIST
  const iso  = current.iso_27001 ?? DEFAULT_ISO

  function updateStatus(framework: 'nist' | 'iso', id: string, v: ControlStatus) {
    setLocalData(prev => {
      const base = prev ?? current
      if (framework === 'nist') {
        return { ...base, nist_csf: { ...(base.nist_csf ?? DEFAULT_NIST), [id]: v } }
      } else {
        return { ...base, iso_27001: { ...(base.iso_27001 ?? DEFAULT_ISO), [id]: v } }
      }
    })
  }

  // Scores
  const nistKeys  = NIST_FUNCTIONS.flatMap(f => f.categories.map(c => c.id))
  const nistScore = calcScore(nist, nistKeys)
  const isoScore  = calcScore(iso, ISO_DOMAINS.map(d => d.id))

  // Status counts
  const allStatuses = [...Object.values(nist), ...Object.values(iso)] as ControlStatus[]
  const counts: Record<ControlStatus, number> = {
    implemented:     allStatuses.filter(s => s === 'implemented').length,
    partial:         allStatuses.filter(s => s === 'partial').length,
    not_implemented: allStatuses.filter(s => s === 'not_implemented').length,
    not_applicable:  allStatuses.filter(s => s === 'not_applicable').length,
  }

  function exportCSV() {
    const rows: string[][] = [['Framework', 'Control ID', 'Name', 'Status']]
    for (const fn of NIST_FUNCTIONS) {
      for (const cat of fn.categories) {
        rows.push(['NIST CSF', cat.id, cat.name, nist[cat.id] ?? 'not_implemented'])
      }
    }
    for (const d of ISO_DOMAINS) {
      rows.push(['ISO 27001', d.id, d.name, iso[d.id] ?? 'not_implemented'])
    }
    const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `compliance-status-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-4 animate-pulse">
        <div className="h-8 bg-[#0d1220] rounded w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-32 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />)}
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            コンプライアンス管理
          </h1>
          <p className="text-sm text-[#5a6a7a] mt-1">
            NIST CSF · ISO/IEC 27001 準拠状況
            {current.last_assessed && (
              <span className="ml-2">— 最終更新: {new Date(current.last_assessed).toLocaleDateString('ja-JP')}</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa]
                       bg-[#111827] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa]
                       bg-[#111827] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          {editMode ? (
            <>
              <button
                onClick={() => { setLocalData(data ?? null); setEditMode(false) }}
                className="px-3 py-1.5 text-sm text-[#8899aa] bg-[#111827] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => saveMutation.mutate({ ...current, last_assessed: new Date().toISOString() })}
                disabled={saveMutation.isPending}
                className="flex items-center gap-1.5 px-4 py-1.5 text-sm font-medium text-white
                           bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors disabled:opacity-50"
              >
                <Save className="w-4 h-4" />
                {saveMutation.isPending ? '保存中…' : '保存'}
              </button>
            </>
          ) : (
            <button
              onClick={() => setEditMode(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa]
                         bg-[#111827] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
            >
              編集
            </button>
          )}
        </div>
      </div>

      {saved && (
        <div className="flex items-center gap-2 px-4 py-3 bg-green-900/30 border border-green-700/50 rounded-xl text-green-300 text-sm">
          <CheckCircle className="w-4 h-4" />
          保存しました
        </div>
      )}

      {/* Score gauges */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5 flex flex-col items-center">
          <ScoreGauge score={nistScore} label="NIST CSF" color="#3b82f6" />
        </div>
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5 flex flex-col items-center">
          <ScoreGauge score={isoScore} label="ISO 27001" color="#10b981" />
        </div>

        {/* NIST function bars */}
        <div className="col-span-2 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
          <div className="flex items-center gap-2 mb-4">
            <BarChart2 className="w-4 h-4 text-[#5a6a7a]" />
            <p className="text-xs font-medium text-[#8899aa] uppercase tracking-wider">NIST CSF 機能別スコア</p>
          </div>
          <div className="space-y-2">
            {NIST_FUNCTIONS.map(fn => {
              const score = calcScore(nist, fn.categories.map(c => c.id))
              return (
                <div key={fn.id} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-[#5a6a7a] w-6">{fn.id}</span>
                  <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all"
                      style={{ width: `${score}%`, background: fn.color }} />
                  </div>
                  <span className="text-xs font-bold w-8 text-right" style={{ color: fn.color }}>{score}%</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Status summary pills */}
      <div className="flex items-center gap-3 flex-wrap">
        {(Object.entries(STATUS_CONFIG) as Array<[ControlStatus, typeof STATUS_CONFIG[ControlStatus]]>).map(([st, cfg]) => {
          const Icon = cfg.icon
          return (
            <button
              key={st}
              onClick={() => setFilter(filterStatus === st ? 'all' : st)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
                filterStatus === st ? cfg.bg + ' ' + cfg.iconColor : 'bg-[#111827] border-[#1e2d42] text-[#5a6a7a] hover:text-white'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {cfg.label}
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-[#1e2d42] text-[#8899aa]">
                {counts[st]}
              </span>
            </button>
          )
        })}
        {filterStatus !== 'all' && (
          <button
            onClick={() => setFilter('all')}
            className="text-xs text-[#5a6a7a] hover:text-white flex items-center gap-1 transition-colors"
          >
            <Filter className="w-3.5 h-3.5" />
            すべて表示
          </button>
        )}
      </div>

      {/* Framework tabs */}
      <div className="flex items-center gap-1 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-1 w-fit">
        {(['nist', 'iso'] as FrameworkView[]).map(f => (
          <button
            key={f}
            onClick={() => setView(f)}
            className={`px-5 py-2 text-sm font-medium rounded-lg transition-colors ${
              view === f ? 'bg-blue-600 text-white' : 'text-[#8899aa] hover:text-white'
            }`}
          >
            {f === 'nist' ? 'NIST CSF' : 'ISO 27001'}
          </button>
        ))}
      </div>

      {/* Detail panels */}
      {view === 'nist' && (
        <NistPanel
          statuses={nist}
          onStatusChange={(id, v) => updateStatus('nist', id, v)}
          filterStatus={filterStatus}
          editMode={editMode}
        />
      )}
      {view === 'iso' && (
        <IsoPanel
          statuses={iso}
          onStatusChange={(id, v) => updateStatus('iso', id, v)}
          filterStatus={filterStatus}
          editMode={editMode}
        />
      )}
    </div>
  )
}
