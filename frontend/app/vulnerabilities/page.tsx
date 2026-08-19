'use client'

import { useState, useMemo, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { DataUnavailable } from '@/components/DataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import {
  ShieldAlert, AlertTriangle, AlertCircle, Info, Search,
  X, ExternalLink, ChevronLeft, ChevronRight, RefreshCw,
  CheckSquare, Square, Download, Ticket, Monitor,
} from 'lucide-react'
import { m, USE_MOCK } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

interface SoftwareInventoryItem {
  id: string
  agent_id: string
  hostname?: string
  name: string
  version?: string
  cve_id?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
  cvss_score?: number
  status?: 'open' | 'patched' | 'accepted' | 'in_progress'
  detected_at?: string
  fixed_version?: string
}

interface Agent {
  id: string
  hostname: string
}

interface VulnRow {
  id: string
  agent_id: string
  hostname: string
  name: string
  version: string
  fixed_version: string
  cve_id: string
  cvss_score: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'patched' | 'accepted' | 'in_progress'
  detected_at: string
  isMock: boolean
}

// ── Constants ──────────────────────────────────────────────────────────────

const SEV_CONFIG = {
  critical: {
    label: 'Critical',
    badgeClass: 'bg-red-900/60 border-red-700 text-red-300',
    barColor: '#ef4444',
    pieColor: '#dc2626',
    iconClass: 'text-red-400',
    cardClass: 'bg-red-900/20 border-red-800',
    countClass: 'text-red-300',
    tabActive: 'bg-red-900/60 text-red-300 border-red-700',
    Icon: AlertTriangle,
  },
  high: {
    label: 'High',
    badgeClass: 'bg-orange-900/60 border-orange-700 text-orange-300',
    barColor: '#f97316',
    pieColor: '#ea580c',
    iconClass: 'text-orange-400',
    cardClass: 'bg-orange-900/20 border-orange-800',
    countClass: 'text-orange-300',
    tabActive: 'bg-orange-900/60 text-orange-300 border-orange-700',
    Icon: AlertTriangle,
  },
  medium: {
    label: 'Medium',
    badgeClass: 'bg-yellow-900/50 border-yellow-700 text-yellow-300',
    barColor: '#eab308',
    pieColor: '#ca8a04',
    iconClass: 'text-yellow-400',
    cardClass: 'bg-yellow-900/20 border-yellow-800',
    countClass: 'text-yellow-300',
    tabActive: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    Icon: AlertCircle,
  },
  low: {
    label: 'Low',
    badgeClass: 'bg-blue-900/40 border-blue-700 text-blue-300',
    barColor: '#3b82f6',
    pieColor: '#2563eb',
    iconClass: 'text-blue-400',
    cardClass: 'bg-blue-900/20 border-blue-800',
    countClass: 'text-blue-300',
    tabActive: 'bg-blue-900/40 text-blue-300 border-blue-700',
    Icon: Info,
  },
} as const

const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  open:        { label: '未対処',       className: 'bg-red-900/40 border-red-700 text-red-300' },
  patched:     { label: 'パッチ適用済', className: 'bg-green-900/40 border-green-700 text-green-300' },
  accepted:    { label: 'リスク受容',   className: 'bg-gray-700/60 border-gray-600 text-gray-300' },
  in_progress: { label: '対応中',       className: 'bg-blue-900/40 border-blue-700 text-blue-300' },
}

const PAGE_SIZE = 20

// ── Mock CVE generation ────────────────────────────────────────────────────

const MOCK_CVE_DB: Record<string, { cve_id: string; cvss_score: number; severity: 'critical' | 'high' | 'medium' | 'low'; fixed_version: string }[]> = {
  openssl:    [{ cve_id: 'CVE-2023-0286', cvss_score: 9.8, severity: 'critical', fixed_version: '3.0.8' }, { cve_id: 'CVE-2022-4450', cvss_score: 7.5, severity: 'high', fixed_version: '3.0.8' }],
  log4j:      [{ cve_id: 'CVE-2021-44228', cvss_score: 10.0, severity: 'critical', fixed_version: '2.17.1' }, { cve_id: 'CVE-2021-45046', cvss_score: 9.0, severity: 'critical', fixed_version: '2.17.0' }],
  curl:       [{ cve_id: 'CVE-2023-38545', cvss_score: 9.8, severity: 'critical', fixed_version: '8.4.0' }],
  openssh:    [{ cve_id: 'CVE-2023-38408', cvss_score: 9.8, severity: 'critical', fixed_version: '9.3p2' }],
  apache:     [{ cve_id: 'CVE-2021-41773', cvss_score: 9.8, severity: 'critical', fixed_version: '2.4.51' }, { cve_id: 'CVE-2021-42013', cvss_score: 9.8, severity: 'critical', fixed_version: '2.4.51' }],
  nginx:      [{ cve_id: 'CVE-2022-41741', cvss_score: 7.1, severity: 'high', fixed_version: '1.23.2' }],
  bash:       [{ cve_id: 'CVE-2014-6271', cvss_score: 9.8, severity: 'critical', fixed_version: '4.3-30' }],
  python:     [{ cve_id: 'CVE-2023-24329', cvss_score: 7.5, severity: 'high', fixed_version: '3.11.3' }],
  php:        [{ cve_id: 'CVE-2023-0662', cvss_score: 7.5, severity: 'high', fixed_version: '8.2.3' }],
  zlib:       [{ cve_id: 'CVE-2022-37434', cvss_score: 9.8, severity: 'critical', fixed_version: '1.2.13' }],
  libssl:     [{ cve_id: 'CVE-2023-0215', cvss_score: 7.5, severity: 'high', fixed_version: '3.0.8' }],
  glibc:      [{ cve_id: 'CVE-2023-4911', cvss_score: 7.8, severity: 'high', fixed_version: '2.38-1' }],
  sudo:       [{ cve_id: 'CVE-2021-3156', cvss_score: 7.8, severity: 'high', fixed_version: '1.9.5p2' }],
  expat:      [{ cve_id: 'CVE-2022-25236', cvss_score: 9.8, severity: 'critical', fixed_version: '2.4.5' }],
  git:        [{ cve_id: 'CVE-2023-23946', cvss_score: 6.5, severity: 'medium', fixed_version: '2.39.2' }],
}

// 呼び出し側でも USE_MOCK を見ているが、ここでも m() を通す。将来ガード無しの
// 呼び出しが増えたときに、架空の CVE が本番の脆弱性一覧に混ざるのを防ぐ
// （モック無効時は {} になり、ループが回らず null が返る）。
function getMockCVEs(name: string) {
  const lower = name.toLowerCase()
  for (const [key, entries] of Object.entries(m(MOCK_CVE_DB))) {
    if (lower.includes(key)) return entries
  }
  return null
}

function generateRows(
  items: SoftwareInventoryItem[],
  agentMap: Record<string, string>,
): { rows: VulnRow[]; hasMock: boolean } {
  const rows: VulnRow[] = []
  let hasMock = false

  for (const item of items) {
    const hostname = item.hostname ?? agentMap[item.agent_id] ?? item.agent_id.slice(0, 8)
    const detected = item.detected_at ?? new Date().toISOString()

    if (item.cve_id) {
      rows.push({
        id: item.id,
        agent_id: item.agent_id,
        hostname,
        name: item.name,
        version: item.version ?? '—',
        fixed_version: item.fixed_version ?? '—',
        cve_id: item.cve_id,
        cvss_score: item.cvss_score ?? 0,
        severity: item.severity ?? 'low',
        status: (item.status ?? 'open') as VulnRow['status'],
        detected_at: detected,
        isMock: false,
      })
    } else if (USE_MOCK) {
      const mocks = getMockCVEs(item.name)
      if (mocks) {
        hasMock = true
        for (const m of mocks) {
          rows.push({
            id: `${item.id}-${m.cve_id}`,
            agent_id: item.agent_id,
            hostname,
            name: item.name,
            version: item.version ?? '—',
            fixed_version: m.fixed_version,
            cve_id: m.cve_id,
            cvss_score: m.cvss_score,
            severity: m.severity,
            status: 'open',
            detected_at: detected,
            isMock: true,
          })
        }
      }
    }
  }
  return { rows, hasMock }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtDate(s: string) {
  try {
    return new Date(s).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
  } catch {
    return s
  }
}

function SeverityBadge({ sev }: { sev: 'critical' | 'high' | 'medium' | 'low' }) {
  const cfg = SEV_CONFIG[sev]
  return (
    <span className={`inline-block px-2 py-0.5 text-[11px] font-semibold rounded-sm border ${cfg.badgeClass}`}>
      {cfg.label}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? { label: status, className: 'bg-gray-700 border-gray-600 text-gray-300' }
  return (
    <span className={`inline-block px-2 py-0.5 text-[11px] font-medium rounded-sm border ${cfg.className}`}>
      {cfg.label}
    </span>
  )
}

// ── Custom Recharts Tooltip ────────────────────────────────────────────────

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number }[]; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#1a2640] border border-[#1e2d42] rounded-lg px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-[#8899aa] mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} className="text-white font-semibold">{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

// ── Affected Endpoints Modal ───────────────────────────────────────────────

function AffectedEndpointsModal({
  cveId,
  hostnames,
  onClose,
}: {
  cveId: string
  hostnames: string[]
  onClose: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={onClose}>
      <div
        className="bg-gray-800 border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-md mx-4"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Monitor className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-semibold text-white">影響エンドポイント</span>
          </div>
          <button onClick={onClose} className="text-[#5a6a7a] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <span className="font-mono text-blue-400 text-sm font-semibold">{cveId}</span>
          <span className="ml-2 text-xs text-[#5a6a7a]">({hostnames.length} エンドポイント)</span>
        </div>
        <div className="px-5 py-3 max-h-64 overflow-y-auto">
          {hostnames.length === 0 ? (
            <p className="text-sm text-[#5a6a7a]">影響エンドポイントなし</p>
          ) : (
            <ul className="space-y-1.5">
              {hostnames.map((h, i) => (
                <li key={i} className="flex items-center gap-2 text-sm">
                  <Monitor className="w-3.5 h-3.5 text-[#5a6a7a] shrink-0" />
                  <span className="font-mono text-[#e2e8f4]">{h}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="px-5 py-3 border-t border-[#1e2d42] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-sm text-[#8899aa] hover:text-white border border-[#1e2d42] rounded-lg hover:border-[#2e3d52] transition-colors"
          >
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Create Ticket Modal ────────────────────────────────────────────────────

interface TicketForm {
  system: 'jira' | 'servicenow'
  title: string
  description: string
  priority: string
  assignee: string
}

function CreateTicketModal({
  row,
  onClose,
  onSubmit,
  isLoading,
}: {
  row: VulnRow | null
  onClose: () => void
  onSubmit: (form: TicketForm) => void
  isLoading: boolean
}) {
  const [form, setForm] = useState<TicketForm>({
    system: 'jira',
    title: row ? `[${row.severity.toUpperCase()}] ${row.cve_id} - ${row.name} ${row.version}` : '',
    description: row
      ? `CVE: ${row.cve_id}\nパッケージ: ${row.name} ${row.version}\n修正バージョン: ${row.fixed_version}\nCVSSスコア: ${row.cvss_score}\n影響ホスト: ${row.hostname}`
      : '',
    priority: row?.severity === 'critical' ? 'Highest' : row?.severity === 'high' ? 'High' : 'Medium',
    assignee: '',
  })

  if (!row) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={onClose}>
      <div
        className="bg-gray-800 border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-lg mx-4"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Ticket className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-semibold text-white">チケット作成</span>
          </div>
          <button onClick={onClose} className="text-[#5a6a7a] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-3">
          {/* System */}
          <div>
            <label className="text-xs text-[#8899aa] mb-1 block">チケットシステム</label>
            <div className="flex gap-2">
              {(['jira', 'servicenow'] as const).map(sys => (
                <button
                  key={sys}
                  onClick={() => setForm(f => ({ ...f, system: sys }))}
                  className={`px-4 py-1.5 text-sm rounded-lg border transition-colors ${
                    form.system === sys
                      ? 'bg-blue-700 border-blue-600 text-white'
                      : 'border-[#1e2d42] text-[#8899aa] hover:border-[#2e3d52]'
                  }`}
                >
                  {sys === 'jira' ? 'Jira' : 'ServiceNow'}
                </button>
              ))}
            </div>
          </div>

          {/* Title */}
          <div>
            <label className="text-xs text-[#8899aa] mb-1 block">タイトル</label>
            <input
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg text-white focus:outline-hidden focus:border-blue-500 transition-colors"
            />
          </div>

          {/* Priority */}
          <div>
            <label className="text-xs text-[#8899aa] mb-1 block">優先度</label>
            <select
              value={form.priority}
              onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg text-white focus:outline-hidden focus:border-blue-500 transition-colors"
            >
              {['Highest', 'High', 'Medium', 'Low', 'Lowest'].map(p => (
                <option key={p} value={p} className="bg-gray-900">{p}</option>
              ))}
            </select>
          </div>

          {/* Assignee */}
          <div>
            <label className="text-xs text-[#8899aa] mb-1 block">担当者</label>
            <input
              value={form.assignee}
              onChange={e => setForm(f => ({ ...f, assignee: e.target.value }))}
              placeholder="担当者名またはメールアドレス"
              className="w-full px-3 py-2 text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-blue-500 transition-colors"
            />
          </div>

          {/* Description */}
          <div>
            <label className="text-xs text-[#8899aa] mb-1 block">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={4}
              className="w-full px-3 py-2 text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg text-white focus:outline-hidden focus:border-blue-500 transition-colors resize-none font-mono"
            />
          </div>
        </div>

        <div className="px-5 py-3 border-t border-[#1e2d42] flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-sm text-[#8899aa] hover:text-white border border-[#1e2d42] rounded-lg hover:border-[#2e3d52] transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSubmit(form)}
            disabled={isLoading || !form.title.trim()}
            className="px-4 py-1.5 text-sm bg-purple-700 hover:bg-purple-600 text-white rounded-lg disabled:opacity-50 transition-colors flex items-center gap-1.5"
          >
            {isLoading ? (
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Ticket className="w-3.5 h-3.5" />
            )}
            作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Bulk Actions Bar ───────────────────────────────────────────────────────

function BulkActionsBar({
  selectedIds,
  allPageIds,
  onSelectAll,
  onClearAll,
  onBulkStatus,
  onExport,
}: {
  selectedIds: Set<string>
  allPageIds: string[]
  onSelectAll: () => void
  onClearAll: () => void
  onBulkStatus: (status: string) => void
  onExport: () => void
}) {
  const count = selectedIds.size
  const allSelected = allPageIds.length > 0 && allPageIds.every(id => selectedIds.has(id))

  return (
    <div className="flex items-center gap-3 bg-blue-900/30 border border-blue-700/50 rounded-xl px-4 py-2.5">
      <button
        onClick={allSelected ? onClearAll : onSelectAll}
        className="flex items-center gap-1.5 text-sm text-blue-300 hover:text-white transition-colors"
      >
        {allSelected ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
        <span>{count > 0 ? `${count} 件選択中` : 'すべて選択'}</span>
      </button>

      {count > 0 && (
        <>
          <div className="h-4 w-px bg-[#1e2d42]" />

          <span className="text-xs text-[#5a6a7a]">ステータス変更:</span>
          {[
            { v: 'in_progress', l: '対応中' },
            { v: 'patched', l: 'パッチ済' },
            { v: 'accepted', l: 'リスク受容' },
            { v: 'open', l: '未対処に戻す' },
          ].map(opt => (
            <button
              key={opt.v}
              onClick={() => onBulkStatus(opt.v)}
              className="px-2.5 py-1 text-xs rounded-sm border border-[#1e2d42] text-[#8899aa] hover:border-blue-600 hover:text-blue-300 transition-colors"
            >
              {opt.l}
            </button>
          ))}

          <div className="h-4 w-px bg-[#1e2d42]" />

          <button
            onClick={onExport}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-sm border border-[#1e2d42] text-[#8899aa] hover:border-green-600 hover:text-green-300 transition-colors"
          >
            <Download className="w-3 h-3" />
            エクスポート
          </button>

          <button
            onClick={onClearAll}
            className="ml-auto text-[#5a6a7a] hover:text-white transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </>
      )}
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function VulnerabilityDashboard() {
  const qc = useQueryClient()

  const [severityTab, setSeverityTab]   = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [search, setSearch]             = useState('')
  const [page, setPage]                 = useState(1)
  const [selectedIds, setSelectedIds]   = useState<Set<string>>(new Set())

  // Affected endpoints modal
  const [endpointsModal, setEndpointsModal] = useState<{ cveId: string; hostnames: string[] } | null>(null)
  // Create ticket modal
  const [ticketRow, setTicketRow] = useState<VulnRow | null>(null)

  // ── Data fetching ──────────────────────────────────────────────────────

  const { data: inventoryData, isLoading: invLoading, error: invError, refetch } = useQuery<{ data: SoftwareInventoryItem[] } | SoftwareInventoryItem[]>({
    queryKey: ['vuln-dashboard-inventory'],
    queryFn: () => apiFetch('/api/v1/software-inventory'),
    staleTime: 60_000,
  })

  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-list-vuln'],
    queryFn: () => apiFetch('/api/v1/agents?limit=500'),
    staleTime: 120_000,
  })

  // ── Per-row status mutation ──────────────────────────────────────────

  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/v1/software-inventory/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vuln-dashboard-inventory'] }),
  })

  // ── Bulk status mutation ──────────────────────────────────────────────

  const bulkStatusMut = useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: string }) =>
      apiFetch('/api/v1/software-inventory/bulk', {
        method: 'PATCH',
        body: JSON.stringify({ ids, status }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vuln-dashboard-inventory'] })
      setSelectedIds(new Set())
    },
  })

  // ── Ticket mutation (SOAR integration) ───────────────────────────────

  const ticketMut = useMutation({
    mutationFn: (form: TicketForm & { cve_id: string }) =>
      apiFetch('/api/v1/soar/tickets', {
        method: 'POST',
        body: JSON.stringify(form),
      }),
    onSuccess: () => {
      setTicketRow(null)
      alert('チケットを作成しました')
    },
  })

  // ── Derived data ───────────────────────────────────────────────────────

  const rawItems: SoftwareInventoryItem[] = useMemo(() => {
    if (!inventoryData) return []
    if (Array.isArray(inventoryData)) return inventoryData
    return (inventoryData as { data: SoftwareInventoryItem[] }).data ?? []
  }, [inventoryData])

  const agentMap = useMemo(() => {
    const agents: Agent[] = agentsData?.agents ?? agentsData?.data ?? []
    return Object.fromEntries(agents.map(a => [a.id, a.hostname]))
  }, [agentsData])

  const { rows: allRows, hasMock } = useMemo(() => generateRows(rawItems, agentMap), [rawItems, agentMap])

  // ── Per-CVE affected endpoints map ────────────────────────────────────

  const cveHostnamesMap = useMemo(() => {
    const map: Record<string, string[]> = {}
    for (const row of allRows) {
      if (!map[row.cve_id]) map[row.cve_id] = []
      if (!map[row.cve_id].includes(row.hostname)) map[row.cve_id].push(row.hostname)
    }
    return map
  }, [allRows])

  // ── Severity counts for tab badges ───────────────────────────────────

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const r of allRows) counts[r.severity] = (counts[r.severity] ?? 0) + 1
    return counts
  }, [allRows])

  // ── Filter ─────────────────────────────────────────────────────────────

  const filtered = useMemo(() => {
    return allRows.filter(r => {
      if (severityTab !== 'all' && r.severity !== severityTab) return false
      if (statusFilter && r.status !== statusFilter) return false
      if (search) {
        const q = search.toLowerCase()
        if (!r.cve_id.toLowerCase().includes(q) && !r.name.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [allRows, severityTab, statusFilter, search])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safePage   = Math.min(page, totalPages)
  const pageRows   = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE)
  const pageIds    = pageRows.map(r => r.id)

  // ── Stats ──────────────────────────────────────────────────────────────

  const stats = useMemo(() => {
    const open = allRows.filter(r => r.status === 'open')
    return {
      total:      allRows.length,
      critical:   open.filter(r => r.severity === 'critical').length,
      high:       open.filter(r => r.severity === 'high').length,
      unresolved: open.length,
    }
  }, [allRows])

  // ── Charts data ────────────────────────────────────────────────────────

  const pieData = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const r of allRows) counts[r.severity] = (counts[r.severity] ?? 0) + 1
    return (Object.keys(SEV_CONFIG) as (keyof typeof SEV_CONFIG)[])
      .filter(k => counts[k] > 0)
      .map(k => ({ name: SEV_CONFIG[k].label, value: counts[k], color: SEV_CONFIG[k].pieColor }))
  }, [allRows])

  const barData = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const r of allRows) counts[r.name] = (counts[r.name] ?? 0) + 1
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name: name.length > 14 ? name.slice(0, 13) + '…' : name, count }))
  }, [allRows])

  // ── Selection helpers ─────────────────────────────────────────────────

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const selectAllPage = useCallback(() => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      pageIds.forEach(id => next.add(id))
      return next
    })
  }, [pageIds])

  const clearAll = useCallback(() => setSelectedIds(new Set()), [])

  // ── Bulk export ───────────────────────────────────────────────────────

  const exportSelected = useCallback(() => {
    const rows = filtered.filter(r => selectedIds.has(r.id))
    const csv = [
      ['CVE ID', 'パッケージ', 'バージョン', '修正バージョン', '重大度', 'CVSSスコア', 'ステータス', 'ホスト名', '検出日'].join(','),
      ...rows.map(r => [
        r.cve_id, r.name, r.version, r.fixed_version, r.severity,
        r.cvss_score.toString(), r.status, r.hostname, fmtDate(r.detected_at),
      ].map(v => `"${v}"`).join(',')),
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vulnerabilities_export_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [filtered, selectedIds])

  const isLoading = invLoading

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="bg-gray-900 min-h-screen text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-8 space-y-6">

        {/* 下のカードは取得に失敗すると 0件 を表示します。
            その 0 が「脆弱性なし」なのかどうかをここで言う。 */}
        <DataUnavailable error={invError} what="ソフトウェアインベントリ" onRetry={refetch} />

        <PageSaveFailed />
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-700/60 rounded-xl flex items-center justify-center shrink-0">
              <ShieldAlert className="w-5 h-5 text-red-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">脆弱性ダッシュボード</h1>
              <p className="text-sm text-[#8899aa] mt-0.5">
                ソフトウェアインベントリを基にした CVE・脆弱性のリアルタイム追跡
              </p>
            </div>
          </div>
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="p-2 rounded-lg text-[#5a6a7a] hover:text-white hover:bg-gray-800 transition-colors disabled:opacity-40 shrink-0"
            title="更新"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* ── Heuristic banner ───────────────────────────────────────────── */}
        {hasMock && (
          <div className="flex items-center gap-3 bg-amber-900/30 border border-amber-700/60 rounded-xl px-4 py-3 text-sm text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>CVEデータはソフトウェアインベントリから生成されたヒューリスティックデータです</span>
          </div>
        )}

        {/* ── Stats row ──────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {/* Total */}
          <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-4">
            <p className="text-xs text-[#5a6a7a] mb-1">総脆弱性数</p>
            <p className="text-3xl font-bold text-white">{stats.total}</p>
            <p className="text-xs text-[#5a6a7a] mt-0.5">全ステータス含む</p>
          </div>
          {/* Critical */}
          <button
            onClick={() => { setSeverityTab(severityTab === 'critical' ? 'all' : 'critical'); setPage(1) }}
            className={`bg-gray-800 border rounded-xl p-4 text-left transition-all hover:opacity-100 ${
              severityTab === 'critical' ? 'ring-2 ring-red-500 border-red-700' : 'border-[#1e2d42] opacity-80'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
              <p className="text-xs text-red-400 font-semibold">重大 (Critical)</p>
            </div>
            <p className="text-3xl font-bold text-red-300">{stats.critical}</p>
            <p className="text-xs text-[#5a6a7a] mt-0.5">未対処</p>
          </button>
          {/* High */}
          <button
            onClick={() => { setSeverityTab(severityTab === 'high' ? 'all' : 'high'); setPage(1) }}
            className={`bg-gray-800 border rounded-xl p-4 text-left transition-all hover:opacity-100 ${
              severityTab === 'high' ? 'ring-2 ring-orange-500 border-orange-700' : 'border-[#1e2d42] opacity-80'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
              <p className="text-xs text-orange-400 font-semibold">高 (High)</p>
            </div>
            <p className="text-3xl font-bold text-orange-300">{stats.high}</p>
            <p className="text-xs text-[#5a6a7a] mt-0.5">未対処</p>
          </button>
          {/* Unresolved */}
          <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-4">
            <p className="text-xs text-[#5a6a7a] mb-1">未対処</p>
            <p className="text-3xl font-bold text-white">{stats.unresolved}</p>
            <p className="text-xs text-[#5a6a7a] mt-0.5">open ステータス</p>
          </div>
        </div>

        {/* ── Charts row ─────────────────────────────────────────────────── */}
        {allRows.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Pie: severity distribution */}
            <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-[#8899aa] mb-4">重大度別 CVE 分布</h2>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} stroke="transparent" />
                    ))}
                  </Pie>
                  <ReTooltip content={<ChartTooltip />} />
                  <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle" className="fill-white" fontSize={22} fontWeight={700}>
                    {allRows.length}
                  </text>
                  <text x="50%" y="50%" dy={18} textAnchor="middle" dominantBaseline="middle" className="fill-[#5a6a7a]" fontSize={11}>
                    件
                  </text>
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap justify-center gap-3 mt-2">
                {pieData.map(d => (
                  <div key={d.name} className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                    <span className="text-xs text-[#8899aa]">{d.name} <span className="text-white font-semibold">{d.value}</span></span>
                  </div>
                ))}
              </div>
            </div>

            {/* Bar: top 10 vulnerable packages */}
            <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-[#8899aa] mb-4">脆弱性の多いソフトウェア Top 10</h2>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={barData} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#5a6a7a', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#8899aa', fontSize: 11 }} axisLine={false} tickLine={false} width={90} />
                  <ReTooltip content={<ChartTooltip />} cursor={{ fill: '#1a2640' }} />
                  <Bar dataKey="count" name="CVE数" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ── Severity Filter Tabs ───────────────────────────────────────── */}
        <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-[#5a6a7a] mr-1">重大度フィルター:</span>
            {/* All tab */}
            <button
              onClick={() => { setSeverityTab('all'); setPage(1) }}
              className={`px-3 py-1 text-xs rounded-lg border transition-colors ${
                severityTab === 'all'
                  ? 'bg-gray-600 border-gray-500 text-white'
                  : 'border-[#1e2d42] text-[#8899aa] hover:border-[#2e3d52] hover:text-white'
              }`}
            >
              All
              <span className="ml-1.5 px-1.5 py-0.5 bg-gray-700/80 rounded-full text-[10px] font-semibold">
                {allRows.length}
              </span>
            </button>
            {/* Severity tabs */}
            {(Object.keys(SEV_CONFIG) as (keyof typeof SEV_CONFIG)[]).map(sev => {
              const cfg = SEV_CONFIG[sev]
              const isActive = severityTab === sev
              const count = sevCounts[sev] ?? 0
              return (
                <button
                  key={sev}
                  onClick={() => { setSeverityTab(isActive ? 'all' : sev); setPage(1) }}
                  className={`px-3 py-1 text-xs rounded-lg border transition-colors flex items-center gap-1.5 ${
                    isActive ? cfg.tabActive : 'border-[#1e2d42] text-[#8899aa] hover:border-[#2e3d52] hover:text-white'
                  }`}
                >
                  {cfg.label}
                  <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-semibold ${
                    isActive ? 'bg-white/20' : 'bg-gray-700/80 text-[#8899aa]'
                  }`}>
                    {count}
                  </span>
                </button>
              )
            })}
          </div>
        </div>

        {/* ── Filter bar ─────────────────────────────────────────────────── */}
        <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1) }}
                placeholder="CVE ID またはパッケージ名で検索..."
                className="w-full pl-9 pr-8 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#080c14] text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-blue-500 transition-colors"
              />
              {search && (
                <button
                  onClick={() => { setSearch(''); setPage(1) }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#5a6a7a] hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Patch Status filter */}
            <div className="flex border border-[#1e2d42] rounded-lg overflow-hidden text-xs">
              {[
                { value: '',            label: 'すべて' },
                { value: 'open',        label: '未対処' },
                { value: 'in_progress', label: '対応中' },
                { value: 'patched',     label: 'パッチ済' },
                { value: 'accepted',    label: 'リスク受容' },
              ].map(opt => (
                <button
                  key={opt.value}
                  onClick={() => { setStatusFilter(opt.value); setPage(1) }}
                  className={`px-3 py-1.5 transition-colors ${
                    statusFilter === opt.value
                      ? 'bg-blue-700 text-white'
                      : 'text-[#8899aa] hover:bg-gray-700'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {/* Count */}
            {filtered.length > 0 && (
              <span className="text-xs text-[#5a6a7a] ml-auto">{filtered.length} 件</span>
            )}
          </div>
        </div>

        {/* ── Bulk Actions Bar ───────────────────────────────────────────── */}
        <BulkActionsBar
          selectedIds={selectedIds}
          allPageIds={pageIds}
          onSelectAll={selectAllPage}
          onClearAll={clearAll}
          onBulkStatus={status => {
            const ids = Array.from(selectedIds)
            if (ids.length === 0) return
            bulkStatusMut.mutate({ ids, status })
          }}
          onExport={exportSelected}
        />

        {/* ── Main table ─────────────────────────────────────────────────── */}
        <div className="bg-gray-800 border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">デバイス別脆弱性</h2>
            <span className="text-xs text-[#5a6a7a]">
              {filtered.length} 件
              {totalPages > 1 && ` (ページ ${safePage} / ${totalPages})`}
            </span>
          </div>

          {isLoading ? (
            <div className="flex justify-center py-16">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
            </div>
          ) : pageRows.length === 0 ? (
            <div className="flex flex-col items-center py-16 text-[#5a6a7a]">
              <ShieldAlert className="w-12 h-12 opacity-20 mb-3" />
              <p className="text-sm">
                {allRows.length === 0
                  ? 'ソフトウェアインベントリにデータがありません'
                  : '条件に一致する脆弱性が見つかりません'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa] bg-[#0e1624]">
                    <th className="px-3 py-3 text-center w-8">
                      <button
                        onClick={() => {
                          const allSel = pageIds.every(id => selectedIds.has(id))
                          allSel ? clearAll() : selectAllPage()
                        }}
                        className="text-[#5a6a7a] hover:text-white transition-colors"
                      >
                        {pageIds.every(id => selectedIds.has(id)) && pageIds.length > 0
                          ? <CheckSquare className="w-4 h-4" />
                          : <Square className="w-4 h-4" />
                        }
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left">ホスト名</th>
                    <th className="px-4 py-3 text-left">CVE ID</th>
                    <th className="px-4 py-3 text-left">CVSSスコア</th>
                    <th className="px-4 py-3 text-left">パッケージ</th>
                    <th className="px-4 py-3 text-left">バージョン</th>
                    <th className="px-4 py-3 text-left">修正バージョン</th>
                    <th className="px-4 py-3 text-left">重大度</th>
                    <th className="px-4 py-3 text-left">パッチステータス</th>
                    <th className="px-4 py-3 text-left">影響EP</th>
                    <th className="px-4 py-3 text-left">検出日</th>
                    <th className="px-4 py-3 text-left">アクション</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map(row => (
                    <tr
                      key={row.id}
                      className={`border-b border-[#1e2d42]/50 transition-colors ${
                        selectedIds.has(row.id) ? 'bg-blue-900/10' : 'hover:bg-[#161f33]/40'
                      }`}
                    >
                      {/* Checkbox */}
                      <td className="px-3 py-2.5 text-center">
                        <button
                          onClick={() => toggleSelect(row.id)}
                          className="text-[#5a6a7a] hover:text-blue-400 transition-colors"
                        >
                          {selectedIds.has(row.id)
                            ? <CheckSquare className="w-4 h-4 text-blue-400" />
                            : <Square className="w-4 h-4" />
                          }
                        </button>
                      </td>

                      {/* Hostname */}
                      <td className="px-4 py-2.5">
                        <span className="text-[#e2e8f4] text-xs font-mono">{row.hostname}</span>
                      </td>

                      {/* CVE ID */}
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-blue-400 text-xs font-semibold">
                          {row.cve_id}
                          {row.isMock && (
                            <span className="ml-1 text-[10px] text-amber-500 font-normal">(推定)</span>
                          )}
                        </span>
                      </td>

                      {/* CVSS Score */}
                      <td className="px-4 py-2.5">
                        <span className={`text-xs font-bold ${
                          row.cvss_score >= 9 ? 'text-red-400'
                          : row.cvss_score >= 7 ? 'text-orange-400'
                          : row.cvss_score >= 4 ? 'text-yellow-400'
                          : 'text-blue-400'
                        }`}>
                          {row.cvss_score > 0 ? row.cvss_score.toFixed(1) : '—'}
                        </span>
                      </td>

                      {/* Package */}
                      <td className="px-4 py-2.5 text-xs text-[#e2e8f4]">{row.name}</td>

                      {/* Version */}
                      <td className="px-4 py-2.5 font-mono text-xs text-[#8899aa]">{row.version}</td>

                      {/* Fixed version */}
                      <td className="px-4 py-2.5 font-mono text-xs text-green-400">
                        {row.fixed_version !== '—' ? row.fixed_version : <span className="text-[#3d4f63]">—</span>}
                      </td>

                      {/* Severity badge */}
                      <td className="px-4 py-2.5">
                        <SeverityBadge sev={row.severity} />
                      </td>

                      {/* Patch Status dropdown */}
                      <td className="px-4 py-2.5">
                        {row.isMock ? (
                          <StatusBadge status={row.status} />
                        ) : (
                          <select
                            value={row.status}
                            onChange={e => statusMut.mutate({ id: row.id, status: e.target.value })}
                            className={`text-[11px] font-medium rounded-sm border px-1.5 py-0.5 bg-transparent cursor-pointer
                              transition-colors appearance-none
                              ${STATUS_CONFIG[row.status]?.className ?? 'border-gray-600 text-gray-300'}`}
                          >
                            <option value="open"        className="bg-gray-900 text-white">未対処</option>
                            <option value="in_progress" className="bg-gray-900 text-white">対応中</option>
                            <option value="patched"     className="bg-gray-900 text-white">パッチ適用済</option>
                            <option value="accepted"    className="bg-gray-900 text-white">リスク受容</option>
                          </select>
                        )}
                      </td>

                      {/* Affected Endpoints */}
                      <td className="px-4 py-2.5">
                        {(() => {
                          const hosts = cveHostnamesMap[row.cve_id] ?? []
                          return (
                            <button
                              onClick={() => setEndpointsModal({ cveId: row.cve_id, hostnames: hosts })}
                              className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-blue-300 transition-colors"
                            >
                              <Monitor className="w-3 h-3" />
                              <span className="px-1.5 py-0.5 bg-gray-700/80 rounded-full text-[10px] font-semibold text-white">
                                {hosts.length}
                              </span>
                            </button>
                          )
                        })()}
                      </td>

                      {/* Detected at */}
                      <td className="px-4 py-2.5 text-xs text-[#8899aa] whitespace-nowrap">
                        {fmtDate(row.detected_at)}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          {/* Create Ticket */}
                          <button
                            onClick={() => setTicketRow(row)}
                            className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300 transition-colors"
                            title="チケット作成"
                          >
                            <Ticket className="w-3.5 h-3.5" />
                          </button>
                          {/* NVD link */}
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                            title="NVDで詳細を表示"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 px-5 py-3 border-t border-[#1e2d42]">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={safePage === 1}
                className="p-1.5 rounded-sm bg-[#0e1624] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>

              {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                const half  = 3
                let start   = Math.max(1, safePage - half)
                const end   = Math.min(totalPages, start + 6)
                start       = Math.max(1, end - 6)
                return start + i
              })
                .filter(n => n >= 1 && n <= totalPages)
                .map(n => (
                  <button
                    key={n}
                    onClick={() => setPage(n)}
                    className={`w-8 h-7 text-xs rounded-sm transition-colors ${
                      n === safePage
                        ? 'bg-blue-700 text-white font-semibold'
                        : 'bg-[#0e1624] text-[#8899aa] hover:bg-[#19253d]'
                    }`}
                  >
                    {n}
                  </button>
                ))}

              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={safePage === totalPages}
                className="p-1.5 rounded-sm bg-[#0e1624] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

      </div>

      {/* ── Modals ──────────────────────────────────────────────────────── */}

      {endpointsModal && (
        <AffectedEndpointsModal
          cveId={endpointsModal.cveId}
          hostnames={endpointsModal.hostnames}
          onClose={() => setEndpointsModal(null)}
        />
      )}

      {ticketRow && (
        <CreateTicketModal
          row={ticketRow}
          onClose={() => setTicketRow(null)}
          onSubmit={form => ticketMut.mutate({ ...form, cve_id: ticketRow.cve_id })}
          isLoading={ticketMut.isPending}
        />
      )}
    </div>
  )
}
