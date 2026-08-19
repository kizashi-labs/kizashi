'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bug, AlertTriangle, Clock, CheckCircle2, AlertCircle,
  Search, Filter, X, ChevronDown, Edit2, UserCheck,
  Users, CalendarClock, Shield, RefreshCw, Check,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type RemStatus = 'open' | 'in_progress' | 'verified'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface RemediationRecord {
  id: string
  cve_id: string
  title: string
  description: string
  agent_id: string
  hostname: string
  severity: Severity
  status: RemStatus
  assignee: string | null
  due_date: string | null
  patch_version: string | null
  last_updated: string
  cvss_score: number
  affected_software: string
  remediation_notes: string
}

interface RemStats {
  open: number
  in_progress: number
  verified: number
  overdue: number
}

// ── Mock Data ──────────────────────────────────────────────────────────────

const now = new Date('2026-03-18')

const MOCK_RECORDS: RemediationRecord[] = [
  {
    id: 'r1',
    cve_id: 'CVE-2021-44228',
    title: 'Log4Shell - Apache Log4j2 RCE',
    description: 'Apache Log4j2 2.x からの JNDI lookup を通じてリモートコード実行が可能な脆弱性。CVSS 10.0 の最高評価。',
    agent_id: 'ag1',
    hostname: 'srv-prod-01',
    severity: 'critical',
    status: 'verified',
    assignee: 'Sato Kenji',
    due_date: '2026-02-28',
    patch_version: '2.17.1',
    last_updated: '2026-03-10T10:00:00Z',
    cvss_score: 10.0,
    affected_software: 'Apache Log4j2 2.14.1',
    remediation_notes: 'Log4j 2.17.1 へアップグレード完了。本番環境での動作確認済み。',
  },
  {
    id: 'r2',
    cve_id: 'CVE-2022-22965',
    title: 'Spring4Shell - Spring Framework RCE',
    description: 'Spring Framework における ClassLoader を通じたリモートコード実行の脆弱性。',
    agent_id: 'ag2',
    hostname: 'app-server-02',
    severity: 'critical',
    status: 'in_progress',
    assignee: 'Tanaka Yuki',
    due_date: '2026-03-20',
    patch_version: '5.3.18',
    last_updated: '2026-03-15T14:30:00Z',
    cvss_score: 9.8,
    affected_software: 'Spring Framework 5.3.16',
    remediation_notes: 'ステージング環境での検証中。本番適用は3/20を予定。',
  },
  {
    id: 'r3',
    cve_id: 'CVE-2021-26855',
    title: 'ProxyLogon - Microsoft Exchange SSRF',
    description: 'Exchange Server におけるSSRF脆弱性。認証バイパスと組み合わせて任意コード実行が可能。',
    agent_id: 'ag3',
    hostname: 'exchange-01',
    severity: 'critical',
    status: 'open',
    assignee: null,
    due_date: '2026-03-10',
    patch_version: null,
    last_updated: '2026-03-01T08:00:00Z',
    cvss_score: 9.8,
    affected_software: 'Microsoft Exchange Server 2019',
    remediation_notes: '',
  },
  {
    id: 'r4',
    cve_id: 'CVE-2021-34527',
    title: 'PrintNightmare - Windows Print Spooler RCE',
    description: 'Windows Print Spoolerサービスにおける特権昇格およびリモートコード実行の脆弱性。',
    agent_id: 'ag1',
    hostname: 'srv-prod-01',
    severity: 'high',
    status: 'in_progress',
    assignee: 'Sato Kenji',
    due_date: '2026-03-25',
    patch_version: 'KB5004945',
    last_updated: '2026-03-12T11:00:00Z',
    cvss_score: 8.8,
    affected_software: 'Windows Server 2019',
    remediation_notes: 'パッチ適用テスト中。Print Spoolerサービスの一時停止で軽減措置実施済み。',
  },
  {
    id: 'r5',
    cve_id: 'CVE-2022-30190',
    title: 'Follina - MSDT Remote Code Execution',
    description: 'Microsoft Support Diagnostic Tool (MSDT) における RCE 脆弱性。Office ドキュメント経由で悪用可能。',
    agent_id: 'ag4',
    hostname: 'workstation-15',
    severity: 'high',
    status: 'open',
    assignee: 'Yamamoto Rie',
    due_date: '2026-03-15',
    patch_version: null,
    last_updated: '2026-03-05T09:30:00Z',
    cvss_score: 7.8,
    affected_software: 'Microsoft Office 2021',
    remediation_notes: '',
  },
  {
    id: 'r6',
    cve_id: 'CVE-2023-23397',
    title: 'Outlook Zero-Click NTLM Hash Leak',
    description: 'Microsoft Outlook における NTLM ハッシュ漏洩の脆弱性。ユーザー操作不要でトリガー可能。',
    agent_id: 'ag2',
    hostname: 'app-server-02',
    severity: 'high',
    status: 'verified',
    assignee: 'Tanaka Yuki',
    due_date: '2026-03-01',
    patch_version: 'March 2023 CU',
    last_updated: '2026-03-08T16:00:00Z',
    cvss_score: 9.8,
    affected_software: 'Microsoft Outlook 2019',
    remediation_notes: 'March 2023 累積更新プログラム適用完了。',
  },
  {
    id: 'r7',
    cve_id: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack (DoS)',
    description: 'HTTP/2 プロトコルにおける大規模 DDoS 攻撃を可能にする脆弱性。',
    agent_id: 'ag5',
    hostname: 'nginx-proxy-01',
    severity: 'high',
    status: 'in_progress',
    assignee: 'Ito Makoto',
    due_date: '2026-03-30',
    patch_version: 'nginx 1.25.3',
    last_updated: '2026-03-16T13:00:00Z',
    cvss_score: 7.5,
    affected_software: 'nginx 1.24.0',
    remediation_notes: 'nginx 1.25.3 へのアップグレード作業中。',
  },
  {
    id: 'r8',
    cve_id: 'CVE-2021-3156',
    title: 'Baron Samedit - Sudo Heap Overflow',
    description: 'sudo における heap-based buffer overflow。ローカル権限昇格が可能。',
    agent_id: 'ag3',
    hostname: 'exchange-01',
    severity: 'high',
    status: 'open',
    assignee: null,
    due_date: '2026-03-05',
    patch_version: null,
    last_updated: '2026-02-20T10:00:00Z',
    cvss_score: 7.8,
    affected_software: 'sudo 1.8.31',
    remediation_notes: '',
  },
  {
    id: 'r9',
    cve_id: 'CVE-2022-47966',
    title: 'ManageEngine Multiple Products RCE',
    description: 'ManageEngine 複数製品における認証不要のリモートコード実行の脆弱性。',
    agent_id: 'ag4',
    hostname: 'workstation-15',
    severity: 'critical',
    status: 'open',
    assignee: 'Yamamoto Rie',
    due_date: '2026-03-08',
    patch_version: null,
    last_updated: '2026-02-25T08:00:00Z',
    cvss_score: 9.8,
    affected_software: 'ManageEngine ServiceDesk Plus 14.0',
    remediation_notes: '',
  },
  {
    id: 'r10',
    cve_id: 'CVE-2023-20198',
    title: 'Cisco IOS XE Web UI Privilege Escalation',
    description: 'Cisco IOS XE Web UI における認証バイパスと特権昇格の脆弱性。',
    agent_id: 'ag5',
    hostname: 'nginx-proxy-01',
    severity: 'critical',
    status: 'open',
    assignee: null,
    due_date: '2026-03-12',
    patch_version: null,
    last_updated: '2026-03-02T07:00:00Z',
    cvss_score: 10.0,
    affected_software: 'Cisco IOS XE 17.x',
    remediation_notes: '',
  },
  {
    id: 'r11',
    cve_id: 'CVE-2023-4863',
    title: 'WebP Heap Buffer Overflow (libwebp)',
    description: 'Google Chrome および libwebp における heap buffer overflow。悪意あるWebP画像で悪用可能。',
    agent_id: 'ag1',
    hostname: 'srv-prod-01',
    severity: 'medium',
    status: 'verified',
    assignee: 'Sato Kenji',
    due_date: '2026-02-15',
    patch_version: 'Chrome 116.0.5845.187',
    last_updated: '2026-02-28T14:00:00Z',
    cvss_score: 8.8,
    affected_software: 'Google Chrome 116.0',
    remediation_notes: 'Chrome アップデート完了。全エンドポイントで確認済み。',
  },
  {
    id: 'r12',
    cve_id: 'CVE-2024-21410',
    title: 'Exchange Server NTLM Relay Attack',
    description: 'Microsoft Exchange Server における NTLM リレー攻撃を可能にする脆弱性。',
    agent_id: 'ag3',
    hostname: 'exchange-01',
    severity: 'critical',
    status: 'in_progress',
    assignee: 'Ito Makoto',
    due_date: '2026-03-22',
    patch_version: 'CU14 Feb 2024',
    last_updated: '2026-03-17T09:00:00Z',
    cvss_score: 9.8,
    affected_software: 'Microsoft Exchange Server 2019 CU13',
    remediation_notes: 'CU14 適用前の前提条件確認中。EPスモード設定対応が必要。',
  },
]

const ASSIGNEES = ['Sato Kenji', 'Tanaka Yuki', 'Yamamoto Rie', 'Ito Makoto', 'Nakamura Hana']

// ── Helpers ────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<Severity, { label: string; badge: string; color: string }> = {
  critical: { label: 'Critical', badge: 'bg-red-900/60 border-red-700 text-red-300', color: '#ef4444' },
  high: { label: 'High', badge: 'bg-orange-900/60 border-orange-700 text-orange-300', color: '#f97316' },
  medium: { label: 'Medium', badge: 'bg-yellow-900/60 border-yellow-700 text-yellow-300', color: '#eab308' },
  low: { label: 'Low', badge: 'bg-blue-900/60 border-blue-700 text-blue-300', color: '#3b82f6' },
}

const STATUS_CONFIG: Record<RemStatus, { label: string; badge: string; icon: React.ElementType }> = {
  open: { label: '未対応', badge: 'bg-red-900/60 border-red-700 text-red-300', icon: AlertCircle },
  in_progress: { label: '対応中', badge: 'bg-yellow-900/60 border-yellow-700 text-yellow-300', icon: Clock },
  verified: { label: '確認済み', badge: 'bg-green-900/60 border-green-700 text-green-300', icon: CheckCircle2 },
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

function isOverdue(due: string | null, status: RemStatus) {
  if (!due || status === 'verified') return false
  return new Date(due) < now
}

function avatarInitial(name: string | null) {
  if (!name) return null
  return name.split(' ').map(p => p[0]).join('').toUpperCase().slice(0, 2)
}

// Simple SVG bar component
function HorizBar({ segments }: { segments: { color: string; value: number; label: string }[] }) {
  const total = segments.reduce((s, x) => s + x.value, 0)
  if (total === 0) return <div className="h-6 bg-[#0d1220] rounded-sm" />
  return (
    <div className="flex h-6 rounded-sm overflow-hidden gap-0.5">
      {segments.filter(s => s.value > 0).map(s => (
        <div
          key={s.label}
          title={`${s.label}: ${s.value}`}
          style={{ width: `${(s.value / total) * 100}%`, backgroundColor: s.color }}
          className="transition-all"
        />
      ))}
    </div>
  )
}

// Simple SVG line chart
function LineChart({ data }: { data: { month: string; value: number }[] }) {
  const w = 480, h = 120, padL = 40, padB = 24, padT = 10, padR = 20
  const maxV = Math.max(...data.map(d => d.value), 1)
  const xStep = (w - padL - padR) / Math.max(data.length - 1, 1)
  const pts = data.map((d, i) => ({
    x: padL + i * xStep,
    y: padT + (h - padT - padB) * (1 - d.value / maxV),
    ...d,
  }))
  const pathD = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" style={{ height: 120 }}>
      {/* Grid */}
      {[0, 0.25, 0.5, 0.75, 1].map(r => {
        const y = padT + (h - padT - padB) * r
        return <line key={r} x1={padL} y1={y} x2={w - padR} y2={y} stroke="#1e2d42" strokeWidth={1} />
      })}
      {/* Y labels */}
      {[0, 0.5, 1].map(r => (
        <text key={r} x={padL - 4} y={padT + (h - padT - padB) * (1 - r) + 4}
          textAnchor="end" fontSize={10} fill="#7d92b0">
          {Math.round(maxV * r)}
        </text>
      ))}
      {/* Line */}
      <path d={pathD} fill="none" stroke="#e8002d" strokeWidth={2} />
      {/* Points */}
      {pts.map(p => (
        <circle key={p.month} cx={p.x} cy={p.y} r={3} fill="#e8002d" />
      ))}
      {/* X labels */}
      {pts.map(p => (
        <text key={p.month} x={p.x} y={h - 4} textAnchor="middle" fontSize={9} fill="#7d92b0">{p.month}</text>
      ))}
    </svg>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function VulnRemediationPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'tasks' | 'stats'>('tasks')

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [assigneeFilter, setAssigneeFilter] = useState<string>('all')
  const [overdueOnly, setOverdueOnly] = useState(false)
  const [cveSearch, setCveSearch] = useState('')

  // Selection
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Modals
  const [editRecord, setEditRecord] = useState<RemediationRecord | null>(null)
  const [editForm, setEditForm] = useState<Partial<RemediationRecord>>({})
  const [showBulkAssign, setShowBulkAssign] = useState(false)
  const [bulkAssignee, setBulkAssignee] = useState('')
  const [verifyConfirm, setVerifyConfirm] = useState<string | null>(null)

  // Local state (mock)
  const [records, setRecords] = useState<RemediationRecord[]>(m(MOCK_RECORDS))

  // API calls (with mock fallback)
  const { data: apiData } = useQuery<RemediationRecord[]>({
    queryKey: ['vuln-remediations'],
    queryFn: () => apiFetch('/api/v1/vuln-remediations'),
    ...(USE_MOCK ? { initialData: MOCK_RECORDS } : {}),
  })

  const updateMutation = useMutation({
    mutationFn: (rec: Partial<RemediationRecord> & { id: string }) =>
      apiFetch(`/api/v1/vuln-remediations/${rec.id}`, {
        method: 'PUT',
        body: JSON.stringify(rec),
      }),
    onSuccess: (_, variables) => {
      setRecords(prev => prev.map(r => r.id === variables.id ? { ...r, ...variables } : r))
    },
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/vuln-remediations/${id}/verify`, { method: 'POST' }),
    onSuccess: (_, id) => {
      setRecords(prev => prev.map(r => r.id === id ? { ...r, status: 'verified' } : r))
      setVerifyConfirm(null)
    },
  })

  const bulkAssignMutation = useMutation({
    mutationFn: (data: { ids: string[]; assignee: string }) =>
      apiFetch('/api/v1/vuln-remediations/bulk-assign', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: (_, { ids, assignee }) => {
      setRecords(prev => prev.map(r => ids.includes(r.id) ? { ...r, assignee } : r))
      setSelected(new Set())
      setShowBulkAssign(false)
    },
  })

  const workingRecords = records

  const filtered = useMemo(() => workingRecords.filter(r => {
    if (statusFilter !== 'all' && r.status !== statusFilter) return false
    if (sevFilter !== 'all' && r.severity !== sevFilter) return false
    if (assigneeFilter !== 'all') {
      if (assigneeFilter === 'unassigned' && r.assignee !== null) return false
      if (assigneeFilter !== 'unassigned' && r.assignee !== assigneeFilter) return false
    }
    if (overdueOnly && !isOverdue(r.due_date, r.status)) return false
    if (cveSearch && !r.cve_id.toLowerCase().includes(cveSearch.toLowerCase()) && !r.title.toLowerCase().includes(cveSearch.toLowerCase())) return false
    return true
  }), [workingRecords, statusFilter, sevFilter, assigneeFilter, overdueOnly, cveSearch])

  const stats: RemStats = useMemo(() => ({
    open: workingRecords.filter(r => r.status === 'open').length,
    in_progress: workingRecords.filter(r => r.status === 'in_progress').length,
    verified: workingRecords.filter(r => r.status === 'verified').length,
    overdue: workingRecords.filter(r => isOverdue(r.due_date, r.status)).length,
  }), [workingRecords])

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selected.size === filtered.length) setSelected(new Set())
    else setSelected(new Set(filtered.map(r => r.id)))
  }

  const openEdit = (rec: RemediationRecord) => {
    setEditRecord(rec)
    setEditForm({ ...rec })
  }

  const saveEdit = () => {
    if (!editRecord) return
    const updated = { ...editRecord, ...editForm }
    setRecords(prev => prev.map(r => r.id === updated.id ? updated : r))
    updateMutation.mutate(updated)
    setEditRecord(null)
  }

  // Stats tab data
  const agentStats = useMemo(() => {
    const map: Record<string, number> = {}
    workingRecords.filter(r => r.status !== 'verified').forEach(r => {
      map[r.hostname] = (map[r.hostname] ?? 0) + 1
    })
    return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 10)
  }, [workingRecords])

  const trendData = [
    { month: '10月', value: 18 },
    { month: '11月', value: 14 },
    { month: '12月', value: 22 },
    { month: '1月', value: 11 },
    { month: '2月', value: 9 },
    { month: '3月', value: 13 },
  ]

  const slaCompliance = Math.round(
    (workingRecords.filter(r => r.status === 'verified' && r.due_date && new Date(r.due_date) >= new Date(r.last_updated)).length /
      Math.max(workingRecords.filter(r => r.status === 'verified').length, 1)) * 100
  )

  const sevStatuses: { sev: Severity; label: string }[] = [
    { sev: 'critical', label: 'Critical' },
    { sev: 'high', label: 'High' },
    { sev: 'medium', label: 'Medium' },
    { sev: 'low', label: 'Low' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed />
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-white">脆弱性修正追跡</h1>
          <p className="text-[#7d92b0] mt-1">CVE修正状況の管理・担当者アサイン・進捗追跡</p>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: '未対応', value: stats.open, color: 'text-red-400', icon: AlertCircle },
            { label: '対応中', value: stats.in_progress, color: 'text-yellow-400', icon: Clock },
            { label: '確認済み', value: stats.verified, color: 'text-green-400', icon: CheckCircle2 },
            { label: '期限超過', value: stats.overdue, color: 'text-red-400 font-bold', icon: AlertTriangle, pulse: true },
          ].map(({ label, value, color, icon: Icon, pulse }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${color}`} />
                <span className="text-[#7d92b0] text-xs">{label}</span>
              </div>
              <p className={`text-3xl font-bold ${color} ${pulse && value > 0 ? 'animate-pulse' : ''}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-[#1e2d42]">
          {([
            { id: 'tasks', label: '修正タスク' },
            { id: 'stats', label: '統計' },
          ] as const).map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab: 修正タスク ────────────────────────────────────── */}
        {activeTab === 'tasks' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-wrap gap-3 items-center">
              <Filter className="w-4 h-4 text-[#7d92b0] shrink-0" />
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
                <input
                  type="text"
                  placeholder="CVE ID / タイトル検索"
                  value={cveSearch}
                  onChange={e => setCveSearch(e.target.value)}
                  className="pl-8 pr-3 py-1.5 text-sm bg-[#0d1220] border border-[#1e2d42] rounded-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d]/50 w-48"
                />
              </div>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded-sm px-3 py-1.5 text-sm"
              >
                <option value="all">ステータス: すべて</option>
                <option value="open">未対応</option>
                <option value="in_progress">対応中</option>
                <option value="verified">確認済み</option>
              </select>
              <select
                value={sevFilter}
                onChange={e => setSevFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded-sm px-3 py-1.5 text-sm"
              >
                <option value="all">深刻度: すべて</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={assigneeFilter}
                onChange={e => setAssigneeFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded-sm px-3 py-1.5 text-sm"
              >
                <option value="all">担当者: すべて</option>
                <option value="unassigned">未割り当て</option>
                {ASSIGNEES.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
              <label className="flex items-center gap-2 cursor-pointer text-sm text-[#7d92b0]">
                <input
                  type="checkbox"
                  checked={overdueOnly}
                  onChange={e => setOverdueOnly(e.target.checked)}
                  className="accent-[#e8002d] w-4 h-4"
                />
                期限超過のみ
              </label>
              {selected.size > 0 && (
                <button
                  onClick={() => setShowBulkAssign(true)}
                  className="ml-auto flex items-center gap-2 px-3 py-1.5 text-sm rounded-sm bg-[#1d2f4a] border border-[#1e2d42] text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-colors"
                >
                  <Users className="w-4 h-4" />
                  一括アサイン ({selected.size}件)
                </button>
              )}
            </div>

            {/* Table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-x-auto">
              <table className="w-full text-sm min-w-[900px]">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="px-3 py-3">
                      <input
                        type="checkbox"
                        checked={selected.size === filtered.length && filtered.length > 0}
                        onChange={toggleSelectAll}
                        className="accent-[#e8002d] w-4 h-4"
                      />
                    </th>
                    {['CVE ID', 'タイトル', 'ホスト', '深刻度', 'ステータス', '担当者', '期限', 'パッチ', '更新日時', 'アクション'].map(h => (
                      <th key={h} className="text-left px-3 py-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(rec => {
                    const sevConf = SEV_CONFIG[rec.severity]
                    const statusConf = STATUS_CONFIG[rec.status]
                    const StatusIcon = statusConf.icon
                    const overdue = isOverdue(rec.due_date, rec.status)
                    const ini = avatarInitial(rec.assignee)

                    return (
                      <tr key={rec.id} className="border-b border-[#1e2d42] hover:bg-[#161f33] transition-colors">
                        <td className="px-3 py-3">
                          <input
                            type="checkbox"
                            checked={selected.has(rec.id)}
                            onChange={() => toggleSelect(rec.id)}
                            className="accent-[#e8002d] w-4 h-4"
                          />
                        </td>
                        <td className="px-3 py-3">
                          <span className="font-mono text-[#e8002d] text-xs whitespace-nowrap">{rec.cve_id}</span>
                        </td>
                        <td className="px-3 py-3 max-w-[180px]">
                          <span className="truncate block text-[#e2e8f4] text-xs" title={rec.title}>{rec.title}</span>
                        </td>
                        <td className="px-3 py-3">
                          <span className="text-[#7d92b0] text-xs whitespace-nowrap">{rec.hostname}</span>
                        </td>
                        <td className="px-3 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border font-medium whitespace-nowrap ${sevConf.badge}`}>
                            {sevConf.label}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border flex items-center gap-1 w-fit whitespace-nowrap ${statusConf.badge}`}>
                            <StatusIcon className="w-3 h-3" />
                            {statusConf.label}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          {ini ? (
                            <div className="flex items-center gap-1.5">
                              <div className="w-6 h-6 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                                <span className="text-[9px] font-bold text-white">{ini}</span>
                              </div>
                              <span className="text-[#7d92b0] text-xs truncate max-w-[80px]">{rec.assignee}</span>
                            </div>
                          ) : (
                            <span className="text-[#3d5068] text-xs">未割り当て</span>
                          )}
                        </td>
                        <td className={`px-3 py-3 text-xs whitespace-nowrap ${overdue ? 'text-red-400 font-medium' : 'text-[#7d92b0]'}`}>
                          {overdue && <span className="mr-1">!</span>}{fmtDate(rec.due_date)}
                        </td>
                        <td className="px-3 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                          {rec.patch_version ?? '未定'}
                        </td>
                        <td className="px-3 py-3 text-[#3d5068] text-xs whitespace-nowrap">
                          {fmtDate(rec.last_updated)}
                        </td>
                        <td className="px-3 py-3">
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => openEdit(rec)}
                              title="編集"
                              className="p-1.5 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            {rec.status !== 'verified' && (
                              <button
                                onClick={() => setVerifyConfirm(rec.id)}
                                title="確認済みにする"
                                className="p-1.5 rounded-sm text-[#7d92b0] hover:text-green-400 hover:bg-green-900/20 transition-colors"
                              >
                                <Check className="w-3.5 h-3.5" />
                              </button>
                            )}
                            {rec.assignee && (
                              <button
                                onClick={() => {
                                  setRecords(prev => prev.map(r => r.id === rec.id ? { ...r, assignee: null } : r))
                                }}
                                title="担当解除"
                                className="p-1.5 rounded-sm text-[#7d92b0] hover:text-red-400 hover:bg-red-900/20 transition-colors"
                              >
                                <X className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <div className="text-center py-12 text-[#7d92b0]">
                  <Bug className="w-8 h-8 mx-auto mb-2 opacity-40" />
                  <p>条件に一致するレコードがありません</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Tab: 統計 ──────────────────────────────────────────── */}
        {activeTab === 'stats' && (
          <div className="space-y-6">
            {/* Severity × Status Stacked Bars */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h2 className="text-white font-semibold mb-4">深刻度別ステータス分布</h2>
              <div className="space-y-3">
                {sevStatuses.map(({ sev, label }) => {
                  const sevRecs = workingRecords.filter(r => r.severity === sev)
                  const segments = [
                    { label: '未対応', value: sevRecs.filter(r => r.status === 'open').length, color: '#ef4444' },
                    { label: '対応中', value: sevRecs.filter(r => r.status === 'in_progress').length, color: '#eab308' },
                    { label: '確認済み', value: sevRecs.filter(r => r.status === 'verified').length, color: '#22c55e' },
                  ]
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className={`text-xs font-medium w-16 shrink-0 ${SEV_CONFIG[sev].badge.includes('red') ? 'text-red-300' : SEV_CONFIG[sev].badge.includes('orange') ? 'text-orange-300' : SEV_CONFIG[sev].badge.includes('yellow') ? 'text-yellow-300' : 'text-blue-300'}`}>
                        {label}
                      </span>
                      <div className="flex-1">
                        <HorizBar segments={segments} />
                      </div>
                      <span className="text-[#7d92b0] text-xs w-8 text-right">{sevRecs.length}</span>
                    </div>
                  )
                })}
                <div className="flex gap-4 pt-2">
                  {[{ color: '#ef4444', label: '未対応' }, { color: '#eab308', label: '対応中' }, { color: '#22c55e', label: '確認済み' }].map(l => (
                    <div key={l.label} className="flex items-center gap-1.5">
                      <div className="w-3 h-3 rounded-xs" style={{ backgroundColor: l.color }} />
                      <span className="text-[#7d92b0] text-xs">{l.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Open by Agent */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h2 className="text-white font-semibold mb-4">エージェント別未対応脆弱性 (上位10)</h2>
              <div className="space-y-2">
                {agentStats.map(([hostname, count]) => {
                  const maxVal = agentStats[0]?.[1] ?? 1
                  return (
                    <div key={hostname} className="flex items-center gap-3">
                      <span className="text-[#7d92b0] text-xs w-32 truncate shrink-0 font-mono">{hostname}</span>
                      <div className="flex-1 h-5 bg-[#070d19] rounded-sm overflow-hidden">
                        <div
                          className="h-full bg-linear-to-r from-[#e8002d] to-[#a80020] rounded-sm transition-all"
                          style={{ width: `${(count / maxVal) * 100}%` }}
                        />
                      </div>
                      <span className="text-[#e2e8f4] text-xs w-6 text-right font-medium">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Time to Resolve Trend */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h2 className="text-white font-semibold mb-1">平均修正日数トレンド</h2>
              <p className="text-[#7d92b0] text-xs mb-4">過去6ヶ月の平均修正所要日数</p>
              <LineChart data={trendData} />
            </div>

            {/* SLA Compliance */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h2 className="text-white font-semibold mb-3">SLAコンプライアンス</h2>
              <div className="flex items-center gap-6">
                <div className="relative w-24 h-24 shrink-0">
                  <svg viewBox="0 0 36 36" className="w-24 h-24 -rotate-90">
                    <circle cx="18" cy="18" r="14" fill="none" stroke="#1e2d42" strokeWidth="3" />
                    <circle
                      cx="18" cy="18" r="14" fill="none"
                      stroke={slaCompliance >= 80 ? '#22c55e' : slaCompliance >= 60 ? '#eab308' : '#ef4444'}
                      strokeWidth="3"
                      strokeDasharray={`${slaCompliance * 0.879} 87.9`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-lg font-bold text-white">{slaCompliance}%</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-[#e2e8f4] font-medium">期限内修正完了率</p>
                  <p className="text-[#7d92b0] text-sm">
                    {workingRecords.filter(r => r.status === 'verified').length} 件中{' '}
                    {Math.round(workingRecords.filter(r => r.status === 'verified').length * slaCompliance / 100)} 件を期限内に対応
                  </p>
                  <p className={`text-sm font-medium ${slaCompliance >= 80 ? 'text-green-400' : slaCompliance >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {slaCompliance >= 80 ? '目標達成' : slaCompliance >= 60 ? '要改善' : '要緊急対応'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Modal: 詳細編集 ───────────────────────────────────────── */}
      {editRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h2 className="text-white font-semibold">脆弱性詳細編集</h2>
                <p className="text-[#7d92b0] text-xs mt-0.5 font-mono">{editRecord.cve_id}</p>
              </div>
              <button onClick={() => setEditRecord(null)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Read-only info */}
              <div className="bg-[#070d19] rounded-lg p-4 space-y-2 border border-[#1e2d42]">
                <div className="flex gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded-sm text-xs border ${SEV_CONFIG[editRecord.severity].badge}`}>
                    {SEV_CONFIG[editRecord.severity].label}
                  </span>
                  <span className="px-2 py-0.5 rounded-sm text-xs border border-[#1e2d42] text-[#7d92b0]">
                    CVSS {editRecord.cvss_score}
                  </span>
                  <span className="px-2 py-0.5 rounded-sm text-xs border border-[#1e2d42] text-[#7d92b0]">
                    {editRecord.hostname}
                  </span>
                </div>
                <p className="text-white text-sm font-medium">{editRecord.title}</p>
                <p className="text-[#7d92b0] text-xs">{editRecord.description}</p>
                <p className="text-[#3d5068] text-xs">影響ソフトウェア: {editRecord.affected_software}</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">ステータス</label>
                  <select
                    value={editForm.status ?? editRecord.status}
                    onChange={e => setEditForm(p => ({ ...p, status: e.target.value as RemStatus }))}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                  >
                    <option value="open">未対応</option>
                    <option value="in_progress">対応中</option>
                    <option value="verified">確認済み</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">担当者</label>
                  <select
                    value={editForm.assignee ?? editRecord.assignee ?? ''}
                    onChange={e => setEditForm(p => ({ ...p, assignee: e.target.value || null }))}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                  >
                    <option value="">未割り当て</option>
                    {ASSIGNEES.map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">期限</label>
                  <input
                    type="date"
                    value={(editForm.due_date ?? editRecord.due_date ?? '').slice(0, 10)}
                    onChange={e => setEditForm(p => ({ ...p, due_date: e.target.value }))}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                  />
                </div>
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">パッチバージョン</label>
                  <input
                    type="text"
                    value={editForm.patch_version ?? editRecord.patch_version ?? ''}
                    onChange={e => setEditForm(p => ({ ...p, patch_version: e.target.value || null }))}
                    placeholder="例: 2.17.1"
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">修正メモ</label>
                <textarea
                  rows={4}
                  value={editForm.remediation_notes ?? editRecord.remediation_notes ?? ''}
                  onChange={e => setEditForm(p => ({ ...p, remediation_notes: e.target.value }))}
                  placeholder="修正手順・進捗・注意事項など"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setEditRecord(null)}
                className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={saveEdit}
                className="flex-1 px-4 py-2 rounded-sm bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm transition-colors"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: 一括アサイン ────────────────────────────────────── */}
      {showBulkAssign && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-sm shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold">一括担当者アサイン</h2>
              <button onClick={() => setShowBulkAssign(false)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <p className="text-[#7d92b0] text-sm mb-4">{selected.size} 件のレコードに担当者をアサインします</p>
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">担当者</label>
              <select
                value={bulkAssignee}
                onChange={e => setBulkAssignee(e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#e2e8f4] text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              >
                <option value="">選択してください</option>
                {ASSIGNEES.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowBulkAssign(false)}
                className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => bulkAssignMutation.mutate({ ids: Array.from(selected), assignee: bulkAssignee })}
                disabled={!bulkAssignee}
                className="flex-1 px-4 py-2 rounded-sm bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm transition-colors disabled:opacity-40"
              >
                アサイン
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: Verify Confirm ─────────────────────────────────── */}
      {verifyConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-sm shadow-xl">
            <div className="flex items-center gap-3 mb-4">
              <CheckCircle2 className="w-6 h-6 text-green-400" />
              <h2 className="text-white font-semibold">修正確認</h2>
            </div>
            <p className="text-[#7d92b0] text-sm mb-6">
              このCVEの修正を確認済みとしてマークしますか？
              <br />CVE ID: <span className="font-mono text-[#e8002d]">{workingRecords.find(r => r.id === verifyConfirm)?.cve_id}</span>
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setVerifyConfirm(null)}
                className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => verifyMutation.mutate(verifyConfirm)}
                className="flex-1 px-4 py-2 rounded-sm bg-green-700 hover:bg-green-600 text-white text-sm transition-colors"
              >
                確認済みにする
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
