'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  UserCheck, ClipboardList, ChevronRight, Clock,
  CheckCircle, XCircle, Shield, RefreshCw, Copy,
  Plus, Trash2, ToggleLeft, ToggleRight, Filter,
  Monitor, Server, Terminal, AlertTriangle, X,
  Check, Info, ArrowRight, Search, Layers,
} from 'lucide-react'

// ─── Types ─────────────────────────────────────────────────────────────────

type OSType = 'windows' | 'linux' | 'macos'
type EnrollmentStatus = 'pending' | 'approved' | 'denied'
type RuleAction = 'auto_approve' | 'auto_deny' | 'manual'
type MatchField = 'hostname' | 'ip_address'

interface EnrollmentRequest {
  id: string
  hostname: string
  ip_address: string
  os_type: OSType
  machine_id: string
  enrollment_token: string
  request_time: string
  status: EnrollmentStatus
  auto_approved: boolean
  agent_id?: string
  deny_reason?: string
}

interface EnrollmentRule {
  id: string
  name: string
  match_field: MatchField
  match_pattern: string
  action: RuleAction
  priority: number
  assign_group_id: string
  assign_group_name: string
  assign_tags: string[]
  enabled: boolean
}

interface Group {
  id: string
  name: string
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function maskToken(token: string) {
  const parts = token.split('-')
  return parts.slice(0, 2).join('-') + '-****'
}

function truncateMachineId(id: string) {
  return id.substring(0, 8) + '...' + id.substring(id.length - 4)
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

const OS_LABELS: Record<OSType, { label: string; color: string }> = {
  windows: { label: 'Windows', color: 'bg-blue-500/15 border-blue-500/25 text-blue-400' },
  linux: { label: 'Linux', color: 'bg-orange-500/15 border-orange-500/25 text-orange-400' },
  macos: { label: 'macOS', color: 'bg-purple-500/15 border-purple-500/25 text-purple-400' },
}

const STATUS_LABELS: Record<EnrollmentStatus, { label: string; color: string }> = {
  pending: { label: '承認待ち', color: 'bg-yellow-500/15 border-yellow-500/25 text-yellow-400' },
  approved: { label: '承認済み', color: 'bg-green-500/15 border-green-500/25 text-green-400' },
  denied: { label: '拒否', color: 'bg-red-500/15 border-red-500/25 text-red-400' },
}

const ACTION_LABELS: Record<RuleAction, { label: string; color: string }> = {
  auto_approve: { label: '自動承認', color: 'bg-green-500/15 border-green-500/25 text-green-400' },
  auto_deny: { label: '自動拒否', color: 'bg-red-500/15 border-red-500/25 text-red-400' },
  manual: { label: '手動', color: 'bg-falcon-border border-[#2a3f5c] text-falcon-muted' },
}

// ─── Stats ───────────────────────────────────────────────────────────────────

function StatsRow({ requests }: { requests: EnrollmentRequest[] }) {
  const pending = requests.filter(r => r.status === 'pending').length
  const approvedToday = requests.filter(r => r.status === 'approved').length
  const denied = requests.filter(r => r.status === 'denied').length
  const autoApproved = requests.filter(r => r.auto_approved).length

  const stats = [
    { label: '承認待ち', value: pending, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20', icon: Clock },
    { label: '本日承認', value: approvedToday, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20', icon: CheckCircle },
    { label: '拒否', value: denied, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', icon: XCircle },
    { label: '自動承認', value: autoApproved, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20', icon: Shield },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {stats.map(({ label, value, color, bg, icon: Icon }) => (
        <div key={label} className={`${bg} border rounded-lg p-4 flex items-center gap-3`}>
          <Icon className={`w-5 h-5 ${color} shrink-0`} />
          <div>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-falcon-muted">{label}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Deny Modal ──────────────────────────────────────────────────────────────

function DenyModal({
  request,
  onDeny,
  onClose,
}: {
  request: EnrollmentRequest
  onDeny: (id: string, reason: string) => void
  onClose: () => void
}) {
  const [reason, setReason] = useState('')

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-md">
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-400" />
            <h2 className="text-white font-semibold text-sm">登録リクエスト拒否</h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="p-3 rounded-sm bg-[#070d19] border border-falcon-border">
            <p className="text-xs text-falcon-muted">対象ホスト</p>
            <p className="text-white font-medium text-sm mt-0.5">{request.hostname}</p>
            <p className="text-falcon-muted text-xs">{request.ip_address}</p>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">拒否理由 *</label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              rows={3}
              placeholder="拒否の理由を入力してください..."
              className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-red-500/50 resize-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-sm text-sm text-falcon-muted bg-falcon-border hover:bg-[#2a3f5c] transition-colors"
            >
              キャンセル
            </button>
            <button
              onClick={() => { if (reason) { onDeny(request.id, reason); onClose() } }}
              disabled={!reason}
              className="px-4 py-2 rounded-sm text-sm bg-red-600 text-white hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              拒否する
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Add Rule Modal ──────────────────────────────────────────────────────────

function AddRuleModal({
  groups,
  onAdd,
  onClose,
}: {
  groups: Group[]
  onAdd: (rule: Omit<EnrollmentRule, 'id'>) => void
  onClose: () => void
}) {
  const [form, setForm] = useState({
    name: '',
    match_field: 'hostname' as MatchField,
    match_pattern: '',
    action: 'auto_approve' as RuleAction,
    priority: 50,
    assign_group_id: '',
    assign_tags: '',
  })

  const handleSubmit = () => {
    if (!form.name || !form.match_pattern) return
    const group = groups.find(g => g.id === form.assign_group_id)
    onAdd({
      ...form,
      assign_group_name: group?.name ?? '',
      assign_tags: form.assign_tags ? form.assign_tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      enabled: true,
    })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-2">
            <Plus className="w-4 h-4 text-falcon-red" />
            <h2 className="text-white font-semibold text-sm">承認ルール追加</h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">ルール名 *</label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: Finance PC Auto-Approve"
              className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">マッチフィールド</label>
              <select
                value={form.match_field}
                onChange={e => setForm(f => ({ ...f, match_field: e.target.value as MatchField }))}
                className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="hostname">ホスト名</option>
                <option value="ip_address">IPアドレス</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">アクション</label>
              <select
                value={form.action}
                onChange={e => setForm(f => ({ ...f, action: e.target.value as RuleAction }))}
                className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="auto_approve">自動承認</option>
                <option value="auto_deny">自動拒否</option>
                <option value="manual">手動</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">マッチパターン (正規表現) *</label>
            <input
              type="text"
              value={form.match_pattern}
              onChange={e => setForm(f => ({ ...f, match_pattern: e.target.value }))}
              placeholder="例: ^DESKTOP-FINANCE-\\d+$"
              className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
            />
            <p className="text-[10px] text-falcon-subtle mt-1">正規表現を使用できます</p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">優先度 (低いほど高優先)</label>
              <input
                type="number"
                value={form.priority}
                onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))}
                min={1}
                max={100}
                className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">割り当てグループ</label>
              <select
                value={form.assign_group_id}
                onChange={e => setForm(f => ({ ...f, assign_group_id: e.target.value }))}
                className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="">グループなし</option>
                {groups.map(g => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">割り当てタグ (カンマ区切り)</label>
            <input
              type="text"
              value={form.assign_tags}
              onChange={e => setForm(f => ({ ...f, assign_tags: e.target.value }))}
              placeholder="例: windows, finance, managed"
              className="w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>
          <div className="flex gap-2 justify-end pt-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-sm text-sm text-falcon-muted bg-falcon-border hover:bg-[#2a3f5c] transition-colors"
            >
              キャンセル
            </button>
            <button
              onClick={handleSubmit}
              disabled={!form.name || !form.match_pattern}
              className="px-4 py-2 rounded-sm text-sm bg-falcon-red text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              追加
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function EnrollmentPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'pending' | 'rules'>('pending')
  const [statusFilter, setStatusFilter] = useState<'all' | EnrollmentStatus>('all')
  const [osFilter, setOsFilter] = useState<'all' | OSType>('all')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [denyModal, setDenyModal] = useState<EnrollmentRequest | null>(null)
  const [addRuleOpen, setAddRuleOpen] = useState(false)
  const [mockRequests, setMockRequests] = useState<EnrollmentRequest[]>([])
  const [mockRules, setMockRules] = useState<EnrollmentRule[]>([])
  const [preToken, setPreToken] = useState<string | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [testerInput, setTesterInput] = useState('')
  const [testerResult, setTesterResult] = useState<{ rule: EnrollmentRule; action: RuleAction } | null | 'no-match'>(null)

  // API fetches with mock fallback
  const { data: requestsData } = useQuery<{ requests: EnrollmentRequest[] }>({
    queryKey: ['enrollment-requests'],
    queryFn: () => apiFetch('/api/v1/admin/enrollment/requests'),
    retry: false,
    staleTime: 30_000,
  })

  const { data: groupsData } = useQuery<{ groups: Group[] }>({
    queryKey: ['groups-list'],
    queryFn: () => apiFetch('/api/v1/groups'),
    retry: false,
    staleTime: 60_000,
  })

  const requests = requestsData?.requests ?? mockRequests
  const groups = groupsData?.groups ?? []

  const approveMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/enrollment/requests/${id}/approve`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enrollment-requests'] }),
    onError: (_err, id) => {
      setMockRequests(prev => prev.map(r =>
        r.id === id ? { ...r, status: 'approved' as const, agent_id: `agent-${id.substring(3)}` } : r
      ))
    },
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFetch(`/api/v1/admin/enrollment/requests/${id}/deny`, { method: 'POST', body: JSON.stringify({ reason }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enrollment-requests'] }),
    onError: (_err, { id, reason }) => {
      setMockRequests(prev => prev.map(r =>
        r.id === id ? { ...r, status: 'denied' as const, deny_reason: reason } : r
      ))
    },
  })

  const handleApprove = (id: string) => {
    approveMutation.mutate(id)
    setMockRequests(prev => prev.map(r =>
      r.id === id ? { ...r, status: 'approved', agent_id: `agent-${id.substring(3)}-new` } : r
    ))
  }

  const handleDeny = (id: string, reason: string) => {
    denyMutation.mutate({ id, reason })
    setMockRequests(prev => prev.map(r =>
      r.id === id ? { ...r, status: 'denied', deny_reason: reason } : r
    ))
  }

  const handleBatchApprove = () => {
    selectedIds.forEach(id => handleApprove(id))
    setSelectedIds(new Set())
  }

  const handleGenerateToken = async () => {
    try {
      const data = await apiFetch('/admin/enrollment/pre-token', { method: 'POST' })
      setPreToken((data as { token: string }).token)
    } catch {
      setPreToken(`pre-enroll-${Math.random().toString(36).substring(2, 18).toUpperCase()}`)
    }
  }

  const handleCopy = (text: string, key: string) => {
    copyToClipboard(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 1500)
  }

  const handleAddRule = (rule: Omit<EnrollmentRule, 'id'>) => {
    const newRule: EnrollmentRule = { ...rule, id: `rule${Date.now()}` }
    setMockRules(prev => [...prev, newRule].sort((a, b) => a.priority - b.priority))
  }

  const handleDeleteRule = (id: string) => {
    setMockRules(prev => prev.filter(r => r.id !== id))
  }

  const handleToggleRule = (id: string) => {
    setMockRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }

  const handleRuleTester = () => {
    if (!testerInput) return
    const matched = mockRules
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority)
      .find(r => {
        try {
          const re = new RegExp(r.match_pattern)
          return re.test(testerInput)
        } catch {
          return false
        }
      })
    setTesterResult(matched ? { rule: matched, action: matched.action } : 'no-match')
  }

  const displayRequests = mockRequests.filter(r => {
    if (statusFilter !== 'all' && r.status !== statusFilter) return false
    if (osFilter !== 'all' && r.os_type !== osFilter) return false
    return true
  })

  const pendingRequests = displayRequests.filter(r => r.status === 'pending')
  const curlCommand = preToken
    ? `curl -X POST https://edr/api/v1/enrollment/request \\
  -H "Content-Type: application/json" \\
  -d '{"pre_token":"${preToken}","hostname":"DESKTOP-EXAMPLE","os":"windows"}'`
    : null

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 text-falcon-subtle text-xs mb-3">
          <span>管理</span>
          <ChevronRight className="w-3 h-3" />
          <span className="text-falcon-muted">エージェント登録承認</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-red/10 border border-falcon-red/20 flex items-center justify-center">
            <UserCheck className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">エージェント登録承認</h1>
            <p className="text-sm text-falcon-muted">新規エンドポイントの登録リクエスト承認・自動承認ルール管理</p>
          </div>
        </div>
      </div>

      {/* Stats */}
      <StatsRow requests={mockRequests} />

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['pending', 'rules'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 rounded text-sm font-medium transition-all ${
              activeTab === tab
                ? 'bg-falcon-red text-white shadow-sm'
                : 'text-falcon-muted hover:text-white'
            }`}
          >
            {tab === 'pending' ? '承認待ち' : '承認ルール'}
          </button>
        ))}
      </div>

      {/* Approval Tab */}
      {activeTab === 'pending' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-falcon-subtle" />
              <span className="text-xs text-falcon-muted">フィルター:</span>
            </div>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value as typeof statusFilter)}
              className="px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全ステータス</option>
              <option value="pending">承認待ち</option>
              <option value="approved">承認済み</option>
              <option value="denied">拒否</option>
            </select>
            <select
              value={osFilter}
              onChange={e => setOsFilter(e.target.value as typeof osFilter)}
              className="px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全OS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </select>
            {selectedIds.size > 0 && (
              <button
                onClick={handleBatchApprove}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-sm bg-green-600 text-white hover:bg-green-700 transition-colors ml-auto"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                一括承認 ({selectedIds.size}件)
              </button>
            )}
          </div>

          {/* Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    <th className="px-4 py-3 text-left w-8">
                      <input
                        type="checkbox"
                        checked={pendingRequests.length > 0 && pendingRequests.every(r => selectedIds.has(r.id))}
                        onChange={e => {
                          if (e.target.checked) {
                            setSelectedIds(new Set(pendingRequests.map(r => r.id)))
                          } else {
                            setSelectedIds(new Set())
                          }
                        }}
                        className="accent-falcon-red"
                      />
                    </th>
                    {['ホスト名', 'IPアドレス', 'OS', 'Machine ID', 'トークン', 'リクエスト時刻', '自動承認', 'ステータス', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-subtle uppercase tracking-wider font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayRequests.map(req => {
                    const os = OS_LABELS[req.os_type]
                    const st = STATUS_LABELS[req.status]
                    const isPending = req.status === 'pending'
                    return (
                      <tr key={req.id} className="border-b border-falcon-border/50 hover:bg-[#0d1825] transition-colors">
                        <td className="px-4 py-3">
                          {isPending && (
                            <input
                              type="checkbox"
                              checked={selectedIds.has(req.id)}
                              onChange={e => {
                                const next = new Set(selectedIds)
                                e.target.checked ? next.add(req.id) : next.delete(req.id)
                                setSelectedIds(next)
                              }}
                              className="accent-falcon-red"
                            />
                          )}
                        </td>
                        <td className="px-4 py-3 text-white font-medium text-sm whitespace-nowrap">{req.hostname}</td>
                        <td className="px-4 py-3 text-falcon-muted text-sm font-mono whitespace-nowrap">{req.ip_address}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border ${os.color}`}>{os.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-falcon-muted" title={req.machine_id}>
                            {truncateMachineId(req.machine_id)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-falcon-subtle">{maskToken(req.enrollment_token)}</span>
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{formatDate(req.request_time)}</td>
                        <td className="px-4 py-3">
                          {req.auto_approved ? (
                            <span className="px-2 py-0.5 rounded-sm text-xs bg-blue-500/15 border border-blue-500/25 text-blue-400">自動</span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-sm text-xs bg-falcon-border border border-[#2a3f5c] text-falcon-subtle">手動</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border ${st.color}`}>{st.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          {isPending && (
                            <div className="flex items-center gap-1.5">
                              <button
                                onClick={() => handleApprove(req.id)}
                                className="flex items-center gap-1 px-2.5 py-1 rounded-sm text-xs bg-green-600/20 border border-green-600/30 text-green-400 hover:bg-green-600/30 transition-colors"
                              >
                                <Check className="w-3 h-3" />
                                承認
                              </button>
                              <button
                                onClick={() => setDenyModal(req)}
                                className="flex items-center gap-1 px-2.5 py-1 rounded-sm text-xs bg-red-600/20 border border-red-600/30 text-red-400 hover:bg-red-600/30 transition-colors"
                              >
                                <X className="w-3 h-3" />
                                拒否
                              </button>
                            </div>
                          )}
                          {req.status === 'approved' && req.agent_id && (
                            <a
                              href={`/endpoints/${req.agent_id}`}
                              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                            >
                              <Monitor className="w-3 h-3" />
                              {req.agent_id.substring(0, 12)}...
                            </a>
                          )}
                          {req.status === 'denied' && req.deny_reason && (
                            <span className="text-xs text-falcon-muted italic" title={req.deny_reason}>
                              {req.deny_reason.substring(0, 20)}...
                            </span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                  {displayRequests.length === 0 && (
                    <tr>
                      <td colSpan={10} className="px-4 py-8 text-center text-falcon-subtle text-sm">
                        条件に一致するリクエストはありません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pre-enrollment Token */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Shield className="w-4 h-4 text-falcon-red" />
              登録トークン生成
            </h2>
            <p className="text-xs text-falcon-muted mb-4">
              事前登録トークンを発行することで、エンドポイントが登録リクエストを送信できます。
            </p>
            <button
              onClick={handleGenerateToken}
              className="flex items-center gap-2 px-4 py-2 rounded-sm text-sm bg-falcon-red text-white hover:bg-[#c00025] transition-colors mb-4"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              トークン生成
            </button>

            {preToken && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 p-3 rounded-sm bg-[#070d19] border border-falcon-border">
                  <code className="flex-1 text-xs font-mono text-green-400 break-all">{preToken}</code>
                  <button
                    onClick={() => handleCopy(preToken, 'token')}
                    className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors shrink-0"
                  >
                    {copiedKey === 'token' ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                {curlCommand && (
                  <div>
                    <p className="text-xs text-falcon-subtle mb-1.5">登録コマンド:</p>
                    <div className="relative">
                      <pre className="text-xs text-[#a8c0d6] font-mono bg-[#070d19] border border-falcon-border rounded-sm p-3 pr-10 overflow-x-auto whitespace-pre">
                        {curlCommand}
                      </pre>
                      <button
                        onClick={() => handleCopy(curlCommand, 'curl')}
                        className="absolute top-2 right-2 p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"
                      >
                        {copiedKey === 'curl' ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-falcon-red" />
                承認ルール ({mockRules.length})
              </h2>
              <button
                onClick={() => setAddRuleOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs bg-falcon-red text-white hover:bg-[#c00025] transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                ルール追加
              </button>
            </div>
            <div className="divide-y divide-falcon-border">
              {mockRules.map(rule => {
                const act = ACTION_LABELS[rule.action]
                return (
                  <div key={rule.id} className={`px-5 py-4 transition-colors ${rule.enabled ? '' : 'opacity-50'}`}>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <span className="text-white font-medium text-sm">{rule.name}</span>
                          <span className={`px-2 py-0.5 rounded-sm text-xs border ${act.color}`}>{act.label}</span>
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-falcon-border border border-[#2a3f5c] text-falcon-muted">
                            優先度 {rule.priority}
                          </span>
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-falcon-border border border-[#2a3f5c] text-falcon-muted">
                            {rule.match_field === 'hostname' ? 'ホスト名' : 'IPアドレス'}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 mb-2">
                          <ArrowRight className="w-3 h-3 text-falcon-subtle shrink-0" />
                          <code className="text-xs font-mono text-[#a8c0d6] bg-[#070d19] border border-falcon-border px-2 py-0.5 rounded-sm">
                            {rule.match_pattern}
                          </code>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {rule.assign_group_name && (
                            <span className="text-xs text-falcon-muted">
                              グループ: <span className="text-[#a8c0d6]">{rule.assign_group_name}</span>
                            </span>
                          )}
                          {rule.assign_tags.map(tag => (
                            <span key={tag} className="px-1.5 py-0.5 rounded-sm text-[10px] bg-falcon-border text-falcon-muted">
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => handleToggleRule(rule.id)}
                          className="text-falcon-muted hover:text-white transition-colors"
                          title={rule.enabled ? '無効化' : '有効化'}
                        >
                          {rule.enabled
                            ? <ToggleRight className="w-5 h-5 text-green-400" />
                            : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />
                          }
                        </button>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1.5 rounded-sm hover:bg-red-500/10 text-falcon-muted hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
              {mockRules.length === 0 && (
                <div className="px-5 py-8 text-center text-falcon-subtle text-sm">
                  承認ルールはまだ設定されていません
                </div>
              )}
            </div>
          </div>

          {/* Rule Tester */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Search className="w-4 h-4 text-falcon-red" />
              ルールテスター
            </h2>
            <p className="text-xs text-falcon-muted mb-3">
              ホスト名またはIPアドレスを入力して、どのルールがマッチするか確認します
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={testerInput}
                onChange={e => { setTesterInput(e.target.value); setTesterResult(null) }}
                placeholder="例: DESKTOP-FINANCE-07 または 192.168.10.35"
                className="flex-1 px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
              />
              <button
                onClick={handleRuleTester}
                disabled={!testerInput}
                className="px-4 py-2 rounded-sm text-sm bg-falcon-red text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                テスト
              </button>
            </div>
            {testerResult !== null && (
              <div className="mt-3">
                {testerResult === 'no-match' ? (
                  <div className="flex items-center gap-2 p-3 rounded-sm bg-falcon-border border border-[#2a3f5c]">
                    <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
                    <p className="text-xs text-falcon-muted">
                      マッチするルールなし — デフォルトアクション: <span className="text-yellow-400">手動承認</span>
                    </p>
                  </div>
                ) : (
                  <div className={`flex items-start gap-3 p-3 rounded border ${
                    testerResult.action === 'auto_approve'
                      ? 'bg-green-500/10 border-green-500/20'
                      : testerResult.action === 'auto_deny'
                      ? 'bg-red-500/10 border-red-500/20'
                      : 'bg-falcon-border border-[#2a3f5c]'
                  }`}>
                    <CheckCircle className={`w-4 h-4 shrink-0 mt-0.5 ${
                      testerResult.action === 'auto_approve' ? 'text-green-400'
                      : testerResult.action === 'auto_deny' ? 'text-red-400'
                      : 'text-falcon-muted'
                    }`} />
                    <div>
                      <p className="text-sm text-white font-medium">ルールマッチ: <span className="text-[#a8c0d6]">{testerResult.rule.name}</span></p>
                      <p className="text-xs text-falcon-muted mt-1">
                        アクション: <span className={`${ACTION_LABELS[testerResult.action].color} px-1.5 py-0.5 rounded-sm border text-xs`}>
                          {ACTION_LABELS[testerResult.action].label}
                        </span>
                        {testerResult.rule.assign_group_name && (
                          <span className="ml-2">グループ: {testerResult.rule.assign_group_name}</span>
                        )}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Deny Modal */}
      {denyModal && (
        <DenyModal
          request={denyModal}
          onDeny={handleDeny}
          onClose={() => setDenyModal(null)}
        />
      )}

      {/* Add Rule Modal */}
      {addRuleOpen && (
        <AddRuleModal
          groups={groups}
          onAdd={handleAddRule}
          onClose={() => setAddRuleOpen(false)}
        />
      )}
    </div>
  )
}
