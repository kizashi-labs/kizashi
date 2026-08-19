'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ShieldOff, Plus, Pencil, Trash2, ToggleLeft, ToggleRight,
  Filter, Download, RefreshCw, X, AlertTriangle, CheckCircle,
  FileText, Lock, Bell, Search, Calendar,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type PatternType = 'regex' | 'keyword' | 'fingerprint'
type DataCategory = 'pii' | 'financial' | 'health' | 'confidential' | 'ip'
type DLPAction = 'alert' | 'block' | 'quarantine'

interface DLPRule {
  id: string
  name: string
  description: string
  pattern: string
  pattern_type: PatternType
  data_category: DataCategory
  action: DLPAction
  severity: number
  enabled: boolean
  created_at: string
  updated_at: string
}

interface DLPViolation {
  id: string
  rule_id: string
  rule_name: string
  agent_hostname: string
  file_path: string
  process_name: string
  matched_pattern: string
  action_taken: DLPAction
  detected_at: string
}

interface DLPStats {
  total_rules: number
  active_violations_today: number
  violations_this_week: number
  blocked_actions: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const patternTypeBadge = (t: PatternType) => {
  const map = {
    regex:       'bg-purple-900/40 text-purple-300 border-purple-700/50',
    keyword:     'bg-blue-900/40 text-blue-300 border-blue-700/50',
    fingerprint: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  }
  return map[t]
}

const dataCategoryBadge = (c: DataCategory) => {
  const map = {
    pii:          'bg-red-900/40 text-red-300 border-red-700/50',
    financial:    'bg-green-900/40 text-green-300 border-green-700/50',
    health:       'bg-pink-900/40 text-pink-300 border-pink-700/50',
    confidential: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
    ip:           'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
  }
  return map[c]
}

const actionBadge = (a: DLPAction) => {
  const map = {
    alert:      { cls: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50', icon: Bell },
    block:      { cls: 'bg-red-900/40 text-red-300 border-red-700/50', icon: Lock },
    quarantine: { cls: 'bg-orange-900/40 text-orange-300 border-orange-700/50', icon: FileText },
  }
  return map[a]
}

const severityColor = (s: number) => {
  if (s >= 9) return 'text-red-400'
  if (s >= 7) return 'text-orange-400'
  if (s >= 5) return 'text-yellow-400'
  return 'text-green-400'
}

const maskPattern = (p: string) => p.slice(0, 3) + '***'

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })

// ─── Modal ────────────────────────────────────────────────────────────────────

interface RuleFormData {
  name: string
  description: string
  pattern: string
  pattern_type: PatternType
  data_category: DataCategory
  action: DLPAction
  severity: number
  enabled: boolean
}

const DEFAULT_FORM: RuleFormData = {
  name: '',
  description: '',
  pattern: '',
  pattern_type: 'regex',
  data_category: 'pii',
  action: 'alert',
  severity: 5,
  enabled: true,
}

function RuleModal({
  rule,
  onClose,
  onSave,
}: {
  rule?: DLPRule
  onClose: () => void
  onSave: (data: RuleFormData) => void
}) {
  const [form, setForm] = useState<RuleFormData>(
    rule
      ? {
          name: rule.name,
          description: rule.description,
          pattern: rule.pattern,
          pattern_type: rule.pattern_type,
          data_category: rule.data_category,
          action: rule.action,
          severity: rule.severity,
          enabled: rule.enabled,
        }
      : DEFAULT_FORM
  )

  const set = (k: keyof RuleFormData, v: unknown) =>
    setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-[560px] max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold text-lg">
            {rule ? 'DLPルール編集' : 'DLPルール追加'}
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ルール名 *</label>
            <input
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="例: クレジットカード検知"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">説明</label>
            <textarea
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60 resize-none"
              rows={2}
              value={form.description}
              onChange={e => set('description', e.target.value)}
            />
          </div>

          {/* Pattern */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">パターン *</label>
            <input
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-hidden focus:border-[#1a6bff]/60"
              value={form.pattern}
              onChange={e => set('pattern', e.target.value)}
              placeholder="\b\d{4}[-\s]?\d{4}...\b"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Pattern Type */}
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">パターンタイプ</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                value={form.pattern_type}
                onChange={e => set('pattern_type', e.target.value as PatternType)}
              >
                <option value="regex">Regex</option>
                <option value="keyword">Keyword</option>
                <option value="fingerprint">Fingerprint</option>
              </select>
            </div>

            {/* Data Category */}
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">データカテゴリ</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                value={form.data_category}
                onChange={e => set('data_category', e.target.value as DataCategory)}
              >
                <option value="pii">PII</option>
                <option value="financial">Financial</option>
                <option value="health">Health</option>
                <option value="confidential">Confidential</option>
                <option value="ip">IP (知的財産)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Action */}
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">アクション</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                value={form.action}
                onChange={e => set('action', e.target.value as DLPAction)}
              >
                <option value="alert">Alert (通知のみ)</option>
                <option value="block">Block (ブロック)</option>
                <option value="quarantine">Quarantine (隔離)</option>
              </select>
            </div>

            {/* Severity */}
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                深刻度: <span className={`font-bold ${severityColor(form.severity)}`}>{form.severity}</span>
              </label>
              <input
                type="range" min={1} max={10}
                value={form.severity}
                onChange={e => set('severity', Number(e.target.value))}
                className="w-full accent-[#e8002d]"
              />
            </div>
          </div>

          {/* Enabled toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => set('enabled', !form.enabled)}
              className="flex items-center gap-2 text-sm text-[#7d92b0] hover:text-white transition-colors"
            >
              {form.enabled
                ? <ToggleRight className="w-6 h-6 text-green-400" />
                : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
              }
              <span>{form.enabled ? '有効' : '無効'}</span>
            </button>
          </div>
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={!form.name || !form.pattern}
            className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {rule ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DLPPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'rules' | 'violations'>('rules')
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule] = useState<DLPRule | undefined>()

  // Violation filters
  const [filterRule, setFilterRule] = useState('')
  const [filterAgent, setFilterAgent] = useState('')
  const [filterAction, setFilterAction] = useState('')
  const [filterDateFrom, setFilterDateFrom] = useState('')
  const [filterDateTo, setFilterDateTo] = useState('')
  const [searchViolation, setSearchViolation] = useState('')

  // ── Queries ──────────────────────────────────────────────────

  const { data: stats } = useQuery<DLPStats>({
    queryKey: ['dlp-stats'],
    queryFn: () => apiFetch('/api/v1/admin/dlp/stats'),
    staleTime: 30_000,
    retry: false,
    // fallback on error
  })

  const { data: rules = [], isLoading: rulesLoading } = useQuery<DLPRule[]>({
    queryKey: ['dlp-rules'],
    queryFn: () => apiFetchList<DLPRule>('/api/v1/admin/dlp/rules'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: violations = [], isLoading: violationsLoading } = useQuery<DLPViolation[]>({
    queryKey: ['dlp-violations'],
    queryFn: () => apiFetchList<DLPViolation>('/api/v1/admin/dlp/violations'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: agents = [] } = useQuery<{ id: string; hostname: string }[]>({
    queryKey: ['agents-list'],
    queryFn: async () => {
      try { return await apiFetchList<{ id: string; hostname: string }>('/api/v1/agents') } catch { return [] }
    },
    staleTime: 60_000,
    retry: false,
  })

  // Unique agent hostnames for filter
  const agentOptions = Array.from(new Set(violations.map(v => v.agent_hostname)))

  // ── Mutations ────────────────────────────────────────────────

  const createRule = useMutation({
    mutationFn: (data: RuleFormData) =>
      apiFetch('/api/v1/admin/dlp/rules', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp-rules'] })
      setShowModal(false)
    },
    onError: () => setShowModal(false),
  })

  const updateRule = useMutation({
    mutationFn: ({ id, data }: { id: string; data: RuleFormData }) =>
      apiFetch(`/api/v1/admin/dlp/rules/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp-rules'] })
      setEditRule(undefined)
    },
    onError: () => setEditRule(undefined),
  })

  const deleteRule = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/dlp/rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlp-rules'] }),
  })

  const toggleRule = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/dlp/rules/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlp-rules'] }),
  })

  // ── Derived Stats ────────────────────────────────────────────

  const EMPTY_STATS: DLPStats = { total_rules: 0, active_violations_today: 0, violations_this_week: 0, blocked_actions: 0 }
  const displayStats = stats ?? EMPTY_STATS

  // ── Filtered Violations ──────────────────────────────────────

  const filteredViolations = violations.filter(v => {
    if (filterRule && v.rule_id !== filterRule) return false
    if (filterAgent && v.agent_hostname !== filterAgent) return false
    if (filterAction && v.action_taken !== filterAction) return false
    if (filterDateFrom && new Date(v.detected_at) < new Date(filterDateFrom)) return false
    if (filterDateTo && new Date(v.detected_at) > new Date(filterDateTo + 'T23:59:59Z')) return false
    if (searchViolation) {
      const q = searchViolation.toLowerCase()
      if (!v.file_path.toLowerCase().includes(q) && !v.agent_hostname.toLowerCase().includes(q) && !v.rule_name.toLowerCase().includes(q)) return false
    }
    return true
  })

  // ── CSV Export ───────────────────────────────────────────────

  const exportCsv = () => {
    const headers = ['Rule Name', 'Agent', 'File Path', 'Process', 'Matched Pattern', 'Action', 'Detected At']
    const rows = filteredViolations.map(v => [
      v.rule_name, v.agent_hostname, v.file_path, v.process_name,
      maskPattern(v.matched_pattern), v.action_taken, v.detected_at,
    ])
    const csv = [headers, ...rows].map(r => r.map(c => `"${c}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'dlp_violations.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  // ────────────────────────────────────────────────────────────

  const displayRules = rules
  const displayViolations = violations

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* ── Header ── */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center shadow-lg">
              <ShieldOff className="w-4 h-4 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">データ損失防止 (DLP)</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">
            機密データの漏洩を検知・防止するルールと違反ログを管理します
          </p>
        </div>

        {/* ── Stats Row ── */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: '総ルール数', value: displayStats.total_rules, icon: FileText, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
            { label: '本日の違反', value: displayStats.active_violations_today, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
            { label: '今週の違反', value: displayStats.violations_this_week, icon: Calendar, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/30' },
            { label: 'ブロック済み', value: displayStats.blocked_actions, icon: Lock, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
          ].map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg} bg-[#0d1220]`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-[#7d92b0]">{s.label}</span>
                <s.icon className={`w-4 h-4 ${s.color}`} />
              </div>
              <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* ── Tabs ── */}
        <div className="flex gap-1 mb-5 border-b border-[#1e2d42]">
          {([['rules', 'DLPルール'], ['violations', '違反ログ']] as const).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setActiveTab(k)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px
                ${activeTab === k
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
                }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ════════════════════════ DLP Rules Tab ══════════════════════════ */}
        {activeTab === 'rules' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm text-[#7d92b0]">{displayRules.length} ルール</p>
              <button
                onClick={() => { setEditRule(undefined); setShowModal(true) }}
                className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                ルール追加
              </button>
            </div>

            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['名前', 'パターン', 'タイプ', 'カテゴリ', 'アクション', '深刻度', '有効', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayRules.map(rule => {
                    const ab = actionBadge(rule.action)
                    const ActionIcon = ab.icon
                    return (
                      <tr key={rule.id} className="border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors">
                        {/* Name */}
                        <td className="px-4 py-3">
                          <p className="text-white font-medium">{rule.name}</p>
                          <p className="text-xs text-[#7d92b0] truncate max-w-[160px]">{rule.description}</p>
                        </td>

                        {/* Pattern */}
                        <td className="px-4 py-3">
                          <code className="text-[#7d92b0] text-xs font-mono bg-[#070d19] px-2 py-1 rounded-sm max-w-[180px] block truncate">
                            {rule.pattern}
                          </code>
                        </td>

                        {/* Pattern Type */}
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${patternTypeBadge(rule.pattern_type)}`}>
                            {rule.pattern_type}
                          </span>
                        </td>

                        {/* Data Category */}
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-sm border uppercase ${dataCategoryBadge(rule.data_category)}`}>
                            {rule.data_category}
                          </span>
                        </td>

                        {/* Action */}
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm border capitalize ${ab.cls}`}>
                            <ActionIcon className="w-3 h-3" />
                            {rule.action}
                          </span>
                        </td>

                        {/* Severity */}
                        <td className="px-4 py-3">
                          <span className={`text-lg font-bold ${severityColor(rule.severity)}`}>{rule.severity}</span>
                          <span className="text-[#3d5068] text-xs">/10</span>
                        </td>

                        {/* Toggle */}
                        <td className="px-4 py-3">
                          <button onClick={() => toggleRule.mutate(rule.id)}>
                            {rule.enabled
                              ? <ToggleRight className="w-6 h-6 text-green-400 hover:text-green-300 transition-colors" />
                              : <ToggleLeft className="w-6 h-6 text-[#3d5068] hover:text-[#7d92b0] transition-colors" />
                            }
                          </button>
                        </td>

                        {/* Actions */}
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => { setEditRule(rule); setShowModal(true) }}
                              className="text-[#7d92b0] hover:text-[#1a6bff] transition-colors"
                            >
                              <Pencil className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => { if (confirm(`ルール「${rule.name}」を削除しますか？`)) deleteRule.mutate(rule.id) }}
                              className="text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ═══════════════════════ Violations Tab ══════════════════════════ */}
        {activeTab === 'violations' && (
          <div>
            {/* Filters */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 mb-4">
              <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                {/* Search */}
                <div className="relative lg:col-span-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
                  <input
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff]/60"
                    placeholder="ホスト・ファイル検索..."
                    value={searchViolation}
                    onChange={e => setSearchViolation(e.target.value)}
                  />
                </div>

                {/* Rule filter */}
                <select
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterRule}
                  onChange={e => setFilterRule(e.target.value)}
                >
                  <option value="">全ルール</option>
                  {displayRules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>

                {/* Agent filter */}
                <select
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterAgent}
                  onChange={e => setFilterAgent(e.target.value)}
                >
                  <option value="">全エージェント</option>
                  {agentOptions.map(a => <option key={a} value={a}>{a}</option>)}
                </select>

                {/* Action filter */}
                <select
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterAction}
                  onChange={e => setFilterAction(e.target.value)}
                >
                  <option value="">全アクション</option>
                  <option value="alert">Alert</option>
                  <option value="block">Block</option>
                  <option value="quarantine">Quarantine</option>
                </select>

                {/* Export */}
                <button
                  onClick={exportCsv}
                  className="flex items-center justify-center gap-2 px-4 py-2 bg-[#131d31] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white text-sm rounded-lg transition-colors"
                >
                  <Download className="w-4 h-4" />
                  CSV出力
                </button>
              </div>

              {/* Date range */}
              <div className="flex items-center gap-3 mt-3">
                <Calendar className="w-4 h-4 text-[#3d5068]" />
                <input
                  type="date"
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterDateFrom}
                  onChange={e => setFilterDateFrom(e.target.value)}
                />
                <span className="text-[#3d5068]">〜</span>
                <input
                  type="date"
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterDateTo}
                  onChange={e => setFilterDateTo(e.target.value)}
                />
                {(filterRule || filterAgent || filterAction || filterDateFrom || filterDateTo || searchViolation) && (
                  <button
                    onClick={() => { setFilterRule(''); setFilterAgent(''); setFilterAction(''); setFilterDateFrom(''); setFilterDateTo(''); setSearchViolation('') }}
                    className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
                  >
                    <X className="w-3 h-3" /> フィルターをクリア
                  </button>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-[#7d92b0]">{filteredViolations.length} 件の違反</p>
            </div>

            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ルール名', 'エージェント', 'ファイルパス', 'プロセス', 'マッチパターン', 'アクション', '検知日時'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredViolations.map(v => {
                    const ab = actionBadge(v.action_taken)
                    const ActionIcon = ab.icon
                    return (
                      <tr key={v.id} className="border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors">
                        <td className="px-4 py-3 text-white font-medium">{v.rule_name}</td>
                        <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{v.agent_hostname}</td>
                        <td className="px-4 py-3">
                          <p className="text-[#7d92b0] text-xs font-mono max-w-[200px] truncate" title={v.file_path}>
                            {v.file_path}
                          </p>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{v.process_name}</td>
                        <td className="px-4 py-3">
                          <code className="text-orange-300 text-xs font-mono bg-[#070d19] px-2 py-0.5 rounded-sm">
                            {maskPattern(v.matched_pattern)}
                          </code>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm border capitalize ${ab.cls}`}>
                            <ActionIcon className="w-3 h-3" />
                            {v.action_taken}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDate(v.detected_at)}</td>
                      </tr>
                    )
                  })}
                  {filteredViolations.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-10 text-center text-[#3d5068]">
                        <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-700/50" />
                        <p>条件に一致する違反ログはありません</p>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ── Rule Modal ── */}
      {(showModal || editRule) && (
        <RuleModal
          rule={editRule}
          onClose={() => { setShowModal(false); setEditRule(undefined) }}
          onSave={data => {
            if (editRule) {
              updateRule.mutate({ id: editRule.id, data })
            } else {
              createRule.mutate(data)
            }
          }}
        />
      )}
    </div>
  )
}
