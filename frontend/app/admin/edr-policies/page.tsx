'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Shield, Plus, Edit2, Trash2, Eye, ToggleLeft, ToggleRight,
  Users, Clock, X, ChevronDown, AlertTriangle, CheckCircle,
  Settings, Network, FileText, Activity, Layers,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

type PolicyType = 'standard' | 'strict' | 'minimal' | 'custom'
type Sensitivity = 'low' | 'medium' | 'high'

interface RulesConfig {
  process_monitoring: {
    enabled: boolean
    excluded_paths: string
  }
  file_monitoring: {
    enabled: boolean
    monitored_extensions: string
  }
  network_monitoring: {
    enabled: boolean
    blocked_ports: string
  }
  threat_detection: {
    sensitivity: Sensitivity
  }
}

interface EDRPolicy {
  id: string
  name: string
  description: string
  policy_type: PolicyType
  enabled: boolean
  assigned_groups: number
  rules_config: RulesConfig
  last_updated: string
}

interface PolicyAssignment {
  id: string
  policy_id: string
  policy_name: string
  target_type: 'agent' | 'group'
  target_id: string
  target_name: string
  assigned_at: string
}

interface Agent {
  id: string
  hostname: string
}

interface Group {
  id: string
  name: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const policyTypeBadge: Record<PolicyType, { label: string; cls: string }> = {
  standard: { label: 'スタンダード', cls: 'bg-blue-500/20 text-blue-400 border border-blue-500/30' },
  strict:   { label: 'ストリクト',   cls: 'bg-red-500/20 text-red-400 border border-red-500/30' },
  minimal:  { label: 'ミニマル',     cls: 'bg-gray-500/20 text-gray-400 border border-gray-500/30' },
  custom:   { label: 'カスタム',     cls: 'bg-purple-500/20 text-purple-400 border border-purple-500/30' },
}

const sensitivityColors: Record<Sensitivity, string> = {
  low:    'bg-gray-600',
  medium: 'bg-yellow-500',
  high:   'bg-red-500',
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

// ─── Default form state ───────────────────────────────────────────────────────

function defaultForm(): Omit<EDRPolicy, 'id' | 'assigned_groups' | 'last_updated'> {
  return {
    name: '',
    description: '',
    policy_type: 'standard',
    enabled: true,
    rules_config: {
      process_monitoring: { enabled: true, excluded_paths: '' },
      file_monitoring: { enabled: true, monitored_extensions: '.exe,.dll,.bat,.ps1' },
      network_monitoring: { enabled: true, blocked_ports: '' },
      threat_detection: { sensitivity: 'medium' },
    },
  }
}

// ─── PolicyModal ──────────────────────────────────────────────────────────────

function PolicyModal({
  policy,
  onClose,
  onSave,
}: {
  policy?: EDRPolicy
  onClose: () => void
  onSave: (data: Omit<EDRPolicy, 'id' | 'assigned_groups' | 'last_updated'>) => void
}) {
  const [form, setForm] = useState<Omit<EDRPolicy, 'id' | 'assigned_groups' | 'last_updated'>>(
    policy
      ? {
          name: policy.name,
          description: policy.description,
          policy_type: policy.policy_type,
          enabled: policy.enabled,
          rules_config: policy.rules_config,
        }
      : defaultForm()
  )

  const setRules = (section: keyof RulesConfig, key: string, value: unknown) => {
    setForm(f => ({
      ...f,
      rules_config: {
        ...f.rules_config,
        [section]: { ...(f.rules_config[section] as Record<string, unknown>), [key]: value },
      },
    }))
  }

  const sensitivityLevels: Sensitivity[] = ['low', 'medium', 'high']
  const sensitivityIdx = sensitivityLevels.indexOf(form.rules_config.threat_detection.sensitivity)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-falcon-red" />
            <h2 className="text-white font-semibold text-base">
              {policy ? 'ポリシーを編集' : 'ポリシーを作成'}
            </h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Basic Info */}
          <section>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5" /> 基本情報
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-falcon-muted mb-1">ポリシー名 <span className="text-falcon-red">*</span></label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: 標準セキュリティポリシー"
                  className="w-full px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">説明</label>
                <textarea
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="ポリシーの用途・目的を記述"
                  rows={2}
                  className="w-full px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 resize-none"
                />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">ポリシータイプ</label>
                <select
                  value={form.policy_type}
                  onChange={e => setForm(f => ({ ...f, policy_type: e.target.value as PolicyType }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                >
                  <option value="standard">スタンダード</option>
                  <option value="strict">ストリクト</option>
                  <option value="minimal">ミニマル</option>
                  <option value="custom">カスタム</option>
                </select>
              </div>
            </div>
          </section>

          {/* Process Monitoring */}
          <section>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5" /> プロセス監視
            </h3>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.rules_config.process_monitoring.enabled}
                  onChange={e => setRules('process_monitoring', 'enabled', e.target.checked)}
                  className="w-4 h-4 accent-falcon-red"
                />
                <span className="text-sm text-white">プロセス監視を有効化</span>
              </label>
              {form.rules_config.process_monitoring.enabled && (
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">除外パス (1行に1パス)</label>
                  <textarea
                    value={form.rules_config.process_monitoring.excluded_paths}
                    onChange={e => setRules('process_monitoring', 'excluded_paths', e.target.value)}
                    placeholder="C:\Windows\System32&#10;C:\Program Files\Trusted"
                    rows={3}
                    className="w-full px-3 py-2 bg-falcon-surface border border-falcon-border rounded-sm text-white text-xs font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 resize-none"
                  />
                </div>
              )}
            </div>
          </section>

          {/* File Monitoring */}
          <section>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5" /> ファイル監視
            </h3>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.rules_config.file_monitoring.enabled}
                  onChange={e => setRules('file_monitoring', 'enabled', e.target.checked)}
                  className="w-4 h-4 accent-falcon-red"
                />
                <span className="text-sm text-white">ファイル監視を有効化</span>
              </label>
              {form.rules_config.file_monitoring.enabled && (
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">監視する拡張子 (カンマ区切り)</label>
                  <input
                    type="text"
                    value={form.rules_config.file_monitoring.monitored_extensions}
                    onChange={e => setRules('file_monitoring', 'monitored_extensions', e.target.value)}
                    placeholder=".exe,.dll,.bat,.ps1,.vbs"
                    className="w-full px-3 py-2 bg-falcon-surface border border-falcon-border rounded-sm text-white text-sm font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                </div>
              )}
            </div>
          </section>

          {/* Network Monitoring */}
          <section>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <Network className="w-3.5 h-3.5" /> ネットワーク監視
            </h3>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.rules_config.network_monitoring.enabled}
                  onChange={e => setRules('network_monitoring', 'enabled', e.target.checked)}
                  className="w-4 h-4 accent-falcon-red"
                />
                <span className="text-sm text-white">ネットワーク監視を有効化</span>
              </label>
              {form.rules_config.network_monitoring.enabled && (
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">ブロックするポート (カンマ区切り)</label>
                  <input
                    type="text"
                    value={form.rules_config.network_monitoring.blocked_ports}
                    onChange={e => setRules('network_monitoring', 'blocked_ports', e.target.value)}
                    placeholder="4444,1337,31337"
                    className="w-full px-3 py-2 bg-falcon-surface border border-falcon-border rounded-sm text-white text-sm font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                </div>
              )}
            </div>
          </section>

          {/* Threat Detection */}
          <section>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5" /> 脅威検知
            </h3>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-white">検知感度</label>
                  <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                    form.rules_config.threat_detection.sensitivity === 'low' ? 'text-gray-400 bg-gray-500/20' :
                    form.rules_config.threat_detection.sensitivity === 'medium' ? 'text-yellow-400 bg-yellow-500/20' :
                    'text-red-400 bg-red-500/20'
                  }`}>
                    {form.rules_config.threat_detection.sensitivity === 'low' ? '低' :
                     form.rules_config.threat_detection.sensitivity === 'medium' ? '中' : '高'}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={2}
                  value={sensitivityIdx}
                  onChange={e => setRules('threat_detection', 'sensitivity', sensitivityLevels[parseInt(e.target.value)])}
                  className="w-full accent-falcon-red"
                />
                <div className="flex justify-between text-[10px] text-falcon-subtle mt-1">
                  <span>低</span><span>中</span><span>高</span>
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { if (form.name.trim()) onSave(form) }}
            disabled={!form.name.trim()}
            className="px-5 py-2 bg-falcon-red hover:bg-[#c8001f] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-colors"
          >
            {policy ? '保存' : '作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── AssignModal ──────────────────────────────────────────────────────────────

function AssignModal({
  policies,
  targetType,
  targetId,
  onClose,
  onAssign,
}: {
  policies: EDRPolicy[]
  targetType: 'agent' | 'group'
  targetId: string
  onClose: () => void
  onAssign: (policyId: string) => void
}) {
  const [selectedPolicy, setSelectedPolicy] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-base">ポリシーを割り当て</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1">ポリシーを選択</label>
            <select
              value={selectedPolicy}
              onChange={e => setSelectedPolicy(e.target.value)}
              className="w-full px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="">-- ポリシーを選択 --</option>
              {policies.filter(p => p.enabled).map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">キャンセル</button>
          <button
            onClick={() => { if (selectedPolicy) onAssign(selectedPolicy) }}
            disabled={!selectedPolicy}
            className="px-5 py-2 bg-falcon-red hover:bg-[#c8001f] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-colors"
          >
            割り当て
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EDRPoliciesPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'list' | 'assignments'>('list')
  const [modalOpen, setModalOpen] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<EDRPolicy | undefined>()
  const [assignModalOpen, setAssignModalOpen] = useState(false)
  const [selectedTargetType, setSelectedTargetType] = useState<'agent' | 'group'>('group')
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [viewAssignOpen, setViewAssignOpen] = useState<string | null>(null)

  // ── Queries ──────────────────────────────────────────────────
  const { data: policies = [] } = useQuery<EDRPolicy[]>({
    queryKey: ['edr-policies'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ policies: any[] }>('/api/v1/admin/edr-policies')
        const list = res.policies ?? []
        return list.map((p: any): EDRPolicy => ({
          id: p.id,
          name: p.name,
          description: p.description ?? '',
          policy_type: p.policy_type ?? 'standard',
          enabled: p.enabled ?? true,
          assigned_groups: p.assignment_count ?? 0,
          rules_config: (() => {
            const r = (p.rules && typeof p.rules === 'object') ? p.rules as any : {}
            return {
              process_monitoring: r.process_monitoring ?? { enabled: true, excluded_paths: '' },
              file_monitoring: r.file_monitoring ?? { enabled: true, monitored_extensions: '.exe,.dll,.bat,.ps1' },
              network_monitoring: r.network_monitoring ?? { enabled: true, blocked_ports: '' },
              threat_detection: r.threat_detection ?? { sensitivity: 'medium' },
            }
          })(),
          last_updated: p.updated_at ?? p.created_at ?? new Date().toISOString(),
        }))
      } catch { return [] }
    },
  })

  const { data: assignments = [] } = useQuery<PolicyAssignment[]>({
    queryKey: ['edr-policy-assignments', selectedTargetId],
    queryFn: async () => {
      if (!selectedTargetId) return []
      try { return await apiFetchList<PolicyAssignment>(`/api/v1/admin/edr-policies/assignments?target_id=${selectedTargetId}`) } catch { return [] }
    },
    enabled: activeTab === 'assignments',
  })

  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-simple'],
    queryFn: async () => {
      try { return await apiFetchList<Agent>('/api/v1/agents') } catch { return [] }
    },
  })

  const { data: groups = [] } = useQuery<Group[]>({
    queryKey: ['groups-simple'],
    queryFn: async () => {
      try { return await apiFetchList<Group>('/api/v1/groups') } catch { return [] }
    },
  })

  // ── Mutations ─────────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: (data: Omit<EDRPolicy, 'id' | 'assigned_groups' | 'last_updated'>) =>
      apiFetch('/api/v1/admin/edr-policies', {
        method: 'POST',
        body: JSON.stringify({
          name: data.name,
          description: data.description,
          policy_type: data.policy_type,
          enabled: data.enabled,
          rules: data.rules_config,
        }),
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policies'] }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<EDRPolicy> }) =>
      apiFetch(`/api/v1/admin/edr-policies/${id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: data.name,
          description: data.description,
          policy_type: data.policy_type,
          enabled: data.enabled,
          rules: data.rules_config,
        }),
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policies'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/edr-policies/${id}`, { method: 'DELETE' }).catch(() => null),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policies'] }),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/edr-policies/${id}/toggle`, { method: 'POST' }).catch(() => null),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policies'] }),
  })

  const assignMutation = useMutation({
    mutationFn: ({ id, policyId }: { id: string; policyId: string }) =>
      apiFetch(`/api/v1/admin/edr-policies/${policyId}/assign`, {
        method: 'POST',
        body: JSON.stringify({ target_id: id, target_type: selectedTargetType }),
      }).catch(() => null),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policy-assignments'] }),
  })

  const unassignMutation = useMutation({
    mutationFn: (assignmentId: string) =>
      apiFetch(`/api/v1/admin/edr-policies/assignments/${assignmentId}`, { method: 'DELETE' }).catch(() => null),
    onSettled: () => qc.invalidateQueries({ queryKey: ['edr-policy-assignments'] }),
  })

  // ── Stats ─────────────────────────────────────────────────────
  const totalPolicies = policies.length
  const enabledCount = policies.filter(p => p.enabled).length
  const totalAssignments = policies.reduce((s, p) => s + p.assigned_groups, 0)
  const registeredAgents = agents.length

  const filteredAssignments = selectedTargetId
    ? assignments.filter(a => a.target_id === selectedTargetId)
    : assignments

  const targetList = selectedTargetType === 'agent' ? agents : groups

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <Shield className="w-6 h-6 text-falcon-red" />
            <h1 className="text-2xl font-bold text-white">EDRポリシー管理</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-9">エンドポイントセキュリティポリシーの作成・管理・割り当て</p>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {[
            { label: '総ポリシー数',     value: totalPolicies,     icon: Shield,        color: 'text-blue-400' },
            { label: '有効数',           value: enabledCount,       icon: CheckCircle,   color: 'text-green-400' },
            { label: '総割り当て数',     value: totalAssignments,   icon: Layers,        color: 'text-yellow-400' },
            { label: '登録エージェント数', value: registeredAgents,  icon: Settings,      color: 'text-purple-400' },
          ].map(stat => (
            <div key={stat.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
                <span className="text-xs text-falcon-muted">{stat.label}</span>
              </div>
              <p className="text-2xl font-bold text-white">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
          {(['list', 'assignments'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === tab
                  ? 'bg-falcon-active text-white'
                  : 'text-falcon-muted hover:text-white'
              }`}
            >
              {tab === 'list' ? 'ポリシー一覧' : 'ポリシー割り当て'}
            </button>
          ))}
        </div>

        {/* ── Policy List Tab ──────────────────────────────────── */}
        {activeTab === 'list' && (
          <>
            <div className="flex justify-end mb-4">
              <button
                onClick={() => { setEditingPolicy(undefined); setModalOpen(true) }}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-semibold rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" /> ポリシー作成
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {policies.map(policy => {
                const badge = policyTypeBadge[policy.policy_type]
                return (
                  <div key={policy.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-5 hover:border-[#2e4a6e] transition-all">
                    {/* Card Header */}
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <h3 className="text-white font-semibold text-sm truncate">{policy.name}</h3>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${badge.cls}`}>
                            {badge.label}
                          </span>
                        </div>
                        <p className="text-falcon-muted text-xs line-clamp-2">{policy.description}</p>
                      </div>
                    </div>

                    {/* Rules summary */}
                    <div className="grid grid-cols-2 gap-2 mb-3">
                      {[
                        { label: 'プロセス', enabled: policy.rules_config.process_monitoring.enabled, icon: Activity },
                        { label: 'ファイル', enabled: policy.rules_config.file_monitoring.enabled, icon: FileText },
                        { label: 'ネットワーク', enabled: policy.rules_config.network_monitoring.enabled, icon: Network },
                        { label: `感度: ${policy.rules_config.threat_detection.sensitivity === 'low' ? '低' : policy.rules_config.threat_detection.sensitivity === 'medium' ? '中' : '高'}`,
                          enabled: true, icon: AlertTriangle },
                      ].map(item => (
                        <div key={item.label} className="flex items-center gap-1.5 text-xs">
                          <item.icon className={`w-3 h-3 ${item.enabled ? 'text-green-400' : 'text-falcon-subtle'}`} />
                          <span className={item.enabled ? 'text-falcon-muted' : 'text-falcon-subtle'}>{item.label}</span>
                        </div>
                      ))}
                    </div>

                    {/* Meta */}
                    <div className="flex items-center gap-3 text-xs text-falcon-muted mb-3">
                      <span className="flex items-center gap-1">
                        <Users className="w-3 h-3" /> {policy.assigned_groups} グループ
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" /> {fmtDate(policy.last_updated)}
                      </span>
                    </div>

                    {/* Toggle + Actions */}
                    <div className="flex items-center justify-between pt-3 border-t border-falcon-border">
                      <button
                        onClick={() => toggleMutation.mutate(policy.id)}
                        className="flex items-center gap-1.5 text-xs"
                      >
                        {policy.enabled
                          ? <ToggleRight className="w-5 h-5 text-green-400" />
                          : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />
                        }
                        <span className={policy.enabled ? 'text-green-400' : 'text-falcon-subtle'}>
                          {policy.enabled ? '有効' : '無効'}
                        </span>
                      </button>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setViewAssignOpen(viewAssignOpen === policy.id ? null : policy.id)}
                          className="p-1.5 text-falcon-muted hover:text-white hover:bg-falcon-active rounded-sm transition-colors"
                          title="割り当て確認"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => { setEditingPolicy(policy); setModalOpen(true) }}
                          className="p-1.5 text-falcon-muted hover:text-white hover:bg-falcon-active rounded-sm transition-colors"
                          title="編集"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => { if (confirm(`「${policy.name}」を削除しますか？`)) deleteMutation.mutate(policy.id) }}
                          className="p-1.5 text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 rounded-sm transition-colors"
                          title="削除"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Expanded assignments view */}
                    {viewAssignOpen === policy.id && (
                      <div className="mt-3 pt-3 border-t border-falcon-border">
                        <p className="text-xs text-falcon-muted mb-2">割り当て済みターゲット</p>
                        {assignments.filter(a => a.policy_id === policy.id).length === 0 ? (
                          <p className="text-xs text-falcon-subtle">割り当てなし</p>
                        ) : (
                          <div className="space-y-1">
                            {assignments.filter(a => a.policy_id === policy.id).map(a => (
                              <div key={a.id} className="flex items-center gap-2 text-xs">
                                <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${a.target_type === 'group' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'}`}>
                                  {a.target_type === 'group' ? 'グループ' : 'エージェント'}
                                </span>
                                <span className="text-falcon-muted">{a.target_name}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </>
        )}

        {/* ── Assignments Tab ──────────────────────────────────── */}
        {activeTab === 'assignments' && (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            {/* Controls */}
            <div className="flex flex-wrap items-center gap-3 px-5 py-4 border-b border-falcon-border">
              <div className="flex items-center gap-2">
                <select
                  value={selectedTargetType}
                  onChange={e => { setSelectedTargetType(e.target.value as 'agent' | 'group'); setSelectedTargetId('') }}
                  className="px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm focus:outline-hidden"
                >
                  <option value="group">グループ</option>
                  <option value="agent">エージェント</option>
                </select>
                <select
                  value={selectedTargetId}
                  onChange={e => setSelectedTargetId(e.target.value)}
                  className="px-3 py-2 bg-[#070d19] border border-falcon-border rounded-sm text-white text-sm focus:outline-hidden min-w-[200px]"
                >
                  <option value="">-- すべて表示 --</option>
                  {targetList.map((t: Agent | Group) => (
                    <option key={t.id} value={t.id}>
                      {'hostname' in t ? t.hostname : t.name}
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={() => setAssignModalOpen(true)}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-semibold rounded-lg transition-colors ml-auto"
              >
                <Plus className="w-4 h-4" /> ポリシー割り当て
              </button>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['ポリシー名', 'タイプ', 'ターゲット種別', 'ターゲット名', '割り当て日', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {filteredAssignments.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-falcon-muted text-sm">
                        割り当てがありません
                      </td>
                    </tr>
                  ) : (
                    filteredAssignments.map(asgn => {
                      const policy = policies.find(p => p.id === asgn.policy_id)
                      const badge = policy ? policyTypeBadge[policy.policy_type] : policyTypeBadge.standard
                      return (
                        <tr key={asgn.id} className="hover:bg-[#0a1128] transition-colors">
                          <td className="px-4 py-3 text-sm text-white font-medium">{asgn.policy_name}</td>
                          <td className="px-4 py-3">
                            {policy && (
                              <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${badge.cls}`}>
                                {badge.label}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-xs px-2 py-0.5 rounded-sm ${asgn.target_type === 'group' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'}`}>
                              {asgn.target_type === 'group' ? 'グループ' : 'エージェント'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-falcon-muted">{asgn.target_name}</td>
                          <td className="px-4 py-3 text-sm text-falcon-muted">{fmtDate(asgn.assigned_at)}</td>
                          <td className="px-4 py-3">
                            <button
                              onClick={() => { if (confirm('割り当てを解除しますか？')) unassignMutation.mutate(asgn.id) }}
                              className="text-xs px-3 py-1 text-falcon-red border border-falcon-red/30 hover:bg-falcon-red/10 rounded-sm transition-colors"
                            >
                              割り当て解除
                            </button>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {modalOpen && (
        <PolicyModal
          policy={editingPolicy}
          onClose={() => { setModalOpen(false); setEditingPolicy(undefined) }}
          onSave={data => {
            if (editingPolicy) {
              updateMutation.mutate({ id: editingPolicy.id, data })
            } else {
              createMutation.mutate(data)
            }
            setModalOpen(false)
            setEditingPolicy(undefined)
          }}
        />
      )}

      {assignModalOpen && selectedTargetId && (
        <AssignModal
          policies={policies}
          targetType={selectedTargetType}
          targetId={selectedTargetId}
          onClose={() => setAssignModalOpen(false)}
          onAssign={policyId => {
            assignMutation.mutate({ id: selectedTargetId, policyId })
            setAssignModalOpen(false)
          }}
        />
      )}
    </div>
  )
}
