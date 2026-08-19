'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Plus, Pencil, Trash2, X, Check, RefreshCw,
  ChevronDown, Cpu, HardDrive, Clock, ScanLine, Network,
  FileSearch, AlertTriangle, Layers
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface AgentPolicy {
  id: string
  name: string
  description: string
  tenant_id: string
  scan_interval_min: number
  full_scan_hour: number
  monitored_extensions: string[]
  excluded_paths: string[]
  cpu_limit_pct: number
  mem_limit_mb: number
  monitor_network: boolean
  monitor_dns: boolean
  log_level: string
  created_at: string
  updated_at: string
}

interface AgentGroup {
  id: string
  name: string
  description: string
  agent_count: number
  policy_id?: string
  created_at: string
}

interface PolicyForm {
  name: string
  description: string
  scan_interval_min: number
  full_scan_hour: number
  monitored_extensions: string[]
  excluded_paths: string[]
  cpu_limit_pct: number
  mem_limit_mb: number
  monitor_network: boolean
  monitor_dns: boolean
  log_level: string
}

// ─── 定数 ──────────────────────────────────────────────────────────────────

const DEFAULT_POLICY_ID = '00000000-0000-0000-0000-000000000002'

const KNOWN_EXTENSIONS = ['.exe', '.dll', '.sh', '.ps1', '.py', '.bat', '.cmd', '.vbs', '.js', '.msi']

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const

const EMPTY_FORM: PolicyForm = {
  name: '',
  description: '',
  scan_interval_min: 60,
  full_scan_hour: 2,
  monitored_extensions: ['.exe', '.dll', '.sh', '.ps1', '.py'],
  excluded_paths: [],
  cpu_limit_pct: 20,
  mem_limit_mb: 256,
  monitor_network: true,
  monitor_dns: true,
  log_level: 'info',
}

const LOG_LEVEL_STYLES: Record<string, string> = {
  debug: 'bg-slate-800/60 text-slate-300 border border-slate-600/50',
  info:  'bg-blue-900/40 text-blue-300 border border-blue-700/50',
  warn:  'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
  error: 'bg-red-900/40 text-red-300 border border-red-700/50',
}

// ─── サブコンポーネント ────────────────────────────────────────────────────

function SliderField({
  label, value, min, max, step = 1, unit,
  onChange
}: {
  label: string
  value: number
  min: number
  max: number
  step?: number
  unit: string
  onChange: (v: number) => void
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <label className="text-[#8899aa] text-sm">{label}</label>
        <span className="text-white text-sm font-mono font-medium">
          {value}{unit}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full h-1.5 bg-[#1e2d42] rounded-full appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[#1a6bff] [&::-webkit-slider-thumb]:cursor-pointer"
      />
      <div className="flex justify-between text-[#5a6a7a] text-xs">
        <span>{min}{unit}</span>
        <span>{max}{unit}</span>
      </div>
    </div>
  )
}

function ExtensionCheckboxes({
  selected,
  onChange
}: {
  selected: string[]
  onChange: (exts: string[]) => void
}) {
  const toggle = (ext: string) => {
    if (selected.includes(ext)) {
      onChange(selected.filter(e => e !== ext))
    } else {
      onChange([...selected, ext])
    }
  }

  return (
    <div className="flex flex-wrap gap-2">
      {KNOWN_EXTENSIONS.map(ext => (
        <button
          key={ext}
          type="button"
          onClick={() => toggle(ext)}
          className={`text-xs px-2.5 py-1 rounded-full border transition-colors font-mono
            ${selected.includes(ext)
              ? 'bg-[#1a6bff]/20 text-blue-300 border-blue-500/50'
              : 'bg-[#0d1625] text-[#5a6a7a] border-[#1e2d42] hover:border-[#2a3d5a]'
            }`}
        >
          {ext}
        </button>
      ))}
    </div>
  )
}

function PathListEditor({
  paths,
  onChange
}: {
  paths: string[]
  onChange: (paths: string[]) => void
}) {
  const [input, setInput] = useState('')

  const add = () => {
    const v = input.trim()
    if (v && !paths.includes(v)) {
      onChange([...paths, v])
      setInput('')
    }
  }

  const remove = (p: string) => onChange(paths.filter(x => x !== p))

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }}
          placeholder="/var/log  または  C:\\Windows\\Temp"
          className="flex-1 bg-[#080c14] text-white px-3 py-1.5 rounded-lg border border-[#1e2d42] text-xs font-mono focus:outline-hidden focus:border-[#1a6bff]"
        />
        <button
          type="button"
          onClick={add}
          className="px-3 py-1.5 bg-[#1a6bff]/20 text-blue-300 rounded-lg text-xs hover:bg-[#1a6bff]/30 transition-colors"
        >
          追加
        </button>
      </div>
      {paths.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {paths.map(p => (
            <span
              key={p}
              className="flex items-center gap-1 text-xs font-mono bg-[#0d1625] text-[#8899aa] border border-[#1e2d42] rounded-sm px-2 py-0.5"
            >
              {p}
              <button type="button" onClick={() => remove(p)} className="text-[#5a6a7a] hover:text-red-400 transition-colors ml-0.5">
                <X className="w-2.5 h-2.5" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── ポリシーフォームモーダル ──────────────────────────────────────────────

function PolicyFormModal({
  initial,
  onClose,
  onSubmit,
  isPending,
  title,
}: {
  initial: PolicyForm
  onClose: () => void
  onSubmit: (f: PolicyForm) => void
  isPending: boolean
  title: string
}) {
  const [form, setForm] = useState<PolicyForm>(initial)
  const set = <K extends keyof PolicyForm>(k: K, v: PolicyForm[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-start justify-center z-50 overflow-y-auto py-8 px-4">
      <div className="bg-[#111827] rounded-2xl w-full max-w-2xl border border-[#1e2d42] shadow-2xl">
        {/* ヘッダー */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            {title}
          </h2>
          <button onClick={onClose} className="text-[#5a6a7a] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form
          onSubmit={e => { e.preventDefault(); onSubmit(form) }}
          className="p-6 space-y-6"
        >
          {/* 基本情報 */}
          <section className="space-y-4">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-3.5 h-3.5" /> 基本情報
            </h3>
            <div>
              <label className="text-[#8899aa] text-sm block mb-1">
                ポリシー名 <span className="text-red-400">*</span>
              </label>
              <input
                value={form.name}
                onChange={e => set('name', e.target.value)}
                required
                placeholder="Production Servers"
                className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
              />
            </div>
            <div>
              <label className="text-[#8899aa] text-sm block mb-1">説明</label>
              <textarea
                value={form.description}
                onChange={e => set('description', e.target.value)}
                rows={2}
                placeholder="このポリシーの用途や適用範囲を入力..."
                className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] resize-none"
              />
            </div>
          </section>

          {/* スキャン設定 */}
          <section className="space-y-4">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <ScanLine className="w-3.5 h-3.5" /> スキャン設定
            </h3>
            <SliderField
              label="スキャン間隔"
              value={form.scan_interval_min}
              min={5} max={1440} step={5} unit="分"
              onChange={v => set('scan_interval_min', v)}
            />
            <SliderField
              label="フルスキャン実行時刻"
              value={form.full_scan_hour}
              min={0} max={23} step={1} unit="時"
              onChange={v => set('full_scan_hour', v)}
            />
          </section>

          {/* 監視対象拡張子 */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <FileSearch className="w-3.5 h-3.5" /> 監視対象拡張子
            </h3>
            <ExtensionCheckboxes
              selected={form.monitored_extensions}
              onChange={v => set('monitored_extensions', v)}
            />
          </section>

          {/* 除外パス */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <X className="w-3.5 h-3.5" /> 除外パス
            </h3>
            <PathListEditor
              paths={form.excluded_paths}
              onChange={v => set('excluded_paths', v)}
            />
          </section>

          {/* リソース制限 */}
          <section className="space-y-4">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5" /> リソース制限
            </h3>
            <SliderField
              label="CPU使用率上限"
              value={form.cpu_limit_pct}
              min={5} max={80} step={5} unit="%"
              onChange={v => set('cpu_limit_pct', v)}
            />
            <SliderField
              label="メモリ上限"
              value={form.mem_limit_mb}
              min={64} max={1024} step={64} unit="MB"
              onChange={v => set('mem_limit_mb', v)}
            />
          </section>

          {/* ネットワーク監視 */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <Network className="w-3.5 h-3.5" /> ネットワーク監視
            </h3>
            <div className="grid grid-cols-2 gap-3">
              {([
                { key: 'monitor_network', label: 'ネットワーク監視' },
                { key: 'monitor_dns',     label: 'DNS監視' },
              ] as { key: 'monitor_network' | 'monitor_dns'; label: string }[]).map(({ key, label }) => (
                <label
                  key={key}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl border cursor-pointer transition-colors
                    ${form[key]
                      ? 'bg-blue-900/20 border-blue-700/50 text-blue-300'
                      : 'bg-[#0d1625] border-[#1e2d42] text-[#8899aa]'
                    }`}
                >
                  <input
                    type="checkbox"
                    checked={form[key]}
                    onChange={e => set(key, e.target.checked)}
                    className="w-4 h-4 accent-blue-500"
                  />
                  <span className="text-sm">{label}</span>
                </label>
              ))}
            </div>
          </section>

          {/* ログ設定 */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-[#8899aa] uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5" /> ログレベル
            </h3>
            <div className="flex gap-2 flex-wrap">
              {LOG_LEVELS.map(level => (
                <button
                  key={level}
                  type="button"
                  onClick={() => set('log_level', level)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors
                    ${form.log_level === level
                      ? LOG_LEVEL_STYLES[level]
                      : 'bg-[#0d1625] text-[#5a6a7a] border-[#1e2d42] hover:border-[#2a3d5a]'
                    }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </section>

          {/* フッター */}
          <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#1e2d42]">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-[#8899aa] hover:text-white transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="flex items-center gap-2 px-5 py-2 bg-[#1a6bff] text-white rounded-lg text-sm hover:bg-[#1557d4] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isPending ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Check className="w-4 h-4" />
              )}
              保存
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── グループ割り当てドロップダウン ───────────────────────────────────────

function GroupAssignDropdown({
  group,
  policies,
  onAssign,
  isPending,
}: {
  group: AgentGroup
  policies: AgentPolicy[]
  onAssign: (groupId: string, policyId: string) => void
  isPending: boolean
}) {
  const current = policies.find(p => p.id === group.policy_id)

  return (
    <div className="flex items-center gap-2">
      <span className="text-[#5a6a7a] text-xs">ポリシー:</span>
      <div className="relative">
        <select
          value={group.policy_id ?? DEFAULT_POLICY_ID}
          onChange={e => onAssign(group.id, e.target.value)}
          disabled={isPending}
          className="appearance-none bg-[#0d1625] text-[#8899aa] border border-[#1e2d42] rounded-lg pl-3 pr-7 py-1 text-xs focus:outline-hidden focus:border-[#1a6bff] hover:border-[#2a3d5a] transition-colors disabled:opacity-50 cursor-pointer"
        >
          {policies.map(p => (
            <option key={p.id} value={p.id}>
              {p.name}{p.id === DEFAULT_POLICY_ID ? ' (デフォルト)' : ''}
            </option>
          ))}
        </select>
        <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#5a6a7a] pointer-events-none" />
      </div>
    </div>
  )
}

// ─── ポリシーカード ────────────────────────────────────────────────────────

function PolicyCard({
  policy,
  onEdit,
  onDelete,
}: {
  policy: AgentPolicy
  onEdit: (p: AgentPolicy) => void
  onDelete: (id: string) => void
}) {
  const isDefault = policy.id === DEFAULT_POLICY_ID
  const [confirmDelete, setConfirmDelete] = useState(false)

  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5 space-y-4 hover:border-[#2a3d5a] transition-colors">
      {/* カードヘッダー */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-white font-semibold truncate">{policy.name}</h3>
            {isDefault && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-300 border border-green-700/50 shrink-0">
                デフォルト
              </span>
            )}
            <span className={`text-xs px-2 py-0.5 rounded-full border shrink-0 ${LOG_LEVEL_STYLES[policy.log_level] ?? LOG_LEVEL_STYLES.info}`}>
              {policy.log_level}
            </span>
          </div>
          {policy.description && (
            <p className="text-[#8899aa] text-sm mt-0.5 line-clamp-2">{policy.description}</p>
          )}
        </div>
        {!isDefault && (
          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={() => onEdit(policy)}
              className="p-1.5 text-[#5a6a7a] hover:text-blue-400 transition-colors rounded-lg hover:bg-blue-900/20"
              title="編集"
            >
              <Pencil className="w-4 h-4" />
            </button>
            {confirmDelete ? (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => onDelete(policy.id)}
                  className="text-xs text-red-300 bg-red-900/40 px-2 py-1 rounded-sm hover:bg-red-900/60 transition-colors"
                >
                  確認
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="text-xs text-[#8899aa] hover:text-white transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmDelete(true)}
                className="p-1.5 text-[#5a6a7a] hover:text-red-400 transition-colors rounded-lg hover:bg-red-900/20"
                title="削除"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        )}
      </div>

      {/* スキャン設定 */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-center gap-2 bg-[#080c14] rounded-lg px-3 py-2">
          <Clock className="w-3.5 h-3.5 text-blue-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-[#5a6a7a] text-xs">スキャン間隔</p>
            <p className="text-white text-sm font-medium">{policy.scan_interval_min}分</p>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-[#080c14] rounded-lg px-3 py-2">
          <ScanLine className="w-3.5 h-3.5 text-purple-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-[#5a6a7a] text-xs">フルスキャン</p>
            <p className="text-white text-sm font-medium">{policy.full_scan_hour}時</p>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-[#080c14] rounded-lg px-3 py-2">
          <Cpu className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-[#5a6a7a] text-xs">CPU上限</p>
            <p className="text-white text-sm font-medium">{policy.cpu_limit_pct}%</p>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-[#080c14] rounded-lg px-3 py-2">
          <HardDrive className="w-3.5 h-3.5 text-green-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-[#5a6a7a] text-xs">メモリ上限</p>
            <p className="text-white text-sm font-medium">{policy.mem_limit_mb}MB</p>
          </div>
        </div>
      </div>

      {/* 監視フラグ */}
      <div className="flex items-center gap-3 text-xs">
        <span className={`flex items-center gap-1 px-2 py-1 rounded-full border
          ${policy.monitor_network
            ? 'bg-blue-900/20 text-blue-300 border-blue-700/50'
            : 'bg-[#0d1625] text-[#5a6a7a] border-[#1e2d42]'}`}
        >
          <Network className="w-3 h-3" />
          ネットワーク監視{policy.monitor_network ? 'ON' : 'OFF'}
        </span>
        <span className={`flex items-center gap-1 px-2 py-1 rounded-full border
          ${policy.monitor_dns
            ? 'bg-blue-900/20 text-blue-300 border-blue-700/50'
            : 'bg-[#0d1625] text-[#5a6a7a] border-[#1e2d42]'}`}
        >
          <Network className="w-3 h-3" />
          DNS監視{policy.monitor_dns ? 'ON' : 'OFF'}
        </span>
      </div>

      {/* 監視拡張子 */}
      {policy.monitored_extensions.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {policy.monitored_extensions.map(ext => (
            <span
              key={ext}
              className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#0d1625] text-[#8899aa] border border-[#1e2d42]"
            >
              {ext}
            </span>
          ))}
        </div>
      )}

      {/* 更新日時 */}
      <p className="text-[#5a6a7a] text-xs">
        更新: {new Date(policy.updated_at).toLocaleString('ja-JP')}
      </p>
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────

export default function AdminPoliciesPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<AgentPolicy | null>(null)
  const [error, setError] = useState<string | null>(null)

  // ポリシー一覧
  const { data: policyData, isLoading: policiesLoading, refetch, isFetching } =
    useQuery<{ data: AgentPolicy[]; total: number }>({
      queryKey: ['agent-policies'],
      queryFn: () => apiFetch('/api/v1/agent-policies'),
    })

  // グループ一覧
  const { data: groupData, isLoading: groupsLoading } =
    useQuery<{ data: AgentGroup[]; total: number }>({
      queryKey: ['groups'],
      queryFn: () => apiFetch('/api/v1/groups'),
    })

  // 新規作成
  const createMutation = useMutation({
    mutationFn: (payload: PolicyForm) =>
      apiFetch('/api/v1/agent-policies', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-policies'] })
      setShowCreate(false)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの作成に失敗しました'),
  })

  // 更新
  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: PolicyForm }) =>
      apiFetch(`/api/v1/agent-policies/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-policies'] })
      setEditingPolicy(null)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの更新に失敗しました'),
  })

  // 削除
  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/agent-policies/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-policies'] })
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの削除に失敗しました'),
  })

  // グループへのポリシー割り当て
  const assignMutation = useMutation({
    mutationFn: ({ groupId, policyId }: { groupId: string; policyId: string }) =>
      apiFetch(`/api/v1/groups/${groupId}/policy`, {
        method: 'PUT',
        body: JSON.stringify({ policy_id: policyId }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['groups'] })
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの割り当てに失敗しました'),
  })

  const policies = policyData?.data ?? []
  const groups   = groupData?.data ?? []

  const handleCreate = (form: PolicyForm) => {
    createMutation.mutate(form)
  }

  const handleUpdate = (form: PolicyForm) => {
    if (!editingPolicy) return
    updateMutation.mutate({ id: editingPolicy.id, payload: form })
  }

  const editInitial = editingPolicy
    ? {
        name:                editingPolicy.name,
        description:         editingPolicy.description,
        scan_interval_min:   editingPolicy.scan_interval_min,
        full_scan_hour:      editingPolicy.full_scan_hour,
        monitored_extensions: editingPolicy.monitored_extensions,
        excluded_paths:       editingPolicy.excluded_paths,
        cpu_limit_pct:       editingPolicy.cpu_limit_pct,
        mem_limit_mb:        editingPolicy.mem_limit_mb,
        monitor_network:     editingPolicy.monitor_network,
        monitor_dns:         editingPolicy.monitor_dns,
        log_level:           editingPolicy.log_level,
      } as PolicyForm
    : EMPTY_FORM

  return (
    <div className="p-6 space-y-8">
      <PageDataUnavailable />

      {/* ページヘッダー */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            エージェントポリシー
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            エージェントのスキャン・リソース・監視設定を管理します
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => { refetch(); qc.invalidateQueries({ queryKey: ['groups'] }) }}
            disabled={isFetching}
            className="p-2 text-[#8899aa] hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => { setShowCreate(true); setError(null) }}
            className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm"
          >
            <Plus className="w-4 h-4" />
            ポリシー作成
          </button>
        </div>
      </div>

      {/* エラーバナー */}
      {error && (
        <div className="flex items-center gap-3 bg-red-900/30 border border-red-700/50 rounded-xl px-4 py-3 text-red-300 text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* サマリー */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: '総ポリシー数', value: policies.length,                                  color: 'text-white' },
          { label: 'グループ数',   value: groups.length,                                    color: 'text-blue-400' },
          { label: '未割り当て',   value: groups.filter(g => !g.policy_id).length,          color: 'text-yellow-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
            <p className="text-[#8899aa] text-xs">{label}</p>
            <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* ポリシー一覧 */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" />
          ポリシー一覧
        </h2>

        {policiesLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : policies.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-[#5a6a7a] bg-[#111827] rounded-xl border border-[#1e2d42]">
            <Shield className="w-10 h-10 mb-2 opacity-20" />
            <p className="text-sm">ポリシーがありません</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {policies.map(policy => (
              <PolicyCard
                key={policy.id}
                policy={policy}
                onEdit={p => { setEditingPolicy(p); setError(null) }}
                onDelete={id => deleteMutation.mutate(id)}
              />
            ))}
          </div>
        )}
      </section>

      {/* グループへのポリシー割り当て */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          グループへのポリシー割り当て
        </h2>

        {groupsLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-7 h-7 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : groups.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-[#5a6a7a] bg-[#111827] rounded-xl border border-[#1e2d42]">
            <Layers className="w-8 h-8 mb-2 opacity-20" />
            <p className="text-sm">グループがありません</p>
          </div>
        ) : (
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
                  <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">グループ名</th>
                  <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">エージェント数</th>
                  <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">割り当てポリシー</th>
                </tr>
              </thead>
              <tbody>
                {groups.map(group => (
                  <tr
                    key={group.id}
                    className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33] transition-colors"
                  >
                    <td className="px-4 py-3">
                      <p className="text-white font-medium">{group.name}</p>
                      {group.description && (
                        <p className="text-[#5a6a7a] text-xs">{group.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[#8899aa] text-sm">
                      {group.agent_count}台
                    </td>
                    <td className="px-4 py-3">
                      {policies.length > 0 ? (
                        <GroupAssignDropdown
                          group={group}
                          policies={policies}
                          onAssign={(groupId, policyId) =>
                            assignMutation.mutate({ groupId, policyId })
                          }
                          isPending={assignMutation.isPending}
                        />
                      ) : (
                        <span className="text-[#5a6a7a] text-xs">ポリシーなし</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* 新規作成モーダル */}
      {showCreate && (
        <PolicyFormModal
          title="ポリシー作成"
          initial={EMPTY_FORM}
          onClose={() => { setShowCreate(false); setError(null) }}
          onSubmit={handleCreate}
          isPending={createMutation.isPending}
        />
      )}

      {/* 編集モーダル */}
      {editingPolicy && (
        <PolicyFormModal
          title={`編集: ${editingPolicy.name}`}
          initial={editInitial}
          onClose={() => { setEditingPolicy(null); setError(null) }}
          onSubmit={handleUpdate}
          isPending={updateMutation.isPending}
        />
      )}
    </div>
  )
}
