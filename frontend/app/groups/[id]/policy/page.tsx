'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, useRouter } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  Shield, ChevronLeft, Save, RefreshCw, Plus, X,
  Clock, Cpu, HardDrive, Network, FileText, AlertTriangle,
  CheckCircle, Settings, Layers,
} from 'lucide-react'
import Link from 'next/link'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Group {
  id: string
  name: string
  description?: string
  color?: string
}

interface AgentPolicy {
  id: string
  name: string
  description?: string
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

interface GroupPolicyAssignment {
  policy_id?: string
  policy?: AgentPolicy
}

const DEFAULT_POLICY: Omit<AgentPolicy, 'id' | 'name'> = {
  description: '',
  scan_interval_min: 60,
  full_scan_hour: 3,
  monitored_extensions: ['.exe', '.dll', '.sh', '.ps1', '.py'],
  excluded_paths: [],
  cpu_limit_pct: 20,
  mem_limit_mb: 256,
  monitor_network: true,
  monitor_dns: true,
  log_level: 'info',
}

// ─── Section Card ──────────────────────────────────────────────────────────────

function SectionCard({ title, icon: Icon, iconColor, children }: {
  title: string
  icon: React.ElementType
  iconColor: string
  children: React.ReactNode
}) {
  return (
    <div className="bg-falcon-card rounded-xl border border-falcon-border p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className={`w-4 h-4 ${iconColor}`} />
        <h2 className="text-sm font-semibold text-falcon-text">{title}</h2>
      </div>
      {children}
    </div>
  )
}

// ─── Field Row ─────────────────────────────────────────────────────────────────

function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-3 border-b border-falcon-border/50 last:border-0">
      <div className="shrink-0 w-48">
        <p className="text-sm text-falcon-text">{label}</p>
        {hint && <p className="text-xs text-[#5a6a7a] mt-0.5">{hint}</p>}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  )
}

// ─── Tag Input ─────────────────────────────────────────────────────────────────

function TagInput({ values, onChange, placeholder }: {
  values: string[]
  onChange: (v: string[]) => void
  placeholder?: string
}) {
  const [input, setInput] = useState('')

  const add = () => {
    const v = input.trim()
    if (v && !values.includes(v)) {
      onChange([...values, v])
    }
    setInput('')
  }

  return (
    <div>
      <div className="flex flex-wrap gap-1.5 mb-2">
        {values.map(v => (
          <span key={v} className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm bg-falcon-border text-[#8899aa]">
            {v}
            <button onClick={() => onChange(values.filter(x => x !== v))} className="hover:text-white">
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }}
          placeholder={placeholder}
          className="flex-1 text-xs bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5
                     text-falcon-text placeholder-falcon-subtle focus:outline-hidden focus:border-blue-500"
        />
        <button
          onClick={add}
          className="flex items-center gap-1 px-2.5 py-1.5 text-xs bg-falcon-border hover:bg-[#253649]
                     text-[#8899aa] rounded-lg transition-colors"
        >
          <Plus className="w-3 h-3" />
          追加
        </button>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function GroupPolicyPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const qc = useQueryClient()

  const [form, setForm] = useState<Omit<AgentPolicy, 'id'> & { name: string }>({
    name: '',
    ...DEFAULT_POLICY,
  })
  const [saved, setSaved] = useState(false)
  const [dirty, setDirty] = useState(false)

  // ── Queries ──
  const { data: group } = useQuery<Group>({
    queryKey: ['group', id],
    queryFn: () => apiFetch(`/api/v1/groups/${id}`),
    enabled: !!id,
  })

  const { data: policies } = useQuery<{ data?: AgentPolicy[] }>({
    queryKey: ['agent-policies'],
    queryFn: () => apiFetch('/api/v1/agent-policies'),
    staleTime: 60_000,
  })

  const { data: assignment, isLoading } = useQuery<GroupPolicyAssignment>({
    queryKey: ['group-policy', id],
    queryFn: () => apiFetch<GroupPolicyAssignment>(`/api/v1/groups/${id}/policy`).catch(() => ({} as GroupPolicyAssignment)),
    enabled: !!id,
    staleTime: 30_000,
  })

  // Sync form with loaded policy
  useEffect(() => {
    if (assignment?.policy) {
      const p = assignment.policy
      setForm({
        name:                p.name,
        description:         p.description ?? '',
        scan_interval_min:   p.scan_interval_min,
        full_scan_hour:      p.full_scan_hour,
        monitored_extensions: p.monitored_extensions ?? [],
        excluded_paths:      p.excluded_paths ?? [],
        cpu_limit_pct:       p.cpu_limit_pct,
        mem_limit_mb:        p.mem_limit_mb,
        monitor_network:     p.monitor_network,
        monitor_dns:         p.monitor_dns,
        log_level:           p.log_level,
      })
    }
  }, [assignment])

  const set = <K extends keyof typeof form>(key: K, value: typeof form[K]) => {
    setForm(prev => ({ ...prev, [key]: value }))
    setDirty(true)
  }

  // ── Assign existing policy ──
  const assignMutation = useMutation({
    mutationFn: (policyId: string) =>
      apiFetch(`/api/v1/groups/${id}/policy`, { method: 'PUT', body: JSON.stringify({ policy_id: policyId }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-policy', id] })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  // ── Create & assign new policy ──
  const createMutation = useMutation({
    mutationFn: async () => {
      const created = await apiFetch<AgentPolicy>('/api/v1/agent-policies', {
        method: 'POST',
        body: JSON.stringify({ ...form, name: form.name || `${group?.name ?? 'Group'} Policy` }),
      })
      await apiFetch(`/api/v1/groups/${id}/policy`, {
        method: 'PUT',
        body: JSON.stringify({ policy_id: created.id }),
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-policy', id] })
      qc.invalidateQueries({ queryKey: ['agent-policies'] })
      setDirty(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  const handleSave = () => {
    if (assignment?.policy?.id) {
      // Update via reassignment with new form data embedded
      createMutation.mutate()
    } else {
      createMutation.mutate()
    }
  }

  const isPending = createMutation.isPending || assignMutation.isPending

  return (
    <div className="p-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button onClick={() => router.push('/groups')}
          className="p-1.5 rounded-lg hover:bg-falcon-border text-[#5a6a7a] hover:text-white transition-colors">
          <ChevronLeft className="w-5 h-5" />
        </button>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: group?.color ?? '#3b82f6' }}>
          <Layers className="w-4 h-4 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">
            {group?.name ?? 'グループ'} — ポリシー設定
          </h1>
          <p className="text-xs text-[#5a6a7a]">エージェントの動作設定をグループ単位で管理します</p>
        </div>
      </div>

      {/* Assign existing policy */}
      {(policies?.data ?? []).length > 0 && (
        <div className="mb-6 p-4 bg-falcon-card rounded-xl border border-falcon-border">
          <div className="flex items-center gap-2 mb-3">
            <Settings className="w-4 h-4 text-[#5a6a7a]" />
            <span className="text-sm font-medium text-falcon-text">既存ポリシーを割り当て</span>
          </div>
          <div className="flex gap-2">
            <select
              onChange={e => { if (e.target.value) assignMutation.mutate(e.target.value) }}
              defaultValue=""
              className="flex-1 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                         text-falcon-text focus:outline-hidden focus:border-blue-500"
            >
              <option value="">ポリシーを選択...</option>
              {(policies?.data ?? []).map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            {assignMutation.isPending && (
              <div className="flex items-center px-3">
                <RefreshCw className="w-4 h-4 text-[#5a6a7a] animate-spin" />
              </div>
            )}
          </div>
          {assignment?.policy && (
            <p className="mt-2 text-xs text-blue-400">
              現在: <span className="font-medium">{assignment.policy.name}</span>
            </p>
          )}
        </div>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <div key={i} className="h-24 bg-falcon-card rounded-xl animate-pulse" />)}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Policy Name */}
          <SectionCard title="基本設定" icon={FileText} iconColor="text-blue-400">
            <FieldRow label="ポリシー名" hint="新規作成時に使用されます">
              <input
                value={form.name}
                onChange={e => set('name', e.target.value)}
                placeholder={`${group?.name ?? 'Group'} Policy`}
                className="w-full bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                           text-falcon-text placeholder-falcon-subtle focus:outline-hidden focus:border-blue-500"
              />
            </FieldRow>
            <FieldRow label="説明" hint="オプション">
              <input
                value={form.description}
                onChange={e => set('description', e.target.value)}
                placeholder="このポリシーの説明"
                className="w-full bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                           text-falcon-text placeholder-falcon-subtle focus:outline-hidden focus:border-blue-500"
              />
            </FieldRow>
          </SectionCard>

          {/* Scan Schedule */}
          <SectionCard title="スキャンスケジュール" icon={Clock} iconColor="text-yellow-400">
            <FieldRow label="スキャン間隔" hint="5〜1440分">
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={form.scan_interval_min}
                  min={5} max={1440}
                  onChange={e => set('scan_interval_min', Number(e.target.value))}
                  className="w-24 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                             text-falcon-text focus:outline-hidden focus:border-blue-500"
                />
                <span className="text-xs text-[#5a6a7a]">分ごと</span>
              </div>
            </FieldRow>
            <FieldRow label="フルスキャン時刻" hint="毎日この時刻に実行 (0〜23時)">
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={form.full_scan_hour}
                  min={0} max={23}
                  onChange={e => set('full_scan_hour', Number(e.target.value))}
                  className="w-24 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                             text-falcon-text focus:outline-hidden focus:border-blue-500"
                />
                <span className="text-xs text-[#5a6a7a]">時 (00:00 〜 23:00)</span>
              </div>
            </FieldRow>
          </SectionCard>

          {/* Detection Settings */}
          <SectionCard title="検知設定" icon={Shield} iconColor="text-red-400">
            <FieldRow label="監視対象拡張子" hint="Enterまたは追加ボタンで入力">
              <TagInput
                values={form.monitored_extensions}
                onChange={v => set('monitored_extensions', v)}
                placeholder=".exe, .dll, .sh ..."
              />
            </FieldRow>
            <FieldRow label="除外パス" hint="スキャンから除外するディレクトリ">
              <TagInput
                values={form.excluded_paths}
                onChange={v => set('excluded_paths', v)}
                placeholder="/tmp, C:\\Windows\\Temp ..."
              />
            </FieldRow>
          </SectionCard>

          {/* Resource Limits */}
          <SectionCard title="リソース制限" icon={Cpu} iconColor="text-green-400">
            <FieldRow label="CPU使用上限" hint="5〜80%">
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  value={form.cpu_limit_pct}
                  min={5} max={80} step={5}
                  onChange={e => set('cpu_limit_pct', Number(e.target.value))}
                  className="flex-1 accent-green-500"
                />
                <span className="text-sm font-mono text-falcon-text w-12 text-right">
                  {form.cpu_limit_pct}%
                </span>
              </div>
            </FieldRow>
            <FieldRow label="メモリ上限" hint="64MB以上">
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={form.mem_limit_mb}
                  min={64} step={64}
                  onChange={e => set('mem_limit_mb', Number(e.target.value))}
                  className="w-28 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                             text-falcon-text focus:outline-hidden focus:border-blue-500"
                />
                <span className="text-xs text-[#5a6a7a]">MB</span>
              </div>
            </FieldRow>
          </SectionCard>

          {/* Monitoring */}
          <SectionCard title="監視オプション" icon={Network} iconColor="text-cyan-400">
            <FieldRow label="ネットワーク監視">
              <button
                onClick={() => set('monitor_network', !form.monitor_network)}
                className={`relative inline-flex h-5 w-10 rounded-full border-2 transition-colors
                  ${form.monitor_network ? 'bg-green-500 border-green-500' : 'bg-falcon-border border-falcon-border'}`}
              >
                <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform mt-px
                  ${form.monitor_network ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </FieldRow>
            <FieldRow label="DNS監視">
              <button
                onClick={() => set('monitor_dns', !form.monitor_dns)}
                className={`relative inline-flex h-5 w-10 rounded-full border-2 transition-colors
                  ${form.monitor_dns ? 'bg-green-500 border-green-500' : 'bg-falcon-border border-falcon-border'}`}
              >
                <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform mt-px
                  ${form.monitor_dns ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </FieldRow>
            <FieldRow label="ログレベル">
              <select
                value={form.log_level}
                onChange={e => set('log_level', e.target.value)}
                className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm
                           text-falcon-text focus:outline-hidden focus:border-blue-500"
              >
                {['debug', 'info', 'warn', 'error'].map(l => (
                  <option key={l} value={l}>{l.toUpperCase()}</option>
                ))}
              </select>
            </FieldRow>
          </SectionCard>

          {/* Save bar */}
          <div className="flex items-center justify-between p-4 bg-falcon-card rounded-xl border border-falcon-border">
            <div className="flex items-center gap-2 text-xs text-[#5a6a7a]">
              {saved ? (
                <>
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-green-400">保存しました</span>
                </>
              ) : dirty ? (
                <>
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  <span className="text-yellow-400">未保存の変更があります</span>
                </>
              ) : (
                <span>変更なし</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Link href="/groups"
                className="px-3 py-1.5 text-sm text-[#5a6a7a] hover:text-white transition-colors">
                キャンセル
              </Link>
              <button
                onClick={handleSave}
                disabled={isPending}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500
                           disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
              >
                {isPending ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {isPending ? '保存中...' : '保存して適用'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
