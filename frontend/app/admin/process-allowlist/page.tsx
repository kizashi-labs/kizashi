'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  CheckCircle, Plus, Trash2, X, Shield, ShieldOff,
  ToggleLeft, ToggleRight, Users, Monitor, ChevronDown,
} from 'lucide-react'

interface ProcessRule {
  id: string
  name: string
  process_name: string
  rule_type: 'allow' | 'deny'
  scope: 'all' | 'group' | 'agent'
  scope_id?: string
  action: string
  enabled: boolean
  severity: string
  created_at: string
}

interface ProcessRulesResponse {
  data: ProcessRule[]
  total: number
}

// ── Placeholder data ──────────────────────────────────────────────────────────
const PLACEHOLDER: ProcessRulesResponse = {
  total: 0,
  data: [],
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

const SCOPE_LABELS: Record<string, string> = { all: '全体', group: 'グループ', agent: 'エージェント' }
const SCOPE_ICONS: Record<string, React.ReactNode> = {
  all: <Shield className="w-3 h-3 inline" />,
  group: <Users className="w-3 h-3 inline" />,
  agent: <Monitor className="w-3 h-3 inline" />,
}

interface FormState {
  name: string
  process_name: string
  rule_type: 'allow' | 'deny'
  scope: 'all' | 'group' | 'agent'
  scope_id: string
  action: 'alert' | 'block' | 'alert_and_block'
  severity: 'low' | 'medium' | 'high' | 'critical'
  enabled: boolean
}

const EMPTY_FORM: FormState = {
  name: '',
  process_name: '',
  rule_type: 'allow',
  scope: 'all',
  scope_id: '',
  action: 'alert',
  severity: 'high',
  enabled: true,
}

export default function ProcessAllowlistPage() {
  const queryClient = useQueryClient()

  const [showAddModal, setShowAddModal] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)

  const { data, isLoading } = useQuery<ProcessRulesResponse>({
    queryKey: ['process-rules'],
    queryFn: () => apiFetch('/api/v1/process-rules'),
    placeholderData: PLACEHOLDER,
  })

  const rules = data?.data ?? []

  const stats = useMemo(() => ({
    allow: rules.filter(r => r.rule_type === 'allow').length,
    deny: rules.filter(r => r.rule_type === 'deny').length,
    enabled: rules.filter(r => r.enabled).length,
    total: rules.length,
  }), [rules])

  const addMutation = useMutation({
    mutationFn: (body: FormState) =>
      apiFetch('/api/v1/process-rules', {
        method: 'POST',
        body: JSON.stringify({
          name: body.name,
          process_name: body.process_name,
          rule_type: body.rule_type,
          scope: body.scope,
          scope_id: body.scope !== 'all' ? body.scope_id || undefined : undefined,
          action: body.action,
          severity: body.severity,
          enabled: body.enabled,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['process-rules'] })
      setShowAddModal(false)
      setForm(EMPTY_FORM)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}/toggle`, { method: 'PUT' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['process-rules'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['process-rules'] })
      setDeleteConfirm(null)
    },
  })

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <CheckCircle className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">プロセス許可リスト</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">プロセス名・パス・署名者による許可/拒否ルール</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded transition-colors"
        >
          <Plus className="w-4 h-4" />
          ルールを追加
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '許可ルール', value: stats.allow, icon: Shield, color: 'text-green-400' },
          { label: '拒否ルール', value: stats.deny, icon: ShieldOff, color: 'text-[#e8002d]' },
          { label: '有効', value: stats.enabled, icon: CheckCircle, color: 'text-cyan-400' },
          { label: '合計', value: stats.total, icon: ToggleRight, color: 'text-orange-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <Icon className={`w-5 h-5 flex-shrink-0 ${color}`} />
            <div>
              <p className="text-[#7d92b0] text-xs mb-0.5">{label}</p>
              <p className="text-2xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">ルール一覧</h2>
          <span className="text-xs text-[#7d92b0]">{rules.length} 件</span>
        </div>

        {isLoading ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">読み込み中...</div>
        ) : rules.length === 0 ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">ルールがありません</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ルール名', 'プロセス名', 'タイプ', 'アクション', '重大度', 'スコープ', '有効', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {rules.map(rule => (
                  <tr
                    key={rule.id}
                    className={`hover:bg-[#0a1628] transition-colors ${!rule.enabled ? 'opacity-50' : ''}`}
                  >
                    <td className="px-4 py-3 text-sm text-[#e2e8f4] max-w-[140px] truncate" title={rule.name}>{rule.name}</td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm text-[#e2e8f4]">{rule.process_name}</span>
                    </td>
                    <td className="px-4 py-3">
                      {rule.rule_type === 'allow' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                          <Shield className="w-3 h-3" /> 許可
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20">
                          <ShieldOff className="w-3 h-3" /> 拒否
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">
                      {{ alert: 'アラート', block: 'ブロック', alert_and_block: 'アラート+ブロック' }[rule.action] ?? rule.action}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <span className={{ critical: 'text-[#e8002d]', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-green-400' }[rule.severity] ?? 'text-[#7d92b0]'}>
                        {{ critical: 'クリティカル', high: '高', medium: '中', low: '低' }[rule.severity] ?? rule.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">
                        {SCOPE_ICONS[rule.scope]}
                        <span className="ml-1">{SCOPE_LABELS[rule.scope]}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleMutation.mutate(rule.id)}
                        disabled={toggleMutation.isPending}
                        className="p-1 rounded transition-colors hover:bg-[#1e2d42]"
                        title={rule.enabled ? '無効化' : '有効化'}
                      >
                        {rule.enabled ? (
                          <ToggleRight className="w-5 h-5 text-green-400" />
                        ) : (
                          <ToggleLeft className="w-5 h-5 text-[#3d5068]" />
                        )}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setDeleteConfirm(rule.id)}
                        className="p-1.5 rounded text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42] flex-shrink-0">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-[#e8002d]" />
                ルールを追加
              </h2>
              <button onClick={() => setShowAddModal(false)} className="p-1 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4 overflow-y-auto">
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  ルール名 <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: Chrome許可ルール"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  プロセス名 <span className="text-[#e8002d]">*</span>
                  <span className="text-[#3d5068] ml-1 font-normal">(glob パターン可)</span>
                </label>
                <input
                  type="text"
                  value={form.process_name}
                  onChange={e => setForm(f => ({ ...f, process_name: e.target.value }))}
                  placeholder="例: chrome.exe または *.tmp"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 font-mono"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">タイプ</label>
                  <div className="flex gap-2">
                    {(['allow', 'deny'] as const).map(t => (
                      <button
                        key={t}
                        onClick={() => setForm(f => ({ ...f, rule_type: t }))}
                        className={`flex-1 py-1.5 rounded text-xs font-medium transition-colors border ${
                          form.rule_type === t
                            ? t === 'allow'
                              ? 'bg-green-500/20 text-green-400 border-green-500/30'
                              : 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30'
                            : 'text-[#7d92b0] border-[#1e2d42] hover:border-[#7d92b0]/40 hover:text-white'
                        }`}
                      >
                        {t === 'allow' ? '許可' : '拒否'}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">アクション</label>
                  <div className="relative">
                    <select
                      value={form.action}
                      onChange={e => setForm(f => ({ ...f, action: e.target.value as FormState['action'] }))}
                      className="w-full appearance-none bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50 pr-8"
                    >
                      <option value="alert">アラート</option>
                      <option value="block">ブロック</option>
                      <option value="alert_and_block">アラート+ブロック</option>
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068] pointer-events-none" />
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">重大度</label>
                  <div className="relative">
                    <select
                      value={form.severity}
                      onChange={e => setForm(f => ({ ...f, severity: e.target.value as FormState['severity'] }))}
                      className="w-full appearance-none bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50 pr-8"
                    >
                      <option value="critical">クリティカル</option>
                      <option value="high">高</option>
                      <option value="medium">中</option>
                      <option value="low">低</option>
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068] pointer-events-none" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">スコープ</label>
                  <div className="relative">
                    <select
                      value={form.scope}
                      onChange={e => setForm(f => ({ ...f, scope: e.target.value as FormState['scope'], scope_id: '' }))}
                      className="w-full appearance-none bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50 pr-8"
                    >
                      <option value="all">全体</option>
                      <option value="group">グループ</option>
                      <option value="agent">エージェント</option>
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068] pointer-events-none" />
                  </div>
                </div>
              </div>
              {form.scope !== 'all' && (
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                    {form.scope === 'group' ? 'グループID' : 'エージェントID'}
                  </label>
                  <input
                    type="text"
                    value={form.scope_id}
                    onChange={e => setForm(f => ({ ...f, scope_id: e.target.value }))}
                    placeholder={form.scope === 'group' ? 'グループUUID' : 'エージェントUUID'}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 font-mono"
                  />
                </div>
              )}
              <div>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <button
                    type="button"
                    onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
                    className="p-0.5 rounded transition-colors"
                  >
                    {form.enabled ? (
                      <ToggleRight className="w-6 h-6 text-green-400" />
                    ) : (
                      <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                    )}
                  </button>
                  <span className="text-sm text-[#e2e8f4]">
                    {form.enabled ? '有効' : '無効'}
                  </span>
                </label>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[#1e2d42] flex-shrink-0">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => addMutation.mutate(form)}
                disabled={!form.name.trim() || !form.process_name.trim() || addMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded font-medium transition-colors disabled:opacity-50"
              >
                {addMutation.isPending ? '追加中...' : '追加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">ルールを削除しますか？</h2>
            <p className="text-sm text-[#7d92b0] mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded font-medium transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
