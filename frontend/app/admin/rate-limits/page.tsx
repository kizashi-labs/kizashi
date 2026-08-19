'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Gauge, Plus, Pencil, Trash2, RefreshCw, X, Save,
  ShieldAlert, Clock, Zap, ToggleLeft, ToggleRight, AlertTriangle
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────

interface RateLimitRule {
  id: string
  name: string
  endpoint_pattern: string
  requests_per_window: number
  window_size: number
  burst_limit: number
  enabled: boolean
}

interface RateLimitsResponse {
  rules: RateLimitRule[]
}

interface RateLimitedIP {
  ip: string
  requests: number
  rule: string
  last_hit: string
}

// ── Helpers ────────────────────────────────────────────────────

const emptyRule = (): Omit<RateLimitRule, 'id'> => ({
  name: '',
  endpoint_pattern: '',
  requests_per_window: 100,
  window_size: 60,
  burst_limit: 120,
  enabled: true,
})

// ── Sub-components ─────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color }: { label: string; value: string | number; icon: any; color: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-[#7d92b0] text-xs">{label}</p>
        <p className="text-white text-xl font-bold mt-0.5">{value}</p>
      </div>
    </div>
  )
}

function ToggleSwitch({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="flex items-center gap-1 transition-colors"
    >
      {checked
        ? <ToggleRight className="w-6 h-6 text-[#e8002d]" />
        : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
      }
      <span className={`text-xs font-medium ${checked ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>
        {checked ? '有効' : '無効'}
      </span>
    </button>
  )
}

// ── Modal ──────────────────────────────────────────────────────

interface ModalProps {
  rule: Partial<RateLimitRule> | null
  onClose: () => void
  onSave: (rule: Omit<RateLimitRule, 'id'>) => void
  isSaving: boolean
}

function RuleModal({ rule, onClose, onSave, isSaving }: ModalProps) {
  const isEdit = !!(rule as RateLimitRule)?.id
  const [form, setForm] = useState<Omit<RateLimitRule, 'id'>>({
    name: rule?.name ?? '',
    endpoint_pattern: rule?.endpoint_pattern ?? '',
    requests_per_window: rule?.requests_per_window ?? 100,
    window_size: rule?.window_size ?? 60,
    burst_limit: rule?.burst_limit ?? 120,
    enabled: rule?.enabled ?? true,
  })

  const set = (k: keyof typeof form, v: any) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Gauge className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm">
              {isEdit ? 'レートリミットルール編集' : 'レートリミットルール追加'}
            </h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <div className="px-6 py-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ルール名</label>
            <input
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="例: API Global"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
            />
          </div>

          {/* Endpoint pattern */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">エンドポイントパターン</label>
            <input
              value={form.endpoint_pattern}
              onChange={e => set('endpoint_pattern', e.target.value)}
              placeholder="例: /api/v1/*"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm font-mono placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
            />
          </div>

          {/* Numeric fields */}
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">リクエスト数/窓</label>
              <input
                type="number"
                min={1}
                value={form.requests_per_window}
                onChange={e => set('requests_per_window', parseInt(e.target.value) || 1)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">窓サイズ (秒)</label>
              <input
                type="number"
                min={1}
                value={form.window_size}
                onChange={e => set('window_size', parseInt(e.target.value) || 1)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">バースト上限</label>
              <input
                type="number"
                min={1}
                value={form.burst_limit}
                onChange={e => set('burst_limit', parseInt(e.target.value) || 1)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              />
            </div>
          </div>

          {/* Enabled */}
          <div className="flex items-center justify-between py-2 border-t border-[#1e2d42]">
            <span className="text-sm text-[#7d92b0]">ルールを有効にする</span>
            <ToggleSwitch checked={form.enabled} onChange={v => set('enabled', v)} />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={isSaving || !form.name || !form.endpoint_pattern}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c5001f] text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            {isSaving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Delete confirmation ────────────────────────────────────────

function DeleteConfirm({ rule, onConfirm, onCancel, isDeleting }: { rule: RateLimitRule; onConfirm: () => void; onCancel: () => void; isDeleting: boolean }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-6 text-center">
        <AlertTriangle className="w-10 h-10 text-[#e8002d] mx-auto mb-3" />
        <h3 className="text-white font-semibold mb-1">ルールを削除</h3>
        <p className="text-[#7d92b0] text-sm mb-5">
          <span className="text-white font-medium">"{rule.name}"</span> を削除しますか？この操作は元に戻せません。
        </p>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 py-2 text-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg transition-colors">
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isDeleting}
            className="flex-1 py-2 text-sm bg-[#e8002d] hover:bg-[#c5001f] text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {isDeleting ? '削除中...' : '削除する'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────

type TopIP = { ip: string; requests: number; blocked: number; rule: string; last_hit: string }

export default function RateLimitsPage() {
  const qc = useQueryClient()
  const [modalRule, setModalRule] = useState<Partial<RateLimitRule> | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RateLimitRule | null>(null)

  // ── Fetch rules
  const { data, isLoading, refetch, isFetching } = useQuery<RateLimitsResponse>({
    queryKey: ['admin', 'rate-limits'],
    queryFn: async () => {
      try {
        const res = await apiFetch<RateLimitsResponse>('/api/v1/admin/rate-limits')

        return res
      } catch (err: any) {
        const status = err?.status ?? (err?.message?.includes('404') ? 404 : undefined)
        if (status === 404 || status === undefined) {
          return { rules: [] }
        }
        throw err
      }
    },
    retry: false,
  })

  const rules: RateLimitRule[] = data?.rules ?? []

  // ── Create mutation
  const createMut = useMutation({
    mutationFn: (body: Omit<RateLimitRule, 'id'>) =>
      apiFetch('/api/v1/admin/rate-limits', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin', 'rate-limits'] }); setModalRule(null) },
    onError: () => {
      // On mock mode just close
      setModalRule(null)
    },
  })

  // ── Update mutation
  const updateMut = useMutation({
    mutationFn: ({ id, ...body }: RateLimitRule) =>
      apiFetch(`/api/v1/admin/rate-limits/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin', 'rate-limits'] }); setModalRule(null) },
    onError: () => { setModalRule(null) },
  })

  // ── Delete mutation
  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/rate-limits/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin', 'rate-limits'] }); setDeleteTarget(null) },
    onError: () => { setDeleteTarget(null) },
  })

  const handleSave = (form: Omit<RateLimitRule, 'id'>) => {
    const existingId = (modalRule as RateLimitRule)?.id
    if (existingId) {
      updateMut.mutate({ id: existingId, ...form })
    } else {
      createMut.mutate(form)
    }
  }

  const isSaving = createMut.isPending || updateMut.isPending

  const enabledCount = rules.filter(r => r.enabled).length
  const disabledCount = rules.filter(r => !r.enabled).length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* ── Header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Gauge className="w-6 h-6 text-[#e8002d]" />
            <h1 className="text-2xl font-bold text-white">レートリミット設定</h1>
          </div>
          <p className="text-[#7d92b0] text-sm">APIエンドポイントのリクエストレートを制御するルールを管理します。</p>
        </div>
        <div className="flex items-center gap-2">

          <button
            onClick={() => refetch()}
            disabled={isLoading || isFetching}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
          <button
            onClick={() => setModalRule(emptyRule())}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c5001f] text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            ルール追加
          </button>
        </div>
      </div>

      {/* ── Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="総ルール数" value={rules.length} icon={Gauge} color="bg-[#1e2d42] text-[#7d92b0]" />
        <StatCard label="有効なルール" value={enabledCount} icon={ShieldAlert} color="bg-[#e8002d]/10 text-[#e8002d]" />
        <StatCard label="無効なルール" value={disabledCount} icon={ToggleLeft} color="bg-[#1e2d42] text-[#3d5068]" />
        <StatCard label="監視中のIP" value={0} icon={Zap} color="bg-orange-900/30 text-orange-400" />
      </div>

      {/* ── Rules table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl mb-6">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-white font-semibold text-sm">レートリミットルール一覧</h2>
          <span className="text-[#3d5068] text-xs">{rules.length} ルール</span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-16 text-[#7d92b0]">
            <RefreshCw className="w-5 h-5 animate-spin mr-2" />
            読み込み中...
          </div>
        ) : rules.length === 0 ? (
          <div className="py-16 text-center text-[#7d92b0]">
            <Gauge className="w-10 h-10 mx-auto mb-3 text-[#3d5068]" />
            <p className="text-sm">ルールが登録されていません</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">ルール名</th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">エンドポイントパターン</th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">リクエスト/窓</th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">窓サイズ</th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">バースト</th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">状態</th>
                  <th className="text-right px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {rules.map(rule => (
                  <tr key={rule.id} className="hover:bg-[#19253d]/40 transition-colors">
                    <td className="px-5 py-3.5 text-white font-medium">{rule.name}</td>
                    <td className="px-5 py-3.5">
                      <code className="text-[#7d92b0] text-xs bg-[#070d19] px-2 py-0.5 rounded-sm font-mono">
                        {rule.endpoint_pattern}
                      </code>
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#e2e8f4] font-mono text-xs">{(rule.requests_per_window ?? 0).toLocaleString()}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5 text-[#7d92b0] font-mono text-xs">{rule.window_size}s</td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 text-orange-400" />
                        <span className="text-[#e2e8f4] font-mono text-xs">{(rule.burst_limit ?? 0).toLocaleString()}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      {rule.enabled ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20">
                          有効
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">
                          無効
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setModalRule(rule)}
                          className="p-1.5 text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] rounded-sm transition-colors"
                          title="編集"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setDeleteTarget(rule)}
                          className="p-1.5 text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 rounded-sm transition-colors"
                          title="削除"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Top rate-limited IPs */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-3">
          <ShieldAlert className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-white font-semibold text-sm">レートリミットに引っかかったIP (Top 5)</h2>
          <span className="ml-auto text-[#3d5068] text-xs">過去1時間</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">IPアドレス</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">リクエスト数</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">適用ルール</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">最終ヒット</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/50">
              {([] as TopIP[]).map((ip, i) => (
                <tr key={i} className="hover:bg-[#19253d]/40 transition-colors">
                  <td className="px-5 py-3.5">
                    <code className="text-[#e2e8f4] font-mono text-sm">{ip.ip}</code>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 max-w-[100px] h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-[#e8002d] rounded-full"
                          style={{ width: `${ip.requests > 0 ? 100 : 0}%` }}
                        />
                      </div>
                      <span className="text-white font-mono text-xs">{(ip.requests ?? 0).toLocaleString()}</span>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="text-[#7d92b0] text-xs">{ip.rule}</span>
                  </td>
                  <td className="px-5 py-3.5 text-[#7d92b0] text-xs">
                    {new Date(ip.last_hit).toLocaleString('ja-JP', {
                      hour: '2-digit', minute: '2-digit', second: '2-digit',
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Modals */}
      {modalRule !== null && (
        <RuleModal
          rule={modalRule}
          onClose={() => setModalRule(null)}
          onSave={handleSave}
          isSaving={isSaving}
        />
      )}

      {deleteTarget && (
        <DeleteConfirm
          rule={deleteTarget}
          onConfirm={() => deleteMut.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          isDeleting={deleteMut.isPending}
        />
      )}
    </div>
  )
}
