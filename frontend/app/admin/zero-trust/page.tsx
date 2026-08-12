'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Lock, Shield, CheckCircle, XCircle, AlertTriangle,
  Monitor, RefreshCw, Plus, Pencil, Trash2,
  ChevronDown, ChevronUp, X,
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

type TrustLevel = 'high' | 'medium' | 'low' | 'untrusted'

interface ZTPolicy {
  id: string
  name: string
  resource: string
  min_trust: TrustLevel
  require_mfa: boolean
  enabled: boolean
}

interface DevicePosture {
  agent_id: string
  hostname: string
  trust_score: number
  trust_level: TrustLevel
  agent_healthy: boolean
  os_patched: boolean
  disk_encrypted: boolean
  firewall_enabled: boolean
  av_enabled: boolean
  mfa_enabled: boolean
  no_active_alerts: boolean
  on_corp_network: boolean
  active_alert_count: number
  compliance_passed: boolean
  last_seen: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TRUST_COLORS: Record<TrustLevel, string> = {
  high:      'text-green-400 bg-green-500/10 border-green-500/30',
  medium:    'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low:       'text-orange-400 bg-orange-500/10 border-orange-500/30',
  untrusted: 'text-red-400 bg-red-500/10 border-red-500/30',
}

const TRUST_LABELS: Record<TrustLevel, string> = {
  high: '高信頼', medium: '中信頼', low: '低信頼', untrusted: '非信頼',
}

const TRUST_SCORES: Record<TrustLevel, number> = {
  high: 80, medium: 50, low: 20, untrusted: 0,
}

function TrustScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : score >= 20 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-300 w-8 text-right">{score}</span>
    </div>
  )
}

function PostureCheck({ label, value }: { label: string; value: boolean }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      {value
        ? <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
        : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
      <span className={value ? 'text-gray-300' : 'text-gray-500'}>{label}</span>
    </div>
  )
}

// ── Policy Modal ───────────────────────────────────────────────────────────────

const EMPTY_POLICY: Omit<ZTPolicy, 'id'> = {
  name: '', resource: '', min_trust: 'medium', require_mfa: false, enabled: true,
}

const RESOURCE_SUGGESTIONS = ['admin', 'reports', 'api', 'live_response', 'forensics', 'alerts', 'incidents', 'settings']

function PolicyModal({
  policy,
  onClose,
  onSave,
  saving,
}: {
  policy: Partial<ZTPolicy> | null
  onClose: () => void
  onSave: (data: Omit<ZTPolicy, 'id'>) => void
  saving: boolean
}) {
  const isEdit = !!(policy && policy.id)
  const [form, setForm] = useState<Omit<ZTPolicy, 'id'>>({
    name:        policy?.name        ?? EMPTY_POLICY.name,
    resource:    policy?.resource    ?? EMPTY_POLICY.resource,
    min_trust:   policy?.min_trust   ?? EMPTY_POLICY.min_trust,
    require_mfa: policy?.require_mfa ?? EMPTY_POLICY.require_mfa,
    enabled:     policy?.enabled     ?? EMPTY_POLICY.enabled,
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-lg">
            {isEdit ? 'ポリシー編集' : '新規ポリシー作成'}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-gray-400 text-xs font-medium mb-1">ポリシー名 <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: 管理者パネルアクセス"
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-green-500 transition-colors"
            />
          </div>

          {/* Resource */}
          <div>
            <label className="block text-gray-400 text-xs font-medium mb-1">リソース <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={form.resource}
              onChange={e => setForm(f => ({ ...f, resource: e.target.value }))}
              placeholder="例: admin"
              list="resource-suggestions"
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-green-500 transition-colors"
            />
            <datalist id="resource-suggestions">
              {RESOURCE_SUGGESTIONS.map(r => <option key={r} value={r} />)}
            </datalist>
            <p className="text-gray-500 text-xs mt-1">アクセス制御の対象リソース識別子</p>
          </div>

          {/* Min Trust */}
          <div>
            <label className="block text-gray-400 text-xs font-medium mb-1">最低信頼レベル</label>
            <div className="grid grid-cols-2 gap-2">
              {(['high', 'medium', 'low', 'untrusted'] as TrustLevel[]).map(level => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setForm(f => ({ ...f, min_trust: level }))}
                  className={`px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
                    form.min_trust === level
                      ? TRUST_COLORS[level]
                      : 'border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  {TRUST_LABELS[level]}（スコア≥{TRUST_SCORES[level]}）
                </button>
              ))}
            </div>
          </div>

          {/* Toggles */}
          <div className="flex flex-col gap-3">
            <label className="flex items-center justify-between cursor-pointer">
              <span className="text-gray-300 text-sm">MFA必須</span>
              <button
                type="button"
                onClick={() => setForm(f => ({ ...f, require_mfa: !f.require_mfa }))}
                className={`relative w-10 h-5 rounded-full transition-colors ${form.require_mfa ? 'bg-green-500' : 'bg-gray-600'}`}
              >
                <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${form.require_mfa ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </label>
            <label className="flex items-center justify-between cursor-pointer">
              <span className="text-gray-300 text-sm">有効</span>
              <button
                type="button"
                onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
                className={`relative w-10 h-5 rounded-full transition-colors ${form.enabled ? 'bg-green-500' : 'bg-gray-600'}`}
              >
                <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${form.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </label>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-gray-700 text-gray-400 hover:text-white text-sm transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={saving || !form.name.trim() || !form.resource.trim()}
            className="px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
          >
            {saving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

const BASE = '/api/v1/admin/zero-trust/engine'

export default function ZeroTrustPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'postures' | 'policies'>('postures')
  const [expandedPosture, setExpandedPosture] = useState<string | null>(null)
  const [modalPolicy, setModalPolicy] = useState<Partial<ZTPolicy> | null | false>(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  // ── Queries ──────────────────────────────────────────────────────────────────

  const { data: policiesData } = useQuery({
    queryKey: ['zt-engine-policies'],
    queryFn: () => apiFetch<{ policies: ZTPolicy[] }>(`${BASE}/policies`)
      .catch(() => ({ policies: [] })),
  })
  const policies: ZTPolicy[] = policiesData?.policies ?? []

  const { data: posturesData, isLoading: posturesLoading } = useQuery({
    queryKey: ['zt-engine-postures'],
    queryFn: () => apiFetch<{ postures: DevicePosture[] }>(`${BASE}/postures`)
      .catch(() => ({ postures: [] })),
    refetchInterval: 30000,
  })
  const postures: DevicePosture[] = posturesData?.postures ?? []

  // ── Mutations ─────────────────────────────────────────────────────────────────

  const evaluateMutation = useMutation({
    mutationFn: (agentId: string) =>
      apiFetch(`${BASE}/evaluate/${agentId}`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['zt-engine-postures'] }),
  })

  const createMutation = useMutation({
    mutationFn: (data: Omit<ZTPolicy, 'id'>) =>
      apiFetch(`${BASE}/policies`, { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['zt-engine-policies'] })
      setModalPolicy(false)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Omit<ZTPolicy, 'id'> }) =>
      apiFetch(`${BASE}/policies/${id}`, { method: 'PUT', body: JSON.stringify({ id, ...data }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['zt-engine-policies'] })
      setModalPolicy(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`${BASE}/policies/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['zt-engine-policies'] })
      setDeleteConfirm(null)
    },
  })

  // ── Derived ───────────────────────────────────────────────────────────────────

  const highCount      = postures.filter(p => p.trust_level === 'high').length
  const mediumCount    = postures.filter(p => p.trust_level === 'medium').length
  const lowCount       = postures.filter(p => p.trust_level === 'low').length
  const untrustedCount = postures.filter(p => p.trust_level === 'untrusted').length

  const isSaving = createMutation.isPending || updateMutation.isPending

  function handleSave(data: Omit<ZTPolicy, 'id'>) {
    if (!modalPolicy) return
    if ((modalPolicy as ZTPolicy).id) {
      updateMutation.mutate({ id: (modalPolicy as ZTPolicy).id, data })
    } else {
      createMutation.mutate(data)
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Modal */}
      {modalPolicy !== false && (
        <PolicyModal
          policy={modalPolicy}
          onClose={() => setModalPolicy(false)}
          onSave={handleSave}
          saving={isSaving}
        />
      )}

      {/* Delete Confirm */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 w-80 shadow-2xl">
            <h3 className="text-white font-semibold mb-2">ポリシーを削除しますか？</h3>
            <p className="text-gray-400 text-sm mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 rounded-lg border border-gray-700 text-gray-400 hover:text-white text-sm transition-colors">キャンセル</button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm font-medium transition-colors"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Lock className="w-7 h-7 text-green-400" />
            Zero Trust
          </h1>
          <p className="text-gray-400 text-sm mt-1">デバイス信頼スコアリングとアクセスポリシー管理</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {([
          { label: '高信頼',  count: highCount,      level: 'high'      as TrustLevel },
          { label: '中信頼',  count: mediumCount,    level: 'medium'    as TrustLevel },
          { label: '低信頼',  count: lowCount,       level: 'low'       as TrustLevel },
          { label: '非信頼',  count: untrustedCount, level: 'untrusted' as TrustLevel },
        ]).map(item => (
          <div key={item.level} className={`rounded-xl p-4 border ${TRUST_COLORS[item.level]}`}>
            <div className="text-3xl font-bold">{item.count}</div>
            <div className="text-sm mt-1">{item.label}</div>
            <div className="text-xs opacity-60 mt-0.5">スコア ≥ {TRUST_SCORES[item.level]}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="flex items-center border-b border-gray-700">
          {(['postures', 'policies'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium transition-colors ${activeTab === tab ? 'text-white border-b-2 border-green-500 bg-gray-700/50' : 'text-gray-400 hover:text-white'}`}
            >
              {tab === 'postures' ? `デバイスポスチャ (${postures.length})` : `ポリシー (${policies.length})`}
            </button>
          ))}
          {activeTab === 'policies' && (
            <button
              onClick={() => setModalPolicy({})}
              className="ml-auto mr-3 flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              新規ポリシー
            </button>
          )}
        </div>

        <div className="p-4">
          {/* ── Postures Tab ── */}
          {activeTab === 'postures' && (
            <div className="space-y-3">
              {posturesLoading ? (
                <div className="text-center py-8 text-gray-500">読み込み中...</div>
              ) : postures.length === 0 ? (
                <div className="text-center py-8 text-gray-500">デバイスが見つかりません</div>
              ) : postures.map(posture => {
                const isExpanded = expandedPosture === posture.agent_id
                return (
                  <div key={posture.agent_id} className="bg-gray-700/50 rounded-lg border border-gray-600/50 overflow-hidden">
                    <div
                      className="p-4 flex items-center gap-4 cursor-pointer hover:bg-gray-700/70 transition-colors"
                      onClick={() => setExpandedPosture(isExpanded ? null : posture.agent_id)}
                    >
                      <div className={`p-2 rounded-lg border ${TRUST_COLORS[posture.trust_level]}`}>
                        <Monitor className="w-4 h-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-semibold text-white">{posture.hostname}</div>
                        <div className="text-xs text-gray-400 mt-0.5">
                          最終確認: {new Date(posture.last_seen).toLocaleString('ja-JP')}
                        </div>
                      </div>
                      <div className="w-32">
                        <TrustScoreBar score={posture.trust_score} />
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${TRUST_COLORS[posture.trust_level]}`}>
                        {TRUST_LABELS[posture.trust_level]}
                      </span>
                      {posture.active_alert_count > 0 && (
                        <span className="flex items-center gap-1 text-xs text-red-400">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {posture.active_alert_count}
                        </span>
                      )}
                      <button
                        onClick={e => { e.stopPropagation(); evaluateMutation.mutate(posture.agent_id) }}
                        className="p-1.5 rounded-lg bg-gray-600 hover:bg-gray-500 text-gray-300 transition-colors ml-1"
                        title="再評価"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${evaluateMutation.isPending ? 'animate-spin' : ''}`} />
                      </button>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                    </div>

                    {isExpanded && (
                      <div className="border-t border-gray-600/50 p-4 bg-gray-700/30">
                        <h4 className="text-xs font-semibold text-gray-400 mb-3">ポスチャチェック</h4>
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                          <PostureCheck label="エージェント正常"    value={posture.agent_healthy} />
                          <PostureCheck label="OS最新パッチ適用済み" value={posture.os_patched} />
                          <PostureCheck label="ディスク暗号化"       value={posture.disk_encrypted} />
                          <PostureCheck label="ファイアウォール有効" value={posture.firewall_enabled} />
                          <PostureCheck label="ウイルス対策有効"     value={posture.av_enabled} />
                          <PostureCheck label="MFA有効"              value={posture.mfa_enabled} />
                          <PostureCheck label="アクティブアラートなし" value={posture.no_active_alerts} />
                          <PostureCheck label="社内ネットワーク"     value={posture.on_corp_network} />
                          <PostureCheck label="コンプライアンス準拠" value={posture.compliance_passed} />
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* ── Policies Tab ── */}
          {activeTab === 'policies' && (
            <div className="space-y-3">
              {policies.length === 0 ? (
                <div className="text-center py-8 text-gray-500">ポリシーが登録されていません</div>
              ) : policies.map(policy => (
                <div key={policy.id} className="bg-gray-700/50 rounded-lg p-4 border border-gray-600/50 flex items-center gap-4">
                  <div className={`p-2 rounded-lg border flex-shrink-0 ${TRUST_COLORS[policy.min_trust]}`}>
                    <Shield className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-white">{policy.name}</div>
                    <div className="text-xs text-gray-400 mt-0.5">リソース: <span className="font-mono text-gray-300">{policy.resource}</span></div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap justify-end">
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${TRUST_COLORS[policy.min_trust]}`}>
                      最小: {TRUST_LABELS[policy.min_trust]}
                    </span>
                    {policy.require_mfa && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">
                        MFA必須
                      </span>
                    )}
                    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${policy.enabled ? 'bg-green-500/10 text-green-400 border-green-500/30' : 'bg-gray-700 text-gray-500 border-gray-600'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${policy.enabled ? 'bg-green-400' : 'bg-gray-500'}`} />
                      {policy.enabled ? '有効' : '無効'}
                    </span>
                    <button
                      onClick={() => setModalPolicy(policy)}
                      className="p-1.5 rounded-lg bg-gray-600 hover:bg-blue-600 text-gray-300 hover:text-white transition-colors"
                      title="編集"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(policy.id)}
                      className="p-1.5 rounded-lg bg-gray-600 hover:bg-red-600 text-gray-300 hover:text-white transition-colors"
                      title="削除"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
