'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useCanWrite } from '@/lib/auth'
import {
  GitBranch, Plus, Edit2, Trash2, AlertTriangle,
  Target, Calendar, Shield, Users, ChevronRight,
  Search, X, Crosshair,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Campaign {
  id: string
  name: string
  description?: string
  threat_actor?: string
  status?: string        // active | monitoring | inactive
  severity?: string      // critical | high | medium | low
  first_seen?: string
  last_seen?: string
  ioc_count?: number
  alert_count?: number
  techniques?: string[]
}

type CampaignInput = Omit<Campaign, 'id'>

// ─── Config maps ──────────────────────────────────────────────────────────────

const STATUS_CFG: Record<string, { label: string; cls: string }> = {
  active:     { label: 'アクティブ',   cls: 'bg-red-900/40 text-red-300 border border-red-700/50' },
  monitoring: { label: 'モニタリング', cls: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50' },
  inactive:   { label: '非アクティブ', cls: 'bg-gray-700/60 text-gray-400 border border-gray-600/50' },
}

const SEV_CFG: Record<string, { label: string; cls: string; border: string }> = {
  critical: { label: 'クリティカル', cls: 'bg-red-900/40 text-red-300',      border: 'border-l-red-500' },
  high:     { label: '高',           cls: 'bg-orange-900/40 text-orange-300', border: 'border-l-orange-500' },
  medium:   { label: '中',           cls: 'bg-yellow-900/40 text-yellow-300', border: 'border-l-yellow-500' },
  low:      { label: '低',           cls: 'bg-blue-900/40 text-blue-300',     border: 'border-l-blue-500' },
}

const EMPTY_FORM: CampaignInput = {
  name: '',
  description: '',
  threat_actor: '',
  status: 'active',
  severity: 'medium',
  first_seen: '',
  last_seen: '',
  ioc_count: 0,
  alert_count: 0,
  techniques: [],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(s?: string) {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  return d.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

function normalise(raw: unknown): Campaign[] {
  if (!raw) return []
  if (Array.isArray(raw)) return raw as Campaign[]
  const obj = raw as Record<string, unknown>
  if (Array.isArray(obj.data)) return obj.data as Campaign[]
  if (Array.isArray(obj.campaigns)) return obj.campaigns as Campaign[]
  return []
}

// ─── Modal ────────────────────────────────────────────────────────────────────

interface ModalProps {
  initial: CampaignInput & { id?: string }
  onClose: () => void
  onSave: (data: CampaignInput, id?: string) => void
  saving: boolean
}

function CampaignModal({ initial, onClose, onSave, saving }: ModalProps) {
  const [form, setForm] = useState<CampaignInput & { id?: string }>(initial)
  const [techText, setTechText] = useState((initial.techniques ?? []).join(', '))

  function set(field: keyof CampaignInput, value: unknown) {
    setForm(f => ({ ...f, [field]: value }))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const techniques = techText
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
    onSave({ ...form, techniques }, form.id)
  }

  const inputCls = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm ' +
    'placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors'
  const labelCls = 'block text-xs font-medium text-gray-400 mb-1'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-xl mx-4 shadow-2xl">
        {/* Modal header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-rose-400" />
            <h2 className="text-white font-semibold">
              {form.id ? 'キャンペーンを編集' : '新しいキャンペーン'}
            </h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4 max-h-[75vh] overflow-y-auto">
          {/* Name */}
          <div>
            <label className={labelCls}>キャンペーン名 <span className="text-red-400">*</span></label>
            <input
              required
              className={inputCls}
              placeholder="APT-X Summer Campaign"
              value={form.name}
              onChange={e => set('name', e.target.value)}
            />
          </div>

          {/* Description */}
          <div>
            <label className={labelCls}>説明</label>
            <textarea
              rows={2}
              className={inputCls + ' resize-none'}
              placeholder="キャンペーンの概要..."
              value={form.description ?? ''}
              onChange={e => set('description', e.target.value)}
            />
          </div>

          {/* Threat actor */}
          <div>
            <label className={labelCls}>脅威アクター</label>
            <input
              className={inputCls}
              placeholder="APT28, Lazarus Group, ..."
              value={form.threat_actor ?? ''}
              onChange={e => set('threat_actor', e.target.value)}
            />
          </div>

          {/* Status + Severity row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>ステータス</label>
              <select
                className={inputCls}
                value={form.status ?? 'active'}
                onChange={e => set('status', e.target.value)}
              >
                <option value="active">アクティブ</option>
                <option value="monitoring">モニタリング</option>
                <option value="inactive">非アクティブ</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>深刻度</label>
              <select
                className={inputCls}
                value={form.severity ?? 'medium'}
                onChange={e => set('severity', e.target.value)}
              >
                <option value="critical">クリティカル</option>
                <option value="high">高</option>
                <option value="medium">中</option>
                <option value="low">低</option>
              </select>
            </div>
          </div>

          {/* Dates row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>初回確認日</label>
              <input
                type="date"
                className={inputCls}
                value={form.first_seen ? form.first_seen.slice(0, 10) : ''}
                onChange={e => set('first_seen', e.target.value)}
              />
            </div>
            <div>
              <label className={labelCls}>最終確認日</label>
              <input
                type="date"
                className={inputCls}
                value={form.last_seen ? form.last_seen.slice(0, 10) : ''}
                onChange={e => set('last_seen', e.target.value)}
              />
            </div>
          </div>

          {/* MITRE techniques */}
          <div>
            <label className={labelCls}>MITREテクニック（カンマ区切り）</label>
            <input
              className={inputCls}
              placeholder="T1059, T1078, T1566.001"
              value={techText}
              onChange={e => setTechText(e.target.value)}
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-400 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm text-white bg-rose-600 hover:bg-rose-500 disabled:opacity-50 rounded-lg transition-colors font-medium"
            >
              {saving ? '保存中...' : '保存'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CampaignsPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()

  // modal state
  const [modal, setModal] = useState<(CampaignInput & { id?: string }) | null>(null)

  // filters
  const [search, setSearch]       = useState('')
  const [statusF, setStatusF]     = useState('')
  const [severityF, setSeverityF] = useState('')

  // delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null)

  // ── Queries / mutations ──────────────────────────────────────────────────────

  const { data: raw, isLoading } = useQuery({
    queryKey: ['campaigns'],
    queryFn: () => apiFetch<unknown>('/api/v1/campaigns'),
    refetchInterval: 60_000,
  })

  const campaigns: Campaign[] = normalise(raw)

  const createMut = useMutation({
    mutationFn: (body: CampaignInput) =>
      apiFetch<Campaign>('/api/v1/campaigns', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['campaigns'] }); setModal(null) },
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: CampaignInput }) =>
      apiFetch<Campaign>(`/api/v1/campaigns/${id}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['campaigns'] }); setModal(null) },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/v1/campaigns/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['campaigns'] }); setDeleteId(null) },
  })

  // ── Derived ──────────────────────────────────────────────────────────────────

  const filtered = campaigns.filter(c => {
    const q = search.toLowerCase()
    const matchSearch = !q ||
      c.name.toLowerCase().includes(q) ||
      (c.threat_actor ?? '').toLowerCase().includes(q)
    const matchStatus   = !statusF   || c.status   === statusF
    const matchSeverity = !severityF || c.severity === severityF
    return matchSearch && matchStatus && matchSeverity
  })

  const totalIOCs   = campaigns.reduce((s, c) => s + (c.ioc_count ?? 0), 0)
  const totalAlerts = campaigns.reduce((s, c) => s + (c.alert_count ?? 0), 0)
  const activeCount = campaigns.filter(c => c.status === 'active').length

  const saving = createMut.isPending || updateMut.isPending

  // ── Handlers ─────────────────────────────────────────────────────────────────

  function handleSave(data: CampaignInput, id?: string) {
    if (id) {
      updateMut.mutate({ id, body: data })
    } else {
      createMut.mutate(data)
    }
  }

  function openEdit(c: Campaign) {
    setModal({ ...c })
  }

  // ── Render ───────────────────────────────────────────────────────────────────

  const selectCls = 'bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-gray-300 text-sm ' +
    'focus:outline-none focus:border-blue-500 transition-colors'

  return (
    <div className="p-6 space-y-6 min-h-screen bg-gray-900">

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-rose-600 rounded-xl flex items-center justify-center shadow-lg shadow-rose-900/40">
            <GitBranch className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">脅威キャンペーン</h1>
            <p className="text-sm text-gray-400">組織的な攻撃キャンペーンの追跡・管理</p>
          </div>
        </div>
        {canWrite && (
          <button
            onClick={() => setModal({ ...EMPTY_FORM })}
            className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500
                       text-white text-sm font-medium rounded-xl transition-colors shadow-lg shadow-rose-900/30"
          >
            <Plus className="w-4 h-4" />
            新しいキャンペーン
          </button>
        )}
      </div>

      {/* ── Stats bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { icon: <GitBranch className="w-5 h-5 text-white" />, bg: 'bg-rose-600',   label: 'キャンペーン数',   val: campaigns.length },
          { icon: <AlertTriangle className="w-5 h-5 text-white" />, bg: 'bg-orange-600', label: 'アクティブ',       val: activeCount },
          { icon: <Target className="w-5 h-5 text-white" />, bg: 'bg-purple-600',  label: '合計IOC',           val: totalIOCs },
          { icon: <Shield className="w-5 h-5 text-white" />, bg: 'bg-blue-600',    label: '関連アラート合計',   val: totalAlerts },
        ].map(({ icon, bg, label, val }) => (
          <div key={label} className="bg-gray-800 border border-gray-700/50 rounded-xl p-4 flex items-center gap-3">
            <div className={`w-9 h-9 ${bg} rounded-lg flex items-center justify-center flex-shrink-0`}>
              {icon}
            </div>
            <div>
              <p className="text-xs text-gray-400">{label}</p>
              <p className="text-2xl font-bold text-white">{val}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
          <input
            type="text"
            placeholder="名前・脅威アクターで検索..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white
                       text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Status filter */}
        <select className={selectCls} value={statusF} onChange={e => setStatusF(e.target.value)}>
          <option value="">すべてのステータス</option>
          <option value="active">アクティブ</option>
          <option value="monitoring">モニタリング</option>
          <option value="inactive">非アクティブ</option>
        </select>

        {/* Severity filter */}
        <select className={selectCls} value={severityF} onChange={e => setSeverityF(e.target.value)}>
          <option value="">すべての深刻度</option>
          <option value="critical">クリティカル</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>

        {(statusF || severityF || search) && (
          <button
            onClick={() => { setSearch(''); setStatusF(''); setSeverityF('') }}
            className="text-xs text-gray-400 hover:text-white flex items-center gap-1 transition-colors"
          >
            <X className="w-3 h-3" /> クリア
          </button>
        )}
      </div>

      {/* ── Campaign grid ── */}
      {isLoading ? (
        <div className="flex justify-center py-24">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-500" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-800 rounded-xl border border-gray-700 py-24 text-center">
          <GitBranch className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-gray-400 font-medium">
            {campaigns.length === 0 ? 'キャンペーンはまだありません' : '条件に一致するキャンペーンがありません'}
          </p>
          <p className="text-gray-600 text-sm mt-1">
            {campaigns.length === 0 ? '「新しいキャンペーン」ボタンで追加できます' : 'フィルターを変更してください'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(c => {
            const sev    = SEV_CFG[c.severity ?? ''] ?? SEV_CFG.low
            const status = STATUS_CFG[c.status ?? ''] ?? STATUS_CFG.inactive
            const techs  = c.techniques ?? []

            return (
              <div
                key={c.id}
                className={`bg-gray-800 border border-gray-700/50 border-l-4 ${sev.border}
                            rounded-xl flex flex-col gap-3 p-5 hover:border-gray-600 transition-colors`}
              >
                {/* Card top */}
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-white font-semibold text-sm leading-snug truncate">{c.name}</h3>
                    {c.threat_actor && (
                      <div className="flex items-center gap-1 mt-1">
                        <Users className="w-3 h-3 text-gray-500 flex-shrink-0" />
                        <span className="text-xs text-blue-400 font-mono truncate">{c.threat_actor}</span>
                      </div>
                    )}
                  </div>
                  {canWrite && (
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <button
                        onClick={() => openEdit(c)}
                        className="p-1.5 text-gray-500 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
                        title="編集"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteId(c.id)}
                        className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-900/30 rounded-lg transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>

                {/* Badges */}
                <div className="flex flex-wrap gap-2">
                  <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${status.cls}`}>
                    {status.label}
                  </span>
                  <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${sev.cls}`}>
                    {sev.label}
                  </span>
                </div>

                {/* Description */}
                {c.description && (
                  <p className="text-xs text-gray-400 leading-relaxed line-clamp-2">{c.description}</p>
                )}

                {/* Dates */}
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    初回: {fmtDate(c.first_seen)}
                  </span>
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    最終: {fmtDate(c.last_seen)}
                  </span>
                </div>

                {/* Counts */}
                <div className="flex items-center gap-4 text-xs">
                  <span className="flex items-center gap-1 text-purple-300">
                    <Target className="w-3 h-3" />
                    IOC: {c.ioc_count ?? 0}
                  </span>
                  <span className="flex items-center gap-1 text-orange-300">
                    <AlertTriangle className="w-3 h-3" />
                    アラート: {c.alert_count ?? 0}
                  </span>
                </div>

                {/* MITRE techniques */}
                {techs.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1 border-t border-gray-700/50">
                    {techs.slice(0, 6).map(t => (
                      <span
                        key={t}
                        className="flex items-center gap-0.5 text-[10px] px-1.5 py-0.5
                                   bg-purple-900/30 text-purple-300 border border-purple-700/40 rounded font-mono"
                      >
                        <Crosshair className="w-2.5 h-2.5" />{t}
                      </span>
                    ))}
                    {techs.length > 6 && (
                      <span className="text-[10px] text-gray-500 self-center">+{techs.length - 6}</span>
                    )}
                  </div>
                )}

                {/* View more link */}
                <div className="flex justify-end">
                  <button className="flex items-center gap-1 text-xs text-gray-500 hover:text-white transition-colors">
                    詳細 <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* ── Create / Edit modal ── */}
      {modal && (
        <CampaignModal
          initial={modal}
          onClose={() => setModal(null)}
          onSave={handleSave}
          saving={saving}
        />
      )}

      {/* ── Delete confirm dialog ── */}
      {deleteId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-sm mx-4 p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 bg-red-900/40 rounded-lg flex items-center justify-center">
                <Trash2 className="w-5 h-5 text-red-400" />
              </div>
              <h3 className="text-white font-semibold">キャンペーンを削除</h3>
            </div>
            <p className="text-gray-400 text-sm mb-5">
              このキャンペーンを削除しますか？この操作は元に戻せません。
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteId(null)}
                disabled={deleteMut.isPending}
                className="px-4 py-2 text-sm text-gray-400 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMut.mutate(deleteId)}
                disabled={deleteMut.isPending}
                className="px-4 py-2 text-sm text-white bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-lg transition-colors font-medium"
              >
                {deleteMut.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
