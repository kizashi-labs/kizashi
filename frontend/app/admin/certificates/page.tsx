'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Lock, Plus, Edit2, Trash2, X, Filter,
  Shield, AlertTriangle, ChevronDown, ChevronUp, Info,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type CertType = 'single' | 'wildcard'
type CertStatus = 'valid' | 'expiring' | 'expired' | 'error'

// CertEntry is what GET /api/v1/admin/certificates actually returns. The page
// used to declare a much richer Certificate — type, valid_from, auto_renew,
// sans, fingerprint, chain — that no endpoint has ever produced, and read the
// list from `certificates` when the response key is `data`, so it rendered an
// empty table however many certificates were being monitored.
interface CertEntry {
  id: string
  domain: string
  port: number
  issuer: string
  expires_at: string
  days_remaining: number
  status: string
  last_checked: string
}

// Certificate is the view model, derived only from fields the API supplies.
interface Certificate {
  id: string
  domain: string
  port: number
  type: CertType
  issuer: string
  expires_at: string
  last_checked: string
  days_remaining: number
  status: CertStatus
}

// toCertificate maps one API row. `type` is derived from the domain itself
// rather than stored: a leading "*." is what makes a certificate a wildcard,
// and that is the only distinction this page can make honestly.
function toCertificate(e: CertEntry): Certificate {
  const status: CertStatus =
    e.status === 'expiring_soon' ? 'expiring'
    : e.status === 'expired' ? 'expired'
    : e.status === 'error' ? 'error'
    : 'valid'
  return {
    id: e.id,
    domain: e.domain,
    port: e.port,
    type: e.domain.startsWith('*.') ? 'wildcard' : 'single',
    issuer: e.issuer,
    expires_at: e.expires_at,
    last_checked: e.last_checked,
    days_remaining: e.days_remaining,
    status,
  }
}

// fmtTimestamp renders an RFC3339 timestamp as a date, or a dash when the
// checker has not filled it in yet.
function fmtTimestamp(v: string): string {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().slice(0, 10)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TYPE_COLORS: Record<CertType, string> = {
  single:   'bg-blue-500/20 text-blue-300 border-blue-500/30',
  wildcard: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
}

// The four statuses monitored_certificates.status may hold. "error" means the
// host could not be reached, which is a different thing from a bad certificate
// and has to look different from "valid".
const STATUS_COLORS: Record<CertStatus, string> = {
  valid:    'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  expiring: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  expired:  'bg-red-500/20 text-red-300 border-red-500/30',
  error:    'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

const STATUS_LABELS: Record<CertStatus, string> = {
  valid: '有効', expiring: '期限切れ間近', expired: '期限切れ', error: '接続失敗',
}

function daysColor(days: number): string {
  if (days < 0)  return 'text-red-400 font-bold'
  if (days < 30) return 'text-orange-400 font-bold'
  if (days < 60) return 'text-yellow-400'
  return 'text-emerald-400'
}

function daysText(days: number): string {
  if (days < 0) return `${Math.abs(days)}日前に期限切れ`
  return `${days}日`
}

// ─── Add/Edit Modal ────────────────────────────────────────────────────────────

// CertFormData is what POST/PUT /api/v1/admin/certificates accept. The form
// used to collect issuer, validity dates, auto-renew and notes as well; the API
// has never taken any of them, so every one of those fields was discarded on
// submit while the dialog reported success.
interface CertFormData {
  domain: string
  port: number
}

const defaultForm: CertFormData = { domain: '', port: 443 }

function CertModal({
  initial, onClose, onSave,
}: {
  initial?: Certificate | null; onClose: () => void; onSave: (d: CertFormData) => void
}) {
  const [form, setForm] = useState<CertFormData>(
    initial ? { domain: initial.domain, port: initial.port } : defaultForm
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">{initial ? '証明書編集' : '証明書追加'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>

        <div className="px-6 py-4 space-y-4 max-h-[65vh] overflow-y-auto">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ドメイン *</label>
            <input
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/60 font-mono"
              placeholder="example.com または *.example.com"
              value={form.domain}
              onChange={e => setForm(f => ({ ...f, domain: e.target.value }))}
            />
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ポート</label>
            <input
              type="number" min={1} max={65535}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden font-mono"
              value={form.port}
              onChange={e => setForm(f => ({ ...f, port: Number(e.target.value) || 443 }))}
            />
            <p className="text-[11px] text-[#3d5068] mt-1.5">
              既定は 443。ここに登録したドメインとポートに対して、24時間ごとに TLS 証明書の
              有効期限を確認します。発行者・有効期限・確認時刻は確認結果から自動的に記録されます。
            </p>
          </div>
        </div>

        <div className="flex gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose}
            className="flex-1 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-all text-sm">
            キャンセル
          </button>
          <button
            onClick={() => { if (form.domain) { onSave(form); onClose() } }}
            disabled={!form.domain}
            className="flex-1 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-all text-sm disabled:opacity-50"
          >
            {initial ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Detail Modal ──────────────────────────────────────────────────────────────

function DetailModal({ cert, onClose }: { cert: Certificate; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm font-mono">{cert.domain}</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>

        <div className="px-5 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              { label: '種別',     value: cert.type },
              { label: '監視ポート', value: String(cert.port) },
              { label: '発行者',    value: cert.issuer || '—' },
              { label: '有効期限',  value: fmtTimestamp(cert.expires_at) },
              { label: '残り日数',  value: daysText(cert.days_remaining), colored: true },
              { label: '最終確認',  value: fmtTimestamp(cert.last_checked) },
            ].map(row => (
              <div key={row.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-2.5">
                <p className="text-[#3d5068] mb-0.5">{row.label}</p>
                <p className={`font-medium ${row.colored ? daysColor(cert.days_remaining) : 'text-white'}`}>
                  {row.value}
                </p>
              </div>
            ))}
          </div>

          {cert.status === 'error' && (
            <p className="text-xs text-orange-300 bg-orange-500/10 border border-orange-500/30 rounded-lg px-3 py-2">
              直近の確認でホストに接続できませんでした。証明書の状態ではなく到達性の問題です。
            </p>
          )}
          {!cert.issuer && cert.status !== 'error' && (
            <p className="text-xs text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
              まだ確認が行われていません。登録直後は次回の定期確認まで空欄になります。
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const qc = useQueryClient()
  const [filterType, setFilterType] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterExpiry, setFilterExpiry] = useState<string>('all')
  const [showModal, setShowModal] = useState(false)
  const [editItem, setEditItem] = useState<Certificate | null>(null)
  const [detailItem, setDetailItem] = useState<Certificate | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [toastMsg, setToastMsg] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), 3000)
  }

  // The response key is `data`, not `certificates`. Reading the wrong key gave
  // undefined, the `?? []` turned that into an empty list, and the page showed
  // "条件に合う証明書が見つかりません" however many domains were registered.
  const { data: certData, isError } = useQuery<{ data: CertEntry[]; total: number }>({
    queryKey: ['certificates'],
    queryFn: () => apiFetch('/api/v1/admin/certificates'),
    retry: 1,
  })

  const allCerts: Certificate[] = useMemo(() => {
    if (isError || !certData) return []
    return (certData.data ?? []).map(toCertificate)
  }, [certData, isError])

  // onError used to be a no-op on all three. The PUT and DELETE routes did not
  // exist, so both answered 404 and the operator saw the dialog close and
  // nothing change — the failure had nowhere to surface.
  const addMutation = useMutation({
    mutationFn: (data: CertFormData) => apiFetch('/api/v1/admin/certificates', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { showToast('証明書を登録しました'); qc.invalidateQueries({ queryKey: ['certificates'] }) },
    onError: () => showToast('証明書の登録に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: CertFormData }) =>
      apiFetch(`/api/v1/admin/certificates/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => { showToast('証明書を更新しました'); qc.invalidateQueries({ queryKey: ['certificates'] }) },
    onError: () => showToast('証明書の更新に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/certificates/${id}`, { method: 'DELETE' }),
    onSuccess: () => { showToast('証明書を削除しました'); qc.invalidateQueries({ queryKey: ['certificates'] }) },
    onError: () => showToast('証明書の削除に失敗しました'),
  })

  const filtered = useMemo(() => {
    let list = [...allCerts]
    if (filterType !== 'all') list = list.filter(c => c.type === filterType)
    if (filterStatus !== 'all') list = list.filter(c => c.status === filterStatus)
    if (filterExpiry === 'expired') list = list.filter(c => c.days_remaining < 0)
    else if (filterExpiry === '30') list = list.filter(c => c.days_remaining >= 0 && c.days_remaining <= 30)
    else if (filterExpiry === '60') list = list.filter(c => c.days_remaining >= 0 && c.days_remaining <= 60)
    list.sort((a, b) => sortDir === 'asc' ? a.days_remaining - b.days_remaining : b.days_remaining - a.days_remaining)
    return list
  }, [allCerts, filterType, filterStatus, filterExpiry, sortDir])

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const handleSave = (data: CertFormData) => {
    if (editItem) updateMutation.mutate({ id: editItem.id, data })
    else addMutation.mutate(data)
  }

  const totalCount = allCerts.length
  const expiring30 = allCerts.filter(c => c.days_remaining >= 0 && c.days_remaining <= 30).length
  const expiredCount = allCerts.filter(c => c.days_remaining < 0).length
  const wildcards = allCerts.filter(c => c.type === 'wildcard').length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Toast */}
      {toastMsg && (
        <div className="fixed top-4 right-4 z-50 px-4 py-2.5 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-white text-sm shadow-xl">
          {toastMsg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
            <Lock className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">証明書管理</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">SSL/TLS証明書の一元管理・更新管理</p>
          </div>
        </div>
        <button
          onClick={() => { setEditItem(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-all"
        >
          <Plus className="w-4 h-4" />
          証明書追加
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: '総証明書数',        value: totalCount,   icon: Lock,          color: 'text-white',       icon_bg: 'bg-blue-500/20' },
          { label: '30日以内に期限切れ', value: expiring30,  icon: AlertTriangle,  color: 'text-orange-400', icon_bg: 'bg-orange-500/20' },
          { label: '期限切れ',          value: expiredCount, icon: X,              color: 'text-red-400',    icon_bg: 'bg-red-500/20' },
          { label: 'ワイルドカード',     value: wildcards,   icon: Shield,         color: 'text-purple-400', icon_bg: 'bg-purple-500/20' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg ${stat.icon_bg} flex items-center justify-center shrink-0`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <div>
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-[#7d92b0] mt-0.5">{stat.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Certificates Tab */}
      {(
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-[#1e2d42]">
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-[#7d92b0]" />
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-hidden"
                value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="all">全種別</option>
                {(['single', 'wildcard'] as CertType[]).map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-hidden"
                value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
                <option value="all">全ステータス</option>
                {(Object.keys(STATUS_LABELS) as CertStatus[]).map(s => (
                  <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                ))}
              </select>
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-hidden"
                value={filterExpiry} onChange={e => setFilterExpiry(e.target.value)}>
                <option value="all">全期限</option>
                <option value="expired">期限切れ</option>
                <option value="30">30日以内</option>
                <option value="60">60日以内</option>
              </select>
              <button
                onClick={() => setSortDir(d => d === 'asc' ? 'desc' : 'asc')}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-[#070d19] border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white transition-all"
              >
                残日数 {sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            </div>
            {selected.size > 0 && (
              <button
                onClick={() => { selected.forEach(id => deleteMutation.mutate(id)); setSelected(new Set()) }}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-900/40 hover:bg-red-900/70 text-red-300 text-xs font-medium transition-all">
                <Trash2 className="w-3.5 h-3.5" />
                選択を監視対象から削除 ({selected.size}件)
              </button>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[1000px]">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-4 py-3 w-10">
                    <input type="checkbox" className="w-3.5 h-3.5 accent-[#e8002d]"
                      checked={selected.size === filtered.length && filtered.length > 0}
                      onChange={e => setSelected(e.target.checked ? new Set(filtered.map(c => c.id)) : new Set())}
                    />
                  </th>
                  {['ドメイン', 'ポート', '種別', '発行者', '有効期限', '残り日数', '最終確認', 'ステータス', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(cert => (
                  <tr key={cert.id} className="border-b border-[#1e2d42]/60 hover:bg-[#070d19]/60 transition-colors">
                    <td className="px-4 py-3">
                      <input type="checkbox" className="w-3.5 h-3.5 accent-[#e8002d]"
                        checked={selected.has(cert.id)}
                        onChange={() => toggleSelect(cert.id)}
                      />
                    </td>
                    <td className="px-4 py-3 text-white text-xs font-medium font-mono">{cert.domain}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono">{cert.port}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${TYPE_COLORS[cert.type]}`}>{cert.type}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{cert.issuer || '—'}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{fmtTimestamp(cert.expires_at)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs ${daysColor(cert.days_remaining)}`}>
                        {daysText(cert.days_remaining)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{fmtTimestamp(cert.last_checked)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${STATUS_COLORS[cert.status]}`}>
                        {STATUS_LABELS[cert.status]}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button onClick={() => setDetailItem(cert)}
                          className="p-1.5 rounded-md bg-[#1e2d42]/60 hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-all" title="詳細">
                          <Info className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => { setEditItem(cert); setShowModal(true) }}
                          className="p-1.5 rounded-md bg-[#1e2d42]/60 hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-all" title="編集">
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => deleteMutation.mutate(cert.id)}
                          className="p-1.5 rounded-md bg-red-900/30 hover:bg-red-900/60 text-red-400 hover:text-red-300 transition-all" title="削除">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="text-center py-12 text-[#3d5068] text-sm">
                条件に合う証明書が見つかりません
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modals */}
      {showModal && (
        <CertModal
          initial={editItem}
          onClose={() => { setShowModal(false); setEditItem(null) }}
          onSave={handleSave}
        />
      )}
      {detailItem && (
        <DetailModal cert={detailItem} onClose={() => setDetailItem(null)} />
      )}
    </div>
  )
}
