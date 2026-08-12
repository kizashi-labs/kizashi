'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Lock, Plus, Edit2, Trash2, X, Filter, RefreshCw,
  Shield, AlertTriangle, CheckCircle, ChevronDown, ChevronUp,
  Upload, Info, History,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type CertType = 'single' | 'wildcard' | 'SAN' | 'self-signed'
type CertStatus = 'valid' | 'expiring' | 'expired' | 'revoked'

interface Certificate {
  id: string
  domain: string
  type: CertType
  issuer: string
  valid_from: string
  valid_to: string
  days_remaining: number
  auto_renew: boolean
  status: CertStatus
  notes: string
  sans: string[]
  fingerprint: string
  chain: string
}

interface RenewalRecord {
  id: string
  domain: string
  renewed_at: string
  new_expiry: string
  method: 'auto' | 'manual'
  success: boolean
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TYPE_COLORS: Record<CertType, string> = {
  single:        'bg-blue-500/20 text-blue-300 border-blue-500/30',
  wildcard:      'bg-purple-500/20 text-purple-300 border-purple-500/30',
  SAN:           'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  'self-signed': 'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

const STATUS_COLORS: Record<CertStatus, string> = {
  valid:    'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  expiring: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  expired:  'bg-red-500/20 text-red-300 border-red-500/30',
  revoked:  'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

const STATUS_LABELS: Record<CertStatus, string> = {
  valid: '有効', expiring: '期限切れ間近', expired: '期限切れ', revoked: '失効',
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

interface CertFormData {
  domain: string; type: CertType; issuer: string
  valid_from: string; valid_to: string; auto_renew: boolean; notes: string
}

const defaultForm: CertFormData = {
  domain: '', type: 'single', issuer: '', valid_from: '', valid_to: '', auto_renew: false, notes: '',
}

function CertModal({
  initial, onClose, onSave,
}: {
  initial?: Certificate | null; onClose: () => void; onSave: (d: CertFormData) => void
}) {
  const [form, setForm] = useState<CertFormData>(
    initial ? {
      domain: initial.domain, type: initial.type, issuer: initial.issuer,
      valid_from: initial.valid_from, valid_to: initial.valid_to,
      auto_renew: initial.auto_renew, notes: initial.notes,
    } : defaultForm
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
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/60 font-mono"
              placeholder="example.com または *.example.com"
              value={form.domain}
              onChange={e => setForm(f => ({ ...f, domain: e.target.value }))}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">種別</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none"
                value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value as CertType }))}>
                <option value="single">Single</option>
                <option value="wildcard">Wildcard</option>
                <option value="SAN">SAN</option>
                <option value="self-signed">Self-signed</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">発行者</label>
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none"
                placeholder="Let's Encrypt"
                value={form.issuer}
                onChange={e => setForm(f => ({ ...f, issuer: e.target.value }))}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">有効期限 (開始)</label>
              <input type="date"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none"
                value={form.valid_from} onChange={e => setForm(f => ({ ...f, valid_from: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">有効期限 (終了)</label>
              <input type="date"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none"
                value={form.valid_to} onChange={e => setForm(f => ({ ...f, valid_to: e.target.value }))}
              />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <input type="checkbox" id="auto_renew" className="w-4 h-4 accent-[#e8002d]"
              checked={form.auto_renew}
              onChange={e => setForm(f => ({ ...f, auto_renew: e.target.checked }))}
            />
            <label htmlFor="auto_renew" className="text-sm text-[#7d92b0] cursor-pointer">自動更新を有効化</label>
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">備考</label>
            <textarea rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none resize-none"
              value={form.notes}
              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
            />
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">PEMファイル (任意)</label>
            <label className="w-full border-2 border-dashed border-[#1e2d42] rounded-lg p-4 flex flex-col items-center gap-2 cursor-pointer hover:border-[#7d92b0]/40 transition-all">
              <Upload className="w-5 h-5 text-[#3d5068]" />
              <p className="text-xs text-[#3d5068]">クリックしてPEMファイルをアップロード</p>
              <input type="file" accept=".pem,.crt,.cer" className="hidden" />
            </label>
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
              { label: '種別',           value: cert.type },
              { label: '発行者',         value: cert.issuer },
              { label: '有効期限 (開始)', value: cert.valid_from },
              { label: '有効期限 (終了)', value: cert.valid_to },
              { label: '残り日数',        value: daysText(cert.days_remaining), colored: true },
              { label: '自動更新',        value: cert.auto_renew ? '有効' : '無効' },
            ].map(row => (
              <div key={row.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-2.5">
                <p className="text-[#3d5068] mb-0.5">{row.label}</p>
                <p className={`font-medium ${row.colored ? daysColor(cert.days_remaining) : 'text-white'}`}>
                  {row.value}
                </p>
              </div>
            ))}
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">Subject Alternative Names</p>
            <div className="flex flex-wrap gap-1.5">
              {cert.sans.map(san => (
                <span key={san} className="text-[10px] px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] font-mono">{san}</span>
              ))}
            </div>
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">フィンガープリント</p>
            <p className="text-[10px] font-mono text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 break-all">
              {cert.fingerprint}
            </p>
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">チェーン情報</p>
            <p className="text-[10px] font-mono text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
              {cert.chain}
            </p>
          </div>

          {cert.notes && (
            <div>
              <p className="text-xs text-[#7d92b0] mb-1">備考</p>
              <p className="text-xs text-white">{cert.notes}</p>
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-[#1e2d42] flex justify-end">
          <button onClick={onClose}
            className="px-4 py-2 rounded-lg bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-white text-sm transition-all">
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'certs' | 'history'>('certs')
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

  const { data: certData, isError } = useQuery<{ certificates: Certificate[] }>({
    queryKey: ['certificates'],
    queryFn: () => apiFetch('/api/v1/admin/certificates'),
    retry: 1,
  })

  const allCerts: Certificate[] = useMemo(() => {
    if (isError || !certData) return []
    return certData.certificates ?? []
  }, [certData, isError])

  const addMutation = useMutation({
    mutationFn: (data: CertFormData) => apiFetch('/api/v1/admin/certificates', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certificates'] }),
    onError: () => {},
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: CertFormData }) =>
      apiFetch(`/api/v1/admin/certificates/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certificates'] }),
    onError: () => {},
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/certificates/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certificates'] }),
    onError: () => {},
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

  const handleBulkRenew = () => {
    if (selected.size === 0) return
    showToast(`${selected.size}件の証明書を更新中... (モック)`)
    setSelected(new Set())
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
      {/* Toast */}
      {toastMsg && (
        <div className="fixed top-4 right-4 z-50 px-4 py-2.5 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-white text-sm shadow-xl">
          {toastMsg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
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
            <div className={`w-10 h-10 rounded-lg ${stat.icon_bg} flex items-center justify-center flex-shrink-0`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <div>
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-[#7d92b0] mt-0.5">{stat.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
        {(['certs', 'history'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === tab ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab === 'certs'
              ? <><Lock className="w-3.5 h-3.5" />証明書一覧</>
              : <><History className="w-3.5 h-3.5" />更新履歴</>
            }
          </button>
        ))}
      </div>

      {/* Certificates Tab */}
      {activeTab === 'certs' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-[#1e2d42]">
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-[#7d92b0]" />
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-none"
                value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="all">全種別</option>
                {(['single', 'wildcard', 'SAN', 'self-signed'] as CertType[]).map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-none"
                value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
                <option value="all">全ステータス</option>
                {(Object.keys(STATUS_LABELS) as CertStatus[]).map(s => (
                  <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                ))}
              </select>
              <select className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-none"
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
              <button onClick={handleBulkRenew}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-xs font-medium transition-all">
                <RefreshCw className="w-3.5 h-3.5" />
                一括更新 ({selected.size}件)
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
                  {['ドメイン', '種別', '発行者', '有効開始', '有効終了', '残り日数', '自動更新', 'ステータス', '操作'].map(h => (
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
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${TYPE_COLORS[cert.type]}`}>{cert.type}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{cert.issuer}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{cert.valid_from}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{cert.valid_to}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs ${daysColor(cert.days_remaining)}`}>
                        {daysText(cert.days_remaining)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                        cert.auto_renew
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-500/20 text-slate-300 border-slate-500/30'
                      }`}>
                        {cert.auto_renew ? '有効' : '無効'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${STATUS_COLORS[cert.status]}`}>
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

      {/* Renewal History Tab */}
      {activeTab === 'history' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <div className="px-5 py-4 border-b border-[#1e2d42]">
            <h2 className="text-white font-semibold text-sm">更新履歴</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ドメイン', '更新日時', '新有効期限', '方法', 'ステータス'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as RenewalRecord[]).map(rec => (
                  <tr key={rec.id} className="border-b border-[#1e2d42]/60 hover:bg-[#070d19]/60 transition-colors">
                    <td className="px-4 py-3 text-white text-xs font-mono font-medium">{rec.domain}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{rec.renewed_at}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{rec.new_expiry}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                        rec.method === 'auto'
                          ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                          : 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                      }`}>
                        {rec.method === 'auto' ? '自動' : '手動'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {rec.success
                          ? <CheckCircle className="w-4 h-4 text-emerald-400" />
                          : <X className="w-4 h-4 text-red-400" />
                        }
                        <span className={`text-xs ${rec.success ? 'text-emerald-400' : 'text-red-400'}`}>
                          {rec.success ? '成功' : '失敗'}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
