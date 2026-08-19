'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Globe, Plus, Trash2, X, Search, Upload, Shield, ShieldOff,
  Clock, AlertTriangle, CheckCircle2, BarChart2,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface IPBlockEntry {
  id: string
  ip_or_cidr: string
  entry_type: 'block' | 'allow'
  description?: string
  expires_at?: string
  hit_count: number
  created_at: string
  is_expired: boolean
}

interface IPBlockResponse {
  data: IPBlockEntry[]
  total: number
}

// ── Placeholder data ──────────────────────────────────────────────────────────
const PLACEHOLDER: IPBlockResponse = {
  total: 8,
  data: [
    { id: '1', ip_or_cidr: '192.168.1.100', entry_type: 'block', description: '不正アクセス試行', hit_count: 142, created_at: '2026-03-01T10:00:00Z', expires_at: undefined, is_expired: false },
    { id: '2', ip_or_cidr: '10.0.0.0/8', entry_type: 'allow', description: '社内ネットワーク', hit_count: 8932, created_at: '2026-01-15T08:00:00Z', expires_at: undefined, is_expired: false },
    { id: '3', ip_or_cidr: '45.33.32.156', entry_type: 'block', description: 'Shodan スキャナー', hit_count: 77, created_at: '2026-02-20T14:30:00Z', expires_at: '2026-04-20T00:00:00Z', is_expired: false },
    { id: '4', ip_or_cidr: '103.21.244.0/22', entry_type: 'block', description: 'Cloudflare abuse report', hit_count: 12, created_at: '2026-03-05T09:15:00Z', expires_at: undefined, is_expired: false },
    { id: '5', ip_or_cidr: '185.220.101.0/24', entry_type: 'block', description: 'Tor exit node range', hit_count: 354, created_at: '2026-02-10T11:00:00Z', expires_at: '2026-03-10T00:00:00Z', is_expired: true },
    { id: '6', ip_or_cidr: '172.16.0.0/12', entry_type: 'allow', description: 'プライベートアドレス空間', hit_count: 21043, created_at: '2026-01-01T00:00:00Z', expires_at: undefined, is_expired: false },
    { id: '7', ip_or_cidr: '5.188.206.0/24', entry_type: 'block', description: 'RDP ブルートフォース', hit_count: 891, created_at: '2026-03-10T16:45:00Z', expires_at: undefined, is_expired: false },
    { id: '8', ip_or_cidr: '198.51.100.42', entry_type: 'block', description: 'フィッシングC2サーバー', hit_count: 5, created_at: '2026-03-15T07:22:00Z', expires_at: '2026-06-15T00:00:00Z', is_expired: false },
  ],
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

export default function IPBlocklistPage() {
  const queryClient = useQueryClient()

  // Filters
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<'all' | 'block' | 'allow'>('all')
  const [showExpired, setShowExpired] = useState(false)

  // Modals
  const [showAddModal, setShowAddModal] = useState(false)
  const [showBulkModal, setShowBulkModal] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  // Add form state
  const [form, setForm] = useState({
    ip_or_cidr: '',
    entry_type: 'block' as 'block' | 'allow',
    description: '',
    expires_at: '',
  })

  // Bulk import state
  const [bulkText, setBulkText] = useState('')
  const [bulkType, setBulkType] = useState<'block' | 'allow'>('block')

  const { data, isLoading } = useQuery<IPBlockResponse>({
    queryKey: ['ip-blocklist'],
    queryFn: () => apiFetch('/api/v1/ioc/ip-block'),
    placeholderData: PLACEHOLDER,
  })

  const entries = data?.data ?? []

  const stats = useMemo(() => ({
    total: entries.length,
    active: entries.filter(e => !e.is_expired).length,
    expired: entries.filter(e => e.is_expired).length,
    todayBlocked: entries
      .filter(e => e.entry_type === 'block' && !e.is_expired)
      .reduce((sum, e) => sum + e.hit_count, 0),
  }), [entries])

  const filtered = useMemo(() => {
    return entries.filter(e => {
      if (!showExpired && e.is_expired) return false
      if (typeFilter !== 'all' && e.entry_type !== typeFilter) return false
      if (search) {
        const q = search.toLowerCase()
        if (!e.ip_or_cidr.toLowerCase().includes(q) &&
            !e.description?.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [entries, search, typeFilter, showExpired])

  const addMutation = useMutation({
    mutationFn: (body: typeof form) =>
      apiFetch('/api/v1/ioc/ip-block', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-blocklist'] })
      setShowAddModal(false)
      setForm({ ip_or_cidr: '', entry_type: 'block', description: '', expires_at: '' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/ioc/ip-block/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-blocklist'] })
      setDeleteConfirm(null)
    },
  })

  const bulkMutation = useMutation({
    mutationFn: (lines: string[]) =>
      Promise.all(
        lines.map(ip =>
          apiFetch('/api/v1/ioc/ip-block', {
            method: 'POST',
            body: JSON.stringify({ ip_or_cidr: ip.trim(), entry_type: bulkType }),
          })
        )
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-blocklist'] })
      setShowBulkModal(false)
      setBulkText('')
    },
  })

  const handleBulkImport = () => {
    const lines = bulkText.split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length > 0) bulkMutation.mutate(lines)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <Globe className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">IPブロックリスト管理</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">IPアドレスおよびCIDR範囲のブロック/許可リスト</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBulkModal(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm text-[#7d92b0] border border-[#1e2d42] rounded-sm hover:bg-[#0d1220] hover:text-white transition-colors"
          >
            <Upload className="w-4 h-4" />
            一括インポート
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            エントリを追加
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総エントリ', value: stats.total, icon: BarChart2, color: 'text-[#7d92b0]' },
          { label: 'アクティブ', value: stats.active, icon: CheckCircle2, color: 'text-green-400' },
          { label: '期限切れ', value: stats.expired, icon: Clock, color: 'text-orange-400' },
          { label: '今日ブロック数', value: (stats.todayBlocked ?? 0).toLocaleString(), icon: AlertTriangle, color: 'text-[#e8002d]' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <Icon className={`w-5 h-5 shrink-0 ${color}`} />
            <div>
              <p className="text-[#7d92b0] text-xs mb-0.5">{label}</p>
              <p className="text-2xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3 mb-4 flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="IP / 説明を検索..."
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm pl-9 pr-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
          />
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'block', 'allow'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1.5 text-xs rounded-sm font-medium transition-colors ${
                typeFilter === t
                  ? 'bg-[#e8002d] text-white'
                  : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]'
              }`}
            >
              {t === 'all' ? 'すべて' : t === 'block' ? 'ブロック' : '許可'}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-xs text-[#7d92b0] cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showExpired}
            onChange={e => setShowExpired(e.target.checked)}
            className="rounded-sm border-[#1e2d42] bg-[#070d19] accent-[#e8002d]"
          />
          期限切れを表示
        </label>
        <span className="ml-auto text-xs text-[#7d92b0]">{filtered.length} 件</span>
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">読み込み中...</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">エントリが見つかりません</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['IP / CIDR', 'タイプ', '説明', '追加日', '有効期限', 'アクション数', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {filtered.map(entry => (
                  <tr
                    key={entry.id}
                    className={`hover:bg-[#0a1628] transition-colors ${entry.is_expired ? 'opacity-50' : ''}`}
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm text-[#e2e8f4]">{entry.ip_or_cidr}</span>
                    </td>
                    <td className="px-4 py-3">
                      {entry.entry_type === 'block' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20">
                          <ShieldOff className="w-3 h-3" /> ブロック
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                          <Shield className="w-3 h-3" /> 許可
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-[200px] truncate">
                      {entry.description ?? <span className="text-[#3d5068]">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                      {formatDate(entry.created_at)}
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap">
                      {entry.expires_at ? (
                        <span className={entry.is_expired ? 'text-orange-400' : 'text-[#7d92b0]'}>
                          {entry.is_expired && <Clock className="w-3 h-3 inline mr-1" />}
                          {formatDate(entry.expires_at)}
                        </span>
                      ) : (
                        <span className="text-[#3d5068]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-bold ${entry.hit_count > 500 ? 'text-[#e8002d]' : entry.hit_count > 100 ? 'text-orange-400' : 'text-white'}`}>
                        {(entry.hit_count ?? 0).toLocaleString()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setDeleteConfirm(entry.id)}
                        className="p-1.5 rounded-sm text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
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
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md mx-4 shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#e8002d]" />
                エントリを追加
              </h2>
              <button onClick={() => setShowAddModal(false)} className="p-1 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">IP アドレス / CIDR <span className="text-[#e8002d]">*</span></label>
                <input
                  type="text"
                  value={form.ip_or_cidr}
                  onChange={e => setForm(f => ({ ...f, ip_or_cidr: e.target.value }))}
                  placeholder="例: 192.168.1.100 または 10.0.0.0/8"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">タイプ</label>
                <div className="flex gap-3">
                  {(['block', 'allow'] as const).map(t => (
                    <label key={t} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="entry_type"
                        value={t}
                        checked={form.entry_type === t}
                        onChange={() => setForm(f => ({ ...f, entry_type: t }))}
                        className="accent-[#e8002d]"
                      />
                      <span className="text-sm text-[#e2e8f4]">
                        {t === 'block' ? 'ブロック' : '許可'}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">説明</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="例: 不正アクセス試行"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">有効期限（任意）</label>
                <input
                  type="date"
                  value={form.expires_at}
                  onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[#1e2d42]">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => addMutation.mutate(form)}
                disabled={!form.ip_or_cidr.trim() || addMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {addMutation.isPending ? '追加中...' : '追加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Import Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-[#e8002d]" />
                一括インポート
              </h2>
              <button onClick={() => setShowBulkModal(false)} className="p-1 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">タイプ</label>
                <div className="flex gap-3">
                  {(['block', 'allow'] as const).map(t => (
                    <label key={t} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="bulk_type"
                        value={t}
                        checked={bulkType === t}
                        onChange={() => setBulkType(t)}
                        className="accent-[#e8002d]"
                      />
                      <span className="text-sm text-[#e2e8f4]">{t === 'block' ? 'ブロック' : '許可'}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  IPアドレス（1行に1エントリ）
                </label>
                <textarea
                  value={bulkText}
                  onChange={e => setBulkText(e.target.value)}
                  rows={10}
                  placeholder={'192.168.1.1\n10.0.0.0/8\n172.16.5.23'}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 font-mono resize-none"
                />
                <p className="text-xs text-[#7d92b0] mt-1">
                  {bulkText.split('\n').filter(l => l.trim()).length} 件のエントリ
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[#1e2d42]">
              <button
                onClick={() => setShowBulkModal(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleBulkImport}
                disabled={!bulkText.trim() || bulkMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {bulkMutation.isPending ? 'インポート中...' : 'インポート'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">エントリを削除しますか？</h2>
            <p className="text-sm text-[#7d92b0] mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
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
