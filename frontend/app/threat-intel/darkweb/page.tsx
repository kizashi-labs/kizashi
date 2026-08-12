'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  ShieldAlert, Globe, Plus, Trash2, RefreshCw,
  AlertTriangle, CheckCircle2, Eye, Server,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DarkwebStatus {
  enabled: boolean
  total_sites: number
  active_sites: number
  total_findings: number
  total_monitors: number
}

interface DarkwebFinding {
  id: string
  source: string
  group_name: string | null
  severity: number
  title: string
  description: string | null
  monitor_value: string | null
  alerted: boolean
  found_at: string
}

interface DarkwebMonitor {
  id: string
  monitor_type: 'domain' | 'email' | 'keyword'
  value: string
  enabled: boolean
  created_at: string
}

interface DarkwebSite {
  group_name: string
  onion_url: string
  is_active: boolean
  fail_count: number
  last_alive_at: string | null
  last_checked_at: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function sevColor(s: number) {
  if (s >= 9) return 'text-red-400 bg-red-900/30 border-red-700/40'
  if (s >= 7) return 'text-orange-400 bg-orange-900/30 border-orange-700/40'
  return 'text-yellow-400 bg-yellow-900/30 border-yellow-700/40'
}

function sevLabel(s: number) {
  if (s >= 9) return 'クリティカル'
  if (s >= 7) return '高'
  return '中'
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DarkWebMonitorPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [tab, setTab] = useState<'findings' | 'monitors' | 'sites'>('findings')
  const [newType, setNewType] = useState<'domain' | 'email' | 'keyword'>('domain')
  const [newValue, setNewValue] = useState('')

  const { data: status } = useQuery<DarkwebStatus>({
    queryKey: ['darkweb-status'],
    queryFn: () => apiFetch('/api/v1/threat-intel/darkweb/status'),
    refetchInterval: 60_000,
  })

  const { data: findingsData, isLoading: findingsLoading } = useQuery<{ findings: DarkwebFinding[]; total: number }>({
    queryKey: ['darkweb-findings'],
    queryFn: () => apiFetch('/api/v1/threat-intel/darkweb/findings'),
    refetchInterval: 120_000,
  })

  const { data: monitorsData } = useQuery<{ monitors: DarkwebMonitor[] }>({
    queryKey: ['darkweb-monitors'],
    queryFn: () => apiFetch('/api/v1/threat-intel/darkweb/monitors'),
    refetchInterval: 60_000,
  })

  const { data: sitesData, isLoading: sitesLoading } = useQuery<{ sites: DarkwebSite[]; total: number }>({
    queryKey: ['darkweb-sites'],
    queryFn: () => apiFetch('/api/v1/threat-intel/darkweb/sites'),
    refetchInterval: 300_000,
    enabled: tab === 'sites',
  })

  const addMonitor = useMutation({
    mutationFn: () => apiFetch('/api/v1/threat-intel/darkweb/monitors', {
      method: 'POST',
      body: JSON.stringify({ monitor_type: newType, value: newValue }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['darkweb-monitors'] })
      setNewValue('')
    },
  })

  const deleteMonitor = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/threat-intel/darkweb/monitors/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['darkweb-monitors'] }),
  })

  const findings = findingsData?.findings ?? []
  const monitors = monitorsData?.monitors ?? []
  const sites    = sitesData?.sites ?? []

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-900/20 rounded-lg border border-red-700/30">
            <Globe className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ダークウェブ監視</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">
              ランサムウェアリークサイトの被害者リストと監視キーワードを照合
            </p>
          </div>
        </div>
        <button
          onClick={() => {
            qc.invalidateQueries({ queryKey: ['darkweb-findings'] })
            qc.invalidateQueries({ queryKey: ['darkweb-status'] })
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0]
                     bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          更新
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: '監視サイト数', value: status?.active_sites ?? '—', sub: `全${status?.total_sites ?? 0}件`, color: 'text-blue-400' },
          { label: '監視キーワード', value: status?.total_monitors ?? '—', sub: '有効な監視対象', color: 'text-green-400' },
          { label: '検知件数', value: status?.total_findings ?? '—', sub: '累計', color: status?.total_findings ? 'text-red-400' : 'text-[#7d92b0]' },
          { label: 'Torプロキシ', value: status?.enabled ? '稼働中' : '停止', sub: 'ヘルスチェック', color: status?.enabled ? 'text-green-400' : 'text-[#3d5068]' },
        ].map(({ label, value, sub, color }) => (
          <div key={label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] px-4 py-3">
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-[#7d92b0] mt-0.5">{label}</p>
            <p className="text-[10px] text-[#3d5068] mt-0.5">{sub}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-1">
        {([
          ['findings', '検知結果'],
          ['monitors', '監視設定'],
          ['sites', 'サイト一覧'],
        ] as const).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${
              tab === id ? 'bg-[#1d2f4a] text-white' : 'text-[#3d5068] hover:text-[#7d92b0]'
            }`}
          >
            {label}
            {id === 'findings' && findings.length > 0 && (
              <span className="ml-1.5 text-[10px] bg-red-900/60 text-red-300 px-1.5 py-0.5 rounded-full">
                {findings.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── 検知結果タブ ── */}
      {tab === 'findings' && (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          {findingsLoading ? (
            <div className="flex items-center justify-center py-16 text-[#3d5068]">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" />読み込み中...
            </div>
          ) : findings.length === 0 ? (
            <div className="text-center py-16">
              <CheckCircle2 className="w-10 h-10 text-green-400/40 mx-auto mb-3" />
              <p className="text-[#7d92b0] text-sm font-medium">検知結果なし</p>
              <p className="text-[#3d5068] text-xs mt-1">
                監視キーワードが設定され、スキャンが実行されると結果が表示されます
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#1e2d42]">
              {findings.map(f => (
                <div key={f.id} className="px-5 py-4 hover:bg-[#111827] transition-colors">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${sevColor(f.severity)}`}>
                          {sevLabel(f.severity)}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                          f.source === 'ransomware_live'
                            ? 'bg-purple-900/30 text-purple-400'
                            : 'bg-[#161f33] text-[#7d92b0]'
                        }`}>
                          {f.source === 'ransomware_live' ? 'ransomware.live' : 'ransomwatch'}
                        </span>
                        {f.group_name && (
                          <span className="text-[10px] text-[#7d92b0] bg-[#161f33] px-2 py-0.5 rounded font-mono">
                            {f.group_name}
                          </span>
                        )}
                        <span className="text-[10px] text-[#3d5068] ml-auto">{fmtDate(f.found_at)}</span>
                      </div>
                      <p className="text-sm text-[#e2e8f4] font-medium">{f.title}</p>
                      {f.description && (
                        <p className="text-xs text-[#7d92b0] mt-1 leading-relaxed">{f.description}</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── 監視設定タブ ── */}
      {tab === 'monitors' && (
        <div className="space-y-4">
          {/* 追加フォーム */}
          {canWrite && (
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
              <p className="text-sm font-medium text-[#e2e8f4] mb-3">監視対象を追加</p>
              <div className="flex gap-2 flex-wrap">
                <select
                  value={newType}
                  onChange={e => setNewType(e.target.value as typeof newType)}
                  className="bg-[#161f33] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none"
                >
                  <option value="domain">ドメイン</option>
                  <option value="email">メール</option>
                  <option value="keyword">キーワード</option>
                </select>
                <input
                  value={newValue}
                  onChange={e => setNewValue(e.target.value)}
                  placeholder={newType === 'domain' ? 'example.com' : newType === 'email' ? 'admin@example.com' : '株式会社〇〇'}
                  onKeyDown={e => e.key === 'Enter' && newValue && addMonitor.mutate()}
                  className="flex-1 min-w-[200px] bg-[#161f33] border border-[#1e2d42] rounded-lg px-3 py-2
                             text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                />
                <button
                  onClick={() => newValue && addMonitor.mutate()}
                  disabled={!newValue || addMonitor.isPending}
                  className="flex items-center gap-1.5 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f]
                             text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />追加
                </button>
              </div>
              <p className="text-[10px] text-[#3d5068] mt-2">
                追加したキーワードは次回のスキャン（毎日3:00）から監視されます
              </p>
            </div>
          )}

          {/* 監視一覧 */}
          <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
            {monitors.length === 0 ? (
              <div className="text-center py-12">
                <Eye className="w-8 h-8 text-[#1e2d42] mx-auto mb-2" />
                <p className="text-[#7d92b0] text-sm">監視対象がまだ設定されていません</p>
                <p className="text-[#3d5068] text-xs mt-1">
                  自社のドメイン・メールアドレス・会社名を追加してください
                </p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#080c14]/40">
                    {['タイプ', '値', '追加日', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {monitors.map(m => (
                    <tr key={m.id} className="hover:bg-[#111827] transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-xs px-2 py-0.5 rounded border bg-blue-900/30 text-blue-300 border-blue-700/40">
                          {m.monitor_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#e2e8f4] font-mono text-sm">{m.value}</td>
                      <td className="px-4 py-3 text-xs text-[#3d5068]">{fmtDate(m.created_at)}</td>
                      <td className="px-4 py-3">
                        {canWrite && (
                          <button
                            onClick={() => deleteMonitor.mutate(m.id)}
                            className="text-[#3d5068] hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── サイト一覧タブ ── */}
      {tab === 'sites' && (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          {sitesLoading ? (
            <div className="flex items-center justify-center py-16 text-[#3d5068]">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" />読み込み中...
            </div>
          ) : sites.length === 0 ? (
            <div className="text-center py-12">
              <Server className="w-8 h-8 text-[#1e2d42] mx-auto mb-2" />
              <p className="text-[#7d92b0] text-sm">サイトデータがまだありません</p>
              <p className="text-[#3d5068] text-xs mt-1">ransomwatch 同期後に表示されます（毎日3:00自動実行）</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#080c14]/40">
                  {['グループ名', '.onion URL', '状態', '最終生存確認', '失敗回数'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {sites.map((s, i) => (
                  <tr key={i} className="hover:bg-[#111827] transition-colors">
                    <td className="px-4 py-3 text-[#e2e8f4] font-medium capitalize">{s.group_name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-[#7d92b0] truncate max-w-[200px]">
                      {s.onion_url}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                        s.is_active
                          ? 'bg-green-900/30 text-green-400'
                          : 'bg-[#1e2d42] text-[#3d5068]'
                      }`}>
                        {s.is_active ? '有効' : '無効'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#3d5068]">{fmtDate(s.last_alive_at)}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={s.fail_count >= 3 ? 'text-orange-400' : 'text-[#3d5068]'}>
                        {s.fail_count}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
