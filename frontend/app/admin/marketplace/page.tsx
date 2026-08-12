'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ShoppingBag, Search, X, Star, Download, Settings,
  CheckCircle, AlertTriangle, Package, Code2, ExternalLink,
  ChevronRight, Loader2, Filter, RefreshCw, Zap
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type Category = 'SIEM' | 'EDR' | 'Network' | 'Cloud' | 'ITSM' | 'Comms' | 'TI' | 'GRC' | 'Custom'
type PriceType = 'free' | 'paid' | 'included'
type HealthStatus = 'healthy' | 'degraded' | 'error' | 'unknown'

interface Integration {
  id: string
  name: string
  vendor: string
  category: Category
  description: string
  long_description: string
  version: string
  rating: number
  review_count: number
  install_count: number
  price_type: PriceType
  price?: string
  installed: boolean
  features: string[]
  requirements: string[]
  changelog: string[]
  logo_placeholder: string
  logo_color: string
  health?: HealthStatus
  installed_version?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const categoryColor: Record<Category, string> = {
  SIEM: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  EDR: 'bg-red-500/20 text-red-300 border-red-500/30',
  Network: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  Cloud: 'bg-sky-500/20 text-sky-300 border-sky-500/30',
  ITSM: 'bg-green-500/20 text-green-300 border-green-500/30',
  Comms: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  TI: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  GRC: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  Custom: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
}

const priceColor: Record<PriceType, string> = {
  free: 'bg-green-500/20 text-green-300',
  paid: 'bg-yellow-500/20 text-yellow-300',
  included: 'bg-blue-500/20 text-blue-300',
}
const priceLabel: Record<PriceType, string> = { free: '無料', paid: '有料', included: '含む' }

const healthColor: Record<HealthStatus, string> = {
  healthy: 'text-green-400', degraded: 'text-yellow-400', error: 'text-red-400', unknown: 'text-[#7d92b0]',
}
const healthLabel: Record<HealthStatus, string> = {
  healthy: '正常', degraded: '低下', error: 'エラー', unknown: '不明',
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${cls}`}>{text}</span>
}

function StarRating({ rating }: { rating: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map(i => (
        <Star key={i} className={`w-3 h-3 ${i <= Math.round(rating) ? 'text-yellow-400 fill-yellow-400' : 'text-[#3d5068]'}`} />
      ))}
      <span className="text-[11px] text-[#7d92b0] ml-1">{rating}</span>
    </div>
  )
}

// ─── Integration Detail Modal ─────────────────────────────────────────────────

function IntegrationDetailModal({ integration, onClose, onInstall, onUninstall, isLoading }: {
  integration: Integration; onClose: () => void
  onInstall: () => void; onUninstall: () => void; isLoading: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${integration.logo_color} flex items-center justify-center text-white font-bold text-sm`}>
              {integration.logo_placeholder}
            </div>
            <div>
              <h3 className="text-white font-semibold">{integration.name}</h3>
              <p className="text-xs text-[#7d92b0]">{integration.vendor} · v{integration.version}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-5">
          <div className="flex items-center gap-3">
            <Badge text={integration.category} cls={categoryColor[integration.category]} />
            <span className={`text-xs px-2 py-0.5 rounded ${priceColor[integration.price_type]}`}>
              {priceLabel[integration.price_type]}{integration.price ? ` (${integration.price})` : ''}
            </span>
            <StarRating rating={integration.rating} />
            <span className="text-xs text-[#7d92b0]">{integration.review_count}レビュー</span>
            <span className="text-xs text-[#7d92b0] ml-auto">{(integration.install_count ?? 0).toLocaleString()}件インストール</span>
          </div>

          <p className="text-sm text-[#7d92b0] leading-relaxed">{integration.long_description}</p>

          <div>
            <p className="text-xs font-medium text-white mb-2">主な機能</p>
            <div className="grid grid-cols-2 gap-1.5">
              {integration.features.map(f => (
                <div key={f} className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                  <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" /> {f}
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-xs font-medium text-white mb-2">必要要件</p>
            <ul className="space-y-1">
              {integration.requirements.map(r => (
                <li key={r} className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                  <ChevronRight className="w-3.5 h-3.5 text-[#e8002d]" /> {r}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="text-xs font-medium text-white mb-2">変更履歴</p>
            <ul className="space-y-1">
              {integration.changelog.map(c => (
                <li key={c} className="text-xs text-[#7d92b0]">· {c}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white">閉じる</button>
          {integration.installed ? (
            <button onClick={onUninstall} disabled={isLoading}
              className="px-4 py-2 border border-red-500/30 text-red-400 hover:text-white hover:border-red-500/60 text-sm rounded-lg transition-colors disabled:opacity-40">
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'アンインストール'}
            </button>
          ) : (
            <button onClick={onInstall} disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors disabled:opacity-40">
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Download className="w-4 h-4" /> インストール</>}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Developer Doc Modal ──────────────────────────────────────────────────────

function DevDocModal({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">カスタム統合の開発</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-sm text-[#7d92b0]">Kizashi Integration SDKを使用してカスタム統合を開発できます。</p>
          <div className="space-y-2">
            {[
              { title: 'REST API リファレンス', desc: '全エンドポイントのドキュメント' },
              { title: 'Webhook SDK', desc: 'イベント受信・送信フレームワーク' },
              { title: 'サンプルコード', desc: 'Python/Node.jsサンプル集' },
              { title: 'テストサンドボックス', desc: '本番環境を使わずテスト可能' },
            ].map(d => (
              <div key={d.title} className="flex items-center gap-3 p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg hover:border-[#7d92b0]/30 cursor-pointer transition-colors group">
                <Code2 className="w-4 h-4 text-[#e8002d]" />
                <div className="flex-1">
                  <p className="text-sm text-white">{d.title}</p>
                  <p className="text-[11px] text-[#7d92b0]">{d.desc}</p>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-[#3d5068] group-hover:text-[#7d92b0]" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function MarketplacePage() {
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [search, setSearch] = useState('')
  const [catFilter, setCatFilter] = useState<Category | 'all'>('all')
  const [showFilter, setShowFilter] = useState<'all' | 'installed' | 'available'>('all')
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null)
  const [showDevDoc, setShowDevDoc] = useState(false)
  const [loadingId, setLoadingId] = useState<string | null>(null)

  const { data: _integrations } = useQuery<Integration[]>({
    queryKey: ['marketplace-integrations'],
    queryFn: () => apiFetch('/api/v1/marketplace/integrations'),
  })

  const handleInstall = async (id: string) => {
    setLoadingId(id)
    try {
      await apiFetch(`/api/v1/marketplace/integrations/${id}/install`, { method: 'POST' })
    } catch {}
    setIntegrations(prev => prev.map(i => i.id === id ? { ...i, installed: true, health: 'healthy', installed_version: i.version } : i))
    setLoadingId(null)
    setSelectedIntegration(null)
  }

  const handleUninstall = async (id: string) => {
    setLoadingId(id)
    try {
      await apiFetch(`/api/v1/marketplace/integrations/${id}/uninstall`, { method: 'DELETE' })
    } catch {}
    setIntegrations(prev => prev.map(i => i.id === id ? { ...i, installed: false, health: undefined } : i))
    setLoadingId(null)
    setSelectedIntegration(null)
  }

  const filtered = integrations.filter(i => {
    if (search && !i.name.toLowerCase().includes(search.toLowerCase()) && !i.vendor.toLowerCase().includes(search.toLowerCase())) return false
    if (catFilter !== 'all' && i.category !== catFilter) return false
    if (showFilter === 'installed' && !i.installed) return false
    if (showFilter === 'available' && i.installed) return false
    return true
  })

  const installed = integrations.filter(i => i.installed)
  const categories: Array<Category | 'all'> = ['all', 'SIEM', 'EDR', 'Network', 'Cloud', 'ITSM', 'Comms', 'TI', 'GRC', 'Custom']

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <ShoppingBag className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">統合マーケットプレース</h1>
            <p className="text-xs text-[#7d92b0]">{integrations.length}個の統合 · {installed.length}個インストール済み</p>
          </div>
        </div>
        <button
          onClick={() => setShowDevDoc(true)}
          className="flex items-center gap-2 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 text-sm rounded-lg transition-colors"
        >
          <Code2 className="w-4 h-4" /> カスタム統合を開発
        </button>
      </div>

      {/* Search and filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
          <input
            className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-none focus:border-[#e8002d]/40"
            placeholder="統合を検索..."
            value={search} onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1">
          {(['all', 'installed', 'available'] as const).map(f => (
            <button key={f} onClick={() => setShowFilter(f)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${showFilter === f ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
              {f === 'all' ? '全て' : f === 'installed' ? 'インストール済み' : '未インストール'}
            </button>
          ))}
        </div>
        <div className="flex gap-1 flex-wrap">
          {categories.map(c => (
            <button key={c} onClick={() => setCatFilter(c)}
              className={`px-2 py-1 rounded text-xs transition-colors ${catFilter === c ? 'bg-[#1d2f4a] text-white' : 'text-[#3d5068] hover:text-[#7d92b0]'}`}>
              {c === 'all' ? '全カテゴリ' : c}
            </button>
          ))}
        </div>
      </div>

      {/* Installed integrations section */}
      {installed.length > 0 && showFilter !== 'available' && (
        <div>
          <p className="text-sm font-medium text-white mb-3">インストール済み ({installed.length})</p>
          <div className="grid grid-cols-3 gap-3">
            {installed.map(i => (
              <div key={i.id} className="bg-[#0d1220] border border-green-500/20 rounded-xl p-3 flex items-center gap-3">
                <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${i.logo_color} flex items-center justify-center text-white font-bold text-xs flex-shrink-0`}>
                  {i.logo_placeholder}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white font-medium truncate">{i.name}</p>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span className={`text-[10px] ${i.health ? healthColor[i.health] : 'text-[#7d92b0]'}`}>
                      ● {i.health ? healthLabel[i.health] : '不明'}
                    </span>
                    <span className="text-[10px] text-[#3d5068]">v{i.installed_version}</span>
                  </div>
                </div>
                <div className="flex gap-1">
                  <button className="p-1.5 text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded transition-colors">
                    <Settings className="w-3.5 h-3.5" />
                  </button>
                  <button onClick={() => handleUninstall(i.id)} className="p-1.5 text-[#7d92b0] hover:text-red-400 border border-[#1e2d42] rounded transition-colors">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Available integrations grid */}
      <div>
        <p className="text-sm font-medium text-white mb-3">利用可能な統合 ({filtered.length}件)</p>
        <div className="grid grid-cols-3 gap-4">
          {filtered.map(i => (
            <div key={i.id} className={`bg-[#0d1220] border rounded-xl p-4 flex flex-col gap-3 hover:border-[#e8002d]/30 transition-all cursor-pointer ${i.installed ? 'border-green-500/20' : 'border-[#1e2d42]'}`}
              onClick={() => setSelectedIntegration(i)}>
              <div className="flex items-start gap-3">
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${i.logo_color} flex items-center justify-center text-white font-bold text-sm flex-shrink-0`}>
                  {i.logo_placeholder}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <p className="text-sm text-white font-medium truncate">{i.name}</p>
                    {i.installed && <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />}
                  </div>
                  <p className="text-[11px] text-[#3d5068]">{i.vendor}</p>
                </div>
              </div>
              <p className="text-xs text-[#7d92b0] leading-relaxed flex-1">{i.description}</p>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge text={i.category} cls={categoryColor[i.category]} />
                <span className={`text-[11px] px-2 py-0.5 rounded ${priceColor[i.price_type]}`}>
                  {priceLabel[i.price_type]}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <StarRating rating={i.rating} />
                <span className="text-[10px] text-[#3d5068]">{(i.install_count ?? 0).toLocaleString()}件</span>
              </div>
              <button
                onClick={e => { e.stopPropagation(); i.installed ? setSelectedIntegration(i) : handleInstall(i.id) }}
                disabled={loadingId === i.id}
                className={`w-full flex items-center justify-center gap-1.5 py-2 text-xs rounded-lg transition-colors disabled:opacity-40 ${
                  i.installed
                    ? 'border border-[#1e2d42] text-[#7d92b0] hover:text-white'
                    : 'bg-[#e8002d] hover:bg-[#c0001f] text-white'
                }`}
              >
                {loadingId === i.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  : i.installed ? <><Settings className="w-3.5 h-3.5" /> 設定</>
                  : <><Download className="w-3.5 h-3.5" /> インストール</>
                }
              </button>
            </div>
          ))}
        </div>
        {filtered.length === 0 && (
          <div className="text-center py-12 text-[#7d92b0]">
            <Package className="w-8 h-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm">条件に一致する統合が見つかりません</p>
          </div>
        )}
      </div>

      {selectedIntegration && (
        <IntegrationDetailModal
          integration={selectedIntegration}
          onClose={() => setSelectedIntegration(null)}
          onInstall={() => handleInstall(selectedIntegration.id)}
          onUninstall={() => handleUninstall(selectedIntegration.id)}
          isLoading={loadingId === selectedIntegration.id}
        />
      )}
      {showDevDoc && <DevDocModal onClose={() => setShowDevDoc(false)} />}
    </div>
  )
}
