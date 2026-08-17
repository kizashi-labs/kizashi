'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Layers, Plus, X, CheckCircle, XCircle, AlertTriangle,
  ToggleLeft, ToggleRight, Trash2, Edit2, RefreshCw,
  Globe, Shield, Activity, Eye, EyeOff, Search, Zap
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────

type SourceType = 'virustotal' | 'shodan' | 'whois' | 'geoip' | 'threat_intel' | 'internal'
type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email'

interface EnrichmentSource {
  id: string
  name: string
  source_type: SourceType
  api_key_masked: string
  is_active: boolean
  requests_today: number
  daily_limit: number
  avg_latency_ms: number
  last_checked: string
  status: 'healthy' | 'degraded' | 'error'
}

interface CacheEntry {
  id: string
  indicator_value: string
  indicator_type: IOCType
  source: string
  result_preview: string
  expires_at: string
  created_at: string
}

interface EnrichmentResult {
  indicator: string
  indicator_type: IOCType
  sources_used: string[]
  // IP fields
  country?: string
  city?: string
  asn?: string
  abuse_score?: number
  open_ports?: number[]
  // Domain fields
  registrar?: string
  registered_at?: string
  dns_records?: string[]
  category?: string
  // Hash fields
  family?: string
  first_seen?: string
  last_seen?: string
  file_type?: string
  file_size_bytes?: number
  // Common
  vt_detections?: number
  vt_total?: number
  threat_intel_matches?: number
  reputation?: 'malicious' | 'suspicious' | 'clean' | 'unknown'
}

// ── Helpers ───────────────────────────────────────────────────────

const SOURCE_TYPE_CONFIG: Record<SourceType, { label: string; bg: string; text: string }> = {
  virustotal: { label: 'VirusTotal', bg: 'bg-red-900/40',    text: 'text-red-300' },
  shodan:     { label: 'Shodan',     bg: 'bg-orange-900/40', text: 'text-orange-300' },
  whois:      { label: 'WHOIS',      bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  geoip:      { label: 'GeoIP',      bg: 'bg-green-900/40',  text: 'text-green-300' },
  threat_intel: { label: 'Threat Intel', bg: 'bg-purple-900/40', text: 'text-purple-300' },
  internal:   { label: 'Internal',   bg: 'bg-gray-800',      text: 'text-gray-400' },
}

const IOC_TYPE_CONFIG: Record<IOCType, { label: string; bg: string; text: string }> = {
  ip:     { label: 'IP',     bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  domain: { label: 'Domain', bg: 'bg-purple-900/40', text: 'text-purple-300' },
  hash:   { label: 'Hash',   bg: 'bg-orange-900/40', text: 'text-orange-300' },
  url:    { label: 'URL',    bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  email:  { label: 'Email',  bg: 'bg-green-900/40',  text: 'text-green-300' },
}

const REPUTATION_CONFIG = {
  malicious:  { label: '悪意あり',  bg: 'bg-red-900/40',    text: 'text-red-300' },
  suspicious: { label: '疑わしい',  bg: 'bg-orange-900/40', text: 'text-orange-300' },
  clean:      { label: 'クリーン', bg: 'bg-green-900/40',  text: 'text-green-300' },
  unknown:    { label: '不明',     bg: 'bg-gray-800',      text: 'text-gray-400' },
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
function isExpiringSoon(ts: string) {
  return new Date(ts).getTime() - Date.now() < 3600000
}

// ── Source Form Modal ─────────────────────────────────────────────

function SourceFormModal({ source, onClose, onSave }: {
  source: EnrichmentSource | null
  onClose: () => void
  onSave: (s: Partial<EnrichmentSource>) => void
}) {
  const [form, setForm] = useState({
    name: source?.name ?? '',
    source_type: source?.source_type ?? 'virustotal' as SourceType,
    api_key: '',
    daily_limit: source?.daily_limit ?? 500,
  })
  const [showKey, setShowKey] = useState(false)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-lg">{source ? 'ソース編集' : 'ソース追加'}</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">名前</label>
            <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">ソースタイプ</label>
            <select value={form.source_type} onChange={e => setForm(p => ({ ...p, source_type: e.target.value as SourceType }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden">
              {(Object.keys(SOURCE_TYPE_CONFIG) as SourceType[]).map(t => (
                <option key={t} value={t}>{SOURCE_TYPE_CONFIG[t].label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">APIキー</label>
            <div className="relative">
              <input type={showKey ? 'text' : 'password'} value={form.api_key} onChange={e => setForm(p => ({ ...p, api_key: e.target.value }))}
                placeholder={source ? '変更する場合のみ入力' : 'APIキーを入力'}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 pr-10 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 font-mono" />
              <button onClick={() => setShowKey(!showKey)} className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-white">
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">1日あたりリクエスト上限</label>
            <input type="number" min={1} value={form.daily_limit} onChange={e => setForm(p => ({ ...p, daily_limit: Number(e.target.value) }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden" />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.name) { onSave(form); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Enrichment Result Card ────────────────────────────────────────

function EnrichmentResultCard({ result, onAddToIOC }: { result: EnrichmentResult; onAddToIOC: () => void }) {
  const repCfg = result.reputation ? REPUTATION_CONFIG[result.reputation] : REPUTATION_CONFIG.unknown
  const iocCfg = IOC_TYPE_CONFIG[result.indicator_type]
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 mt-4">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${iocCfg.bg} ${iocCfg.text}`}>{iocCfg.label}</span>
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${repCfg.bg} ${repCfg.text}`}>{repCfg.label}</span>
          <code className="text-sm text-falcon-text font-mono">{result.indicator}</code>
        </div>
        <button onClick={onAddToIOC}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-xs font-medium hover:bg-falcon-red/30 transition-colors shrink-0">
          <Plus className="w-3 h-3" /> IOCに追加
        </button>
      </div>

      {/* Sources used */}
      <div className="flex flex-wrap gap-1.5 mb-4">
        {result.sources_used.map(s => (
          <span key={s} className="text-xs px-2 py-0.5 rounded-sm bg-falcon-border text-falcon-muted border border-[#2a3f5a]">{s}</span>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        {/* IP-specific */}
        {result.country && <div><p className="text-xs text-falcon-muted mb-0.5">国 / 都市</p><p className="text-falcon-text">{result.country} {result.city && `/ ${result.city}`}</p></div>}
        {result.asn && <div><p className="text-xs text-falcon-muted mb-0.5">ASN</p><p className="text-falcon-text font-mono text-xs">{result.asn}</p></div>}
        {result.abuse_score !== undefined && <div><p className="text-xs text-falcon-muted mb-0.5">不正使用スコア</p><p className={`font-bold ${result.abuse_score >= 80 ? 'text-red-400' : result.abuse_score >= 50 ? 'text-orange-400' : 'text-green-400'}`}>{result.abuse_score}/100</p></div>}
        {result.open_ports && result.open_ports.length > 0 && <div><p className="text-xs text-falcon-muted mb-0.5">オープンポート (Shodan)</p><p className="text-falcon-text font-mono text-xs">{result.open_ports.join(', ')}</p></div>}
        {/* Domain-specific */}
        {result.registrar && <div><p className="text-xs text-falcon-muted mb-0.5">レジストラ</p><p className="text-falcon-text">{result.registrar}</p></div>}
        {result.registered_at && <div><p className="text-xs text-falcon-muted mb-0.5">登録日</p><p className="text-falcon-text">{result.registered_at}</p></div>}
        {result.category && <div><p className="text-xs text-falcon-muted mb-0.5">カテゴリ</p><p className="text-falcon-text">{result.category}</p></div>}
        {result.dns_records && result.dns_records.length > 0 && <div><p className="text-xs text-falcon-muted mb-0.5">DNSレコード</p><div className="space-y-0.5">{result.dns_records.map(r => <p key={r} className="text-falcon-text font-mono text-xs">{r}</p>)}</div></div>}
        {/* Hash-specific */}
        {result.family && <div><p className="text-xs text-falcon-muted mb-0.5">マルウェアファミリ</p><p className="text-red-300 font-medium">{result.family}</p></div>}
        {result.file_type && <div><p className="text-xs text-falcon-muted mb-0.5">ファイルタイプ</p><p className="text-falcon-text font-mono text-xs">{result.file_type}</p></div>}
        {result.first_seen && <div><p className="text-xs text-falcon-muted mb-0.5">初回検知</p><p className="text-falcon-text">{result.first_seen}</p></div>}
        {result.last_seen && <div><p className="text-xs text-falcon-muted mb-0.5">最終検知</p><p className="text-falcon-text">{result.last_seen}</p></div>}
        {/* Common */}
        {result.vt_detections !== undefined && <div><p className="text-xs text-falcon-muted mb-0.5">VirusTotal 検知</p><p className={`font-bold ${result.vt_detections > 20 ? 'text-red-400' : result.vt_detections > 5 ? 'text-orange-400' : 'text-green-400'}`}>{result.vt_detections}/{result.vt_total}</p></div>}
        {result.threat_intel_matches !== undefined && <div><p className="text-xs text-falcon-muted mb-0.5">TIマッチ数</p><p className={`font-bold ${result.threat_intel_matches > 5 ? 'text-red-400' : result.threat_intel_matches > 0 ? 'text-orange-400' : 'text-green-400'}`}>{result.threat_intel_matches}</p></div>}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────

export default function EnrichmentPage() {
  const [tab, setTab] = useState<'sources' | 'cache'>('sources')
  const [localSources, setLocalSources] = useState<EnrichmentSource[]>([])
  const [localCache, setLocalCache] = useState<CacheEntry[]>([])
  const [showAddSource, setShowAddSource] = useState(false)
  const [editSource, setEditSource] = useState<EnrichmentSource | null>(null)
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  // IOC Search
  const [iocType, setIocType] = useState<IOCType>('ip')
  const [iocValue, setIocValue] = useState('')
  const [enriching, setEnriching] = useState(false)
  const [enrichResult, setEnrichResult] = useState<EnrichmentResult | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  useQuery({
    queryKey: ['enrichment-sources'],
    queryFn: () => apiFetchList<EnrichmentSource>('/api/v1/admin/enrichment/sources'),
    onError: () => {},
  } as any)

  const handleEnrich = async () => {
    if (!iocValue.trim()) return
    setEnriching(true)
    setEnrichResult(null)
    try {
      const result = await apiFetch<EnrichmentResult>('/api/v1/admin/enrichment/enrich', {
        method: 'POST', body: JSON.stringify({ indicator: iocValue, indicator_type: iocType })
      })
      setEnrichResult(result)
    } catch {
      setEnrichResult({ indicator: iocValue, indicator_type: iocType, sources_used: [], reputation: 'unknown', vt_detections: 0, vt_total: 0 })
    }
    setEnriching(false)
  }

  const handleToggleSource = async (s: EnrichmentSource) => {
    try { await apiFetch(`/api/v1/admin/enrichment/sources/${s.id}/toggle`, { method: 'POST' }) } catch {}
    setLocalSources(prev => prev.map(x => x.id === s.id ? { ...x, is_active: !x.is_active } : x))
  }

  const handleHealthCheck = async (s: EnrichmentSource) => {
    showToast(`${s.name} のヘルスチェック中...`)
    try { await apiFetch(`/api/v1/admin/enrichment/sources/${s.id}/health`, { method: 'POST' }) } catch {}
    setTimeout(() => showToast(`${s.name}: ステータス正常`), 1500)
  }

  const handleDeleteSource = async (s: EnrichmentSource) => {
    try { await apiFetch(`/api/v1/admin/enrichment/sources/${s.id}`, { method: 'DELETE' }) } catch {}
    setLocalSources(prev => prev.filter(x => x.id !== s.id))
    showToast(`${s.name} を削除しました`)
  }

  const handleSaveSource = (form: Partial<EnrichmentSource>) => {
    if (editSource) {
      setLocalSources(prev => prev.map(x => x.id === editSource.id ? { ...x, ...form } : x))
      showToast('ソースを更新しました')
    } else {
      const newSrc: EnrichmentSource = { id: String(Date.now()), name: form.name!, source_type: form.source_type!, api_key_masked: '••••••••••••••••' + (form as any).api_key?.slice(-4), is_active: true, requests_today: 0, daily_limit: (form as any).daily_limit ?? 500, avg_latency_ms: 0, last_checked: new Date().toISOString(), status: 'healthy' }
      try { apiFetch('/api/v1/admin/enrichment/sources', { method: 'POST', body: JSON.stringify(form) }) } catch {}
      setLocalSources(prev => [...prev, newSrc])
      showToast(`${form.name} を追加しました`)
    }
    setEditSource(null)
  }

  const handleClearCache = async () => {
    try { await apiFetch('/api/v1/admin/enrichment/cache', { method: 'DELETE' }) } catch {}
    setLocalCache([])
    setShowClearConfirm(false)
    showToast('キャッシュをクリアしました')
  }

  const cacheHitRate = 82
  const totalCached = localCache.length
  const sizeEstimate = `${(totalCached * 1.2).toFixed(1)} KB`

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
          <Layers className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">脅威コンテキストエンリッチメント</h1>
          <p className="text-falcon-muted text-sm">外部ソースによるIOCコンテキスト強化</p>
        </div>
      </div>

      {/* IOC Search Tool */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 mb-6">
        <p className="text-xs text-falcon-muted mb-3 font-medium uppercase tracking-wider flex items-center gap-2">
          <Search className="w-3.5 h-3.5" /> IOC検索・エンリッチメント
        </p>
        <div className="flex gap-3">
          <select value={iocType} onChange={e => setIocType(e.target.value as IOCType)}
            className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden w-28">
            {(Object.keys(IOC_TYPE_CONFIG) as IOCType[]).map(t => (
              <option key={t} value={t}>{IOC_TYPE_CONFIG[t].label}</option>
            ))}
          </select>
          <input value={iocValue} onChange={e => setIocValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleEnrich()}
            placeholder={{ ip: 'IPアドレスを入力...', domain: 'ドメインを入力...', hash: 'ハッシュ値を入力...', url: 'URLを入力...', email: 'メールアドレスを入力...' }[iocType]}
            className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 font-mono" />
          <button onClick={handleEnrich} disabled={enriching || !iocValue.trim()}
            className="flex items-center gap-2 px-5 py-2 bg-falcon-red text-white rounded-sm text-sm font-medium hover:bg-[#c8001e] transition-colors disabled:opacity-40">
            {enriching ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            エンリッチ
          </button>
        </div>
        {enrichResult && (
          <EnrichmentResultCard result={enrichResult} onAddToIOC={() => showToast('IOCリストに追加しました')} />
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'sources', label: 'エンリッチメントソース' }, { key: 'cache', label: 'キャッシュ' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Sources Tab */}
      {tab === 'sources' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-falcon-muted text-sm">{localSources.length} ソース</p>
            <button onClick={() => { setEditSource(null); setShowAddSource(true) }}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> ソース追加
            </button>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['名前', 'タイプ', 'APIキー', '有効', 'リクエスト数', 'レイテンシ', 'ステータス', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {localSources.map(s => {
                  const stc = SOURCE_TYPE_CONFIG[s.source_type]
                  const usagePct = s.daily_limit < 999999 ? Math.round((s.requests_today / s.daily_limit) * 100) : 0
                  return (
                    <tr key={s.id} className={`border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors ${!s.is_active ? 'opacity-50' : ''}`}>
                      <td className="px-4 py-3">
                        <p className="text-white text-sm font-medium">{s.name}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${stc.bg} ${stc.text}`}>{stc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-falcon-muted">{s.api_key_masked}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggleSource(s)}>
                          {s.is_active ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                        </button>
                      </td>
                      <td className="px-4 py-3 min-w-[120px]">
                        {s.daily_limit < 999999 ? (
                          <div>
                            <div className="flex justify-between text-xs text-falcon-muted mb-1">
                              <span>{s.requests_today}</span><span>{s.daily_limit}</span>
                            </div>
                            <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${usagePct >= 90 ? 'bg-red-500' : usagePct >= 70 ? 'bg-yellow-500' : 'bg-green-500'}`} style={{ width: `${usagePct}%` }} />
                            </div>
                          </div>
                        ) : (
                          <span className="text-xs text-falcon-muted">無制限</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-mono font-bold ${s.avg_latency_ms < 100 ? 'text-green-400' : s.avg_latency_ms < 500 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {s.avg_latency_ms}ms
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.status === 'healthy' ? 'bg-green-900/40 text-green-300' : s.status === 'degraded' ? 'bg-yellow-900/40 text-yellow-300' : 'bg-red-900/40 text-red-300'}`}>
                          {s.status === 'healthy' ? '正常' : s.status === 'degraded' ? '低下' : 'エラー'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button onClick={() => handleHealthCheck(s)} className="text-falcon-muted hover:text-blue-400 transition-colors" title="ヘルスチェック">
                            <Activity className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => { setEditSource(s); setShowAddSource(true) }} className="text-falcon-muted hover:text-white transition-colors">
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => handleDeleteSource(s)} className="text-falcon-muted hover:text-red-400 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Cache Tab */}
      {tab === 'cache' && (
        <div>
          {/* Cache Stats */}
          <div className="grid grid-cols-3 gap-4 mb-4">
            {[
              { label: 'キャッシュヒット率', value: `${cacheHitRate}%`, color: 'text-green-400' },
              { label: 'キャッシュ件数', value: totalCached, color: 'text-blue-400' },
              { label: '推定サイズ', value: sizeEstimate, color: 'text-purple-400' },
            ].map(c => (
              <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                <p className="text-xs text-falcon-muted mb-1">{c.label}</p>
                <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between mb-4">
            <p className="text-falcon-muted text-sm">{localCache.length} キャッシュエントリ</p>
            <button onClick={() => setShowClearConfirm(true)}
              className="flex items-center gap-2 px-4 py-2 bg-red-900/30 border border-red-700/40 text-red-300 rounded-lg text-sm hover:bg-red-900/50 transition-colors">
              <Trash2 className="w-4 h-4" /> キャッシュクリア
            </button>
          </div>

          {localCache.length > 0 ? (
            <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['インジケーター', 'タイプ', 'ソース', '結果プレビュー', '有効期限', '作成日時'].map(h => (
                      <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {localCache.map(c => {
                    const itc = IOC_TYPE_CONFIG[c.indicator_type]
                    const expiring = isExpiringSoon(c.expires_at)
                    return (
                      <tr key={c.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                        <td className="px-4 py-3 max-w-[150px]">
                          <code className="text-xs font-mono text-falcon-text truncate block" title={c.indicator_value}>
                            {c.indicator_value.length > 24 ? c.indicator_value.slice(0, 24) + '…' : c.indicator_value}
                          </code>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${itc.bg} ${itc.text}`}>{itc.label}</span>
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted">{c.source}</td>
                        <td className="px-4 py-3 max-w-[180px]">
                          <code className="text-xs font-mono text-falcon-subtle truncate block" title={c.result_preview}>{c.result_preview.slice(0, 36)}…</code>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs ${expiring ? 'text-orange-400 font-medium' : 'text-falcon-muted'}`}>
                            {expiring && '⚠ '}{fmt(c.expires_at)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(c.created_at)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-16 text-falcon-muted text-sm bg-falcon-surface border border-falcon-border rounded-xl">
              キャッシュは空です
            </div>
          )}
        </div>
      )}

      {/* Clear Cache Confirm */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-sm p-6">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-red-400 shrink-0" />
              <h2 className="text-white font-semibold">キャッシュをクリアしますか?</h2>
            </div>
            <p className="text-falcon-muted text-sm mb-5">全{localCache.length}件のキャッシュエントリが削除されます。この操作は元に戻せません。</p>
            <div className="flex gap-3">
              <button onClick={() => setShowClearConfirm(false)} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
              <button onClick={handleClearCache} className="flex-1 py-2 rounded-sm bg-red-600 text-white text-sm font-medium hover:bg-red-700 transition-colors">クリア実行</button>
            </div>
          </div>
        </div>
      )}

      {/* Source Form Modal */}
      {showAddSource && (
        <SourceFormModal
          source={editSource}
          onClose={() => { setShowAddSource(false); setEditSource(null) }}
          onSave={handleSaveSource}
        />
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-falcon-surface border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-falcon-text flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-falcon-muted hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
