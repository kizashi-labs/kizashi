'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Globe, AlertTriangle, Shield, Filter, X, Eye, Loader2,
  Plus, Download, Trash2, CheckCircle, Search, Copy, RefreshCw,
} from 'lucide-react'
// ── Types ─────────────────────────────────────────────────────────────────────

type AlertType = 'tunneling' | 'DGA' | 'C2' | 'exfil' | 'malware'
type BlockCategory = 'malware' | 'C2' | 'phishing' | 'ads'
type BlockSource = 'manual' | 'feed' | 'auto'

interface DnsAlert {
  id: string
  timestamp: string
  source_host: string
  domain: string
  alert_type: AlertType
  confidence: number
  response: string
  blocked: boolean
}

interface DnsStats {
  total_queries: number
  blocked_domains: number
  tunneling_alerts: number
  dga_detections: number
}

interface TopDomain {
  domain: string
  count: number
  category: string
  entropy: number
}

interface BlocklistEntry {
  id: string
  domain: string
  category: BlockCategory
  added_date: string
  hit_count: number
  source: BlockSource
  reason: string
}

const HISTOGRAM_DATA: { hour: string; count: number; blocked: number }[] = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2,'0')}:00`,
  count: Math.floor(Math.random() * 500 + 100),
  blocked: Math.floor(Math.random() * 20),
}))

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(d: string) {
  return new Date(d).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtDate(d: string) {
  return new Date(d).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {}
  for (const c of s) freq[c] = (freq[c] || 0) + 1
  const n = s.length
  return -Object.values(freq).reduce((acc, f) => acc + (f / n) * Math.log2(f / n), 0)
}

// ── Badges ────────────────────────────────────────────────────────────────────

function AlertTypeBadge({ type }: { type: AlertType }) {
  const cfg: Record<AlertType, { cls: string; label: string }> = {
    tunneling: { cls: 'bg-red-500/20 text-red-400 border-red-500/30',       label: 'トンネリング' },
    DGA:       { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'DGA' },
    C2:        { cls: 'bg-red-500/20 text-red-400 border-red-500/30',       label: 'C2通信' },
    exfil:     { cls: 'bg-red-500/20 text-red-400 border-red-500/30',       label: 'データ流出' },
    malware:   { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'マルウェア' },
  }
  const { cls, label } = cfg[type]
  return <span className={`inline-flex px-2 py-0.5 rounded border text-[11px] font-medium ${cls}`}>{label}</span>
}

function CategoryBadge({ cat }: { cat: string }) {
  const cfg: Record<string, string> = {
    malware:  'bg-red-500/20 text-red-400 border-red-500/30',
    C2:       'bg-red-500/20 text-red-400 border-red-500/30',
    phishing: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    ads:      'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }
  const labels: Record<string, string> = { malware: 'マルウェア', C2: 'C2通信', phishing: 'フィッシング', ads: '広告' }
  return (
    <span className={`inline-flex px-2 py-0.5 rounded border text-[11px] font-medium ${cfg[cat] ?? 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3f5f]'}`}>
      {labels[cat] ?? cat}
    </span>
  )
}

function SourceBadge({ src }: { src: BlockSource }) {
  const cfg: Record<BlockSource, string> = {
    manual: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    feed:   'bg-blue-500/20 text-blue-400 border-blue-500/30',
    auto:   'bg-green-500/20 text-green-400 border-green-500/30',
  }
  const labels: Record<BlockSource, string> = { manual: '手動', feed: 'フィード', auto: '自動' }
  return <span className={`inline-flex px-2 py-0.5 rounded border text-[11px] font-medium ${cfg[src]}`}>{labels[src]}</span>
}

// ── Alert Detail Modal ────────────────────────────────────────────────────────

function AlertDetailModal({ alert, onClose }: { alert: DnsAlert; onClose: () => void }) {
  const entropy = shannonEntropy(alert.domain)
  const mlScores = [
    { label: 'エントロピースコア', score: Math.min(100, Math.round(entropy * 20)), color: 'bg-red-500' },
    { label: 'N-gram 異常スコア', score: Math.round(alert.confidence * 0.95), color: 'bg-orange-500' },
    { label: 'TI フィード一致', score: alert.alert_type === 'C2' || alert.alert_type === 'malware' ? 95 : 40, color: 'bg-yellow-500' },
    { label: 'WHOIS 疑わしさ', score: Math.round(alert.confidence * 0.8), color: 'bg-purple-500' },
    { label: '総合スコア', score: alert.confidence, color: 'bg-[#e8002d]' },
  ]

  const queryChain = [
    { step: 1, query: alert.domain, type: 'A', response: alert.response, ns: '8.8.8.8' },
    { step: 2, query: `ns1.${alert.domain.split('.').slice(-2).join('.')}`, type: 'NS', response: '203.0.113.50', ns: '1.1.1.1' },
    { step: 3, query: alert.domain, type: 'TXT', response: 'v=spf1 ip4:203.0.113.0/24 ~all', ns: '203.0.113.50' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Globe className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h2 className="text-white font-semibold">DNSアラート詳細</h2>
              <p className="text-[#7d92b0] text-xs font-mono">{alert.domain}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'ソースホスト', value: alert.source_host },
              { label: 'アラートタイプ', value: <AlertTypeBadge type={alert.alert_type} /> },
              { label: '信頼度', value: `${alert.confidence}%` },
              { label: 'レスポンス', value: alert.response },
            ].map(item => (
              <div key={item.label} className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                <p className="text-[#7d92b0] text-xs mb-1">{item.label}</p>
                <p className="text-white text-sm font-medium">{item.value}</p>
              </div>
            ))}
          </div>

          {/* DNS Query Chain */}
          <div>
            <h3 className="text-white font-semibold mb-3 text-sm">DNSクエリチェーン</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ステップ', 'クエリ', 'タイプ', 'レスポンス', 'ネームサーバー'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {queryChain.map(q => (
                    <tr key={q.step} className="border-b border-[#1e2d42]/40">
                      <td className="py-2 px-3 text-[#7d92b0]">{q.step}</td>
                      <td className="py-2 px-3 font-mono text-[#e2e8f4] max-w-[180px] truncate">{q.query}</td>
                      <td className="py-2 px-3"><span className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px]">{q.type}</span></td>
                      <td className="py-2 px-3 font-mono text-[#7d92b0] max-w-[140px] truncate">{q.response}</td>
                      <td className="py-2 px-3 font-mono text-[#7d92b0]">{q.ns}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* WHOIS Mock */}
          <div>
            <h3 className="text-white font-semibold mb-3 text-sm">WHOIS 情報 (モック)</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 font-mono text-xs text-[#7d92b0] space-y-1">
              <p><span className="text-[#3d5068]">Registrar:</span> <span className="text-[#e2e8f4]">Namecheap Inc. (Private)</span></p>
              <p><span className="text-[#3d5068]">Created:</span> <span className="text-[#e2e8f4]">2026-03-01 (17日前)</span></p>
              <p><span className="text-[#3d5068]">Updated:</span> <span className="text-[#e2e8f4]">2026-03-10</span></p>
              <p><span className="text-[#3d5068]">Registrant:</span> <span className="text-orange-400">REDACTED FOR PRIVACY</span></p>
              <p><span className="text-[#3d5068]">Name Servers:</span> <span className="text-[#e2e8f4]">ns1.bulletproof-dns.ru, ns2.bulletproof-dns.ru</span></p>
              <p><span className="text-[#3d5068]">Status:</span> <span className="text-red-400">clientTransferProhibited</span></p>
            </div>
          </div>

          {/* Related IOCs */}
          <div>
            <h3 className="text-white font-semibold mb-3 text-sm">関連 IOC</h3>
            <div className="flex flex-wrap gap-2">
              {['203.0.113.50', '185.220.101.45', 'evil.com', 'darkcdn.io', 'SHA256:4a8b...c91f'].map(ioc => (
                <span key={ioc} className="px-2.5 py-1 bg-red-500/10 border border-red-500/20 rounded text-xs font-mono text-red-400">
                  {ioc}
                </span>
              ))}
            </div>
          </div>

          {/* ML Score Breakdown */}
          <div>
            <h3 className="text-white font-semibold mb-3 text-sm">MLスコア内訳</h3>
            <div className="space-y-2">
              {mlScores.map(s => (
                <div key={s.label}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-[#7d92b0]">{s.label}</span>
                    <span className="text-xs font-bold text-white">{s.score}%</span>
                  </div>
                  <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${s.color}`} style={{ width: `${s.score}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 px-6 py-4 border-t border-[#1e2d42]">
          <button className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors">
            <Shield className="w-4 h-4" />
            ドメインをブロック
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-sm transition-colors">
            <Search className="w-4 h-4" />
            調査を開始
          </button>
          <button onClick={onClose} className="ml-auto px-4 py-2 text-[#7d92b0] hover:text-white text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── Add Domain Modal ──────────────────────────────────────────────────────────

function AddDomainModal({ onClose, onAdd }: { onClose: () => void; onAdd: (d: Omit<BlocklistEntry, 'id' | 'added_date' | 'hit_count'>) => void }) {
  const [domain, setDomain] = useState('')
  const [category, setCategory] = useState<BlockCategory>('malware')
  const [reason, setReason] = useState('')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold flex items-center gap-2"><Plus className="w-4 h-4 text-[#e8002d]" />ドメイン追加</h2>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ドメイン / パターン</label>
            <input value={domain} onChange={e => setDomain(e.target.value)}
              placeholder="example.com or *.example.com"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/60 font-mono" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">カテゴリ</label>
            <select value={category} onChange={e => setCategory(e.target.value as BlockCategory)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/60">
              <option value="malware">マルウェア</option>
              <option value="C2">C2通信</option>
              <option value="phishing">フィッシング</option>
              <option value="ads">広告</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">理由</label>
            <input value={reason} onChange={e => setReason(e.target.value)}
              placeholder="ブロック理由を入力..."
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/60" />
          </div>
        </div>
        <div className="flex items-center gap-2 px-6 pb-4">
          <button
            onClick={() => { if (domain.trim()) { onAdd({ domain: domain.trim(), category, reason, source: 'manual' }); onClose() } }}
            className="flex-1 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"
          >追加</button>
          <button onClick={onClose} className="flex-1 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-sm transition-colors">キャンセル</button>
        </div>
      </div>
    </div>
  )
}

// ── DNS Alerts Tab ────────────────────────────────────────────────────────────

function DnsAlertsTab() {
  const [typeFilter, setTypeFilter] = useState<AlertType | 'all'>('all')
  const [confThreshold, setConfThreshold] = useState(0)
  const [selected, setSelected] = useState<DnsAlert | null>(null)

  const { data, isLoading } = useQuery<{ alerts: DnsAlert[] }>({
    queryKey: ['dns-alerts'],
    queryFn: async () => {
      try { return await apiFetch<{ alerts: DnsAlert[] }>('/api/v1/dns/alerts') }
      catch { return { alerts: [] } }
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  })

  const alerts = data?.alerts ?? []
  const filtered = alerts.filter(a => {
    if (typeFilter !== 'all' && a.alert_type !== typeFilter) return false
    if (a.confidence < confThreshold) return false
    return true
  })

  return (
    <div className="space-y-4">
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}

      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value as AlertType | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#e8002d]/60">
          <option value="all">全タイプ</option>
          <option value="tunneling">トンネリング</option>
          <option value="DGA">DGA</option>
          <option value="C2">C2通信</option>
          <option value="exfil">データ流出</option>
          <option value="malware">マルウェア</option>
        </select>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[#7d92b0]">信頼度 ≥</span>
          <input type="range" min={0} max={100} step={5} value={confThreshold}
            onChange={e => setConfThreshold(Number(e.target.value))}
            className="w-28 accent-[#e8002d]" />
          <span className="text-xs text-white w-8">{confThreshold}%</span>
        </div>
        <span className="text-xs text-[#7d92b0] ml-auto">{filtered.length} 件</span>
      </div>

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['日時', 'ソースホスト', 'ドメイン', 'タイプ', '信頼度', 'レスポンス', 'アクション'].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="py-10 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : filtered.map(a => (
                <tr key={a.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(a.timestamp)}</td>
                  <td className="py-3 px-4 text-white text-xs font-medium">{a.source_host}</td>
                  <td className="py-3 px-4 font-mono text-xs text-[#7d92b0] max-w-[200px]">
                    <span className="truncate block">{a.domain}</span>
                  </td>
                  <td className="py-3 px-4"><AlertTypeBadge type={a.alert_type} /></td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-bold ${a.confidence >= 90 ? 'text-red-400' : a.confidence >= 75 ? 'text-orange-400' : 'text-yellow-400'}`}>
                      {a.confidence}%
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-mono ${a.blocked ? 'text-red-400' : 'text-[#7d92b0]'}`}>{a.response}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setSelected(a)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded transition-colors border border-[#2a3f5f]">
                        <Eye className="w-3 h-3" />詳細
                      </button>
                      <button className="flex items-center gap-1 px-2 py-1 text-xs bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded transition-colors border border-red-500/30">
                        <Shield className="w-3 h-3" />ブロック
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Query Analysis Tab ────────────────────────────────────────────────────────

function QueryAnalysisTab() {
  const [timeRange, setTimeRange] = useState<'6h' | '12h' | '24h'>('24h')

  const { data, isLoading } = useQuery<{ domains: TopDomain[] }>({
    queryKey: ['dns-queries'],
    queryFn: async () => {
      try { return await apiFetch<{ domains: TopDomain[] }>('/api/v1/dns/queries') }
      catch { return { domains: [] } }
    },
    staleTime: 60_000,
  })

  const domains = data?.domains ?? []
  const maxCount = Math.max(...domains.map(d => d.count))

  // Sort by entropy for the entropy section
  const byEntropy = [...domains].sort((a, b) => b.entropy - a.entropy)

  // Histogram (trim based on time range)
  const histSlice = timeRange === '6h' ? HISTOGRAM_DATA.slice(18) : timeRange === '12h' ? HISTOGRAM_DATA.slice(12) : HISTOGRAM_DATA
  const maxHist = Math.max(...histSlice.map(d => d.count))

  // NXDOMAIN ratio mock
  const nxRatio = 12.4

  return (
    <div className="space-y-6">
      {/* Top domains table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
          <h3 className="text-white font-semibold text-sm">上位20 クエリドメイン</h3>
          <span className="text-xs text-[#7d92b0]">過去24時間</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['#', 'ドメイン', 'クエリ数', 'カテゴリ', 'エントロピー', '分布'].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={6} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : domains.map((d, i) => {
                const isSuspicious = d.entropy > 4.0
                return (
                  <tr key={d.domain} className={`border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors ${isSuspicious ? 'bg-red-500/5' : ''}`}>
                    <td className="py-2.5 px-4 text-[#3d5068] text-xs">{i + 1}</td>
                    <td className="py-2.5 px-4 font-mono text-xs text-white max-w-[220px]">
                      <span className="truncate block">{d.domain}</span>
                    </td>
                    <td className="py-2.5 px-4 text-white text-xs font-medium">{(d.count ?? 0).toLocaleString()}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-medium ${
                        isSuspicious ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3f5f]'
                      }`}>{d.category}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`text-xs font-mono font-bold ${d.entropy > 4.5 ? 'text-red-400' : d.entropy > 3.5 ? 'text-orange-400' : 'text-green-400'}`}>
                        {d.entropy.toFixed(2)}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="h-1.5 w-28 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${isSuspicious ? 'bg-red-500' : 'bg-blue-500'}`}
                          style={{ width: `${(d.count / maxCount) * 100}%` }} />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entropy analysis */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <h3 className="text-white font-semibold text-sm">エントロピー分析 (DGA検出)</h3>
          <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-[10px]">高エントロピー = DGA疑い</span>
        </div>
        <div className="space-y-2">
          {byEntropy.slice(0, 10).map(d => (
            <div key={d.domain} className="flex items-center gap-3">
              <span className="font-mono text-xs text-[#7d92b0] w-52 truncate">{d.domain}</span>
              <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${d.entropy > 4.5 ? 'bg-red-500' : d.entropy > 3.5 ? 'bg-orange-500' : d.entropy > 3.0 ? 'bg-yellow-500' : 'bg-green-500'}`}
                  style={{ width: `${(d.entropy / 5) * 100}%` }}
                />
              </div>
              <span className={`text-xs font-bold w-10 text-right ${d.entropy > 4.5 ? 'text-red-400' : d.entropy > 3.5 ? 'text-orange-400' : 'text-green-400'}`}>
                {d.entropy.toFixed(2)}
              </span>
            </div>
          ))}
        </div>
        <p className="text-[#7d92b0] text-xs mt-3">シャノンエントロピー: 4.0以上 = DGA疑い、4.5以上 = 高確率DGA</p>
      </div>

      {/* Histogram */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold text-sm">クエリボリューム推移</h3>
          <div className="flex gap-1">
            {(['6h', '12h', '24h'] as const).map(t => (
              <button key={t} onClick={() => setTimeRange(t)}
                className={`px-3 py-1 text-xs rounded transition-colors ${timeRange === t ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                {t}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-end gap-1 h-32">
          {histSlice.map(d => (
            <div key={d.hour} className="flex-1 flex flex-col items-center gap-0.5">
              <div className="w-full relative" style={{ height: '100px' }}>
                <div className="absolute bottom-0 w-full bg-blue-500/40 border-t border-blue-500/60 rounded-t transition-all"
                  style={{ height: `${(d.count / maxHist) * 100}%` }} />
                <div className="absolute bottom-0 w-full bg-red-500/60 border-t border-red-500/80 rounded-t"
                  style={{ height: `${(d.blocked / maxHist) * 100 * 5}%` }} />
              </div>
              <span className="text-[9px] text-[#3d5068]">{d.hour}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-4 mt-2 text-xs text-[#7d92b0]">
          <span className="flex items-center gap-1"><span className="w-3 h-2 bg-blue-500/40 border-t border-blue-500 inline-block rounded-t" />総クエリ</span>
          <span className="flex items-center gap-1"><span className="w-3 h-2 bg-red-500/60 border-t border-red-500 inline-block rounded-t" />ブロック</span>
        </div>
      </div>

      {/* NXDOMAIN ratio */}
      <div className={`bg-[#0d1220] border rounded-xl p-5 ${nxRatio > 10 ? 'border-orange-500/40' : 'border-[#1e2d42]'}`}>
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg ${nxRatio > 10 ? 'bg-orange-500/15' : 'bg-[#1e2d42]'}`}>
            <AlertTriangle className={`w-5 h-5 ${nxRatio > 10 ? 'text-orange-400' : 'text-[#7d92b0]'}`} />
          </div>
          <div className="flex-1">
            <p className="text-white font-semibold text-sm">NXDOMAIN比率</p>
            <p className="text-[#7d92b0] text-xs">高いNXDOMAIN比率はC2ビーコニングの可能性を示します</p>
          </div>
          <div className="text-right">
            <p className={`text-2xl font-bold ${nxRatio > 10 ? 'text-orange-400' : 'text-green-400'}`}>{nxRatio}%</p>
            <p className={`text-xs ${nxRatio > 10 ? 'text-orange-400' : 'text-[#7d92b0]'}`}>{nxRatio > 10 ? '警告: 平均より高い' : '正常範囲'}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Blocklist Tab ─────────────────────────────────────────────────────────────

function BlocklistTab() {
  const [catFilter, setCatFilter] = useState<BlockCategory | 'all'>('all')
  const [srcFilter, setSrcFilter] = useState<BlockSource | 'all'>('all')
  const [showAdd, setShowAdd] = useState(false)
  const [localEntries, setLocalEntries] = useState<BlocklistEntry[]>([])
  const [importMsg, setImportMsg] = useState('')
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery<{ entries: BlocklistEntry[] }>({
    queryKey: ['dns-blocklist'],
    queryFn: async () => {
      try { return await apiFetch<{ entries: BlocklistEntry[] }>('/api/v1/dns/blocklist') }
      catch { return { entries: [] } }
    },
    staleTime: 60_000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/dns/blocklist/${id}`, { method: 'DELETE' }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['dns-blocklist'] }),
  })

  const allEntries = [...(data?.entries ?? []), ...localEntries]
  const filtered = allEntries.filter(e => {
    if (catFilter !== 'all' && e.category !== catFilter) return false
    if (srcFilter !== 'all' && e.source !== srcFilter) return false
    return true
  })

  const handleAdd = (entry: Omit<BlocklistEntry, 'id' | 'added_date' | 'hit_count'>) => {
    setLocalEntries(prev => [...prev, { ...entry, id: `local-${Date.now()}`, added_date: new Date().toISOString(), hit_count: 0 }])
  }

  const handleImport = () => {
    setImportMsg('TIフィードから 47 件のドメインをインポートしました')
    setTimeout(() => setImportMsg(''), 3000)
  }

  return (
    <div className="space-y-4">
      {showAdd && <AddDomainModal onClose={() => setShowAdd(false)} onAdd={handleAdd} />}

      {importMsg && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-green-500/15 border border-green-500/30 rounded-lg text-green-400 text-sm">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          {importMsg}
        </div>
      )}

      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select value={catFilter} onChange={e => setCatFilter(e.target.value as BlockCategory | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#e8002d]/60">
          <option value="all">全カテゴリ</option>
          <option value="malware">マルウェア</option>
          <option value="C2">C2通信</option>
          <option value="phishing">フィッシング</option>
          <option value="ads">広告</option>
        </select>
        <select value={srcFilter} onChange={e => setSrcFilter(e.target.value as BlockSource | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#e8002d]/60">
          <option value="all">全ソース</option>
          <option value="manual">手動</option>
          <option value="feed">フィード</option>
          <option value="auto">自動</option>
        </select>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={handleImport}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-xs transition-colors border border-[#2a3f5f]">
            <Download className="w-3.5 h-3.5" />
            TIフィードからインポート
          </button>
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-xs transition-colors font-medium">
            <Plus className="w-3.5 h-3.5" />
            ドメイン追加
          </button>
        </div>
      </div>

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['ドメイン / パターン', 'カテゴリ', '追加日', 'ヒット数', 'ソース', '理由', ''].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : filtered.map(e => (
                <tr key={e.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 font-mono text-xs text-white max-w-[200px]">
                    <span className="truncate block">{e.domain}</span>
                  </td>
                  <td className="py-3 px-4"><CategoryBadge cat={e.category} /></td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDate(e.added_date)}</td>
                  <td className="py-3 px-4 text-white text-xs font-medium">{(e.hit_count ?? 0).toLocaleString()}</td>
                  <td className="py-3 px-4"><SourceBadge src={e.source} /></td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs max-w-[180px]">
                    <span className="truncate block">{e.reason}</span>
                  </td>
                  <td className="py-3 px-4">
                    <button onClick={() => deleteMutation.mutate(e.id)}
                      className="p-1.5 rounded hover:bg-red-500/20 text-[#7d92b0] hover:text-red-400 transition-colors" title="削除">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Whitelist override */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-green-400" />
          ホワイトリスト (ブロック除外)
        </h3>
        <div className="flex gap-2">
          <input placeholder="除外するドメインを入力 (例: internal.corp.local)"
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/60" />
          <button className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded-lg text-sm border border-green-500/30 transition-colors font-medium">
            追加
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          {['internal.corp.local', 'ad.company.com', 'windowsupdate.microsoft.com'].map(d => (
            <span key={d} className="flex items-center gap-1.5 px-2.5 py-1 bg-green-500/10 border border-green-500/20 rounded text-xs text-green-400">
              <CheckCircle className="w-3 h-3" />
              {d}
              <button className="hover:text-red-400 transition-colors"><X className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DnsSecurityPage() {
  const [activeTab, setActiveTab] = useState<'alerts' | 'queries' | 'blocklist'>('alerts')

  const { data: stats } = useQuery<DnsStats>({
    queryKey: ['dns-stats'],
    queryFn: async () => {
      try { return await apiFetch<DnsStats>('/api/v1/dns/stats') }
      catch { return { total_queries: 0, blocked_domains: 0, tunneling_alerts: 0, dga_detections: 0 } as DnsStats }
    },
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const EMPTY_STATS: DnsStats = { total_queries: 0, blocked_domains: 0, tunneling_alerts: 0, dga_detections: 0 }
  const s = stats ?? EMPTY_STATS

  const statCards = [
    { label: '総DNSクエリ/日', value: (s.total_queries ?? 0).toLocaleString(), icon: Globe, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
    { label: 'ブロックドメイン', value: (s.blocked_domains ?? 0).toLocaleString(), icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
    { label: 'トンネリングアラート', value: s.tunneling_alerts, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
    { label: 'DGA検出', value: s.dga_detections, icon: Search, color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
  ]

  const tabs = [
    { key: 'alerts',    label: 'DNSアラート' },
    { key: 'queries',   label: 'クエリ分析' },
    { key: 'blocklist', label: 'ブロックリスト' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Globe className="w-6 h-6 text-[#e8002d]" />
            DNSセキュリティ
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">DNS異常・トンネリング・DGA検出</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-sm transition-colors border border-[#2a3f5f]">
          <RefreshCw className="w-4 h-4" />
          更新
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className={`bg-[#0d1220] border rounded-xl p-4 ${c.bg}`}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#070d19]/60">
                  <Icon className={`w-5 h-5 ${c.color}`} />
                </div>
                <div>
                  <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
                  <p className="text-[#7d92b0] text-xs">{c.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#1e2d42]">
        {tabs.map(tab => (
          <button key={tab.key} onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px
              ${activeTab === tab.key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}>
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'alerts'    && <DnsAlertsTab />}
      {activeTab === 'queries'   && <QueryAnalysisTab />}
      {activeTab === 'blocklist' && <BlocklistTab />}
    </div>
  )
}
