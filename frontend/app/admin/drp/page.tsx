'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { mockOr } from '@/lib/mock'
import { Plus, ChevronDown, ChevronRight, ExternalLink, ToggleLeft, ToggleRight } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface DRPMonitor {
  id: string
  name: string
  type: 'brand' | 'domain' | 'credential' | 'dark_web' | 'data_leak' | 'social_media'
  enabled: boolean
  findings_count: number
  last_scanned_at: string | null
}

interface DRPFinding {
  id: string
  title: string
  monitor_id: string
  monitor_name: string
  monitor_type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'mitigated' | 'false_positive'
  found_at: string
  source_url: string
  content_preview: string
  metadata: Record<string, string>
}

interface DRPData {
  monitors: DRPMonitor[]
  findings: DRPFinding[]
}

// 取得できなかったときに出すもの。MOCK は USE_MOCK のときだけです。
const EMPTY: DRPData = { monitors: [], findings: [] }

const MOCK: DRPData = {
  monitors: [
    { id: 'm1', name: 'ブランド名モニタリング', type: 'brand', enabled: true, findings_count: 8, last_scanned_at: '2026-03-18T10:00:00Z' },
    { id: 'm2', name: 'ドメインなりすまし検知', type: 'domain', enabled: true, findings_count: 5, last_scanned_at: '2026-03-18T09:30:00Z' },
    { id: 'm3', name: '認証情報漏洩モニター', type: 'credential', enabled: true, findings_count: 7, last_scanned_at: '2026-03-18T08:45:00Z' },
    { id: 'm4', name: 'ダークウェブ脅威情報', type: 'dark_web', enabled: true, findings_count: 3, last_scanned_at: '2026-03-17T23:00:00Z' },
    { id: 'm5', name: 'データ漏洩検知', type: 'data_leak', enabled: false, findings_count: 6, last_scanned_at: '2026-03-17T18:00:00Z' },
  ],
  findings: [
    { id: 'f1', title: '認証情報がPastebin上で検出', monitor_id: 'm3', monitor_name: '認証情報漏洩モニター', monitor_type: 'credential', severity: 'critical', status: 'open', found_at: '2026-03-18T07:22:00Z', source_url: 'https://pastebin.com/xxxxx', content_preview: 'admin@example.com:P@ssw0rd123 (partial redacted)', metadata: { source: 'Pastebin', confidence: '97%' } },
    { id: 'f2', title: 'フィッシングドメイン登録を検知', monitor_id: 'm2', monitor_name: 'ドメインなりすまし検知', monitor_type: 'domain', severity: 'high', status: 'investigating', found_at: '2026-03-17T20:15:00Z', source_url: 'https://whois.example.com/examp1e-corp.com', content_preview: 'examp1e-corp.com — 登録日: 2026-03-17, 登録者: 不明', metadata: { registrar: 'Unknown', country: 'RU' } },
    { id: 'f3', title: 'ダークウェブフォーラムで内部資料言及', monitor_id: 'm4', monitor_name: 'ダークウェブ脅威情報', monitor_type: 'dark_web', severity: 'high', status: 'open', found_at: '2026-03-17T14:30:00Z', source_url: 'http://darkforum.onion/thread/xxx', content_preview: '"example-corp internal docs for sale — Q1 financial reports..."', metadata: { forum: 'RansomHub', price: '$2,500' } },
    { id: 'f4', title: 'GitHubにAPIキー露出', monitor_id: 'm5', monitor_name: 'データ漏洩検知', monitor_type: 'data_leak', severity: 'medium', status: 'mitigated', found_at: '2026-03-16T11:00:00Z', source_url: 'https://github.com/user/repo/blob/main/config.js', content_preview: 'const API_KEY = "sk-prod-xxxxx..." (revoked)', metadata: { repo: 'user/repo', language: 'JavaScript' } },
  ],
}

const MONITOR_META: Record<string, { icon: string; color: string; bg: string; label: string }> = {
  brand:        { icon: '🏷', color: 'text-blue-300',   bg: 'bg-blue-900/40',   label: 'ブランド' },
  domain:       { icon: '🌐', color: 'text-orange-300', bg: 'bg-orange-900/40', label: 'ドメイン' },
  credential:   { icon: '🔑', color: 'text-red-300',    bg: 'bg-red-900/40',    label: '認証情報' },
  dark_web:     { icon: '🕷', color: 'text-purple-300', bg: 'bg-purple-900/40', label: 'ダークウェブ' },
  data_leak:    { icon: '💧', color: 'text-red-300',    bg: 'bg-red-900/40',    label: 'データ漏洩' },
  social_media: { icon: '📱', color: 'text-pink-300',   bg: 'bg-pink-900/40',   label: 'ソーシャル' },
}

const SEV_STYLES: Record<string, { badge: string; border: string; label: string }> = {
  critical: { badge: 'bg-red-900/60 text-red-300',    border: 'border-l-red-500',    label: 'クリティカル' },
  high:     { badge: 'bg-orange-900/60 text-orange-300', border: 'border-l-orange-500', label: '高' },
  medium:   { badge: 'bg-yellow-900/60 text-yellow-300', border: 'border-l-yellow-500', label: '中' },
  low:      { badge: 'bg-blue-900/60 text-blue-300',   border: 'border-l-blue-500',   label: '低' },
}

const STATUS_STYLES: Record<string, { badge: string; label: string }> = {
  open:           { badge: 'bg-red-900/40 text-red-300',      label: 'オープン' },
  investigating:  { badge: 'bg-blue-900/40 text-blue-300',    label: '調査中' },
  mitigated:      { badge: 'bg-green-900/40 text-green-300',  label: '緩和済み' },
  false_positive: { badge: 'bg-gray-700/60 text-gray-300',    label: '偽陽性' },
}

const STATS = [
  { label: 'モニター数', value: '5' },
  { label: '総検知', value: '29' },
  { label: 'オープン', value: '12' },
  { label: 'クリティカル', value: '5' },
  { label: '緩和済み', value: '7' },
]

function fmtTime(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const DAYS = ['3/12', '3/13', '3/14', '3/15', '3/16', '3/17', '3/18']
const DAY_COUNTS = [2, 5, 3, 7, 4, 6, 4]

export default function DRPPage() {
  const [selectedMonitor, setSelectedMonitor] = useState<string | null>(null)
  const [sevFilter, setSevFilter] = useState<string>('全て')
  const [statusFilter, setStatusFilter] = useState<string>('全て')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  const { data } = useQuery<DRPData>({
    queryKey: ['drp'],
    queryFn: () => apiFetch<DRPData>('/api/v1/admin/drp'),
  })

  const qc = useQueryClient()
  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      // PATCH はどのルートにも当たりません。サーバにあるのは PUT だけです。
      apiFetch(`/api/v1/admin/drp/findings/${id}`, { method: 'PUT', body: JSON.stringify({ status }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['drp'] }),
  })

  const d = data ?? mockOr(MOCK, EMPTY)

  const filteredFindings = d.findings.filter(f => {
    const monOk = !selectedMonitor || f.monitor_id === selectedMonitor
    const sevOk = sevFilter === '全て' || f.severity === sevFilter
    const stOk  = statusFilter === '全て' || f.status === statusFilter
    return monOk && sevOk && stOk
  })

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">デジタルリスク保護 (DRP)</h1>
          <p className="text-[#7d92b0] text-sm mt-1">外部脅威・ブランドリスク・情報漏洩をリアルタイムでモニタリング</p>
        </div>
        <button onClick={() => setShowForm(true)} className="flex items-center gap-2 bg-[#e8002d] hover:bg-[#c8001d] text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Plus size={16} /> 新規モニター
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4">
        {STATS.map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="text-2xl font-bold text-white">{s.value}</div>
            <div className="text-[#7d92b0] text-sm mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Main Layout */}
      <div className="flex gap-5">
        {/* Left: Monitor list (35%) */}
        <div className="w-[35%] shrink-0 space-y-3">
          <h2 className="font-semibold text-white text-sm">モニター一覧</h2>
          {d.monitors.map(m => {
            const meta = MONITOR_META[m.type] ?? MONITOR_META.brand
            const isSelected = selectedMonitor === m.id
            return (
              <div key={m.id} onClick={() => setSelectedMonitor(isSelected ? null : m.id)}
                className={`bg-[#0d1220] border rounded-xl p-4 cursor-pointer transition-colors ${isSelected ? 'border-[#e8002d]' : 'border-[#1e2d42] hover:border-[#7d92b0]'}`}>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">{meta.icon}</span>
                    <div>
                      <div className="font-medium text-white text-sm">{m.name}</div>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${meta.bg} ${meta.color}`}>{meta.label}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${m.findings_count >= 5 ? 'bg-red-900/60 text-red-300' : m.findings_count >= 3 ? 'bg-yellow-900/60 text-yellow-300' : 'bg-blue-900/60 text-blue-300'}`}>{m.findings_count}</span>
                    {m.enabled ? <ToggleRight size={18} className="text-green-400" /> : <ToggleLeft size={18} className="text-[#7d92b0]" />}
                  </div>
                </div>
                <div className="text-[#7d92b0] text-xs mt-2">最終スキャン: {fmtTime(m.last_scanned_at)}</div>
              </div>
            )
          })}
        </div>

        {/* Right: Findings (65%) */}
        <div className="flex-1 space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex gap-1">
              {['全て', 'critical', 'high', 'medium', 'low'].map(v => (
                <button key={v} onClick={() => setSevFilter(v)} className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${sevFilter === v ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {v === '全て' ? v : SEV_STYLES[v]?.label ?? v}
                </button>
              ))}
            </div>
            <div className="flex gap-1">
              {['全て', 'open', 'investigating', 'mitigated', 'false_positive'].map(v => (
                <button key={v} onClick={() => setStatusFilter(v)} className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${statusFilter === v ? 'bg-[#1e2d42] text-white border border-[#7d92b0]' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {v === '全て' ? v : STATUS_STYLES[v]?.label ?? v}
                </button>
              ))}
            </div>
          </div>

          {filteredFindings.length === 0 && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-8 text-center text-[#7d92b0] text-sm">該当する検知がありません</div>
          )}

          {filteredFindings.map(f => {
            const sev = SEV_STYLES[f.severity] ?? SEV_STYLES.low
            const st  = STATUS_STYLES[f.status] ?? STATUS_STYLES.open
            const mMeta = MONITOR_META[f.monitor_type] ?? MONITOR_META.brand
            const isExp = expanded === f.id
            return (
              <div key={f.id} className={`bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden border-l-4 ${sev.border}`}>
                <div className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-white text-sm">{f.title}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${mMeta.bg} ${mMeta.color}`}>{f.monitor_name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${sev.badge}`}>{sev.label}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${st.badge}`}>{st.label}</span>
                      </div>
                      <div className="text-[#7d92b0] text-xs mt-1">検知: {fmtTime(f.found_at)}</div>
                    </div>
                    <button onClick={() => setExpanded(isExp ? null : f.id)} className="text-[#7d92b0] hover:text-white transition-colors shrink-0">
                      {isExp ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </button>
                  </div>
                  {f.status !== 'mitigated' && f.status !== 'false_positive' && (
                    <div className="flex gap-2 mt-3">
                      <button onClick={() => updateStatus.mutate({ id: f.id, status: 'investigating' })} className="text-xs px-3 py-1 bg-blue-900/40 hover:bg-blue-900/70 text-blue-300 rounded-md transition-colors">調査開始</button>
                      <button onClick={() => updateStatus.mutate({ id: f.id, status: 'mitigated' })} className="text-xs px-3 py-1 bg-green-900/40 hover:bg-green-900/70 text-green-300 rounded-md transition-colors">緩和済み</button>
                      <button onClick={() => updateStatus.mutate({ id: f.id, status: 'false_positive' })} className="text-xs px-3 py-1 bg-gray-700/60 hover:bg-gray-700 text-gray-300 rounded-md transition-colors">偽陽性</button>
                    </div>
                  )}
                </div>
                {isExp && (
                  <div className="border-t border-[#1e2d42] p-4 bg-[#070d19] space-y-3 text-xs">
                    <div>
                      <span className="text-[#7d92b0]">ソースURL: </span>
                      <a href={f.source_url} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1 inline-flex">{f.source_url} <ExternalLink size={10} /></a>
                    </div>
                    <div>
                      <span className="text-[#7d92b0]">コンテンツプレビュー: </span>
                      <span className="text-white font-mono">{f.content_preview}</span>
                    </div>
                    <div className="flex gap-4">
                      {Object.entries(f.metadata).map(([k, v]) => (
                        <div key={k}><span className="text-[#7d92b0]">{k}: </span><span className="text-white">{v}</span></div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h2 className="font-semibold text-white mb-4">過去7日間の検知推移</h2>
        <div className="flex items-end gap-3 h-24">
          {DAYS.map((day, i) => (
            <div key={day} className="flex-1 flex flex-col items-center gap-1">
              <div className="text-[#7d92b0] text-xs">{DAY_COUNTS[i]}</div>
              <div className="w-full bg-[#e8002d]/70 rounded-t" style={{ height: `${(DAY_COUNTS[i] / 8) * 72}px` }} />
              <div className="text-[#7d92b0] text-xs">{day}</div>
            </div>
          ))}
        </div>
      </div>

      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md space-y-4">
            <h3 className="font-semibold text-white">新規DRPモニター</h3>
            <input placeholder="モニター名" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]" />
            <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]">
              {Object.entries(MONITOR_META).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <div className="flex gap-3 pt-2">
              <button className="flex-1 bg-[#e8002d] hover:bg-[#c8001d] text-white rounded-lg py-2 text-sm font-medium transition-colors">作成</button>
              <button onClick={() => setShowForm(false)} className="flex-1 border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg py-2 text-sm font-medium transition-colors">キャンセル</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
