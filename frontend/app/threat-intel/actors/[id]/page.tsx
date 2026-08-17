'use client'

import { useState } from 'react'
import { useParams } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  ChevronLeft, Shield, Globe, Calendar, Copy, ExternalLink,
  ChevronDown, ChevronRight, FileText, Download, Search,
  Filter, RefreshCw, AlertTriangle, Target, Activity,
  CheckCircle, Clock, Tag,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

interface TTP {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  detection_notes: string
}

interface Campaign {
  id: string
  name: string
  start_date: string
  end_date: string | null
  targeted_sectors: string[]
  status: 'active' | 'historical'
  ioc_count: number
  description: string
}

interface IOC {
  id: string
  value: string
  type: 'ip' | 'domain' | 'hash' | 'url'
  first_seen: string
  last_seen: string
  confidence: number
}

interface Report {
  id: string
  title: string
  date: string
  source: string
  summary: string
  pdf_url: string
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  origin_country: string
  origin_flag: string
  threat_level: 'critical' | 'high' | 'medium' | 'low'
  first_seen: string
  last_seen: string
  description: string
  motivation: string[]
  target_industries: string[]
  target_regions: { country: string; flag: string }[]
  ttps: TTP[]
  campaigns: Campaign[]
  iocs: IOC[]
  reports: Report[]
}


// ─── Sub Components ───────────────────────────────────────────────────────────

const TACTICS_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

function MitreMatrix({ ttps }: { ttps: TTP[] }) {
  const byTactic: Record<string, TTP[]> = {}
  ttps.forEach(t => {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = []
    byTactic[t.tactic].push(t)
  })

  const usedTactics = TACTICS_ORDER.filter(t => byTactic[t])

  return (
    <div className="overflow-x-auto">
      <div className="flex gap-2 min-w-max pb-2">
        {usedTactics.map(tactic => (
          <div key={tactic} className="shrink-0 w-44">
            <div className="bg-falcon-border text-falcon-text text-[11px] font-semibold px-2 py-1.5 rounded-t text-center">
              {tactic}
            </div>
            <div className="space-y-1 pt-1">
              {(byTactic[tactic] || []).map(t => (
                <div
                  key={t.technique_id}
                  title={t.technique_name}
                  className="bg-falcon-red/20 border border-falcon-red/30 text-[#f87171] text-[10px] px-2 py-1 rounded-sm cursor-default hover:bg-falcon-red/30 transition-colors"
                >
                  <span className="font-mono font-bold">{t.technique_id}</span>
                  <br />
                  <span className="truncate block">{t.technique_name}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function CampaignCard({ campaign }: { campaign: Campaign }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-falcon-card transition-colors"
        onClick={() => setExpanded(x => !x)}
      >
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <div className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${campaign.status === 'active' ? 'bg-green-400 animate-pulse' : 'bg-falcon-subtle'}`} />
          <div className="min-w-0">
            <h4 className="text-falcon-text font-semibold">{campaign.name}</h4>
            <div className="flex items-center gap-3 mt-1 text-xs text-falcon-muted">
              <span className="flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                {new Date(campaign.start_date).toLocaleDateString('ja-JP')}
                {' → '}
                {campaign.end_date ? new Date(campaign.end_date).toLocaleDateString('ja-JP') : '現在'}
              </span>
              <span>{campaign.ioc_count} IOC</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[11px] px-2 py-0.5 rounded border ${
            campaign.status === 'active'
              ? 'bg-green-500/15 text-green-400 border-green-500/30'
              : 'bg-falcon-border text-falcon-muted border-falcon-border'
          }`}>
            {campaign.status === 'active' ? 'アクティブ' : '終了'}
          </span>
          {expanded ? <ChevronDown className="w-4 h-4 text-falcon-muted" /> : <ChevronRight className="w-4 h-4 text-falcon-muted" />}
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-falcon-border pt-3">
          <p className="text-falcon-muted text-sm mb-3">{campaign.description}</p>
          <div>
            <p className="text-falcon-muted text-xs font-medium mb-1.5">標的セクター</p>
            <div className="flex flex-wrap gap-1.5">
              {campaign.targeted_sectors.map(s => (
                <span key={s} className="px-2 py-0.5 rounded-sm text-[11px] bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  {s}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

const iocTypeBadge = (type: string) => {
  const cfgs: Record<string, string> = {
    ip:     'bg-blue-500/15 text-blue-400 border-blue-500/30',
    domain: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    hash:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    url:    'bg-green-500/15 text-green-400 border-green-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[10px] font-mono font-semibold border uppercase ${cfgs[type] ?? 'bg-falcon-border text-falcon-muted border-falcon-border'}`}>
      {type}
    </span>
  )
}

const confidenceBadge = (score: number) => {
  let cls = 'text-green-400'
  if (score < 70) cls = 'text-red-400'
  else if (score < 85) cls = 'text-yellow-400'
  return <span className={`font-semibold ${cls}`}>{score}%</span>
}

const threatLevelBadge = (level: string) => {
  const configs: Record<string, { label: string; className: string }> = {
    critical: { label: 'クリティカル', className: 'bg-red-500/20 text-red-400 border-red-500/30' },
    high:     { label: '高',           className: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    medium:   { label: '中',           className: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
    low:      { label: '低',           className: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  }
  const cfg = configs[level] ?? configs.low
  return (
    <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium border ${cfg.className}`}>
      <AlertTriangle className="w-3.5 h-3.5" />
      {cfg.label}
    </span>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

const TABS = ['概要', 'TTPs', 'キャンペーン', '関連IOC', 'レポート'] as const
type Tab = typeof TABS[number]

export default function ThreatActorDetailPage() {
  const params = useParams()
  const actorId = params.id as string

  const [activeTab, setActiveTab] = useState<Tab>('概要')
  const [iocSearch, setIocSearch] = useState('')
  const [iocTypeFilter, setIocTypeFilter] = useState('all')
  const [iocPage, setIocPage] = useState(1)
  const [copied, setCopied] = useState<string | null>(null)

  const { data, isLoading } = useQuery<ThreatActor>({
    queryKey: ['threat-actor', actorId],
    queryFn: () => apiFetch(`/api/v1/threat-intel/actors/${actorId}`),
    staleTime: 60_000,
    retry: false,
  })

  const actor = data

  const filteredIOCs = (actor?.iocs ?? []).filter(ioc => {
    const matchSearch = !iocSearch || ioc.value.toLowerCase().includes(iocSearch.toLowerCase())
    const matchType = iocTypeFilter === 'all' || ioc.type === iocTypeFilter
    return matchSearch && matchType
  })

  const IOC_PAGE_SIZE = 25
  const totalIocPages = Math.ceil(filteredIOCs.length / IOC_PAGE_SIZE)
  const pagedIOCs = filteredIOCs.slice((iocPage - 1) * IOC_PAGE_SIZE, iocPage * IOC_PAGE_SIZE)

  const copyToClipboard = (val: string) => {
    navigator.clipboard.writeText(val)
    setCopied(val)
    setTimeout(() => setCopied(null), 2000)
  }

  const motivationLabels: Record<string, string> = {
    financial: '金融目的', espionage: 'スパイ活動', disruption: '妨害・破壊',
  }
  const motivationColors: Record<string, string> = {
    financial: 'bg-green-500/15 text-green-400 border-green-500/30',
    espionage: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    disruption: 'bg-red-500/15 text-red-400 border-red-500/30',
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070d19] flex items-center justify-center">
        <RefreshCw className="w-8 h-8 text-falcon-muted animate-spin" />
      </div>
    )
  }

  if (!actor) {
    return (
      <div className="min-h-screen bg-[#070d19] flex items-center justify-center">
        <p className="text-falcon-muted">脅威アクターが見つかりません</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-falcon-muted mb-4">
        <Link href="/threat-intel" className="hover:text-falcon-text transition-colors">脅威インテリジェンス</Link>
        <ChevronRight className="w-3 h-3" />
        <Link href="/threat-intel/actors" className="hover:text-falcon-text transition-colors">脅威アクター</Link>
        <ChevronRight className="w-3 h-3" />
        <span className="text-falcon-text">{actor.name}</span>
      </div>

      {/* Header */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-6 mb-6">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h1 className="text-3xl font-bold text-falcon-text">{actor.name}</h1>
              {threatLevelBadge(actor.threat_level)}
            </div>
            <div className="flex items-center gap-2 mt-2 text-falcon-muted">
              <span className="text-xl">{actor.origin_flag}</span>
              <span className="text-sm">{actor.origin_country}</span>
            </div>
            <div className="flex flex-wrap gap-1.5 mt-3">
              {actor.aliases.map(alias => (
                <span key={alias} className="px-2 py-0.5 rounded-sm text-[11px] bg-falcon-border text-falcon-muted border border-falcon-border">
                  {alias}
                </span>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border text-center">
              <p className="text-falcon-muted text-xs mb-1">初確認</p>
              <p className="text-falcon-text font-medium flex items-center gap-1 justify-center">
                <Calendar className="w-3.5 h-3.5 text-falcon-muted" />
                {new Date(actor.first_seen).toLocaleDateString('ja-JP')}
              </p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border text-center">
              <p className="text-falcon-muted text-xs mb-1">最終確認</p>
              <p className="text-falcon-text font-medium flex items-center gap-1 justify-center">
                <Clock className="w-3.5 h-3.5 text-falcon-muted" />
                {new Date(actor.last_seen).toLocaleDateString('ja-JP')}
              </p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border text-center">
              <p className="text-falcon-muted text-xs mb-1">キャンペーン</p>
              <p className="text-falcon-text font-medium">{actor.campaigns.length}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border text-center">
              <p className="text-falcon-muted text-xs mb-1">追跡IOC</p>
              <p className="text-falcon-text font-medium">{actor.iocs.length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-falcon-border">
        {TABS.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? 'border-falcon-red text-falcon-text'
                : 'border-transparent text-falcon-muted hover:text-falcon-text'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* ── Tab: 概要 ─────────────────────────────────────────────────────── */}
      {activeTab === '概要' && (
        <div className="space-y-6">
          {/* Description */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-falcon-red" />
              概要
            </h3>
            <p className="text-falcon-muted text-sm leading-relaxed">{actor.description}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Motivation */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
              <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                <Target className="w-4 h-4 text-falcon-red" />
                攻撃動機
              </h3>
              <div className="flex flex-wrap gap-2">
                {actor.motivation.map(m => (
                  <span key={m} className={`px-3 py-1.5 rounded-full text-sm font-medium border ${motivationColors[m] ?? 'bg-falcon-border text-falcon-muted border-falcon-border'}`}>
                    {motivationLabels[m] ?? m}
                  </span>
                ))}
              </div>
            </div>

            {/* Target Industries */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
              <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                <Activity className="w-4 h-4 text-falcon-red" />
                標的業種
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {actor.target_industries.map(ind => (
                  <span key={ind} className="px-2.5 py-1 rounded-sm text-sm bg-falcon-border text-falcon-text border border-falcon-border">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Target Regions */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
              <Globe className="w-4 h-4 text-falcon-red" />
              標的地域
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {actor.target_regions.map(r => (
                <div key={r.country} className="flex items-center gap-2 px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border">
                  <span className="text-xl">{r.flag}</span>
                  <span className="text-sm text-falcon-text">{r.country}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Aliases */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
              <Tag className="w-4 h-4 text-falcon-red" />
              別名・エイリアス
            </h3>
            <div className="flex flex-wrap gap-2">
              {actor.aliases.map(alias => (
                <span key={alias} className="px-3 py-1.5 rounded-sm text-sm bg-falcon-border text-falcon-text border border-falcon-border font-mono">
                  {alias}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: TTPs ─────────────────────────────────────────────────────── */}
      {activeTab === 'TTPs' && (
        <div className="space-y-6">
          {/* MITRE Matrix */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-falcon-text font-semibold flex items-center gap-2">
                <Shield className="w-4 h-4 text-falcon-red" />
                MITRE ATT&CK マトリクス（使用確認済み）
              </h3>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-xs text-falcon-muted">カバレッジ</p>
                  <p className="text-sm font-bold text-falcon-text">
                    {new Set(actor.ttps.map(t => t.tactic)).size}
                    <span className="text-falcon-muted font-normal"> / 14 タクティクス</span>
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-falcon-muted">テクニック数</p>
                  <p className="text-sm font-bold text-falcon-red">{actor.ttps.length}</p>
                </div>
              </div>
            </div>
            {/* Coverage progress bar */}
            <div className="mb-4">
              <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                <div
                  className="h-full bg-linear-to-r from-falcon-red to-[#ff6b6b] rounded-full transition-all"
                  style={{ width: `${(new Set(actor.ttps.map(t => t.tactic)).size / 14) * 100}%` }}
                />
              </div>
            </div>
            <MitreMatrix ttps={actor.ttps} />
          </div>

          {/* TTP Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-falcon-border">
              <h3 className="text-falcon-text font-semibold">テクニック詳細</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['ID', 'テクニック名', 'タクティック', '説明', '検知ノート'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {actor.ttps.map((ttp, i) => (
                    <tr key={ttp.technique_id} className={`border-b border-falcon-border hover:bg-falcon-card transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/30'}`}>
                      <td className="px-4 py-3 font-mono text-falcon-red font-semibold whitespace-nowrap">
                        {ttp.technique_id}
                      </td>
                      <td className="px-4 py-3 text-falcon-text whitespace-nowrap font-medium">
                        {ttp.technique_name}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded-sm text-[10px] bg-blue-500/15 text-blue-400 border border-blue-500/30">
                          {ttp.tactic}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs max-w-xs">{ttp.description}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs max-w-xs">{ttp.detection_notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: キャンペーン ──────────────────────────────────────────────── */}
      {activeTab === 'キャンペーン' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-falcon-muted text-sm">
              {actor.campaigns.length} 件のキャンペーン（{actor.campaigns.filter(c => c.status === 'active').length} アクティブ）
            </p>
          </div>
          {/* Timeline */}
          <div className="relative pl-6">
            <div className="absolute left-2.5 top-0 bottom-0 w-0.5 bg-falcon-border" />
            <div className="space-y-4">
              {actor.campaigns.map(campaign => (
                <div key={campaign.id} className="relative">
                  <div className={`absolute left-[-19px] top-5 w-3 h-3 rounded-full border-2 border-falcon-surface ${
                    campaign.status === 'active' ? 'bg-green-400' : 'bg-falcon-subtle'
                  }`} />
                  <CampaignCard campaign={campaign} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: 関連IOC ──────────────────────────────────────────────────── */}
      {activeTab === '関連IOC' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-muted" />
              <input
                value={iocSearch}
                onChange={e => { setIocSearch(e.target.value); setIocPage(1) }}
                placeholder="IOC値で検索..."
                className="w-full pl-10 pr-4 py-2 bg-falcon-surface border border-falcon-border rounded-lg text-sm text-falcon-text placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-muted/50"
              />
            </div>
            <div className="flex items-center gap-1.5">
              <Filter className="w-4 h-4 text-falcon-muted" />
              {['all', 'ip', 'domain', 'hash', 'url'].map(type => (
                <button
                  key={type}
                  onClick={() => { setIocTypeFilter(type); setIocPage(1) }}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                    iocTypeFilter === type
                      ? 'bg-falcon-red text-white'
                      : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:border-falcon-muted/40'
                  }`}
                >
                  {type === 'all' ? '全て' : type.toUpperCase()}
                </button>
              ))}
            </div>
            <span className="text-xs text-falcon-muted">{filteredIOCs.length} 件</span>
            <button
              onClick={() => {
                const headers = ['value', 'type', 'first_seen', 'last_seen', 'confidence']
                const rows = filteredIOCs.map(ioc => [ioc.value, ioc.type, ioc.first_seen, ioc.last_seen, String(ioc.confidence)])
                const csv = [headers, ...rows].map(r => r.map(v => `"${v.replace(/"/g, '""')}"`).join(',')).join('\n')
                const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `iocs-${actor.name.replace(/\s+/g, '-')}-${new Date().toISOString().slice(0, 10)}.csv`
                a.click()
                URL.revokeObjectURL(url)
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-falcon-text hover:border-falcon-muted/40 text-xs transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              CSV
            </button>
          </div>

          {/* IOC Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['値', 'タイプ', '初確認', '最終確認', '確信度', 'アクション'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {pagedIOCs.map((ioc, i) => (
                    <tr key={ioc.id} className={`border-b border-falcon-border hover:bg-falcon-card transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/30'}`}>
                      <td className="px-4 py-3 font-mono text-falcon-text text-xs max-w-xs truncate">
                        {ioc.value}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">{iocTypeBadge(ioc.type)}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                        {new Date(ioc.first_seen).toLocaleDateString('ja-JP')}
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                        {new Date(ioc.last_seen).toLocaleDateString('ja-JP')}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">{confidenceBadge(ioc.confidence)}</td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => copyToClipboard(ioc.value)}
                            className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors"
                            title="コピー"
                          >
                            {copied === ioc.value ? <CheckCircle className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                          <Link href="/ioc" className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors" title="IOC管理で表示">
                            <ExternalLink className="w-4 h-4" />
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          {totalIocPages > 1 && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-falcon-muted">
                {(iocPage - 1) * IOC_PAGE_SIZE + 1}–{Math.min(iocPage * IOC_PAGE_SIZE, filteredIOCs.length)} / {filteredIOCs.length} 件
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setIocPage(p => Math.max(1, p - 1))}
                  disabled={iocPage === 1}
                  className="px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted disabled:opacity-40 hover:border-falcon-muted/40 transition-colors"
                >
                  前へ
                </button>
                {Array.from({ length: totalIocPages }, (_, i) => i + 1).map(p => (
                  <button
                    key={p}
                    onClick={() => setIocPage(p)}
                    className={`w-8 h-8 rounded text-xs transition-colors ${
                      p === iocPage
                        ? 'bg-falcon-red text-white'
                        : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:border-falcon-muted/40'
                    }`}
                  >
                    {p}
                  </button>
                ))}
                <button
                  onClick={() => setIocPage(p => Math.min(totalIocPages, p + 1))}
                  disabled={iocPage === totalIocPages}
                  className="px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted disabled:opacity-40 hover:border-falcon-muted/40 transition-colors"
                >
                  次へ
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: レポート ──────────────────────────────────────────────────── */}
      {activeTab === 'レポート' && (
        <div className="space-y-4">
          {actor.reports.map(report => (
            <div key={report.id} className="bg-falcon-surface border border-falcon-border rounded-lg p-5 hover:border-falcon-muted/30 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <h4 className="text-falcon-text font-semibold mb-1">{report.title}</h4>
                  <div className="flex items-center gap-3 text-xs text-falcon-muted mb-3">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {new Date(report.date).toLocaleDateString('ja-JP')}
                    </span>
                    <span className="flex items-center gap-1">
                      <Shield className="w-3 h-3" />
                      {report.source}
                    </span>
                  </div>
                  <p className="text-falcon-muted text-sm leading-relaxed">{report.summary}</p>
                </div>
                <a
                  href={report.pdf_url}
                  className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-red/15 border border-falcon-red/30 text-[#f87171] hover:bg-falcon-red/25 transition-colors text-sm font-medium"
                >
                  <Download className="w-4 h-4" />
                  PDF
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
