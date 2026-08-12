'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Brain, Rss, AlertOctagon, GitBranch, Target,
  Crosshair, ScanSearch, ChevronRight,
  TrendingUp, ShieldAlert, Globe, Hash
} from 'lucide-react'

interface IOCStats {
  total: number
  by_type: Record<string, number>
  active: number
}

interface ThreatFeed {
  id: string
  name: string
  is_active: boolean
  last_synced_at?: string
  ioc_count: number
}

interface ThreatFeedResponse {
  data: ThreatFeed[]
}

interface Campaign {
  id: string
  name: string
  threat_actor?: string
  active: boolean
}

interface CampaignResponse {
  data: Campaign[]
  total: number
}

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType
  label: string
  value: string | number
  color: string
}) {
  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl px-4 py-3 flex items-center gap-3">
      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xl font-bold text-white">{value}</p>
        <p className="text-xs text-[#5a6a7a]">{label}</p>
      </div>
    </div>
  )
}

const HUB_CARDS = [
  {
    href: '/threat-intel',
    icon: Rss,
    title: '脅威フィード',
    description: '外部脅威インテリジェンスフィードの管理・同期',
    color: 'bg-blue-900/40 text-blue-400 border-blue-700/30',
    accent: 'hover:border-blue-600/50',
  },
  {
    href: '/ioc',
    icon: AlertOctagon,
    title: 'IOC管理',
    description: 'IP・ドメイン・ハッシュなどの侵害指標を管理',
    color: 'bg-red-900/40 text-red-400 border-red-700/30',
    accent: 'hover:border-red-600/50',
  },
  {
    href: '/campaigns',
    icon: GitBranch,
    title: '脅威キャンペーン',
    description: '攻撃キャンペーンとアクターのトラッキング',
    color: 'bg-orange-900/40 text-orange-400 border-orange-700/30',
    accent: 'hover:border-orange-600/50',
  },
  {
    href: '/mitre',
    icon: Target,
    title: 'MITRE ATT&CK',
    description: '検知済み戦術・手法のATT&CKマッピング',
    color: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/30',
    accent: 'hover:border-yellow-600/50',
  },
  {
    href: '/threat-hunting',
    icon: Crosshair,
    title: 'スレットハンティング',
    description: 'プロアクティブな脅威探索クエリ',
    color: 'bg-purple-900/40 text-purple-400 border-purple-700/30',
    accent: 'hover:border-purple-600/50',
  },
  {
    href: '/intel/vt',
    icon: ScanSearch,
    title: 'VirusTotal検索',
    description: 'ハッシュ・IP・ドメインをVTで即時照会',
    color: 'bg-cyan-900/40 text-cyan-400 border-cyan-700/30',
    accent: 'hover:border-cyan-600/50',
  },
]

export default function IntelHubPage() {
  const { data: iocStats } = useQuery<IOCStats>({
    queryKey: ['ioc-stats-hub'],
    queryFn: () => apiFetch('/api/v1/ioc/stats'),
    staleTime: 60000,
  })

  const { data: feedData } = useQuery<ThreatFeedResponse>({
    queryKey: ['threat-feeds-hub'],
    queryFn: () => apiFetch('/api/v1/threat-feeds'),
    staleTime: 60000,
  })

  const { data: campaignData } = useQuery<CampaignResponse>({
    queryKey: ['campaigns-hub'],
    queryFn: () => apiFetch('/api/v1/campaigns?per_page=5'),
    staleTime: 60000,
  })

  const activeFeeds = (feedData?.data ?? []).filter(f => f.is_active).length
  const totalFeeds  = (feedData?.data ?? []).length
  const activeCampaigns = (campaignData?.data ?? []).filter(c => c.active).length

  return (
    <div className="p-6 space-y-6 max-w-6xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Brain className="w-6 h-6 text-blue-400" />
          脅威インテリジェンスハブ
        </h1>
        <p className="text-[#8899aa] text-sm mt-1">
          脅威情報の収集・分析・管理
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard
          icon={AlertOctagon}
          label="IOC総数"
          value={(iocStats?.total ?? 0).toLocaleString()}
          color="bg-red-900/40 text-red-400"
        />
        <StatCard
          icon={ShieldAlert}
          label="有効IOC"
          value={(iocStats?.active ?? 0).toLocaleString()}
          color="bg-orange-900/40 text-orange-400"
        />
        <StatCard
          icon={Rss}
          label="アクティブフィード"
          value={totalFeeds ? `${activeFeeds} / ${totalFeeds}` : '—'}
          color="bg-blue-900/40 text-blue-400"
        />
        <StatCard
          icon={GitBranch}
          label="進行中キャンペーン"
          value={activeCampaigns}
          color="bg-purple-900/40 text-purple-400"
        />
      </div>

      {/* IOC Type breakdown */}
      {iocStats?.by_type && Object.keys(iocStats.by_type).length > 0 && (
        <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-xs font-medium text-[#8899aa] mb-3 uppercase tracking-wider">IOCタイプ内訳</p>
          <div className="flex flex-wrap gap-3">
            {Object.entries(iocStats.by_type).map(([type, count]) => (
              <div key={type} className="flex items-center gap-2">
                {type === 'ip' && <Globe className="w-3.5 h-3.5 text-blue-400" />}
                {type === 'domain' && <Globe className="w-3.5 h-3.5 text-purple-400" />}
                {(type === 'hash' || type === 'md5' || type === 'sha256') && <Hash className="w-3.5 h-3.5 text-orange-400" />}
                {!['ip', 'domain', 'hash', 'md5', 'sha256'].includes(type) && <TrendingUp className="w-3.5 h-3.5 text-[#5a6a7a]" />}
                <span className="text-xs text-[#8899aa]">{type}</span>
                <span className="text-xs font-semibold text-white">{count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Hub navigation cards */}
      <div>
        <p className="text-xs font-medium text-[#5a6a7a] uppercase tracking-wider mb-3">モジュール</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {HUB_CARDS.map(card => (
            <Link
              key={card.href}
              href={card.href}
              className={`bg-[#111827] border border-[#1e2d42] rounded-xl p-4 flex items-start gap-3
                          transition-all hover:bg-[#0f1c2e] ${card.accent} group`}
            >
              <div className={`w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0 ${card.color}`}>
                <card.icon className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="font-semibold text-white text-sm">{card.title}</p>
                  <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#8899aa] transition-colors flex-shrink-0" />
                </div>
                <p className="text-xs text-[#5a6a7a] mt-1 leading-relaxed">{card.description}</p>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Recent campaigns */}
      {(campaignData?.data ?? []).length > 0 && (
        <div className="bg-[#111827] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <p className="text-sm font-semibold text-white flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-orange-400" />
              最近の脅威キャンペーン
            </p>
            <Link href="/campaigns" className="text-xs text-[#5a6a7a] hover:text-white transition-colors">
              すべて表示 →
            </Link>
          </div>
          <div className="divide-y divide-[#1e2d42]">
            {campaignData!.data.slice(0, 5).map(c => (
              <div key={c.id} className="px-4 py-2.5 flex items-center gap-3 hover:bg-[#161f33] transition-colors">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${c.active ? 'bg-red-400 animate-pulse' : 'bg-[#3d5068]'}`} />
                <span className="text-sm text-white flex-1 truncate">{c.name}</span>
                {c.threat_actor && (
                  <span className="text-xs text-[#5a6a7a] truncate max-w-[120px]">{c.threat_actor}</span>
                )}
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  c.active
                    ? 'bg-red-900/40 text-red-300'
                    : 'bg-[#161f33] text-[#5a6a7a]'
                }`}>
                  {c.active ? '進行中' : '終了'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
