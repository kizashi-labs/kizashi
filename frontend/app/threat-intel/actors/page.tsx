'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  Search, Filter, Shield, Globe, AlertTriangle, Eye,
  Calendar, ChevronRight, Users, Target, RefreshCw,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  origin_country: string
  origin_flag: string
  threat_level: 'critical' | 'high' | 'medium' | 'low'
  motivation: string[]
  target_industries: string[]
  first_seen: string
  last_seen: string
  campaign_count: number
  ioc_count: number
  description: string
}


const THREAT_LEVELS = ['all', 'critical', 'high', 'medium', 'low'] as const

const threatLevelBadge = (level: string) => {
  const configs: Record<string, { label: string; className: string }> = {
    critical: { label: 'クリティカル', className: 'bg-red-500/20 text-red-400 border-red-500/30' },
    high:     { label: '高',           className: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    medium:   { label: '中',           className: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
    low:      { label: '低',           className: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  }
  const cfg = configs[level] ?? configs.low
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${cfg.className}`}>
      {cfg.label}
    </span>
  )
}

const motivationBadge = (m: string) => {
  const configs: Record<string, string> = {
    financial:  'bg-green-500/15 text-green-400 border-green-500/30',
    espionage:  'bg-purple-500/15 text-purple-400 border-purple-500/30',
    disruption: 'bg-red-500/15 text-red-400 border-red-500/30',
  }
  const labels: Record<string, string> = {
    financial: '金融目的', espionage: 'スパイ', disruption: '妨害',
  }
  return (
    <span key={m} className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] border ${configs[m] ?? 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]'}`}>
      {labels[m] ?? m}
    </span>
  )
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function ThreatActorsPage() {
  const [search, setSearch] = useState('')
  const [levelFilter, setLevelFilter] = useState<string>('all')

  const { data, isLoading } = useQuery<ThreatActor[]>({
    queryKey: ['threat-actors'],
    queryFn: () => apiFetch('/api/v1/threat-intel/actors'),
    staleTime: 60_000,
    retry: false,
  })

  const allActors = data ?? []
  const actors = allActors.filter(a => {
    const matchSearch = !search ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.aliases.some(al => al.toLowerCase().includes(search.toLowerCase()))
    const matchLevel = levelFilter === 'all' || a.threat_level === levelFilter
    return matchSearch && matchLevel
  })

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-[#e2e8f4]">脅威アクター</h1>
        <p className="text-[#7d92b0] text-sm mt-1">
          追跡中の脅威グループ・APTアクター一覧
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '追跡中アクター', value: allActors.length, icon: Users, color: 'text-blue-400' },
          { label: 'クリティカル', value: allActors.filter(a => a.threat_level === 'critical').length, icon: AlertTriangle, color: 'text-red-400' },
          { label: '高脅威', value: allActors.filter(a => a.threat_level === 'high').length, icon: Shield, color: 'text-orange-400' },
          { label: '総IOC数', value: allActors.reduce((s, a) => s + a.ioc_count, 0).toLocaleString(), icon: Target, color: 'text-purple-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <stat.icon className={`w-8 h-8 ${stat.color}`} />
            <div>
              <p className="text-2xl font-bold text-[#e2e8f4]">{stat.value}</p>
              <p className="text-[#7d92b0] text-xs">{stat.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="アクター名またはエイリアスで検索..."
            className="w-full pl-10 pr-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[#7d92b0]" />
          <div className="flex gap-1">
            {THREAT_LEVELS.map(lv => (
              <button
                key={lv}
                onClick={() => setLevelFilter(lv)}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  levelFilter === lv
                    ? 'bg-[#e8002d] text-white'
                    : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
                }`}
              >
                {lv === 'all' ? '全て' : lv === 'critical' ? 'クリティカル' : lv === 'high' ? '高' : lv === 'medium' ? '中' : '低'}
              </button>
            ))}
          </div>
        </div>
        {isLoading && <RefreshCw className="w-4 h-4 text-[#7d92b0] animate-spin" />}
      </div>

      {/* Actor Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {actors.map(actor => (
          <Link
            key={actor.id}
            href={`/threat-intel/actors/${actor.id}`}
            className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 hover:border-[#7d92b0]/40 hover:bg-[#111827] transition-all group"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="text-[#e2e8f4] font-semibold text-base group-hover:text-white transition-colors">
                  {actor.name}
                </h3>
                <div className="flex items-center gap-1.5 mt-1">
                  <span className="text-lg">{actor.origin_flag}</span>
                  <span className="text-[#7d92b0] text-xs">{actor.origin_country}</span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1.5">
                {threatLevelBadge(actor.threat_level)}
                <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0] transition-colors" />
              </div>
            </div>

            <p className="text-[#7d92b0] text-xs line-clamp-2 mb-3">{actor.description}</p>

            <div className="flex flex-wrap gap-1 mb-3">
              {actor.motivation.map(m => motivationBadge(m))}
            </div>

            <div className="flex flex-wrap gap-1 mb-3">
              {actor.aliases.slice(0, 3).map(alias => (
                <span key={alias} className="px-1.5 py-0.5 rounded text-[10px] bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">
                  {alias}
                </span>
              ))}
              {actor.aliases.length > 3 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#1e2d42] text-[#7d92b0]">
                  +{actor.aliases.length - 3}
                </span>
              )}
            </div>

            <div className="border-t border-[#1e2d42] pt-3 flex items-center justify-between text-xs text-[#7d92b0]">
              <div className="flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                <span>最終確認: {new Date(actor.last_seen).toLocaleDateString('ja-JP')}</span>
              </div>
              <div className="flex items-center gap-3">
                <span>{actor.campaign_count} キャンペーン</span>
                <span>{(actor.ioc_count ?? 0).toLocaleString()} IOC</span>
              </div>
            </div>
          </Link>
        ))}
      </div>

      {actors.length === 0 && (
        <div className="text-center py-16 text-[#7d92b0]">
          <Globe className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>条件に一致するアクターが見つかりません</p>
        </div>
      )}
    </div>
  )
}
