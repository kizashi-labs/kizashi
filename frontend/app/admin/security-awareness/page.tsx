'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BookOpen, Target, Trophy, Star, Clock, Shield,
  RefreshCw, Users, CheckCircle, AlertTriangle,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type Difficulty = 'beginner' | 'intermediate' | 'advanced'
type SimulationStatus = 'active' | 'completed' | 'scheduled' | 'draft'

interface Course {
  id: string
  title: string
  category: string
  duration_min: number
  difficulty: Difficulty
  passing_score: number
  mandatory: boolean
  enabled: boolean
}

interface PhishingSimulation {
  id: string
  name: string
  template: string
  targets: number
  sent: number
  opened: number
  clicked: number
  reported: number
  credentials_entered: number
  status: SimulationStatus
}

interface AwarenessStats {
  total_courses: number
  mandatory_courses: number
  total_enrollments: number
  completed: number
  completion_rate: number
  avg_score: number
}

interface LeaderboardEntry {
  rank: number
  username: string
  completed: number
  avg_score: number
  badges: string[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const difficultyBadge = (d: Difficulty) => {
  const map: Record<Difficulty, string> = {
    beginner:     'bg-green-900/40 text-green-300 border-green-700/50',
    intermediate: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    advanced:     'bg-red-900/40 text-red-300 border-red-700/50',
  }
  return map[d]
}

const categoryBadge = (c: string) => {
  const colors = [
    'bg-blue-900/40 text-blue-300 border-blue-700/50',
    'bg-purple-900/40 text-purple-300 border-purple-700/50',
    'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
    'bg-orange-900/40 text-orange-300 border-orange-700/50',
  ]
  const hash = c.split('').reduce((a, ch) => a + ch.charCodeAt(0), 0)
  return colors[hash % colors.length]
}

const simulationStatusBadge = (s: SimulationStatus) => {
  const map: Record<SimulationStatus, string> = {
    active:    'bg-green-900/40 text-green-300 border-green-700/50',
    completed: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
    scheduled: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    draft:     'bg-falcon-border text-falcon-muted border-falcon-border',
  }
  return map[s]
}

const pct = (num: number, denom: number) =>
  denom === 0 ? 0 : Math.round((num / denom) * 100)

const rankMedal = (rank: number) => {
  if (rank === 1) return 'text-yellow-400'
  if (rank === 2) return 'text-slate-300'
  if (rank === 3) return 'text-amber-600'
  return 'text-falcon-muted'
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SecurityAwarenessPage() {
  const [activeTab, setActiveTab] = useState<'courses' | 'simulations' | 'leaderboard'>('courses')

  const { data: stats, isLoading: statsLoading, refetch } = useQuery<AwarenessStats>({
    queryKey: ['security-awareness-stats'],
    queryFn: () => apiFetch('/api/v1/admin/security-awareness/stats'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: coursesData, isLoading: coursesLoading } = useQuery<{ courses: Course[] }>({
    queryKey: ['security-awareness-courses'],
    queryFn: () => apiFetch('/api/v1/admin/security-awareness/courses'),
    staleTime: 60_000,
    retry: false,
  })

  const { data: simulationsData, isLoading: simulationsLoading } = useQuery<{ simulations: PhishingSimulation[] }>({
    queryKey: ['security-awareness-simulations'],
    queryFn: () => apiFetch('/api/v1/admin/security-awareness/simulations'),
    staleTime: 30_000,
    retry: false,
  })

  const EMPTY_AWARENESS_STATS: AwarenessStats = { total_courses: 0, mandatory_courses: 0, total_enrollments: 0, completed: 0, completion_rate: 0, avg_score: 0 }
  const displayStats = stats ?? EMPTY_AWARENESS_STATS
  const displayCourses = coursesData?.courses ?? []
  const displaySimulations = simulationsData?.simulations ?? []

  const statCards = [
    { label: 'Total Courses', value: displayStats.total_courses, icon: BookOpen, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
    { label: 'Mandatory', value: displayStats.mandatory_courses, icon: Shield, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: 'Total Enrollments', value: displayStats.total_enrollments, icon: Users, color: 'text-purple-400', bg: 'bg-purple-900/20 border-purple-700/30' },
    { label: 'Completed', value: displayStats.completed, icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
    { label: 'Completion Rate', value: `${displayStats.completion_rate}%`, icon: Target, color: 'text-cyan-400', bg: 'bg-cyan-900/20 border-cyan-700/30' },
    { label: 'Avg Score', value: `${displayStats.avg_score}%`, icon: Star, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg">
                <BookOpen className="w-4 h-4 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Security Awareness Training</h1>
                <p className="text-falcon-muted text-sm">Training courses &amp; phishing simulations</p>
              </div>
            </div>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 px-3 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border hover:border-falcon-muted/40 rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-6 gap-4 mb-6">
          {statCards.map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg} bg-falcon-surface`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-falcon-muted leading-tight">{s.label}</span>
                <s.icon className={`w-4 h-4 shrink-0 ${s.color}`} />
              </div>
              <p className={`text-2xl font-bold ${s.color}`}>
                {statsLoading ? '—' : s.value}
              </p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-falcon-border">
          {([
            ['courses', 'Courses'],
            ['simulations', 'Phishing Simulations'],
            ['leaderboard', 'Leaderboard'],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px
                ${activeTab === key
                  ? 'border-falcon-red text-white'
                  : 'border-transparent text-falcon-muted hover:text-white'
                }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Courses Tab */}
        {activeTab === 'courses' && (
          <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['Title', 'Category', 'Duration', 'Difficulty', 'Passing Score', 'Mandatory', 'Enabled'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayCourses.map(c => (
                  <tr key={c.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                    <td className="px-4 py-3">
                      <span className="text-white font-medium">{c.title}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border ${categoryBadge(c.category)}`}>
                        {c.category}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 text-falcon-muted text-xs">
                        <Clock className="w-3.5 h-3.5" />
                        {c.duration_min} min
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${difficultyBadge(c.difficulty)}`}>
                        {c.difficulty}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-white text-xs font-mono">{c.passing_score}%</span>
                    </td>
                    <td className="px-4 py-3">
                      {c.mandatory ? (
                        <span className="text-yellow-400 text-base">⭐</span>
                      ) : (
                        <span className="text-falcon-subtle text-xs">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium
                        ${c.enabled
                          ? 'bg-green-900/30 text-green-400 border border-green-700/40'
                          : 'bg-falcon-border/60 text-falcon-muted border border-falcon-border'
                        }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${c.enabled ? 'bg-green-400' : 'bg-falcon-muted'}`} />
                        {c.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Phishing Simulations Tab */}
        {activeTab === 'simulations' && (
          <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['Name', 'Template', 'Targets', 'Sent', 'Opened %', 'Clicked %', 'Reported %', 'Creds Entered', 'Status'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displaySimulations.map(sim => {
                  const openedPct = pct(sim.opened, sim.sent)
                  const clickedPct = pct(sim.clicked, sim.sent)
                  const reportedPct = pct(sim.reported, sim.sent)
                  const highClick = clickedPct >= 20
                  return (
                    <tr key={sim.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-white font-medium">{sim.name}</span>
                      </td>
                      <td className="px-4 py-3 max-w-[160px]">
                        <span className="text-falcon-muted text-xs block truncate" title={sim.template}>
                          {sim.template}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-white text-xs">{sim.targets}</td>
                      <td className="px-4 py-3 text-white text-xs">{sim.sent}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold ${openedPct > 60 ? 'text-orange-400' : 'text-falcon-muted'}`}>
                          {sim.sent > 0 ? `${openedPct}%` : '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold ${highClick ? 'text-red-400' : 'text-falcon-muted'}`}>
                          {sim.sent > 0 ? `${clickedPct}%` : '—'}
                          {highClick && <AlertTriangle className="inline w-3 h-3 ml-1" />}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold ${reportedPct > 40 ? 'text-green-400' : 'text-falcon-muted'}`}>
                          {sim.sent > 0 ? `${reportedPct}%` : '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {sim.credentials_entered > 0 ? (
                          <span className="text-xs font-bold text-red-400 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            {sim.credentials_entered}
                          </span>
                        ) : (
                          <span className="text-xs text-falcon-muted">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${simulationStatusBadge(sim.status)}`}>
                          {sim.status}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Leaderboard Tab */}
        {activeTab === 'leaderboard' && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Trophy className="w-5 h-5 text-yellow-400" />
              <h2 className="text-white font-semibold">Top Performers</h2>
              <span className="text-falcon-muted text-sm ml-1">— Training Completion Leaderboard</span>
            </div>
            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Rank', 'Username', 'Courses Completed', 'Avg Score', 'Badges'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {([] as LeaderboardEntry[]).map(entry => (
                    <tr
                      key={entry.rank}
                      className={`border-b border-falcon-border/50 transition-colors
                        ${entry.rank <= 3
                          ? 'bg-yellow-950/10 hover:bg-yellow-950/20'
                          : 'hover:bg-[#131d31]/50'
                        }`}
                    >
                      <td className="px-4 py-3">
                        <span className={`text-lg font-bold ${rankMedal(entry.rank)}`}>
                          {entry.rank === 1 ? '🥇' : entry.rank === 2 ? '🥈' : entry.rank === 3 ? '🥉' : `#${entry.rank}`}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white font-medium">{entry.username}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-24 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                            <div
                              className="h-full bg-blue-500 rounded-full"
                              style={{ width: `${Math.min((entry.completed / 12) * 100, 100)}%` }}
                            />
                          </div>
                          <span className="text-white text-xs font-bold">{entry.completed}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${
                          entry.avg_score >= 90 ? 'text-green-400' :
                          entry.avg_score >= 80 ? 'text-yellow-400' :
                          'text-falcon-muted'
                        }`}>
                          {entry.avg_score}%
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-lg tracking-wide">
                          {entry.badges.length > 0 ? entry.badges.join(' ') : <span className="text-falcon-subtle text-xs">—</span>}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
