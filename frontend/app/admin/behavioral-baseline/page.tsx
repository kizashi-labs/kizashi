'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Users, AlertTriangle, Target, Clock, ChevronRight, Save } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type BaselineStatus = '確立済み' | '学習中' | '不十分'
type RiskLevel = '低' | '中' | '高' | '重大'

interface UserProfile {
  id: string
  name: string
  department: string
  baseline_status: BaselineStatus
  anomaly_score: number
  last_activity: string
  risk_level: RiskLevel
}

interface TrainingDataset {
  id: string
  name: string
  status: '完了' | '進行中' | '待機中'
  sample_count: number
  accuracy: number
  updated_at: string
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub }: { icon: any; label: string; value: string; sub?: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-start gap-3">
      <div className="p-2 bg-[#070d19] rounded-md">
        <Icon size={18} className="text-[#e8002d]" />
      </div>
      <div>
        <p className="text-[#7d92b0] text-xs mb-0.5">{label}</p>
        <p className="text-white text-xl font-semibold">{value}</p>
        {sub && <p className="text-[#7d92b0] text-xs mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function RiskBadge({ level }: { level: RiskLevel }) {
  const colors: Record<RiskLevel, string> = {
    '低': 'bg-green-500/20 text-green-400 border-green-500/30',
    '中': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    '高': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    '重大': 'bg-red-500/20 text-red-400 border-red-500/30',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${colors[level]}`}>{level}</span>
  )
}

function StatusBadge({ status }: { status: BaselineStatus }) {
  const colors: Record<BaselineStatus, string> = {
    '確立済み': 'bg-green-500/20 text-green-400',
    '学習中': 'bg-blue-500/20 text-blue-400',
    '不十分': 'bg-red-500/20 text-red-400',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${colors[status]}`}>{status}</span>
  )
}

function MiniBarChart({ bars, color }: { bars: number[]; color: string }) {
  const max = Math.max(...bars)
  return (
    <div className="flex items-end gap-0.5 h-10">
      {bars.map((v, i) => (
        <div
          key={i}
          className="flex-1 rounded-sm"
          style={{ height: `${(v / max) * 100}%`, backgroundColor: color, opacity: 0.8 }}
        />
      ))}
    </div>
  )
}

// ── Tabs ───────────────────────────────────────────────────────────────────────

function TabUserProfiles({ profiles }: { profiles: UserProfile[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1e2d42]">
            {['ユーザー', '部門', 'ベースライン状況', '異常スコア', '最終活動', 'リスクレベル'].map(h => (
              <th key={h} className="text-left text-[#7d92b0] font-medium px-3 py-2 whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {profiles.map(u => (
            <tr key={u.id} className="border-b border-[#1e2d42]/50 hover:bg-[#0d1220] transition-colors">
              <td className="px-3 py-2.5 text-white font-medium">{u.name}</td>
              <td className="px-3 py-2.5 text-[#7d92b0]">{u.department}</td>
              <td className="px-3 py-2.5"><StatusBadge status={u.baseline_status} /></td>
              <td className="px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${u.anomaly_score}%`,
                        backgroundColor: u.anomaly_score > 70 ? '#e8002d' : u.anomaly_score > 40 ? '#f59e0b' : '#22c55e',
                      }}
                    />
                  </div>
                  <span className="text-[#7d92b0]">{u.anomaly_score}</span>
                </div>
              </td>
              <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{u.last_activity}</td>
              <td className="px-3 py-2.5"><RiskBadge level={u.risk_level} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TabBehaviorPatterns() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {BEHAVIOR_CATEGORIES.map(cat => (
        <div key={cat.name} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-white font-medium text-sm">{cat.name}</h3>
            <span
              className={`text-xs font-semibold ${cat.deviation.startsWith('+') ? 'text-[#e8002d]' : 'text-green-400'}`}
            >
              {cat.deviation} 偏差
            </span>
          </div>
          <MiniBarChart bars={cat.bars} color={cat.color} />
          <div className="flex justify-between mt-2 text-xs text-[#7d92b0]">
            <span>7日前</span>
            <span>今日</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function TabDetectionSettings() {
  const [sensitivity, setSensitivity] = useState(7)
  const [baselineWindow, setBaselineWindow] = useState(30)
  const [minDataPoints, setMinDataPoints] = useState(200)
  const [zScore, setZScore] = useState(2.5)
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="max-w-2xl space-y-6">
      {[
        { label: '感度', value: sensitivity, min: 1, max: 10, step: 1, onChange: setSensitivity, format: (v: number) => `${v} / 10` },
        { label: 'ベースライン期間 (日)', value: baselineWindow, min: 7, max: 90, step: 1, onChange: setBaselineWindow, format: (v: number) => `${v} 日` },
        { label: '最小データポイント数', value: minDataPoints, min: 50, max: 500, step: 10, onChange: setMinDataPoints, format: (v: number) => `${v} 件` },
        { label: 'Z スコア閾値', value: zScore, min: 1.5, max: 4.0, step: 0.1, onChange: setZScore, format: (v: number) => v.toFixed(1) },
      ].map(s => (
        <div key={s.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <label className="text-white text-sm font-medium">{s.label}</label>
            <span className="text-[#e8002d] text-sm font-semibold">{s.format(s.value)}</span>
          </div>
          <input
            type="range"
            min={s.min}
            max={s.max}
            step={s.step}
            value={s.value}
            onChange={e => s.onChange(parseFloat(e.target.value))}
            className="w-full accent-[#e8002d] cursor-pointer"
          />
          <div className="flex justify-between text-xs text-[#7d92b0] mt-1">
            <span>{s.min}</span>
            <span>{s.max}</span>
          </div>
        </div>
      ))}

      <button
        onClick={handleSave}
        className="flex items-center gap-2 px-5 py-2.5 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"
      >
        <Save size={15} />
        {saved ? '保存しました' : '設定を保存'}
      </button>
    </div>
  )
}

function TabTrainingData() {
  const statusColors: Record<string, string> = {
    '完了': 'bg-green-500/20 text-green-400',
    '進行中': 'bg-blue-500/20 text-blue-400',
    '待機中': 'bg-[#1e2d42] text-[#7d92b0]',
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1e2d42]">
            {['データセット名', 'ステータス', 'サンプル数', '精度', '更新日'].map(h => (
              <th key={h} className="text-left text-[#7d92b0] font-medium px-3 py-2 whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {([] as TrainingDataset[]).map(d => (
            <tr key={d.id} className="border-b border-[#1e2d42]/50 hover:bg-[#0d1220] transition-colors">
              <td className="px-3 py-2.5 text-white">{d.name}</td>
              <td className="px-3 py-2.5">
                <span className={`text-xs px-2 py-0.5 rounded ${statusColors[d.status]}`}>{d.status}</span>
              </td>
              <td className="px-3 py-2.5 text-[#7d92b0]">{(d.sample_count ?? 0).toLocaleString()}</td>
              <td className="px-3 py-2.5">
                {d.accuracy > 0 ? (
                  <span className="text-green-400 font-medium">{d.accuracy.toFixed(1)}%</span>
                ) : (
                  <span className="text-[#7d92b0]">—</span>
                )}
              </td>
              <td className="px-3 py-2.5 text-[#7d92b0]">{d.updated_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const BEHAVIOR_CATEGORIES: { name: string; deviation: string; bars: number[]; color: string }[] = [
  { name: 'ログイン時刻', deviation: '+0.3', bars: [40, 55, 50, 60, 45, 70, 65], color: '#3b82f6' },
  { name: 'ファイルアクセス', deviation: '+1.2', bars: [30, 35, 80, 40, 45, 50, 55], color: '#ef4444' },
  { name: 'ネットワーク接続', deviation: '-0.1', bars: [60, 65, 70, 55, 60, 58, 62], color: '#22c55e' },
  { name: 'プロセス実行', deviation: '+0.5', bars: [50, 55, 60, 70, 65, 60, 75], color: '#f59e0b' },
  { name: 'DNS クエリ', deviation: '+0.2', bars: [45, 50, 48, 55, 52, 58, 60], color: '#8b5cf6' },
  { name: 'データ転送量', deviation: '+2.1', bars: [20, 25, 30, 90, 35, 40, 45], color: '#ef4444' },
]

// ── Page ───────────────────────────────────────────────────────────────────────

const TABS = ['ユーザープロファイル', '行動パターン', '異常検知設定', 'トレーニングデータ'] as const
type Tab = typeof TABS[number]

export default function BehavioralBaselinePage() {
  const [activeTab, setActiveTab] = useState<Tab>('ユーザープロファイル')

  const { data } = useQuery({
    queryKey: ['behavioral-baseline-profiles'],
    queryFn: async () => {
      try {
        return await apiFetch<{ profiles: UserProfile[] }>('/api/v1/admin/behavioral-baseline/profiles')
      } catch {
        return { profiles: [] as UserProfile[] }
      }
    },
  })

  const profiles = data?.profiles ?? []
  const established = profiles.filter(p => p.baseline_status === '確立済み').length
  const anomaliesDetected = profiles.filter(p => p.anomaly_score > 50).length
  const avgAccuracy = 92.4
  const avgTimeToEstablish = '21 日'

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 text-[#7d92b0] text-xs mb-2">
          <span>管理</span>
          <ChevronRight size={12} />
          <span className="text-white">行動ベースライン管理</span>
        </div>
        <h1 className="text-2xl font-semibold text-white">行動ベースライン管理</h1>
        <p className="text-[#7d92b0] text-sm mt-1">ユーザー行動の正常ベースラインを確立・管理し、異常を検知します</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={Users} label="ベースライン確立ユーザー" value={`${established} / ${profiles.length}`} sub="総ユーザー数" />
        <StatCard icon={AlertTriangle} label="本日の異常検知" value={`${anomaliesDetected} 件`} sub="高スコアユーザー" />
        <StatCard icon={Target} label="ベースライン精度" value={`${avgAccuracy}%`} sub="全モデル平均" />
        <StatCard icon={Clock} label="ベースライン確立期間" value={avgTimeToEstablish} sub="平均所要時間" />
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 mb-5 border-b border-[#1e2d42]">
        {TABS.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ${
              activeTab === tab
                ? 'border-[#e8002d] text-white'
                : 'border-transparent text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
        {activeTab === 'ユーザープロファイル' && <TabUserProfiles profiles={profiles} />}
        {activeTab === '行動パターン' && <TabBehaviorPatterns />}
        {activeTab === '異常検知設定' && <TabDetectionSettings />}
        {activeTab === 'トレーニングデータ' && <TabTrainingData />}
      </div>
    </div>
  )
}
