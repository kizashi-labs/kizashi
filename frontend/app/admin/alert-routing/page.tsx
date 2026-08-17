'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Plus, GripVertical, Pencil, Trash2, Settings, Send, ToggleLeft, ToggleRight, Bell } from 'lucide-react'

interface RoutingRule {
  id: string
  priority: number
  name: string
  condition: string
  destinations: string[]
  hit_count: number
  last_matched_at: string | null
  enabled: boolean
}

interface Destination {
  id: string
  name: string
  type: 'slack' | 'pagerduty' | 'jira' | 'servicenow' | 'email' | 'teams' | 'sms'
  enabled: boolean
  last_used_at: string | null
}

interface RoutingData {
  rules: RoutingRule[]
  destinations: Destination[]
}

const MOCK: RoutingData = {
  rules: [
    { id: '1', priority: 1, name: 'クリティカルマルウェア即時通知', condition: 'severity=critical AND type=malware', destinations: ['pagerduty', 'slack'], hit_count: 342, last_matched_at: '2026-03-18T09:14:00Z', enabled: true },
    { id: '2', priority: 2, name: 'ランサムウェア検知エスカレーション', condition: 'type=ransomware AND confidence>=80', destinations: ['pagerduty', 'jira', 'slack'], hit_count: 17, last_matched_at: '2026-03-17T22:03:00Z', enabled: true },
    { id: '3', priority: 3, name: '高重要度アラートチケット発行', condition: 'severity=high AND asset_criticality=high', destinations: ['jira', 'email'], hit_count: 581, last_matched_at: '2026-03-18T10:01:00Z', enabled: true },
    { id: '4', priority: 4, name: '深夜帯SMSアラート', condition: 'severity>=high AND hour>=22 OR hour<=6', destinations: ['sms', 'email'], hit_count: 94, last_matched_at: '2026-03-18T02:47:00Z', enabled: false },
  ],
  destinations: [
    { id: 'd1', name: '#soc-alerts', type: 'slack', enabled: true, last_used_at: '2026-03-18T10:12:00Z' },
    { id: 'd2', name: 'SOC PagerDuty', type: 'pagerduty', enabled: true, last_used_at: '2026-03-18T09:14:00Z' },
    { id: 'd3', name: 'Jira SIEM Project', type: 'jira', enabled: true, last_used_at: '2026-03-18T10:01:00Z' },
    { id: 'd4', name: 'ServiceNow ITSM', type: 'servicenow', enabled: true, last_used_at: '2026-03-17T18:30:00Z' },
    { id: 'd5', name: 'SOC Team Email', type: 'email', enabled: true, last_used_at: '2026-03-18T08:55:00Z' },
    { id: 'd6', name: 'MS Teams #incidents', type: 'teams', enabled: false, last_used_at: null },
  ],
}

const DEST_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  slack:       { bg: 'bg-purple-900/40', text: 'text-purple-300', label: 'Slack' },
  pagerduty:   { bg: 'bg-orange-900/40', text: 'text-orange-300', label: 'PagerDuty' },
  jira:        { bg: 'bg-blue-900/40',   text: 'text-blue-300',   label: 'Jira' },
  servicenow:  { bg: 'bg-green-900/40',  text: 'text-green-300',  label: 'ServiceNow' },
  email:       { bg: 'bg-gray-700/60',   text: 'text-gray-300',   label: 'Email' },
  teams:       { bg: 'bg-blue-900/40',   text: 'text-blue-300',   label: 'Teams' },
  sms:         { bg: 'bg-green-900/40',  text: 'text-green-300',  label: 'SMS' },
}

const DEST_ICONS: Record<string, string> = {
  slack: '💬', pagerduty: '🔔', jira: '🔷', servicenow: '🟩', email: '✉️', teams: '🟦', sms: '📱',
}

function fmtTime(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function DestBadge({ type }: { type: string }) {
  const s = DEST_STYLES[type] ?? DEST_STYLES.email
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

const STATS = [
  { label: 'ルール数', value: '12' },
  { label: '宛先数', value: '6' },
  { label: '本日ルーティング', value: '6,801' },
  { label: 'アクティブ宛先', value: '5' },
]

export default function AlertRoutingPage() {
  const [tab, setTab] = useState<'rules' | 'destinations'>('rules')
  const [showForm, setShowForm] = useState(false)

  const { data } = useQuery<RoutingData>({
    queryKey: ['alert-routing'],
    queryFn: () => apiFetch<RoutingData>('/api/v1/admin/alert-routing').catch(() => MOCK),
  })

  const d = data ?? MOCK

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">インテリジェントアラートルーティング</h1>
          <p className="text-falcon-muted text-sm mt-1">アラートを条件に基づき自動的に適切な宛先へルーティングします</p>
        </div>
        <button onClick={() => setShowForm(true)} className="flex items-center gap-2 bg-falcon-red hover:bg-[#c8001d] text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Plus size={16} /> {tab === 'rules' ? '新規ルール' : '新規宛先'}
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {STATS.map(s => (
          <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="text-2xl font-bold text-white">{s.value}</div>
            <div className="text-falcon-muted text-sm mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['rules', 'destinations'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`px-5 py-2 rounded-md text-sm font-medium transition-colors ${tab === t ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}>
            {t === 'rules' ? 'ルーティングルール' : '通知宛先'}
          </button>
        ))}
      </div>

      {/* Tab 1: Rules */}
      {tab === 'rules' && (
        <div className="space-y-3">
          <p className="text-falcon-muted text-xs flex items-center gap-1">
            <Bell size={12} /> ルールは優先度順に評価されます
          </p>
          {d.rules.map(rule => (
            <div key={rule.id} className={`bg-falcon-surface border rounded-xl p-4 flex items-center gap-4 ${rule.enabled ? 'border-falcon-border' : 'border-falcon-border opacity-60'}`}>
              <GripVertical size={18} className="text-falcon-muted cursor-grab shrink-0" />
              <div className="w-8 h-8 rounded-full bg-falcon-border flex items-center justify-center text-sm font-bold text-falcon-red shrink-0">{rule.priority}</div>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-white text-sm">{rule.name}</div>
                <div className="text-falcon-muted text-xs mt-0.5 font-mono">{rule.condition}</div>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {rule.destinations.map(dest => <DestBadge key={dest} type={dest} />)}
                </div>
              </div>
              <div className="text-right shrink-0 space-y-1">
                <div className="text-white text-sm font-semibold">{(rule.hit_count ?? 0).toLocaleString()} hits</div>
                <div className="text-falcon-muted text-xs">最終マッチ: {fmtTime(rule.last_matched_at)}</div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {rule.enabled
                  ? <ToggleRight size={22} className="text-green-400 cursor-pointer" />
                  : <ToggleLeft size={22} className="text-falcon-muted cursor-pointer" />}
                <button className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"><Pencil size={14} /></button>
                <button className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-red transition-colors"><Trash2 size={14} /></button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Destinations */}
      {tab === 'destinations' && (
        <div className="grid grid-cols-3 gap-4">
          {d.destinations.map(dest => {
            const s = DEST_STYLES[dest.type] ?? DEST_STYLES.email
            return (
              <div key={dest.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{DEST_ICONS[dest.type]}</span>
                    <div>
                      <div className="font-medium text-white text-sm">{dest.name}</div>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${s.bg} ${s.text}`}>{s.label}</span>
                    </div>
                  </div>
                  <button className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"><Settings size={14} /></button>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className={`flex items-center gap-1 ${dest.enabled ? 'text-green-400' : 'text-falcon-muted'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${dest.enabled ? 'bg-green-400' : 'bg-gray-500'}`} />
                    {dest.enabled ? 'アクティブ' : '無効'}
                  </span>
                  <span className="text-falcon-muted">最終: {fmtTime(dest.last_used_at)}</span>
                </div>
                <button className="w-full flex items-center justify-center gap-2 border border-falcon-border hover:border-falcon-red hover:text-falcon-red text-falcon-muted rounded-lg py-2 text-xs font-medium transition-colors">
                  <Send size={12} /> テスト送信
                </button>
              </div>
            )
          })}
        </div>
      )}

      {/* Routing Statistics */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-4">
        <h2 className="font-semibold text-white">今日のルーティングサマリー</h2>
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-3">
            {[
              { label: '#soc-alerts (Slack)', count: 2841, max: 3000 },
              { label: 'SOC PagerDuty', count: 1524, max: 3000 },
              { label: 'Jira SIEM Project', count: 1203, max: 3000 },
              { label: 'SOC Team Email', count: 891, max: 3000 },
              { label: 'ServiceNow ITSM', count: 342, max: 3000 },
            ].map(item => (
              <div key={item.label} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-falcon-muted">{item.label}</span>
                  <span className="text-white font-medium">{(item.count ?? 0).toLocaleString()}</span>
                </div>
                <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                  <div className="h-full bg-falcon-red rounded-full transition-all" style={{ width: `${(item.count / item.max) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: '総ルーティング数', value: '6,801', color: 'text-white' },
              { label: '正常送信', value: '6,749', color: 'text-green-400' },
              { label: 'リトライ', value: '38', color: 'text-yellow-400' },
              { label: '失敗', value: '14', color: 'text-falcon-red' },
            ].map(item => (
              <div key={item.label} className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
                <div className={`text-xl font-bold ${item.color}`}>{item.value}</div>
                <div className="text-falcon-muted text-xs mt-1">{item.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Simple Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 w-full max-w-md space-y-4">
            <h3 className="font-semibold text-white">{tab === 'rules' ? '新規ルーティングルール' : '新規通知宛先'}</h3>
            <div className="space-y-3">
              <input placeholder="名前" className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-muted focus:outline-hidden focus:border-falcon-red" />
              {tab === 'rules'
                ? <input placeholder="条件 (例: severity=critical AND type=malware)" className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-muted font-mono focus:outline-hidden focus:border-falcon-red" />
                : <select className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red">
                    {Object.keys(DEST_STYLES).map(t => <option key={t} value={t}>{DEST_STYLES[t].label}</option>)}
                  </select>
              }
            </div>
            <div className="flex gap-3 pt-2">
              <button className="flex-1 bg-falcon-red hover:bg-[#c8001d] text-white rounded-lg py-2 text-sm font-medium transition-colors">作成</button>
              <button onClick={() => setShowForm(false)} className="flex-1 border border-falcon-border hover:border-falcon-muted text-falcon-muted hover:text-white rounded-lg py-2 text-sm font-medium transition-colors">キャンセル</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
