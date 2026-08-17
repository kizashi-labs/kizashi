'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ShieldCheck, Play, Clock, CheckCircle, XCircle, AlertTriangle,
  ChevronDown, ChevronRight, Plus, ToggleLeft, ToggleRight, RefreshCw
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

type RemediationType = 'auto' | 'semi-auto' | 'manual'
type Framework = '全て' | 'CIS' | 'ISO27001' | 'NIST' | 'PCI-DSS'
type ExecStatus = 'pending' | 'approved' | 'running' | 'completed' | 'failed' | 'rejected'
type TabId = 'rules' | 'history' | 'dashboard'

interface RemediationRule {
  id: string
  name: string
  framework: Exclude<Framework, '全て'>
  controlId: string
  type: RemediationType
  autoApprove: boolean
  enabled: boolean
  execCount: number
  successRate: number
}

interface ExecHistory {
  id: string
  ruleName: string
  status: ExecStatus
  trigger: string
  startedAt: string
  completedAt: string | null
  result: string
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const TypeBadge = ({ type }: { type: RemediationType }) => {
  const cfg = {
    auto: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    'semi-auto': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    manual: 'bg-falcon-border text-falcon-muted border-falcon-border',
  }
  const label = { auto: '自動', 'semi-auto': 'セミ自動', manual: '手動' }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs border ${cfg[type]}`}>
      {label[type]}
    </span>
  )
}

const StatusBadge = ({ status }: { status: ExecStatus }) => {
  const cfg: Record<ExecStatus, string> = {
    pending: 'bg-falcon-border text-falcon-muted',
    approved: 'bg-blue-500/20 text-blue-400',
    running: 'bg-blue-500/20 text-blue-300 animate-pulse',
    completed: 'bg-emerald-500/20 text-emerald-400',
    failed: 'bg-red-500/20 text-red-400',
    rejected: 'bg-red-500/10 text-red-500 border border-red-500/30',
  }
  const label: Record<ExecStatus, string> = {
    pending: '承認待ち', approved: '承認済', running: '実行中',
    completed: '完了', failed: '失敗', rejected: '却下',
  }
  return <span className={`px-2 py-0.5 rounded-sm text-xs ${cfg[status]}`}>{label[status]}</span>
}

// ─── Tab 1: Rules ─────────────────────────────────────────────────────────────

function RulesTab({ rules, onToggle, onRun }: {
  rules: RemediationRule[]
  onToggle: (id: string) => void
  onRun: (id: string) => void
}) {
  const [framework, setFramework] = useState<Framework>('全て')
  const frameworks: Framework[] = ['全て', 'CIS', 'ISO27001', 'NIST', 'PCI-DSS']
  const filtered = framework === '全て' ? rules : rules.filter(r => r.framework === framework)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-2">
          {frameworks.map(fw => (
            <button
              key={fw}
              onClick={() => setFramework(fw)}
              className={`px-3 py-1.5 rounded text-sm transition-colors ${
                framework === fw
                  ? 'bg-falcon-red text-white'
                  : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-sm text-sm hover:bg-red-700 transition-colors">
          <Plus className="w-4 h-4" />
          新規ルール
        </button>
      </div>

      <div className="rounded-lg border border-falcon-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-falcon-border bg-[#070d19]">
              {['ルール名', 'フレームワーク', 'コントロールID', '修復タイプ', '自動承認', '有効', '実行数', '成功率', 'アクション'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-falcon-muted font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((rule, i) => (
              <tr
                key={rule.id}
                className={`border-b border-falcon-border hover:bg-falcon-surface/60 transition-colors ${
                  i % 2 === 0 ? 'bg-falcon-surface' : 'bg-[#070d19]'
                }`}
              >
                <td className="px-4 py-3 text-white font-medium">{rule.name}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded-sm text-xs bg-falcon-border text-falcon-muted">{rule.framework}</span>
                </td>
                <td className="px-4 py-3 text-falcon-muted font-mono text-xs">{rule.controlId}</td>
                <td className="px-4 py-3"><TypeBadge type={rule.type} /></td>
                <td className="px-4 py-3">
                  <span className={`text-xs ${rule.autoApprove ? 'text-emerald-400' : 'text-falcon-muted'}`}>
                    {rule.autoApprove ? '✓' : '—'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => onToggle(rule.id)} className="flex items-center">
                    {rule.enabled
                      ? <ToggleRight className="w-6 h-6 text-emerald-400" />
                      : <ToggleLeft className="w-6 h-6 text-falcon-muted" />
                    }
                  </button>
                </td>
                <td className="px-4 py-3 text-falcon-muted">{rule.execCount}</td>
                <td className="px-4 py-3">
                  <span className={rule.successRate >= 90 ? 'text-emerald-400' : 'text-amber-400'}>
                    {rule.successRate}%
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => onRun(rule.id)}
                    className="flex items-center gap-1 px-3 py-1 bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded-sm text-xs hover:bg-blue-600/30 transition-colors"
                  >
                    <Play className="w-3 h-3" /> 実行
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Tab 2: History ───────────────────────────────────────────────────────────

function HistoryTab({ history, onApprove, onReject }: {
  history: ExecHistory[]
  onApprove: (id: string) => void
  onReject: (id: string) => void
}) {
  const [filter, setFilter] = useState<ExecStatus | 'all'>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const statuses: (ExecStatus | 'all')[] = ['all', 'pending', 'running', 'completed', 'failed']
  const filtered = filter === 'all' ? history : history.filter(h => h.status === filter)

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {statuses.map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1.5 rounded text-sm transition-colors ${
              filter === s
                ? 'bg-falcon-red text-white'
                : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
            }`}
          >
            {s === 'all' ? '全て' : ({ pending: '承認待ち', running: '実行中', completed: '完了', failed: '失敗', approved: '承認済み', rejected: '却下' } as Record<string, string>)[s]}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-falcon-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-falcon-border bg-[#070d19]">
              {['', 'ルール名', 'ステータス', 'トリガー', '実行日時', '完了日時', '結果', 'アクション'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-falcon-muted font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((item, i) => (
              <>
                <tr
                  key={item.id}
                  className={`border-b border-falcon-border hover:bg-falcon-surface/60 transition-colors ${
                    i % 2 === 0 ? 'bg-falcon-surface' : 'bg-[#070d19]'
                  }`}
                >
                  <td className="px-4 py-3 w-8">
                    <button onClick={() => setExpanded(expanded === item.id ? null : item.id)}>
                      {expanded === item.id
                        ? <ChevronDown className="w-4 h-4 text-falcon-muted" />
                        : <ChevronRight className="w-4 h-4 text-falcon-muted" />
                      }
                    </button>
                  </td>
                  <td className="px-4 py-3 text-white font-medium">{item.ruleName}</td>
                  <td className="px-4 py-3"><StatusBadge status={item.status} /></td>
                  <td className="px-4 py-3 text-falcon-muted">{item.trigger}</td>
                  <td className="px-4 py-3 text-falcon-muted text-xs font-mono">{item.startedAt}</td>
                  <td className="px-4 py-3 text-falcon-muted text-xs font-mono">{item.completedAt ?? '—'}</td>
                  <td className="px-4 py-3 text-falcon-muted text-xs max-w-[200px] truncate">{item.result}</td>
                  <td className="px-4 py-3">
                    {item.status === 'pending' && (
                      <div className="flex gap-2">
                        <button
                          onClick={() => onApprove(item.id)}
                          className="flex items-center gap-1 px-2 py-1 bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 rounded-sm text-xs hover:bg-emerald-600/30 transition-colors"
                        >
                          <CheckCircle className="w-3 h-3" /> 承認
                        </button>
                        <button
                          onClick={() => onReject(item.id)}
                          className="flex items-center gap-1 px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded-sm text-xs hover:bg-red-500/20 transition-colors"
                        >
                          <XCircle className="w-3 h-3" /> 拒否
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
                {expanded === item.id && (
                  <tr key={`${item.id}-detail`} className="bg-[#070d19] border-b border-falcon-border">
                    <td colSpan={8} className="px-8 py-4">
                      <div className="p-3 rounded-lg bg-falcon-surface border border-falcon-border text-sm text-falcon-muted">
                        <p className="font-semibold text-white mb-1">実行詳細</p>
                        <p>{item.result}</p>
                        <p className="mt-1 text-xs">ID: {item.id} | トリガー: {item.trigger} | 開始: {item.startedAt}</p>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Tab 3: Dashboard ─────────────────────────────────────────────────────────

function DashboardTab() {
  const frameworks = [
    { name: 'CIS', pct: 89, color: 'bg-blue-500' },
    { name: 'ISO27001', pct: 92, color: 'bg-emerald-500' },
    { name: 'NIST', pct: 78, color: 'bg-amber-500' },
    { name: 'PCI-DSS', pct: 85, color: 'bg-purple-500' },
  ]
  const trend = [8, 12, 10, 15, 11, 14, 13]
  const days = ['月', '火', '水', '木', '金', '土', '日']
  const maxTrend = Math.max(...trend)

  const donut = [
    { label: '自動', pct: 42, color: 'bg-emerald-500' },
    { label: 'セミ自動', pct: 38, color: 'bg-blue-500' },
    { label: '手動', pct: 20, color: 'bg-falcon-muted' },
  ]

  return (
    <div className="space-y-6">
      {/* Improvement highlight */}
      <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
        <p className="text-lg font-semibold text-emerald-400">
          30日間のコンプライアンス改善率: <span className="text-2xl">+8%</span>
        </p>
        <p className="text-sm text-falcon-muted mt-1">修復ルールの自動実行により、全フレームワーク平均スコアが向上しました</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Framework compliance bars */}
        <div className="p-4 rounded-lg bg-falcon-surface border border-falcon-border">
          <h3 className="text-white font-semibold mb-4">フレームワーク別コンプライアンス</h3>
          <div className="space-y-3">
            {frameworks.map(fw => (
              <div key={fw.name}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-falcon-muted">{fw.name}</span>
                  <span className="text-white">{fw.pct}%</span>
                </div>
                <div className="h-2 rounded-full bg-falcon-border">
                  <div
                    className={`h-2 rounded-full ${fw.color} transition-all`}
                    style={{ width: `${fw.pct}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Rule type breakdown */}
        <div className="p-4 rounded-lg bg-falcon-surface border border-falcon-border">
          <h3 className="text-white font-semibold mb-4">修復タイプ分布</h3>
          <div className="space-y-3">
            {donut.map(d => (
              <div key={d.label} className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${d.color}`} />
                <span className="text-falcon-muted text-sm flex-1">{d.label}</span>
                <div className="w-32 h-2 rounded-full bg-falcon-border">
                  <div className={`h-2 rounded-full ${d.color}`} style={{ width: `${d.pct}%` }} />
                </div>
                <span className="text-white text-sm w-8 text-right">{d.pct}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 7-day trend chart */}
      <div className="p-4 rounded-lg bg-falcon-surface border border-falcon-border">
        <h3 className="text-white font-semibold mb-4">直近7日間 修復実行件数</h3>
        <div className="flex items-end gap-3 h-32">
          {trend.map((v, i) => (
            <div key={days[i]} className="flex-1 flex flex-col items-center gap-1">
              <span className="text-xs text-falcon-muted">{v}</span>
              <div
                className="w-full bg-falcon-red/70 rounded-t"
                style={{ height: `${(v / maxTrend) * 100}px` }}
              />
              <span className="text-xs text-falcon-muted">{days[i]}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ComplianceRemediationPage() {
  const [activeTab, setActiveTab] = useState<TabId>('rules')
  const [rules, setRules] = useState<RemediationRule[]>([])
  const [history, setHistory] = useState<ExecHistory[]>([])
  const queryClient = useQueryClient()

  useQuery({
    queryKey: ['compliance-remediation-rules'],
    queryFn: () => apiFetchList<RemediationRule>('/api/v1/compliance/remediation/rules').catch(() => []),
    onSuccess: (data: RemediationRule[]) => setRules(data),
  } as Parameters<typeof useQuery>[0])

  useQuery({
    queryKey: ['compliance-remediation-history'],
    queryFn: () => apiFetchList<ExecHistory>('/api/v1/compliance/remediation/history').catch(() => []),
    onSuccess: (data: ExecHistory[]) => setHistory(data),
  } as Parameters<typeof useQuery>[0])

  const stats = [
    { label: '修復ルール数', value: '24', icon: ShieldCheck, color: 'text-blue-400' },
    { label: '本日実行', value: '15', icon: Play, color: 'text-emerald-400' },
    { label: '成功率', value: '86.7%', icon: CheckCircle, color: 'text-emerald-400' },
    { label: '承認待ち', value: '3', icon: Clock, color: 'text-amber-400' },
    { label: '平均修復時間', value: '12.5分', icon: RefreshCw, color: 'text-falcon-muted' },
  ]

  const tabs: { id: TabId; label: string }[] = [
    { id: 'rules', label: '修復ルール' },
    { id: 'history', label: '実行履歴' },
    { id: 'dashboard', label: 'ダッシュボード' },
  ]

  const handleToggle = (id: string) =>
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))

  const handleRun = (id: string) => {
    const rule = rules.find(r => r.id === id)
    if (!rule) return
    const newExec: ExecHistory = {
      id: `h${Date.now()}`,
      ruleName: rule.name,
      status: rule.autoApprove ? 'running' : 'pending',
      trigger: '手動',
      startedAt: new Date().toLocaleString('ja-JP').replace(/\//g, '-').slice(0, 16),
      completedAt: null,
      result: rule.autoApprove ? '実行中...' : '承認待ち',
    }
    setHistory(prev => [newExec, ...prev])
    setActiveTab('history')
  }

  const handleApprove = (id: string) =>
    setHistory(prev => prev.map(h => h.id === id ? { ...h, status: 'approved' as ExecStatus } : h))

  const handleReject = (id: string) =>
    setHistory(prev => prev.map(h => h.id === id ? { ...h, status: 'rejected' as ExecStatus } : h))

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-falcon-red" />
          <div>
            <h1 className="text-2xl font-bold">コンプライアンス自動修復</h1>
            <p className="text-falcon-muted text-sm">フレームワーク違反の自動検出・修復管理</p>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4">
          {stats.map(s => (
            <div key={s.label} className="p-4 rounded-lg bg-falcon-surface border border-falcon-border">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-falcon-muted">{s.label}</span>
              </div>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="border-b border-falcon-border">
          <div className="flex gap-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-6 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  activeTab === tab.id
                    ? 'border-falcon-red text-white'
                    : 'border-transparent text-falcon-muted hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab content */}
        <div>
          {activeTab === 'rules' && (
            <RulesTab rules={rules} onToggle={handleToggle} onRun={handleRun} />
          )}
          {activeTab === 'history' && (
            <HistoryTab history={history} onApprove={handleApprove} onReject={handleReject} />
          )}
          {activeTab === 'dashboard' && <DashboardTab />}
        </div>
      </div>
    </div>
  )
}
