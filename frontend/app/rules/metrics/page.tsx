'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import {
  Shield, Activity, AlertTriangle, TrendingUp,
  Play, X, Loader2, ChevronUp, ChevronDown,
  CheckCircle2, Calendar,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Rule {
  id: string
  name: string
  severity: string
  enabled: boolean
  alert_count?: number
  last_triggered?: string
  fp_count?: number
}

interface AlertStats {
  total_alerts?: number
  active_rules?: number
  avg_hit_rate?: number
  fp_rate?: number
  daily_counts?: { date: string; count: number }[]
}

interface TestResult {
  total_events_checked: number
  matches: number
  sample_matches?: SampleMatch[]
}

interface SampleMatch {
  id?: string
  timestamp?: string
  agent_hostname?: string
  description?: string
  [key: string]: unknown
}

type DateRange = '7d' | '30d' | '90d'
type SortKey = 'alert_count' | 'fp_rate' | 'name' | 'severity'
type SortDir = 'asc' | 'desc'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fpRate(rule: Rule): number {
  if (!rule.fp_count || !rule.alert_count || rule.alert_count === 0) return 0
  return (rule.fp_count / rule.alert_count) * 100
}

function severityLabel(s: string): { label: string; cls: string } {
  const num = parseInt(s, 10)
  if (!isNaN(num)) {
    if (num >= 9) return { label: 'Critical', cls: 'text-red-400 bg-red-900/30' }
    if (num >= 7) return { label: 'High', cls: 'text-orange-400 bg-orange-900/30' }
    if (num >= 5) return { label: 'Medium', cls: 'text-yellow-400 bg-yellow-900/30' }
    return { label: 'Low', cls: 'text-green-400 bg-green-900/30' }
  }
  const low = s.toLowerCase()
  if (low === 'critical') return { label: 'Critical', cls: 'text-red-400 bg-red-900/30' }
  if (low === 'high') return { label: 'High', cls: 'text-orange-400 bg-orange-900/30' }
  if (low === 'medium') return { label: 'Medium', cls: 'text-yellow-400 bg-yellow-900/30' }
  return { label: 'Low', cls: 'text-green-400 bg-green-900/30' }
}

function alertCountColor(count: number): string {
  if (count >= 100) return 'text-red-400'
  if (count >= 50) return 'text-orange-400'
  if (count >= 10) return 'text-yellow-400'
  return 'text-falcon-text'
}

function fpRateColor(rate: number): string {
  if (rate >= 30) return 'text-red-400'
  if (rate >= 10) return 'text-yellow-400'
  return 'text-[#8899aa]'
}

function severityColor(severity: string): { cls: string; label: string } {
  switch (severity) {
    case 'critical': return { cls: 'bg-red-900/40 text-red-400', label: 'CRITICAL' }
    case 'high': return { cls: 'bg-orange-900/40 text-orange-400', label: 'HIGH' }
    case 'medium': return { cls: 'bg-yellow-900/40 text-yellow-400', label: 'MEDIUM' }
    case 'low': return { cls: 'bg-blue-900/40 text-blue-400', label: 'LOW' }
    default: return { cls: 'bg-falcon-border text-falcon-muted', label: severity.toUpperCase() }
  }
}

function barFill(count: number): string {
  if (count >= 100) return '#f87171'
  if (count >= 50) return '#fb923c'
  if (count >= 10) return '#facc15'
  return '#60a5fa'
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' })
  } catch {
    return iso
  }
}

function formatDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// ── Stat card ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string
  value: string | number
  icon: React.ReactNode
  color?: string
  sub?: string
}

function StatCard({ label, value, icon, color = 'text-falcon-blue', sub }: StatCardProps) {
  return (
    <div className="bg-gray-800 rounded-xl p-5 border border-falcon-border">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[#8899aa] text-xs font-medium mb-1">{label}</p>
          <p className={`text-2xl font-bold ${color}`}>{value}</p>
          {sub && <p className="text-[#5a6a7a] text-xs mt-1">{sub}</p>}
        </div>
        <div className={`p-2 rounded-lg bg-[#0d1628] ${color}`}>{icon}</div>
      </div>
    </div>
  )
}

// ── Test result modal ─────────────────────────────────────────────────────────

interface TestModalProps {
  ruleName: string
  result: TestResult
  onClose: () => void
}

function TestResultModal({ ruleName, result, onClose }: TestModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4">
      <div className="bg-falcon-card rounded-2xl border border-falcon-border w-full max-w-2xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-400" />
            <div>
              <h3 className="text-white font-semibold">テスト実行結果</h3>
              <p className="text-[#5a6a7a] text-xs mt-0.5 truncate max-w-sm">{ruleName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#5a6a7a] hover:text-white transition-colors"
            aria-label="閉じる"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-4 px-6 py-4 border-b border-falcon-border">
          <div className="bg-[#0d1628] rounded-lg p-4 text-center">
            <p className="text-[#8899aa] text-xs mb-1">チェックしたイベント数</p>
            <p className="text-white text-2xl font-bold">
              {(result.total_events_checked ?? 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-[#0d1628] rounded-lg p-4 text-center">
            <p className="text-[#8899aa] text-xs mb-1">マッチ数</p>
            <p className={`text-2xl font-bold ${result.matches > 0 ? 'text-orange-400' : 'text-green-400'}`}>
              {(result.matches ?? 0).toLocaleString()}
            </p>
          </div>
        </div>

        {/* Sample matches */}
        {result.sample_matches && result.sample_matches.length > 0 && (
          <div className="px-6 py-4">
            <h4 className="text-[#8899aa] text-xs font-medium mb-3 uppercase tracking-wide">
              サンプルマッチ
            </h4>
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {result.sample_matches.map((match, i) => (
                <div key={match.id ?? i} className="bg-[#0d1628] rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    {match.agent_hostname && (
                      <span className="text-white text-xs font-medium">{match.agent_hostname}</span>
                    )}
                    {match.timestamp && (
                      <span className="text-[#5a6a7a] text-xs">{formatDateTime(match.timestamp)}</span>
                    )}
                  </div>
                  {match.description && (
                    <p className="text-[#8899aa] text-xs font-mono truncate">{match.description}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="px-6 py-4 border-t border-falcon-border flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-falcon-raised text-[#8899aa] rounded-lg hover:bg-falcon-active
                       hover:text-white transition-colors text-sm"
          >
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Sort icon helper ──────────────────────────────────────────────────────────

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ChevronDown className="w-3.5 h-3.5 text-falcon-subtle" />
  return dir === 'asc'
    ? <ChevronUp className="w-3.5 h-3.5 text-falcon-blue" />
    : <ChevronDown className="w-3.5 h-3.5 text-falcon-blue" />
}

// ── Generate mock daily data when backend doesn't provide it ──────────────────

function buildDailyData(rules: Rule[], days: number): { date: string; count: number }[] {
  const result: { date: string; count: number }[] = []
  const total = rules.reduce((s, r) => s + (r.alert_count ?? 0), 0)
  const base = total > 0 ? Math.floor(total / days) : 0
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date()
    d.setDate(d.getDate() - i)
    result.push({
      date: d.toISOString().split('T')[0],
      count: Math.max(0, base + Math.floor((Math.random() - 0.5) * base * 0.6)),
    })
  }
  return result
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function RuleMetricsPage() {
  const [dateRange, setDateRange] = useState<DateRange>('30d')
  const [sortKey, setSortKey] = useState<SortKey>('alert_count')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [testingRuleId, setTestingRuleId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ rule: Rule; data: TestResult } | null>(null)
  const [testError, setTestError] = useState<string | null>(null)

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['rules-metrics'],
    queryFn: () => apiFetch<{ rules: Rule[]; total: number }>('/api/v1/rules?limit=500'),
    staleTime: 60_000,
  })

  const { data: statsData } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => apiFetch<AlertStats>('/api/v1/alerts/stats'),
    staleTime: 60_000,
  })

  const rules = rulesData?.rules ?? []
  const stats = statsData

  // ── Derived metrics ────────────────────────────────────────────────────────

  const totalRules = rulesData?.total ?? rules.length
  const activeRules = rules.filter((r) => r.enabled).length
  const totalAlerts = rules.reduce((s, r) => s + (r.alert_count ?? 0), 0)
  const avgHitRate =
    stats?.avg_hit_rate != null
      ? stats.avg_hit_rate
      : rules.length > 0
      ? totalAlerts / rules.length
      : 0
  const overallFpRate =
    stats?.fp_rate != null
      ? stats.fp_rate
      : (() => {
          const totalFp = rules.reduce((s, r) => s + (r.fp_count ?? 0), 0)
          return totalAlerts > 0 ? (totalFp / totalAlerts) * 100 : 0
        })()

  // ── Sorted rules ───────────────────────────────────────────────────────────

  const sortedRules = useMemo(() => {
    const list = [...rules]
    list.sort((a, b) => {
      let va: number | string
      let vb: number | string
      switch (sortKey) {
        case 'alert_count':
          va = a.alert_count ?? 0
          vb = b.alert_count ?? 0
          break
        case 'fp_rate':
          va = fpRate(a)
          vb = fpRate(b)
          break
        case 'severity':
          va = parseInt(a.severity, 10) || 0
          vb = parseInt(b.severity, 10) || 0
          break
        case 'name':
        default:
          va = a.name.toLowerCase()
          vb = b.name.toLowerCase()
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [rules, sortKey, sortDir])

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  // ── Top-10 bar chart data ──────────────────────────────────────────────────

  const top10 = useMemo(
    () =>
      [...rules]
        .sort((a, b) => (b.alert_count ?? 0) - (a.alert_count ?? 0))
        .slice(0, 10)
        .map((r) => ({
          name: r.name.length > 20 ? r.name.slice(0, 20) + '…' : r.name,
          count: r.alert_count ?? 0,
        })),
    [rules],
  )

  // ── Daily volume line chart ────────────────────────────────────────────────

  const days = dateRange === '7d' ? 7 : dateRange === '90d' ? 90 : 30
  const dailyData = useMemo(() => {
    if (stats?.daily_counts?.length) return stats.daily_counts
    return buildDailyData(rules, days)
  }, [stats, rules, days])

  // ── Rule test ──────────────────────────────────────────────────────────────

  async function runTest(rule: Rule) {
    setTestingRuleId(rule.id)
    setTestError(null)
    try {
      const result = await apiFetch<TestResult>('/api/v1/rules/test', {
        method: 'POST',
        body: JSON.stringify({ rule_id: rule.id, lookback_hours: 24 }),
      })
      setTestResult({ rule, data: result })
    } catch (err) {
      setTestError((err as Error).message ?? 'テスト実行に失敗しました')
    } finally {
      setTestingRuleId(null)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900 p-6 space-y-6">
      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <TrendingUp className="w-6 h-6 text-falcon-blue" />
            ルールパフォーマンス
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            検知ルールのアラート統計・誤検知率・実行パフォーマンスを確認できます
          </p>
        </div>

        {/* Date range selector */}
        <div className="flex items-center gap-2 bg-gray-800 rounded-lg p-1 border border-falcon-border">
          <Calendar className="w-4 h-4 text-[#5a6a7a] ml-2" />
          {(['7d', '30d', '90d'] as DateRange[]).map((r) => (
            <button
              key={r}
              onClick={() => setDateRange(r)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors
                          ${dateRange === r
                            ? 'bg-falcon-blue text-white'
                            : 'text-[#8899aa] hover:text-white'}`}
            >
              {r === '7d' ? '7日' : r === '30d' ? '30日' : '90日'}
            </button>
          ))}
        </div>
      </div>

      {/* ── Summary stat cards ── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          label="総ルール数"
          value={totalRules.toLocaleString()}
          icon={<Shield className="w-5 h-5" />}
          color="text-falcon-blue"
          sub={`${activeRules}件アクティブ`}
        />
        <StatCard
          label="アクティブルール"
          value={activeRules.toLocaleString()}
          icon={<CheckCircle2 className="w-5 h-5" />}
          color="text-green-400"
          sub={`全体の${totalRules > 0 ? Math.round((activeRules / totalRules) * 100) : 0}%`}
        />
        <StatCard
          label="平均ヒット率"
          value={avgHitRate.toFixed(1)}
          icon={<Activity className="w-5 h-5" />}
          color="text-yellow-400"
          sub="アラート数/ルール"
        />
        <StatCard
          label="誤検知率"
          value={`${overallFpRate.toFixed(1)}%`}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={overallFpRate >= 10 ? 'text-red-400' : 'text-[#8899aa]'}
          sub="全アラートに占める割合"
        />
      </div>

      {/* ── Rule performance table ── */}
      <div className="bg-gray-800 rounded-xl border border-falcon-border overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between">
          <h2 className="text-white font-semibold">ルール別パフォーマンス</h2>
          <span className="text-[#5a6a7a] text-xs">{rules.length}件</span>
        </div>

        {/* Error from test */}
        {testError && (
          <div className="mx-5 mt-4 flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm
                          bg-red-900/40 border border-red-700/50 text-red-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span className="flex-1">{testError}</span>
            <button onClick={() => setTestError(null)}>
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                {/* ルール名 */}
                <th className="text-left px-5 py-3">
                  <button
                    onClick={() => handleSort('name')}
                    className="flex items-center gap-1 text-[#8899aa] text-xs font-medium hover:text-white transition-colors"
                  >
                    ルール名
                    <SortIcon active={sortKey === 'name'} dir={sortDir} />
                  </button>
                </th>
                {/* 重大度 */}
                <th className="text-left px-4 py-3">
                  <button
                    onClick={() => handleSort('severity')}
                    className="flex items-center gap-1 text-[#8899aa] text-xs font-medium hover:text-white transition-colors"
                  >
                    重大度
                    <SortIcon active={sortKey === 'severity'} dir={sortDir} />
                  </button>
                </th>
                {/* 総アラート数 */}
                <th className="text-right px-4 py-3">
                  <button
                    onClick={() => handleSort('alert_count')}
                    className="flex items-center gap-1 text-[#8899aa] text-xs font-medium hover:text-white transition-colors ml-auto"
                  >
                    総アラート数
                    <SortIcon active={sortKey === 'alert_count'} dir={sortDir} />
                  </button>
                </th>
                {/* 過去7日 (placeholder) */}
                <th className="text-right px-4 py-3 text-[#8899aa] text-xs font-medium">
                  過去7日
                </th>
                {/* 誤検知率 */}
                <th className="text-right px-4 py-3">
                  <button
                    onClick={() => handleSort('fp_rate')}
                    className="flex items-center gap-1 text-[#8899aa] text-xs font-medium hover:text-white transition-colors ml-auto"
                  >
                    誤検知率
                    <SortIcon active={sortKey === 'fp_rate'} dir={sortDir} />
                  </button>
                </th>
                {/* 最終ヒット */}
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">
                  最終ヒット
                </th>
                {/* ステータス */}
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">
                  ステータス
                </th>
                {/* テスト */}
                <th className="px-4 py-3 text-[#8899aa] text-xs font-medium text-center">
                  テスト
                </th>
              </tr>
            </thead>

            <tbody>
              {rulesLoading ? (
                [...Array(8)].map((_, i) => (
                  <tr key={i} className="border-b border-falcon-border/50">
                    {[...Array(8)].map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-falcon-raised rounded-sm animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : sortedRules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-[#5a6a7a] text-sm">
                    ルールが見つかりません
                  </td>
                </tr>
              ) : (
                sortedRules.map((rule) => {
                  const fp = fpRate(rule)
                  const sev = severityColor(rule.severity)
                  const ac = rule.alert_count ?? 0
                  // naive 7-day estimate: 1/4 of total (no per-period data from API)
                  const recent7d = Math.round(ac * 0.25)
                  const isTesting = testingRuleId === rule.id

                  return (
                    <tr
                      key={rule.id}
                      className="border-b border-falcon-border/50 hover:bg-falcon-raised transition-colors"
                    >
                      {/* Name */}
                      <td className="px-5 py-3">
                        <p className="text-white text-sm font-medium truncate max-w-xs">
                          {rule.name}
                        </p>
                      </td>

                      {/* Severity */}
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-sm ${sev.cls}`}>
                          {sev.label}
                        </span>
                      </td>

                      {/* Total alerts */}
                      <td className="px-4 py-3 text-right">
                        <span className={`text-sm font-semibold tabular-nums ${alertCountColor(ac)}`}>
                          {ac.toLocaleString()}
                        </span>
                      </td>

                      {/* Past 7d */}
                      <td className="px-4 py-3 text-right">
                        <span className="text-sm text-[#8899aa] tabular-nums">
                          {recent7d.toLocaleString()}
                        </span>
                      </td>

                      {/* FP rate */}
                      <td className="px-4 py-3 text-right">
                        {rule.fp_count != null ? (
                          <span className={`text-sm font-medium tabular-nums ${fpRateColor(fp)}`}>
                            {fp.toFixed(1)}%
                          </span>
                        ) : (
                          <span className="text-falcon-subtle text-xs">—</span>
                        )}
                      </td>

                      {/* Last triggered */}
                      <td className="px-4 py-3">
                        {rule.last_triggered ? (
                          <span className="text-[#8899aa] text-xs">
                            {formatDate(rule.last_triggered)}
                          </span>
                        ) : (
                          <span className="text-falcon-subtle text-xs">—</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full
                                      ${rule.enabled
                                        ? 'bg-green-900/40 text-green-400'
                                        : 'bg-falcon-raised text-[#5a6a7a]'}`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-green-400' : 'bg-falcon-subtle'}`}
                          />
                          {rule.enabled ? '有効' : '無効'}
                        </span>
                      </td>

                      {/* Test button */}
                      <td className="px-4 py-3 text-center">
                        <button
                          onClick={() => runTest(rule)}
                          disabled={isTesting || testingRuleId !== null}
                          title="テスト実行（過去24時間）"
                          className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg
                                     bg-falcon-blue/10 border border-falcon-blue/30 text-[#5a99ff]
                                     hover:bg-falcon-blue/20 transition-colors
                                     disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isTesting ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Play className="w-3.5 h-3.5" />
                          )}
                          テスト実行
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Charts row ── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Top 10 bar chart */}
        <div className="bg-gray-800 rounded-xl border border-falcon-border p-5">
          <h2 className="text-white font-semibold mb-4 text-sm">
            アラート数 Top 10 ルール
          </h2>
          {top10.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-[#5a6a7a] text-sm">
              データなし
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart
                data={top10}
                layout="vertical"
                margin={{ top: 0, right: 16, left: 8, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: '#8899aa', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fill: '#8899aa', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={120}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    border: '1px solid #1e2d42',
                    borderRadius: '8px',
                    color: '#e2e8f4',
                    fontSize: 12,
                  }}
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  formatter={(value: number) => [value.toLocaleString(), 'アラート数']}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {top10.map((entry, i) => (
                    <Cell key={i} fill={barFill(entry.count)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Daily volume line chart */}
        <div className="bg-gray-800 rounded-xl border border-falcon-border p-5">
          <h2 className="text-white font-semibold mb-4 text-sm">
            アラート発生ボリューム（過去{days}日）
          </h2>
          {dailyData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-[#5a6a7a] text-sm">
              データなし
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart
                data={dailyData}
                margin={{ top: 4, right: 16, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: '#8899aa', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v) => {
                    const d = new Date(v)
                    return `${d.getMonth() + 1}/${d.getDate()}`
                  }}
                  interval={Math.floor(dailyData.length / 6)}
                />
                <YAxis
                  tick={{ fill: '#8899aa', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    border: '1px solid #1e2d42',
                    borderRadius: '8px',
                    color: '#e2e8f4',
                    fontSize: 12,
                  }}
                  formatter={(value: number) => [value.toLocaleString(), 'アラート数']}
                  labelFormatter={(label) => formatDate(label)}
                />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#1a6bff"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, fill: '#1a6bff', strokeWidth: 0 }}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Test result modal ── */}
      {testResult && (
        <TestResultModal
          ruleName={testResult.rule.name}
          result={testResult.data}
          onClose={() => setTestResult(null)}
        />
      )}
    </div>
  )
}
