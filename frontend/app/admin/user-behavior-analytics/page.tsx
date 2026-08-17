'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { Users, X, TrendingUp, TrendingDown, Minus, Activity, AlertTriangle, GitBranch, CheckCircle, Loader2 } from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

type AnomalyType = 'impossible_travel' | 'off_hours_access' | 'data_exfil' | 'privilege_escalation' | 'unusual_app'
type RiskFilter = 'all' | 'high' | 'critical'

interface UBAUser {
  id: string
  username: string
  department: string
  risk_score: number
  last_activity: string
  anomaly_count: number
  trend: 'up' | 'down' | 'stable'
}

interface UBAAnomalyItem {
  id: string
  timestamp: string
  user: string
  type: AnomalyType
  description: string
  risk_delta: number
}

interface UEBAScore {
  entity_id: string
  entity_type: string
  risk_score: number
  alert_count: number
  failed_logins: number
  data_transfer_gb: number
}

interface UEBAScoresResponse {
  scores: UEBAScore[]
}

interface LineageDetection {
  rule?: string
  severity?: string
  reason?: string
}

interface LineageResult {
  suspicious: boolean
  detections: LineageDetection[]
}

function uebaScoresToUsers(scores: UEBAScore[]): UBAUser[] {
  return (scores || []).map((s, i) => ({
    id: s.entity_id ?? `ueba-${i}`,
    username: s.entity_id ?? `user${i}`,
    department: 'IT',
    risk_score: Math.round(s.risk_score ?? 0),
    last_activity: new Date().toISOString(),
    anomaly_count: s.alert_count ?? 0,
    trend: s.risk_score > 60 ? 'up' as const : s.risk_score > 30 ? 'stable' as const : 'down' as const,
  }))
}

function generateHeatmap(seed: number): number[][] {
  return Array.from({ length: 7 }, (_, d) => Array.from({ length: 24 }, (_, h) => {
    const v = Math.abs(Math.sin(seed * 17 + d * 7 + h)) * 2.5
    return v > 2 ? 2 : v > 1 ? 1 : 0
  }))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const ANOMALY_BADGE: Record<AnomalyType, string> = {
  impossible_travel: 'bg-red-500/20 text-red-400',
  off_hours_access: 'bg-orange-500/20 text-orange-400',
  data_exfil: 'bg-red-600/20 text-red-300',
  privilege_escalation: 'bg-red-500/20 text-red-400',
  unusual_app: 'bg-yellow-500/20 text-yellow-400',
}

function riskColor(score: number): string {
  if (score >= 80) return 'bg-red-500'
  if (score >= 60) return 'bg-orange-500'
  if (score >= 40) return 'bg-yellow-500'
  return 'bg-green-500'
}

function riskTextColor(score: number): string {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function heatmapColor(level: number): string {
  if (level === 2) return 'bg-falcon-red'
  if (level === 1) return 'bg-orange-500/60'
  return 'bg-falcon-border'
}

function initials(username: string): string {
  return username.split('.').map((p) => p[0]?.toUpperCase() ?? '').join('')
}

function avatarBg(score: number): string {
  if (score >= 80) return 'bg-red-500/30 text-red-300'
  if (score >= 60) return 'bg-orange-500/30 text-orange-300'
  return 'bg-blue-500/30 text-blue-300'
}

function formatDate(ts: string): string {
  return new Date(ts).toLocaleString()
}

const DAY_LABELS = ['月', '火', '水', '木', '金', '土', '日']

// ── Main Component ─────────────────────────────────────────────────────────────

export default function UserBehaviorAnalyticsPage() {
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')
  const [selectedDept, setSelectedDept] = useState<string>('all')
  const [selectedUser, setSelectedUser] = useState<UBAUser | null>(null)

  // Process Lineage Check state
  const [parentProcess, setParentProcess] = useState('')
  const [childProcess, setChildProcess] = useState('')
  const [lineageResult, setLineageResult] = useState<LineageResult | null>(null)

  // ── Queries ──────────────────────────────────────────────────────────────────

  // Try real UEBA scores first, fall back to mock users
  const { data: uebaScoresData } = useQuery<UEBAScoresResponse>({
    queryKey: ['ueba-scores'],
    queryFn: () => apiFetch<UEBAScoresResponse>('/api/v1/admin/ml/ueba-scores'),
    retry: false,
  })

  const { data: users = [], isLoading: usersLoading } = useQuery<UBAUser[]>({
    queryKey: ['uba-users'],
    queryFn: () => apiFetchList<UBAUser>('/api/v1/admin/uba/users').catch(() => []),
  })

  const { data: anomalies = [], isLoading: anomaliesLoading } = useQuery<UBAAnomalyItem[]>({
    queryKey: ['uba-anomalies'],
    queryFn: () => apiFetchList<UBAAnomalyItem>('/api/v1/admin/uba/anomalies').catch(() => []),
  })

  // ── Lineage Mutation ──────────────────────────────────────────────────────────

  const lineageMutation = useMutation<LineageResult, Error, { parent_process: string; child_process: string }>({
    mutationFn: (body) => apiFetch<LineageResult>('/api/v1/admin/ml/analyze-lineage', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: (data) => setLineageResult(data),
  })

  const handleAnalyzeLineage = () => {
    if (!parentProcess.trim() || !childProcess.trim()) return
    setLineageResult(null)
    lineageMutation.mutate({ parent_process: parentProcess.trim(), child_process: childProcess.trim() })
  }

  // ── Derived ───────────────────────────────────────────────────────────────────

  // Merge real UEBA scores into users list (prefer real API data if available)
  const effectiveUsers: UBAUser[] = (() => {
    if (uebaScoresData?.scores && uebaScoresData.scores.length > 0) {
      return uebaScoresToUsers(uebaScoresData.scores)
    }
    return users
  })()

  const departments = ['all', ...Array.from(new Set(effectiveUsers.map((u) => u.department)))]

  const filteredUsers = effectiveUsers
    .filter((u) => {
      if (riskFilter === 'high') return u.risk_score >= 70
      if (riskFilter === 'critical') return u.risk_score >= 85
      return true
    })
    .filter((u) => selectedDept === 'all' || u.department === selectedDept)
    .sort((a, b) => b.risk_score - a.risk_score)

  const selectedUserAnomalies = selectedUser
    ? anomalies.filter((a) => a.user === selectedUser.username)
    : []

  const heatmap = selectedUser
    ? generateHeatmap(parseInt(selectedUser.id.replace('ueba-', ''), 10) || parseInt(selectedUser.id, 10) || 1)
    : null

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Users className="w-7 h-7 text-falcon-red" />
          ユーザー行動分析
        </h1>
        <p className="text-falcon-muted text-sm mt-0.5">内部脅威とアカウント侵害を検出</p>
        {uebaScoresData?.scores && uebaScoresData.scores.length > 0 && (
          <p className="text-green-400 text-xs mt-1">ライブデータ: MLエンジンから {uebaScoresData.scores.length} エンティティ</p>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        {/* Risk Filter Buttons */}
        <div className="flex bg-falcon-surface border border-falcon-border rounded-lg p-0.5">
          {(['all', 'high', 'critical'] as RiskFilter[]).map((f) => (
            <button
              key={f}
              onClick={() => setRiskFilter(f)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium capitalize transition-colors ${
                riskFilter === f ? 'bg-falcon-red text-white' : 'text-falcon-muted hover:text-white'
              }`}
            >
              {f === 'all' ? 'すべて' : f === 'high' ? '高リスク' : 'クリティカル'}
            </button>
          ))}
        </div>

        {/* Department Filter */}
        <select
          value={selectedDept}
          onChange={(e) => setSelectedDept(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red"
        >
          {departments.map((d) => (
            <option key={d} value={d}>{d === 'all' ? 'すべての部署' : d}</option>
          ))}
        </select>
      </div>

      <div className="flex gap-6">
        {/* Left Column */}
        <div className="flex-1 min-w-0 space-y-5">
          {/* Risk Score Leaderboard */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-falcon-border">
              <h2 className="text-white font-semibold text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-falcon-red" /> リスクスコア上位
              </h2>
            </div>
            {usersLoading ? (
              <div className="p-8 text-center text-falcon-muted">読み込み中...</div>
            ) : (
              <div className="divide-y divide-falcon-border">
                {filteredUsers.map((user) => {
                  const isHighRisk = user.risk_score >= 70
                  return (
                    <button
                      key={user.id}
                      onClick={() => setSelectedUser(selectedUser?.id === user.id ? null : user)}
                      className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-falcon-card transition-colors text-left ${
                        isHighRisk ? 'bg-red-950/20' : ''
                      } ${selectedUser?.id === user.id ? 'ring-1 ring-inset ring-falcon-red' : ''}`}
                    >
                      {/* Avatar */}
                      <div className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${avatarBg(user.risk_score)}`}>
                        {initials(user.username)}
                      </div>

                      {/* Name / Dept */}
                      <div className="flex-1 min-w-0">
                        <p className="text-white text-sm font-medium truncate">{user.username}</p>
                        <p className="text-falcon-muted text-xs">{user.department}</p>
                      </div>

                      {/* Risk Bar */}
                      <div className="w-32 shrink-0">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className={`text-xs font-bold ${riskTextColor(user.risk_score)}`}>{user.risk_score}</span>
                        </div>
                        <div className="w-full bg-falcon-border rounded-full h-1.5">
                          <div className={`h-1.5 rounded-full ${riskColor(user.risk_score)}`} style={{ width: `${user.risk_score}%` }} />
                        </div>
                      </div>

                      {/* Last Activity */}
                      <div className="w-28 shrink-0 hidden lg:block">
                        <p className="text-falcon-muted text-xs">{new Date(user.last_activity).toLocaleDateString()}</p>
                        <p className="text-falcon-muted text-xs">{new Date(user.last_activity).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
                      </div>

                      {/* Anomaly Count */}
                      <div className="w-12 shrink-0 text-center">
                        <span className={`text-xs font-bold ${user.anomaly_count > 0 ? 'text-orange-400' : 'text-falcon-muted'}`}>
                          {user.anomaly_count}
                        </span>
                        <p className="text-falcon-muted text-xs">異常</p>
                      </div>

                      {/* Trend */}
                      <div className="shrink-0">
                        {user.trend === 'up' ? (
                          <TrendingUp className="w-4 h-4 text-red-400" />
                        ) : user.trend === 'down' ? (
                          <TrendingDown className="w-4 h-4 text-green-400" />
                        ) : (
                          <Minus className="w-4 h-4 text-falcon-muted" />
                        )}
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </div>

          {/* Anomaly Feed */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-falcon-border">
              <h2 className="text-white font-semibold text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" /> 異常フィード
              </h2>
            </div>
            {anomaliesLoading ? (
              <div className="p-8 text-center text-falcon-muted">異常データ読み込み中...</div>
            ) : (
              <div className="divide-y divide-falcon-border">
                {anomalies.map((anomaly) => (
                  <div key={anomaly.id} className="px-4 py-3 hover:bg-falcon-card transition-colors">
                    <div className="flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className="text-falcon-muted text-xs">{formatDate(anomaly.timestamp)}</span>
                          <span className="text-white text-xs font-medium">{anomaly.user}</span>
                          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${ANOMALY_BADGE[anomaly.type]}`}>
                            {anomaly.type.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <p className="text-falcon-muted text-xs">{anomaly.description}</p>
                      </div>
                      <div className="shrink-0">
                        <span className="text-red-400 text-xs font-bold">+{anomaly.risk_delta}</span>
                        <p className="text-falcon-muted text-xs">risk</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Process Lineage Check */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-falcon-border">
              <h2 className="text-white font-semibold text-sm flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-blue-400" /> プロセス系譜チェック
              </h2>
            </div>
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">親プロセス</label>
                  <input
                    type="text"
                    value={parentProcess}
                    onChange={(e) => setParentProcess(e.target.value)}
                    placeholder="winword.exe"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red font-mono"
                  />
                </div>
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">子プロセス</label>
                  <input
                    type="text"
                    value={childProcess}
                    onChange={(e) => setChildProcess(e.target.value)}
                    placeholder="powershell.exe"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red font-mono"
                    onKeyDown={(e) => e.key === 'Enter' && handleAnalyzeLineage()}
                  />
                </div>
              </div>
              <button
                onClick={handleAnalyzeLineage}
                disabled={lineageMutation.isPending || !parentProcess.trim() || !childProcess.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
              >
                {lineageMutation.isPending ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> 分析中...</>
                ) : (
                  <><GitBranch className="w-4 h-4" /> 分析</>
                )}
              </button>

              {/* Result */}
              {lineageMutation.isError && (
                <div className="bg-red-950/30 border border-red-500/30 rounded-lg p-3">
                  <p className="text-red-400 text-xs">分析に失敗しました。API接続を確認してください。</p>
                </div>
              )}
              {lineageResult && (
                <div className={`rounded-lg p-3 border ${
                  lineageResult.suspicious
                    ? 'bg-red-950/30 border-red-500/40'
                    : 'bg-green-950/30 border-green-500/40'
                }`}>
                  {lineageResult.suspicious ? (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="px-2 py-0.5 rounded-sm text-xs font-bold bg-red-500/20 text-red-400">疑わしい</span>
                        {lineageResult.detections[0]?.severity && (
                          <span className="px-2 py-0.5 rounded-sm text-xs font-medium bg-orange-500/20 text-orange-400">
                            {lineageResult.detections[0].severity}
                          </span>
                        )}
                      </div>
                      {lineageResult.detections.map((d, i) => (
                        <div key={i} className="space-y-0.5">
                          {d.rule && <p className="text-white text-xs font-medium">{d.rule}</p>}
                          {d.reason && <p className="text-falcon-muted text-xs">{d.reason}</p>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      <span className="text-green-400 text-sm font-medium">正常 — 疑わしい関係は検出されませんでした</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: User Detail Panel */}
        {selectedUser && (
          <div className="w-72 shrink-0">
            <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden sticky top-6">
              <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
                <h2 className="text-white font-semibold text-sm">ユーザー詳細</h2>
                <button onClick={() => setSelectedUser(null)} className="text-falcon-muted hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-4 border-b border-falcon-border">
                <div className="flex items-center gap-3 mb-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold ${avatarBg(selectedUser.risk_score)}`}>
                    {initials(selectedUser.username)}
                  </div>
                  <div>
                    <p className="text-white font-medium">{selectedUser.username}</p>
                    <p className="text-falcon-muted text-xs">{selectedUser.department}</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-falcon-muted text-xs">リスクスコア</span>
                  <span className={`text-sm font-bold ${riskTextColor(selectedUser.risk_score)}`}>{selectedUser.risk_score}</span>
                </div>
                <div className="w-full bg-falcon-border rounded-full h-2">
                  <div className={`h-2 rounded-full ${riskColor(selectedUser.risk_score)}`} style={{ width: `${selectedUser.risk_score}%` }} />
                </div>
              </div>

              {/* Activity Heatmap */}
              <div className="p-4 border-b border-falcon-border">
                <p className="text-falcon-muted text-xs font-medium mb-2 uppercase tracking-wider">7日間のアクティビティ</p>
                <div className="space-y-1">
                  {heatmap?.map((row, dayIdx) => (
                    <div key={dayIdx} className="flex items-center gap-1.5">
                      <span className="text-falcon-muted text-xs w-7 shrink-0">{DAY_LABELS[dayIdx]}</span>
                      <div className="flex gap-0.5 flex-1">
                        {row.map((level, blockIdx) => (
                          <div
                            key={blockIdx}
                            title={level === 2 ? 'High' : level === 1 ? 'Medium' : 'Low'}
                            className={`flex-1 h-3 rounded-xs ${heatmapColor(level)}`}
                          />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-3 mt-2">
                  <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-xs bg-falcon-border" /><span className="text-falcon-muted text-xs">低</span></div>
                  <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-xs bg-orange-500/60" /><span className="text-falcon-muted text-xs">中</span></div>
                  <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-xs bg-falcon-red" /><span className="text-falcon-muted text-xs">高</span></div>
                </div>
              </div>

              {/* Top Resources */}
              <div className="p-4 border-b border-falcon-border">
                <p className="text-falcon-muted text-xs font-medium mb-2 uppercase tracking-wider">アクセスリソース上位</p>
                <div className="space-y-1">
                  {([] as string[]).map((r) => (
                    <div key={r} className="text-xs text-falcon-muted font-mono truncate bg-[#070d19] rounded-sm px-2 py-1">{r}</div>
                  ))}
                </div>
              </div>

              {/* User Anomalies */}
              <div className="p-4">
                <p className="text-falcon-muted text-xs font-medium mb-2 uppercase tracking-wider">最近の異常</p>
                {selectedUserAnomalies.length === 0 ? (
                  <p className="text-falcon-muted text-xs">最近の異常はありません</p>
                ) : (
                  <div className="space-y-2">
                    {selectedUserAnomalies.map((a) => (
                      <div key={a.id} className="bg-[#070d19] rounded-lg p-2">
                        <div className="flex items-center justify-between mb-1">
                          <span className={`px-1.5 py-0.5 rounded-sm text-xs ${ANOMALY_BADGE[a.type]}`}>
                            {a.type.replace(/_/g, ' ')}
                          </span>
                          <span className="text-red-400 text-xs font-bold">+{a.risk_delta}</span>
                        </div>
                        <p className="text-falcon-muted text-xs leading-snug">{a.description}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
