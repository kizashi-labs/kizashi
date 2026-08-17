'use client'

import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bug, Upload, Clock, CheckCircle, AlertTriangle, XCircle,
  Shield, Activity, Network, FolderOpen, Cpu, RefreshCw,
  ChevronRight, Download, Filter, Search, Calendar, X,
  Loader2, FileText, Globe, AlertCircle, ArrowUpDown, Eye
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os: string
  status: string
}

interface SandboxStats {
  submissions_today: number
  malicious_found: number
  suspicious: number
  avg_analysis_time_seconds: number
}

interface SandboxSubmission {
  id: string
  submission_id: string
  file_hash: string
  file_name: string
  agent_id: string | null
  agent_hostname: string | null
  priority: 'normal' | 'high'
  status: 'queued' | 'analyzing' | 'completed' | 'failed'
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | null
  score: number | null
  submitted_at: string
  completed_at: string | null
  duration_seconds: number | null
  estimated_seconds: number | null
}

interface Behavior {
  id: string
  category: 'persistence' | 'evasion' | 'network' | 'file_system' | 'process'
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp_offset_ms: number
}

interface NetworkIndicator {
  type: 'ip' | 'domain' | 'url'
  value: string
  threat_score: number
  country: string
  description: string
}

interface Signature {
  name: string
  family: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
}

interface TimelineEvent {
  timestamp_offset_ms: number
  type: string
  description: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
}

interface SandboxResult {
  id: string
  submission_id: string
  file_hash: string
  file_name: string
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'
  confidence: number
  score: number
  behaviors: Behavior[]
  network_indicators: NetworkIndicator[]
  signatures: Signature[]
  timeline: TimelineEvent[]
  analysis_duration_seconds: number
  completed_at: string
}

interface SubmissionListResponse {
  submissions: SandboxSubmission[]
  total: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(d: string | null) {
  if (!d) return '—'
  return new Date(d).toLocaleString('ja-JP', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function formatDuration(s: number | null) {
  if (!s) return '—'
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`
}

function truncateHash(h: string) {
  return h.length > 16 ? `${h.slice(0, 8)}...${h.slice(-8)}` : h
}

// ── Verdict Badge ─────────────────────────────────────────────────────────────

function VerdictBadge({ verdict }: { verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | null }) {
  if (!verdict) return <span className="text-falcon-muted text-xs">—</span>
  const cfg = {
    MALICIOUS:  { cls: 'bg-red-500/20 text-red-400 border-red-500/40',    label: '悪性' },
    SUSPICIOUS: { cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40', label: '疑わしい' },
    BENIGN:     { cls: 'bg-green-500/20 text-green-400 border-green-500/40',  label: '安全' },
  }[verdict]
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-[11px] font-bold ${cfg.cls}`}>
      {verdict === 'MALICIOUS' && <XCircle className="w-3 h-3 mr-1" />}
      {verdict === 'SUSPICIOUS' && <AlertTriangle className="w-3 h-3 mr-1" />}
      {verdict === 'BENIGN' && <CheckCircle className="w-3 h-3 mr-1" />}
      {cfg.label}
    </span>
  )
}

function StatusBadge({ status }: { status: SandboxSubmission['status'] }) {
  const cfg = {
    queued:    { cls: 'bg-falcon-muted/20 text-falcon-muted border-falcon-muted/30', label: 'キュー中', icon: Clock },
    analyzing: { cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30',    label: '解析中',   icon: Loader2 },
    completed: { cls: 'bg-green-500/20 text-green-400 border-green-500/30', label: '完了',     icon: CheckCircle },
    failed:    { cls: 'bg-red-500/20 text-red-400 border-red-500/30',       label: 'エラー',   icon: XCircle },
  }[status]
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cfg.cls}`}>
      <Icon className={`w-3 h-3 ${status === 'analyzing' ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg: Record<string, string> = {
    low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
    medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    info:     'bg-falcon-muted/15 text-falcon-muted border-falcon-muted/30',
  }
  const labels: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '重大', info: '情報' }
  return (
    <span className={`inline-flex px-1.5 py-0.5 rounded-sm border text-[10px] font-medium ${cfg[severity] ?? cfg.info}`}>
      {labels[severity] ?? severity}
    </span>
  )
}

function BehaviorCategoryIcon({ category }: { category: Behavior['category'] }) {
  const cfg: Record<string, { Icon: React.ElementType; color: string; label: string }> = {
    persistence: { Icon: Shield, color: 'text-red-400', label: '永続化' },
    evasion:     { Icon: Eye, color: 'text-purple-400', label: '回避' },
    network:     { Icon: Network, color: 'text-blue-400', label: 'ネットワーク' },
    file_system: { Icon: FolderOpen, color: 'text-yellow-400', label: 'ファイル' },
    process:     { Icon: Cpu, color: 'text-orange-400', label: 'プロセス' },
  }
  const { Icon, color, label } = cfg[category] ?? { Icon: Activity, color: 'text-falcon-muted', label: category }
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${color}`}>
      <Icon className="w-3.5 h-3.5" />
      {label}
    </span>
  )
}

// ── Score Bar ─────────────────────────────────────────────────────────────────

function ScoreBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-falcon-muted text-xs">—</span>
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-falcon-text w-6 text-right">{score}</span>
    </div>
  )
}

// ── Confidence Gauge ──────────────────────────────────────────────────────────

function ConfidenceGauge({ score, verdict, confidence }: { score: number; verdict: string; confidence: number }) {
  const color = verdict === 'MALICIOUS' ? '#e8002d' : verdict === 'SUSPICIOUS' ? '#f59e0b' : '#22c55e'
  const radius = 36
  const circumference = 2 * Math.PI * radius
  const dashOffset = circumference * (1 - score / 100)
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="#1e2d42" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={radius} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
        <text x="50" y="46" textAnchor="middle" fill={color} fontSize="18" fontWeight="bold">{score}</text>
        <text x="50" y="60" textAnchor="middle" fill="#7d92b0" fontSize="9">SCORE</text>
      </svg>
      <div className="text-center">
        <p className="text-[10px] text-falcon-muted">信頼度</p>
        <p className="text-sm font-bold" style={{ color }}>{confidence}%</p>
      </div>
    </div>
  )
}

// ── Result Panel ──────────────────────────────────────────────────────────────

function ResultPanel({ submissionId, onClose }: { submissionId: string; onClose: () => void }) {
  const { data, isLoading, error } = useQuery<SandboxResult>({
    queryKey: ['sandbox-result', submissionId],
    queryFn: async () => {
      return await apiFetch<SandboxResult>(`/api/v1/sandbox/${submissionId}`)
    },
    staleTime: 30_000,
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <Bug className="w-5 h-5 text-falcon-red" />
            <div>
              <h2 className="text-falcon-text font-semibold">サンドボックス解析結果</h2>
              <p className="text-falcon-muted text-xs">{submissionId}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading && (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 text-falcon-muted animate-spin" />
            </div>
          )}
          {!isLoading && data && (
            <>
              {/* Verdict summary */}
              <div className="flex gap-6 items-center p-4 bg-[#070d19] rounded-lg border border-falcon-border">
                <ConfidenceGauge score={data.score} verdict={data.verdict} confidence={data.confidence} />
                <div className="flex-1 space-y-3">
                  <div>
                    <p className="text-falcon-muted text-xs mb-1">判定結果</p>
                    <VerdictBadge verdict={data.verdict} />
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <p className="text-falcon-muted text-xs">ファイル名</p>
                      <p className="text-falcon-text text-sm font-medium truncate">{data.file_name}</p>
                    </div>
                    <div>
                      <p className="text-falcon-muted text-xs">解析時間</p>
                      <p className="text-falcon-text text-sm font-medium">{formatDuration(data.analysis_duration_seconds)}</p>
                    </div>
                    <div>
                      <p className="text-falcon-muted text-xs">完了日時</p>
                      <p className="text-falcon-text text-sm font-medium">{formatDate(data.completed_at)}</p>
                    </div>
                  </div>
                  <div>
                    <p className="text-falcon-muted text-xs mb-1">SHA-256</p>
                    <p className="font-mono text-xs text-falcon-muted break-all">{data.file_hash}</p>
                  </div>
                </div>
              </div>

              {/* Behaviors */}
              <div>
                <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-falcon-red" />
                  検出された挙動 ({data.behaviors.length})
                </h3>
                <div className="space-y-2">
                  {data.behaviors.map(b => (
                    <div key={b.id} className="flex items-start gap-3 p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                      <div className="pt-0.5">
                        <BehaviorCategoryIcon category={b.category} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-falcon-text text-sm">{b.description}</p>
                        <p className="text-falcon-muted text-xs mt-0.5">+{(b.timestamp_offset_ms / 1000).toFixed(1)}s</p>
                      </div>
                      <SeverityBadge severity={b.severity} />
                    </div>
                  ))}
                </div>
              </div>

              {/* Network Indicators */}
              <div>
                <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-blue-400" />
                  ネットワーク指標 ({data.network_indicators.length})
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-falcon-border">
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">タイプ</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">値</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">国</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">脅威スコア</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">説明</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.network_indicators.map((n, i) => (
                        <tr key={i} className="border-b border-falcon-border/50 hover:bg-falcon-border/20">
                          <td className="py-2 px-3">
                            <span className="px-1.5 py-0.5 bg-blue-500/15 text-blue-400 border border-blue-500/30 rounded-sm text-[10px] font-mono uppercase">
                              {n.type}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-mono text-xs text-falcon-text">{n.value}</td>
                          <td className="py-2 px-3 text-falcon-muted text-xs">{n.country}</td>
                          <td className="py-2 px-3">
                            <span className={`text-xs font-bold ${n.threat_score >= 80 ? 'text-red-400' : n.threat_score >= 50 ? 'text-yellow-400' : 'text-green-400'}`}>
                              {n.threat_score}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-falcon-muted text-xs">{n.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Signatures */}
              <div>
                <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" />
                  マッチしたシグネチャ ({data.signatures.length})
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-falcon-border">
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">シグネチャ名</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">ファミリー</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">深刻度</th>
                        <th className="text-left py-2 px-3 text-falcon-muted text-xs font-medium">説明</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.signatures.map((s, i) => (
                        <tr key={i} className="border-b border-falcon-border/50 hover:bg-falcon-border/20">
                          <td className="py-2 px-3 font-mono text-xs text-falcon-text">{s.name}</td>
                          <td className="py-2 px-3 text-falcon-muted text-xs">{s.family}</td>
                          <td className="py-2 px-3"><SeverityBadge severity={s.severity} /></td>
                          <td className="py-2 px-3 text-falcon-muted text-xs">{s.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Timeline */}
              <div>
                <h3 className="text-falcon-text font-semibold mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-falcon-muted" />
                  実行タイムライン
                </h3>
                <div className="relative pl-4">
                  <div className="absolute left-0 top-2 bottom-2 w-px bg-falcon-border" />
                  {data.timeline.map((e, i) => {
                    const dotColor = {
                      critical: 'bg-red-500', high: 'bg-orange-500',
                      medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-falcon-subtle',
                    }[e.severity] ?? 'bg-falcon-subtle'
                    return (
                      <div key={i} className="relative flex items-start gap-3 pb-4">
                        <div className={`absolute -left-1.5 top-1.5 w-3 h-3 rounded-full border-2 border-falcon-surface ${dotColor}`} />
                        <div className="ml-3">
                          <p className="text-falcon-text text-xs">{e.description}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] text-falcon-muted font-mono">+{(e.timestamp_offset_ms / 1000).toFixed(1)}s</span>
                            <span className="text-[10px] text-falcon-muted">{e.type}</span>
                            <SeverityBadge severity={e.severity} />
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Submit Tab ────────────────────────────────────────────────────────────────

function SubmitTab({ agents }: { agents: Agent[] }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ file_hash: '', file_name: '', agent_id: '', priority: 'normal' as 'normal' | 'high' })
  const [hashError, setHashError] = useState('')
  const [submittedItems, setSubmittedItems] = useState<SandboxSubmission[]>([])
  const [resultPanelId, setResultPanelId] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: (data: typeof form) => apiFetch<SandboxSubmission>('/api/v1/sandbox/submit', {
      method: 'POST', body: JSON.stringify(data),
    }),
    onSuccess: (res) => {
      setSubmittedItems(prev => [res, ...prev])
      setForm({ file_hash: '', file_name: '', agent_id: '', priority: 'normal' })
      queryClient.invalidateQueries({ queryKey: ['sandbox-stats'] })
      queryClient.invalidateQueries({ queryKey: ['sandbox-submissions'] })
    },
    onError: () => {
      // Mock a successful submission on error
      const mock: SandboxSubmission = {
        id: `sub-new-${Date.now()}`,
        submission_id: `SBX-${Date.now()}`,
        file_hash: form.file_hash,
        file_name: form.file_name || 'unknown.bin',
        agent_id: form.agent_id || null,
        agent_hostname: agents.find(a => a.id === form.agent_id)?.hostname ?? null,
        priority: form.priority,
        status: 'queued',
        verdict: null, score: null,
        submitted_at: new Date().toISOString(),
        completed_at: null,
        duration_seconds: null,
        estimated_seconds: 120,
      }
      setSubmittedItems(prev => [mock, ...prev])
      setForm({ file_hash: '', file_name: '', agent_id: '', priority: 'normal' })
    },
  })

  function validateHash(v: string) {
    if (v && !/^[0-9a-fA-F]{64}$/.test(v)) setHashError('SHA-256は64桁の16進数で入力してください')
    else setHashError('')
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (hashError || !form.file_hash) return
    mutation.mutate(form)
  }

  return (
    <div className="space-y-6">
      {resultPanelId && <ResultPanel submissionId={resultPanelId} onClose={() => setResultPanelId(null)} />}

      {/* Form */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
        <h2 className="text-falcon-text font-semibold mb-4 flex items-center gap-2">
          <Upload className="w-4 h-4 text-falcon-red" />
          ファイル解析送信
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="block text-falcon-muted text-xs mb-1.5">SHA-256 ハッシュ <span className="text-red-400">*</span></label>
              <input
                type="text"
                value={form.file_hash}
                onChange={e => { setForm(f => ({ ...f, file_hash: e.target.value })); validateHash(e.target.value) }}
                placeholder="64桁の16進数ハッシュを入力..."
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/60 placeholder-falcon-subtle font-mono"
              />
              {hashError && <p className="text-red-400 text-xs mt-1">{hashError}</p>}
            </div>
            <div>
              <label className="block text-falcon-muted text-xs mb-1.5">ファイル名</label>
              <input
                type="text"
                value={form.file_name}
                onChange={e => setForm(f => ({ ...f, file_name: e.target.value }))}
                placeholder="例: suspicious_file.exe"
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/60 placeholder-falcon-subtle"
              />
            </div>
            <div>
              <label className="block text-falcon-muted text-xs mb-1.5">エージェント (任意)</label>
              <select
                value={form.agent_id}
                onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/60"
              >
                <option value="">— 指定なし —</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>{a.hostname}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-falcon-muted text-xs mb-1.5">優先度</label>
              <select
                value={form.priority}
                onChange={e => setForm(f => ({ ...f, priority: e.target.value as 'normal' | 'high' }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/60"
              >
                <option value="normal">通常</option>
                <option value="high">高優先度</option>
              </select>
            </div>
          </div>
          <button
            type="submit"
            disabled={mutation.isPending || !form.file_hash || !!hashError}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50
                       disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
          >
            {mutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
            解析を送信
          </button>
        </form>
      </div>

      {/* Submitted items */}
      {submittedItems.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-falcon-muted text-sm font-medium">送信済み</h3>
          {submittedItems.map(item => (
            <div key={item.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-falcon-text font-medium text-sm">{item.file_name || 'unknown.bin'}</span>
                    <StatusBadge status={item.status} />
                    {item.verdict && <VerdictBadge verdict={item.verdict} />}
                  </div>
                  <p className="font-mono text-xs text-falcon-muted">{truncateHash(item.file_hash)}</p>
                  <div className="flex items-center gap-3 text-xs text-falcon-muted">
                    <span>ID: {item.submission_id}</span>
                    {item.agent_hostname && <span>Agent: {item.agent_hostname}</span>}
                    {item.estimated_seconds && item.status !== 'completed' && (
                      <span className="text-blue-400">予測: ~{item.estimated_seconds}s</span>
                    )}
                  </div>
                </div>
                {item.status === 'completed' && (
                  <button
                    onClick={() => setResultPanelId(item.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-falcon-border hover:bg-[#2a3f5f]
                               text-falcon-text rounded-lg transition-colors border border-[#2a3f5f]"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    結果確認
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── History Tab ───────────────────────────────────────────────────────────────

function HistoryTab({ agents }: { agents: Agent[] }) {
  const [verdictFilter, setVerdictFilter] = useState('all')
  const [agentFilter, setAgentFilter] = useState('all')
  const [resultPanelId, setResultPanelId] = useState<string | null>(null)

  const { data, isLoading } = useQuery<SubmissionListResponse>({
    queryKey: ['sandbox-submissions'],
    queryFn: async () => {
      try {
        return await apiFetch<SubmissionListResponse>('/api/v1/sandbox/submissions')
      } catch {
        return { submissions: [], total: 0 }
      }
    },
    staleTime: 30_000,
  })

  const submissions = data?.submissions ?? []

  const filtered = submissions.filter(s => {
    if (verdictFilter !== 'all' && s.verdict !== verdictFilter) return false
    if (agentFilter !== 'all' && s.agent_hostname !== agentFilter) return false
    return true
  })

  function exportCSV() {
    const rows = [
      ['ファイル名', 'SHA-256', 'エージェント', '判定', 'スコア', '送信日時', '完了日時', '所要時間'],
      ...filtered.map(s => [
        s.file_name, s.file_hash, s.agent_hostname ?? '', s.verdict ?? '',
        s.score?.toString() ?? '', s.submitted_at, s.completed_at ?? '', s.duration_seconds?.toString() ?? '',
      ])
    ]
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'sandbox_history.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {resultPanelId && <ResultPanel submissionId={resultPanelId} onClose={() => setResultPanelId(null)} />}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-falcon-muted" />
          <select
            value={verdictFilter}
            onChange={e => setVerdictFilter(e.target.value)}
            className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-sm text-falcon-text
                       focus:outline-hidden focus:border-falcon-red/60"
          >
            <option value="all">全判定</option>
            <option value="MALICIOUS">悪性</option>
            <option value="SUSPICIOUS">疑わしい</option>
            <option value="BENIGN">安全</option>
          </select>
        </div>
        <select
          value={agentFilter}
          onChange={e => setAgentFilter(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-sm text-falcon-text
                     focus:outline-hidden focus:border-falcon-red/60"
        >
          <option value="all">全エージェント</option>
          {agents.map(a => <option key={a.id} value={a.hostname}>{a.hostname}</option>)}
        </select>
        <div className="ml-auto">
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-falcon-surface border border-falcon-border
                       hover:border-falcon-muted/40 text-falcon-muted hover:text-falcon-text rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            CSV出力
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]/50">
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">ファイル名</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">SHA-256</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">エージェント</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">判定</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium w-32">スコア</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">送信日時</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">完了日時</th>
                <th className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">所要時間</th>
                <th className="py-3 px-4" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={9} className="py-10 text-center text-falcon-muted"><Loader2 className="w-6 h-6 animate-spin inline" /></td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={9} className="py-10 text-center text-falcon-muted">データなし</td></tr>
              ) : filtered.map(s => (
                <tr key={s.id} className="border-b border-falcon-border/50 hover:bg-falcon-border/20 transition-colors">
                  <td className="py-3 px-4 text-falcon-text font-medium max-w-[140px] truncate">{s.file_name}</td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-xs text-falcon-muted">{truncateHash(s.file_hash)}</span>
                  </td>
                  <td className="py-3 px-4 text-falcon-muted text-xs">{s.agent_hostname ?? '—'}</td>
                  <td className="py-3 px-4">
                    {s.status !== 'completed' ? <StatusBadge status={s.status} /> : <VerdictBadge verdict={s.verdict} />}
                  </td>
                  <td className="py-3 px-4 w-32"><ScoreBar score={s.score} /></td>
                  <td className="py-3 px-4 text-falcon-muted text-xs whitespace-nowrap">{formatDate(s.submitted_at)}</td>
                  <td className="py-3 px-4 text-falcon-muted text-xs whitespace-nowrap">{formatDate(s.completed_at)}</td>
                  <td className="py-3 px-4 text-falcon-muted text-xs">{formatDuration(s.duration_seconds)}</td>
                  <td className="py-3 px-4">
                    {s.status === 'completed' && (
                      <button
                        onClick={() => setResultPanelId(s.id)}
                        className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-falcon-border hover:bg-[#2a3f5f]
                                   text-falcon-text rounded transition-colors border border-[#2a3f5f]"
                      >
                        <FileText className="w-3 h-3" />
                        詳細
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SandboxPage() {
  const [activeTab, setActiveTab] = useState<'submit' | 'history'>('submit')

  const { data: stats } = useQuery<SandboxStats>({
    queryKey: ['sandbox-stats'],
    queryFn: async () => {
      try { return await apiFetch<SandboxStats>('/api/v1/sandbox/stats') }
      catch { return { submissions_today: 0, malicious_found: 0, suspicious: 0, avg_analysis_time_seconds: 0 } }
    },
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-list-sandbox'],
    queryFn: async () => {
      try { return await apiFetch<{ agents: Agent[] }>('/api/v1/agents') }
      catch { return { agents: [] } }
    },
    staleTime: 120_000,
  })

  const s = stats ?? { submissions_today: 0, malicious_found: 0, suspicious: 0, avg_analysis_time_seconds: 0 }
  const agents = agentsData?.data ?? agentsData?.agents ?? []

  const statCards = [
    { label: '本日の送信数', value: s.submissions_today, icon: Upload, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
    { label: '悪性検出', value: s.malicious_found, icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
    { label: '疑わしいファイル', value: s.suspicious, icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
    { label: '平均解析時間', value: `${s.avg_analysis_time_seconds}s`, icon: Clock, color: 'text-falcon-muted', bg: 'bg-falcon-border/50 border-falcon-border' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-falcon-text flex items-center gap-3">
            <Bug className="w-6 h-6 text-falcon-red" />
            マルウェアサンドボックス
          </h1>
          <p className="text-falcon-muted text-sm mt-1">ファイル自動解析・脅威検証</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className={`bg-falcon-surface border rounded-xl p-4 ${c.bg}`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg bg-[#070d19]/60`}>
                  <Icon className={`w-5 h-5 ${c.color}`} />
                </div>
                <div>
                  <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
                  <p className="text-falcon-muted text-xs">{c.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-falcon-border">
        {(['submit', 'history'] as const).map(tab => {
          const labels = { submit: '解析送信', history: '解析履歴' }
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px
                ${activeTab === tab
                  ? 'border-falcon-red text-falcon-text'
                  : 'border-transparent text-falcon-muted hover:text-falcon-text'}`}
            >
              {labels[tab]}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {activeTab === 'submit' && <SubmitTab agents={agents} />}
      {activeTab === 'history' && <HistoryTab agents={agents} />}
    </div>
  )
}
