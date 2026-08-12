'use client'



import { useState } from 'react'

import { useQuery, useMutation } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  Brain,

  GitBranch,

  Users,

  AlertTriangle,

  CheckCircle,

  Loader2,

  Activity,

  Cpu,

  ShieldAlert,

  TrendingUp,

  Clock,

} from 'lucide-react'



// ── Types ──────────────────────────────────────────────────────────────────────



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



interface AnomalyScoreResult {

  score: number

  is_anomaly: boolean

}



interface BehavioralAlert {

  id: string

  timestamp: string

  entity: string

  detection_type: string

  severity: string

  score?: number

}



interface AlertsResponse {

  alerts: BehavioralAlert[]

}



const ATTACK_PATTERNS: { parent: string; child: string; mitre: string; severity: string }[] = [
  { parent: 'cmd.exe', child: 'powershell.exe -enc ...', mitre: 'T1059.001', severity: 'high' },
  { parent: 'winword.exe', child: 'cmd.exe /c', mitre: 'T1566.001', severity: 'medium' },
  { parent: 'explorer.exe', child: 'regsvr32.exe /s /n /u /i:', mitre: 'T1218.010', severity: 'high' },
  { parent: 'svchost.exe', child: 'mshta.exe vbscript:', mitre: 'T1218.005', severity: 'critical' },
  { parent: 'lsass.exe', child: 'rundll32.exe comsvcs.dll MiniDump', mitre: 'T1003.001', severity: 'critical' },
]

const ANOMALY_FEATURE_FIELDS: { key: string; label: string; min: number; max: number; placeholder: string }[] = [
  { key: 'cpu_usage', label: 'CPU使用率 (%)', min: 0, max: 100, placeholder: '75' },
  { key: 'memory_mb', label: 'メモリ使用量 (MB)', min: 0, max: 32768, placeholder: '4096' },
  { key: 'network_connections', label: 'ネットワーク接続数', min: 0, max: 1000, placeholder: '50' },
  { key: 'file_operations', label: 'ファイル操作数', min: 0, max: 10000, placeholder: '200' },
  { key: 'process_count', label: '子プロセス数', min: 0, max: 500, placeholder: '10' },
  { key: 'data_transfer_gb', label: 'データ転送量 (GB)', min: 0, max: 100, placeholder: '1.5' },
]

// ── Helpers ────────────────────────────────────────────────────────────────────



function riskBarColor(score: number): string {

  if (score >= 71) return 'bg-red-500'

  if (score >= 41) return 'bg-yellow-500'

  return 'bg-green-500'

}



function riskTextColor(score: number): string {

  if (score >= 71) return 'text-red-400'

  if (score >= 41) return 'text-yellow-400'

  return 'text-green-400'

}



function anomalyScoreColor(score: number): { bar: string; text: string; label: string } {

  if (score > 0.6) return { bar: 'bg-red-500', text: 'text-red-400', label: 'Anomaly' }

  if (score > 0.5) return { bar: 'bg-orange-500', text: 'text-orange-400', label: 'Suspicious' }

  return { bar: 'bg-green-500', text: 'text-green-400', label: 'Normal' }

}



function severityBadge(severity: string): string {

  switch (severity.toLowerCase()) {

    case 'critical': return 'bg-red-500/20 text-red-400'

    case 'high': return 'bg-orange-500/20 text-orange-400'

    case 'medium': return 'bg-yellow-500/20 text-yellow-400'

    default: return 'bg-blue-500/20 text-blue-400'

  }

}



function attackSeverityBadge(severity: string): string {

  if (severity === 'Critical') return 'bg-red-500/20 text-red-400'

  return 'bg-orange-500/20 text-orange-400'

}



function formatTs(ts: string): string {

  return new Date(ts).toLocaleString()

}



// ── Main Component ─────────────────────────────────────────────────────────────



export default function MLAnalyticsPage() {

  // Process lineage

  const [parentProcess, setParentProcess] = useState('')

  const [childProcess, setChildProcess] = useState('')

  const [lineageResult, setLineageResult] = useState<LineageResult | null>(null)



  // Anomaly calculator

  const [featureValues, setFeatureValues] = useState<Record<string, string>>({})

  const [anomalyResult, setAnomalyResult] = useState<AnomalyScoreResult | null>(null)



  // ── Queries ──────────────────────────────────────────────────────────────────



  const { data: uebaData, isLoading: uebaLoading } = useQuery<UEBAScoresResponse>({

    queryKey: ['ml-ueba-scores'],

    queryFn: () =>

      apiFetch<UEBAScoresResponse>('/api/v1/admin/ml/ueba-scores').catch(() => ({ scores: [] })),

    refetchInterval: 60_000,

  })



  const { data: alertsData } = useQuery<AlertsResponse>({

    queryKey: ['behavioral-alerts'],

    queryFn: () =>

      apiFetch<AlertsResponse>('/api/v1/alerts?limit=20').catch(() => ({ alerts: [] })),

    refetchInterval: 30_000,

  })



  // ── Mutations ────────────────────────────────────────────────────────────────



  const lineageMutation = useMutation<LineageResult, Error, { parent_process: string; child_process: string }>({

    mutationFn: (body) =>

      apiFetch<LineageResult>('/api/v1/admin/ml/analyze-lineage', {

        method: 'POST',

        body: JSON.stringify(body),

      }),

    onSuccess: (data) => setLineageResult(data),

  })



  const anomalyMutation = useMutation<AnomalyScoreResult, Error, { features: number[] }>({

    mutationFn: (body) =>

      apiFetch<AnomalyScoreResult>('/api/v1/admin/ml/anomaly-score', {

        method: 'POST',

        body: JSON.stringify(body),

      }),

    onSuccess: (data) => setAnomalyResult(data),

  })



  // ── Handlers ─────────────────────────────────────────────────────────────────



  const handleAnalyzeLineage = () => {

    if (!parentProcess.trim() || !childProcess.trim()) return

    setLineageResult(null)

    lineageMutation.mutate({ parent_process: parentProcess.trim(), child_process: childProcess.trim() })

  }



  const handleCalculateScore = () => {

    const features = ANOMALY_FEATURE_FIELDS.map((f) => parseFloat(featureValues[f.key] ?? '0') || 0)

    setAnomalyResult(null)

    anomalyMutation.mutate({ features })

  }



  // ── Derived ───────────────────────────────────────────────────────────────────



  const scores = uebaData?.scores ?? []

  const sortedScores = [...scores].sort((a, b) => b.risk_score - a.risk_score)

  const highRiskCount = scores.filter((s) => s.risk_score >= 70).length



  // Filter behavioral detections

  const behavioralAlerts = (alertsData?.alerts ?? []).filter(

    (a) => ['behavioral', 'suspicious_process_lineage', 'ueba_high_risk', 'off_hours_anomaly'].some(

      (t) => a.detection_type?.includes(t)

    )

  ).slice(0, 20)



  // ── Render ───────────────────────────────────────────────────────────────────



  return (

    <div className="min-h-screen bg-[#070d19] text-white p-6 space-y-6">



      {/* Header */}

      <div>

        <h1 className="text-2xl font-bold flex items-center gap-2">

          <Brain className="w-7 h-7 text-[#e8002d]" />

          ML Behavioral Analytics

        </h1>

        <p className="text-[#7d92b0] text-sm mt-0.5">AI-powered threat detection</p>

      </div>



      {/* Section 1: Model Status */}

      <div>

        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">Model Status</h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

          {/* Isolation Forest */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

            <div className="flex items-center justify-between mb-3">

              <div className="flex items-center gap-2">

                <Cpu className="w-5 h-5 text-blue-400" />

                <span className="text-white font-semibold text-sm">Isolation Forest</span>

              </div>

              <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-500/20 text-green-400">Trained</span>

            </div>

            <div className="space-y-2">

              <div className="flex justify-between">

                <span className="text-[#7d92b0] text-xs">Trees</span>

                <span className="text-white text-xs font-mono">100</span>

              </div>

              <div className="flex justify-between">

                <span className="text-[#7d92b0] text-xs">Sample Size</span>

                <span className="text-white text-xs font-mono">256</span>

              </div>

            </div>

          </div>



          {/* UEBA Scorer */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

            <div className="flex items-center justify-between mb-3">

              <div className="flex items-center gap-2">

                <Users className="w-5 h-5 text-purple-400" />

                <span className="text-white font-semibold text-sm">UEBA Scorer</span>

              </div>

              <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-500/20 text-green-400">Active</span>

            </div>

            {uebaLoading ? (

              <div className="flex items-center gap-2 text-[#7d92b0] text-xs">

                <Loader2 className="w-3 h-3 animate-spin" /> Loading…

              </div>

            ) : (

              <div className="space-y-2">

                <div className="flex justify-between">

                  <span className="text-[#7d92b0] text-xs">Entities Tracked</span>

                  <span className="text-white text-xs font-mono">{scores.length}</span>

                </div>

                <div className="flex justify-between">

                  <span className="text-[#7d92b0] text-xs">High Risk (≥70)</span>

                  <span className={`text-xs font-mono font-bold ${highRiskCount > 0 ? 'text-red-400' : 'text-green-400'}`}>

                    {highRiskCount}

                  </span>

                </div>

              </div>

            )}

          </div>



          {/* Process Lineage */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

            <div className="flex items-center justify-between mb-3">

              <div className="flex items-center gap-2">

                <GitBranch className="w-5 h-5 text-orange-400" />

                <span className="text-white font-semibold text-sm">Process Lineage</span>

              </div>

              <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-500/20 text-green-400">Active</span>

            </div>

            <div className="space-y-2">

              <div className="flex justify-between">

                <span className="text-[#7d92b0] text-xs">Rules Active</span>

                <span className="text-white text-xs font-mono">17</span>

              </div>

              <div className="flex justify-between">

                <span className="text-[#7d92b0] text-xs">Last Detection</span>

                <span className="text-orange-400 text-xs font-mono">

                  {behavioralAlerts.find((a) => a.detection_type === 'suspicious_process_lineage')

                    ? new Date(behavioralAlerts.find((a) => a.detection_type === 'suspicious_process_lineage')!.timestamp).toLocaleDateString()

                    : 'No detections'}

                </span>

              </div>

            </div>

          </div>

        </div>

      </div>



      {/* Section 2: UEBA Risk Leaderboard */}

      <div>

        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">UEBA Risk Leaderboard</h2>

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">

          <div className="overflow-x-auto">

            <table className="w-full">

              <thead>

                <tr className="border-b border-[#1e2d42]">

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider">Entity ID</th>

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider">Type</th>

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider w-48">Risk Score</th>

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider">Alerts</th>

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider">Failed Logins</th>

                  <th className="text-left text-[#7d92b0] text-xs font-medium px-4 py-3 uppercase tracking-wider">Data Transfer</th>

                </tr>

              </thead>

              <tbody className="divide-y divide-[#1e2d42]">

                {sortedScores.map((s, i) => (

                  <tr key={i} className="hover:bg-[#111827] transition-colors">

                    <td className="px-4 py-3">

                      <span className="text-white text-sm font-mono">{s.entity_id}</span>

                    </td>

                    <td className="px-4 py-3">

                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${

                        s.entity_type === 'user' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'

                      }`}>

                        {s.entity_type}

                      </span>

                    </td>

                    <td className="px-4 py-3">

                      <div className="flex items-center gap-2">

                        <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5">

                          <div

                            className={`h-1.5 rounded-full ${riskBarColor(s.risk_score)}`}

                            style={{ width: `${s.risk_score}%` }}

                          />

                        </div>

                        <span className={`text-xs font-bold w-8 text-right ${riskTextColor(s.risk_score)}`}>

                          {Math.round(s.risk_score)}

                        </span>

                      </div>

                    </td>

                    <td className="px-4 py-3">

                      <span className={`text-sm ${s.alert_count > 0 ? 'text-orange-400 font-medium' : 'text-[#7d92b0]'}`}>

                        {s.alert_count}

                      </span>

                    </td>

                    <td className="px-4 py-3">

                      <span className={`text-sm ${s.failed_logins > 3 ? 'text-red-400 font-medium' : 'text-[#7d92b0]'}`}>

                        {s.failed_logins}

                      </span>

                    </td>

                    <td className="px-4 py-3">

                      <span className={`text-sm ${s.data_transfer_gb > 1 ? 'text-yellow-400' : 'text-[#7d92b0]'}`}>

                        {s.data_transfer_gb.toFixed(2)} GB

                      </span>

                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      </div>



      {/* Section 3: Process Lineage Analyzer */}

      <div>

        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">Process Lineage Analyzer</h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Left: Check Process Relationship */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

            <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">

              <GitBranch className="w-4 h-4 text-blue-400" />

              Check Process Relationship

            </h3>

            <div className="space-y-3">

              <div>

                <label className="block text-[#7d92b0] text-xs mb-1">Parent Process</label>

                <input

                  type="text"

                  value={parentProcess}

                  onChange={(e) => setParentProcess(e.target.value)}

                  placeholder="winword.exe"

                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d] font-mono"

                />

              </div>

              <div>

                <label className="block text-[#7d92b0] text-xs mb-1">Child Process</label>

                <input

                  type="text"

                  value={childProcess}

                  onChange={(e) => setChildProcess(e.target.value)}

                  placeholder="powershell.exe"

                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d] font-mono"

                  onKeyDown={(e) => e.key === 'Enter' && handleAnalyzeLineage()}

                />

              </div>

              <button

                onClick={handleAnalyzeLineage}

                disabled={lineageMutation.isPending || !parentProcess.trim() || !childProcess.trim()}

                className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"

              >

                {lineageMutation.isPending ? (

                  <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing…</>

                ) : (

                  <><GitBranch className="w-4 h-4" /> Analyze</>

                )}

              </button>



              {/* Result */}

              {lineageMutation.isError && (

                <div className="bg-red-950/30 border border-red-500/30 rounded-lg p-3">

                  <p className="text-red-400 text-xs">Failed to analyze. Check API connectivity.</p>

                </div>

              )}

              {lineageResult && (

                <div className={`rounded-lg p-4 border ${

                  lineageResult.suspicious

                    ? 'bg-red-950/30 border-red-500/40'

                    : 'bg-green-950/30 border-green-500/40'

                }`}>

                  {lineageResult.suspicious ? (

                    <div className="space-y-2">

                      <div className="flex flex-wrap items-center gap-2">

                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400">SUSPICIOUS</span>

                        {lineageResult.detections[0]?.severity && (

                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${attackSeverityBadge(lineageResult.detections[0].severity)}`}>

                            {lineageResult.detections[0].severity}

                          </span>

                        )}

                      </div>

                      {lineageResult.detections.map((d, i) => (

                        <div key={i} className="space-y-1">

                          {d.rule && <p className="text-white text-xs font-medium">{d.rule}</p>}

                          {d.reason && <p className="text-[#7d92b0] text-xs leading-relaxed">{d.reason}</p>}

                        </div>

                      ))}

                    </div>

                  ) : (

                    <div className="flex items-center gap-2">

                      <CheckCircle className="w-4 h-4 text-green-400" />

                      <span className="text-green-400 text-sm font-medium">Normal — no suspicious relationship detected</span>

                    </div>

                  )}

                </div>

              )}

            </div>

          </div>



          {/* Right: Common Attack Patterns */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

            <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">

              <ShieldAlert className="w-4 h-4 text-orange-400" />

              Common Attack Patterns

            </h3>

            <div className="space-y-2">

              {ATTACK_PATTERNS.map((pattern, i) => (

                <button

                  key={i}

                  onClick={() => {

                    setParentProcess(pattern.parent)

                    setChildProcess(pattern.child)

                    setLineageResult(null)

                  }}

                  className="w-full flex items-center gap-3 p-3 bg-[#070d19] hover:bg-[#111827] border border-[#1e2d42] hover:border-[#e8002d]/30 rounded-lg transition-colors text-left group"

                >

                  <div className="flex-1 min-w-0">

                    <div className="flex items-center gap-1.5 font-mono text-xs">

                      <span className="text-white">{pattern.parent}</span>

                      <span className="text-[#3d5068]">→</span>

                      <span className="text-orange-300">{pattern.child}</span>

                    </div>

                  </div>

                  <div className="flex items-center gap-2 shrink-0">

                    <span className="text-[#7d92b0] text-xs font-mono">{pattern.mitre}</span>

                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${attackSeverityBadge(pattern.severity)}`}>

                      {pattern.severity}

                    </span>

                  </div>

                </button>

              ))}

            </div>

            <p className="text-[#3d5068] text-xs mt-3">Click a pattern to pre-fill the analyzer</p>

          </div>

        </div>

      </div>



      {/* Section 4: Anomaly Score Calculator */}

      <div>

        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">Anomaly Score Calculator</h2>

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Feature inputs */}

            <div>

              <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">

                <Activity className="w-4 h-4 text-purple-400" />

                Feature Vector

              </h3>

              <div className="grid grid-cols-2 gap-3">

                {ANOMALY_FEATURE_FIELDS.map((field) => (

                  <div key={field.key}>

                    <label className="block text-[#7d92b0] text-xs mb-1">{field.label}</label>

                    <input

                      type="number"

                      min={field.min}

                      max={field.max}

                      step={field.key === 'data_transfer_gb' ? '0.1' : '1'}

                      value={featureValues[field.key] ?? ''}

                      onChange={(e) => setFeatureValues((prev) => ({ ...prev, [field.key]: e.target.value }))}

                      placeholder={field.placeholder}

                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d] font-mono"

                    />

                  </div>

                ))}

              </div>

              <button

                onClick={handleCalculateScore}

                disabled={anomalyMutation.isPending}

                className="mt-4 flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"

              >

                {anomalyMutation.isPending ? (

                  <><Loader2 className="w-4 h-4 animate-spin" /> Calculating…</>

                ) : (

                  <><TrendingUp className="w-4 h-4" /> Calculate Score</>

                )}

              </button>

            </div>



            {/* Result visualization */}

            <div className="flex flex-col items-center justify-center">

              {anomalyMutation.isError && (

                <div className="w-full bg-red-950/30 border border-red-500/30 rounded-lg p-4 text-center">

                  <p className="text-red-400 text-sm">Calculation failed. Check API.</p>

                </div>

              )}

              {!anomalyResult && !anomalyMutation.isPending && !anomalyMutation.isError && (

                <div className="text-center">

                  <div className="w-32 h-32 rounded-full border-4 border-[#1e2d42] flex items-center justify-center mb-4">

                    <span className="text-[#3d5068] text-lg font-mono">—</span>

                  </div>

                  <p className="text-[#7d92b0] text-sm">Enter features and calculate</p>

                </div>

              )}

              {anomalyMutation.isPending && (

                <Loader2 className="w-12 h-12 animate-spin text-[#e8002d]" />

              )}

              {anomalyResult && (() => {

                const colors = anomalyScoreColor(anomalyResult.score)

                const pct = Math.round(anomalyResult.score * 100)

                return (

                  <div className="text-center w-full">

                    {/* Gauge bar */}

                    <div className="relative mb-6">

                      <div className="w-full bg-[#1e2d42] rounded-full h-4 overflow-hidden">

                        <div

                          className={`h-4 rounded-full transition-all duration-700 ${colors.bar}`}

                          style={{ width: `${pct}%` }}

                        />

                      </div>

                      <div

                        className="absolute top-0 h-4 w-0.5 bg-white/60"

                        style={{ left: `${pct}%`, transform: 'translateX(-50%)' }}

                      />

                    </div>

                    {/* Score display */}

                    <div className={`text-6xl font-bold font-mono mb-2 ${colors.text}`}>

                      {anomalyResult.score.toFixed(2)}

                    </div>

                    <div className={`text-lg font-semibold mb-1 ${colors.text}`}>{colors.label}</div>

                    <div className="text-[#7d92b0] text-sm">

                      {anomalyResult.is_anomaly ? 'Anomalous behavior detected' : 'Behavior within normal range'}

                    </div>

                    {/* Scale legend */}

                    <div className="flex justify-between mt-4 text-xs text-[#7d92b0]">

                      <span className="text-green-400">0.00 Normal</span>

                      <span className="text-orange-400">0.50 Suspicious</span>

                      <span className="text-red-400">0.60 Anomaly 1.00</span>

                    </div>

                  </div>

                )

              })()}

            </div>

          </div>

        </div>

      </div>



      {/* Section 5: Behavioral Detections Feed */}

      <div>

        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">Behavioral Detections Feed</h2>

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">

          <div className="divide-y divide-[#1e2d42]">

            {behavioralAlerts.length === 0 ? (

              <div className="p-8 text-center text-[#7d92b0]">No behavioral detections found</div>

            ) : (

              behavioralAlerts.map((alert) => (

                <div key={alert.id} className="px-4 py-3 flex items-center gap-4 hover:bg-[#111827] transition-colors">

                  <div className="shrink-0">

                    <Clock className="w-4 h-4 text-[#3d5068]" />

                  </div>

                  <div className="w-36 shrink-0">

                    <p className="text-[#7d92b0] text-xs">{formatTs(alert.timestamp)}</p>

                  </div>

                  <div className="flex-1 min-w-0">

                    <div className="flex items-center gap-2 flex-wrap">

                      <span className="text-white text-sm font-mono font-medium">{alert.entity}</span>

                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-[#1e2d42] text-[#7d92b0]">

                        {alert.detection_type.replace(/_/g, ' ')}

                      </span>

                    </div>

                  </div>

                  <div className="shrink-0">

                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityBadge(alert.severity)}`}>

                      {alert.severity}

                    </span>

                  </div>

                  {alert.score !== undefined && (

                    <div className="shrink-0 w-16 text-right">

                      <span className={`text-xs font-mono font-bold ${anomalyScoreColor(alert.score).text}`}>

                        {alert.score.toFixed(2)}

                      </span>

                    </div>

                  )}

                </div>

              ))

            )}

          </div>

        </div>

      </div>

    </div>

  )

}

