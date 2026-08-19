'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TrendingUp, RefreshCw, Brain, Shield, AlertTriangle,
  Activity, Zap, Clock, CheckCircle, ChevronRight,
  Loader2, BarChart2, Target, X
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type ModelStatus = 'ready' | 'training' | 'error' | 'stale'

// What /api/v1/admin/predictive/models actually returns. The page previously
// declared a PredictionModel with an `accuracy` percentage and a ModelStatus
// union; the server sends neither. It sends status "active" (outside the union,
// so the status chip resolved to undefined) and no accuracy at all, so the
// accuracy readout and its progress bar rendered "undefined%" off a field that
// has never existed.
interface ServerModel {
  id: string
  name: string
  description: string
  version: string
  algorithm: string
  status: string
  feature_count: number
  training_samples: number
  last_trained: string
  next_retrain: string
}

// PredictionModel is the shape this page renders, derived from ServerModel.
interface PredictionModel {
  id: string
  name: string
  description: string
  version: string
  algorithm: string
  trainingSamples: number
  lastTrained: string
  status: ModelStatus
}

// adaptModel maps the server's model metadata onto what the cards render.
// Anything the server does not send is absent here rather than invented.
function adaptModel(m: ServerModel): PredictionModel {
  return {
    id: m.id,
    name: m.name,
    description: m.description,
    version: m.version,
    algorithm: m.algorithm,
    trainingSamples: m.training_samples,
    lastTrained: m.last_trained,
    status: m.status === 'active' ? 'ready' : 'stale',
  }
}

// A prediction as returned by /api/v1/admin/predictive/predictions.
interface Prediction {
  id: string
  model_name: string
  prediction_type: string
  predicted_value: number
  confidence_score: number
  prediction_horizon: string
  contributing_factors: string[]
  recommendation: string
  severity: 'low' | 'medium' | 'high'
}

interface DayForecast {
  date: string
  value: number
  upper: number
  lower: number
}

interface EndpointRisk {
  host: string
  score: number
  trend: 'up' | 'down' | 'stable'
  risk_factors: string[]
}

interface VulnTrend {
  date: string
  score: number
  projected: boolean
}

interface RecommendedAction {
  id: string
  title: string
  description: string
  priority: 'critical' | 'high' | 'medium'
  model_source: string
  confidence: number
}

interface FeatureImportance {
  feature: string
  importance: number
  category: string
}

interface AccuracyPoint {
  date: string
  predicted: number
  actual: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const modelStatusColor: Record<ModelStatus, string> = {
  ready: 'text-green-400 bg-green-500/10',
  training: 'text-blue-400 bg-blue-500/10',
  error: 'text-red-400 bg-red-500/10',
  stale: 'text-yellow-400 bg-yellow-500/10',
}
const modelStatusLabel: Record<ModelStatus, string> = {
  ready: '準備完了', training: '学習中', error: 'エラー', stale: '再学習推奨',
}

// `low` is included because /predictive/predictions emits it: vulnSeverity and
// incidentSeverity default to "low" and only step up at 0.4/0.7 and 0.3/0.6, so
// it is the value a healthy deployment reports. Omitting it made every lookup
// here resolve to undefined for exactly the common case.
const priorityColor = { critical: 'border-red-500/40 bg-red-500/5', high: 'border-orange-500/40 bg-orange-500/5', medium: 'border-yellow-500/30 bg-yellow-500/5', low: 'border-[#1e2d42] bg-[#1e2d42]/20' }
const priorityBadge = { critical: 'bg-red-500/20 text-red-300', high: 'bg-orange-500/20 text-orange-300', medium: 'bg-yellow-500/20 text-yellow-300', low: 'bg-[#1e2d42] text-[#7d92b0]' }
const priorityLabel = { critical: '重大', high: '高', medium: '中', low: '低' }

function timeAgo(ts: string) {
  const h = Math.floor((Date.now() - new Date(ts).getTime()) / 3600000)
  if (h < 24) return `${h}時間前`
  return `${Math.floor(h / 24)}日前`
}

// ─── SVG Charts ───────────────────────────────────────────────────────────────

// Every chart below computes its axis from Math.max(...data.map(...)). On an
// empty array that is -Infinity, the x scale divides by (length - 1) = -1, and
// the axis labels render literally as "-Infinity" beside an empty plot. Each
// chart is called with data that is routinely empty, so they all say so
// instead.
function NoChartData({ height, note }: { height: number; note: string }) {
  return (
    <div
      className="w-full flex items-center justify-center rounded-lg border border-dashed border-[#1e2d42]"
      style={{ height }}
    >
      <p className="text-xs text-[#3d5068]">{note}</p>
    </div>
  )
}

function VolumeChart({ data }: { data: DayForecast[] }) {
  const W = 700, H = 160, PAD = { t: 16, r: 16, b: 32, l: 48 }
  if (data.length < 2) return <NoChartData height={H} note="表示できるデータがありません" />
  const cw = W - PAD.l - PAD.r
  const ch = H - PAD.t - PAD.b
  const maxV = Math.max(...data.map(d => d.upper))
  const minV = Math.min(...data.map(d => d.lower))
  const xPos = (i: number) => PAD.l + (i / (data.length - 1)) * cw
  const yPos = (v: number) => PAD.t + ch - ((v - minV) / (maxV - minV)) * ch

  const upperPath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.upper)}`).join(' ')
  const lowerPath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.lower)}`).join(' ')
  const valuePath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.value)}`).join(' ')
  const bandPath = upperPath + ' ' + data.slice().reverse().map((d, i) => `${i === 0 ? 'L' : 'L'} ${xPos(data.length - 1 - i)} ${yPos(d.lower)}`).join(' ') + ' Z'

  const yGridLines = [0, 0.25, 0.5, 0.75, 1].map(t => minV + t * (maxV - minV))

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
      {yGridLines.map(v => (
        <g key={v}>
          <line x1={PAD.l} x2={W - PAD.r} y1={yPos(v)} y2={yPos(v)} stroke="#1e2d42" strokeWidth="1" />
          <text x={PAD.l - 6} y={yPos(v) + 4} textAnchor="end" fontSize="10" fill="#7d92b0">{Math.round(v)}</text>
        </g>
      ))}
      {data.filter((_, i) => i % 5 === 0).map((d, idx) => {
        const i = idx * 5
        return <text key={i} x={xPos(i)} y={H - 6} textAnchor="middle" fontSize="10" fill="#7d92b0">{d.date.slice(5)}</text>
      })}
      <path d={bandPath} fill="#e8002d" fillOpacity={0.08} />
      <path d={upperPath} fill="none" stroke="#e8002d" strokeWidth="1" strokeDasharray="3 2" strokeOpacity={0.4} />
      <path d={lowerPath} fill="none" stroke="#e8002d" strokeWidth="1" strokeDasharray="3 2" strokeOpacity={0.4} />
      <path d={valuePath} fill="none" stroke="#e8002d" strokeWidth="2" />
    </svg>
  )
}

function AccuracyChart({ data }: { data: AccuracyPoint[] }) {
  const W = 700, H = 130, PAD = { t: 16, r: 16, b: 28, l: 48 }
  if (data.length < 2) return <NoChartData height={H} note="表示できるデータがありません" />
  const cw = W - PAD.l - PAD.r
  const ch = H - PAD.t - PAD.b
  const allVals = data.flatMap(d => [d.predicted, d.actual])
  const maxV = Math.max(...allVals) + 10
  const minV = Math.max(0, Math.min(...allVals) - 10)
  const xPos = (i: number) => PAD.l + (i / (data.length - 1)) * cw
  const yPos = (v: number) => PAD.t + ch - ((v - minV) / (maxV - minV)) * ch

  const predPath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.predicted)}`).join(' ')
  const actPath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.actual)}`).join(' ')

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
      {[0, 0.5, 1].map(t => {
        const v = minV + t * (maxV - minV)
        return <g key={t}>
          <line x1={PAD.l} x2={W - PAD.r} y1={yPos(v)} y2={yPos(v)} stroke="#1e2d42" strokeWidth="1" />
          <text x={PAD.l - 6} y={yPos(v) + 4} textAnchor="end" fontSize="10" fill="#7d92b0">{Math.round(v)}</text>
        </g>
      })}
      {data.filter((_, i) => i % 7 === 0).map((d, idx) => (
        <text key={idx} x={xPos(idx * 7)} y={H - 4} textAnchor="middle" fontSize="10" fill="#7d92b0">{d.date.slice(5)}</text>
      ))}
      <path d={predPath} fill="none" stroke="#e8002d" strokeWidth="2" strokeDasharray="4 2" />
      <path d={actPath} fill="none" stroke="#60a5fa" strokeWidth="2" />
    </svg>
  )
}

function VulnTrendChart({ data }: { data: VulnTrend[] }) {
  const W = 700, H = 130, PAD = { t: 12, r: 16, b: 28, l: 48 }
  if (data.length < 2) return <NoChartData height={H} note="表示できるデータがありません" />
  const cw = W - PAD.l - PAD.r
  const ch = H - PAD.t - PAD.b
  const maxV = Math.max(...data.map(d => d.score)) + 5
  const minV = Math.max(0, Math.min(...data.map(d => d.score)) - 5)
  const xPos = (i: number) => PAD.l + (i / (data.length - 1)) * cw
  const yPos = (v: number) => PAD.t + ch - ((v - minV) / (maxV - minV)) * ch

  const pastData = data.filter(d => !d.projected)
  const futureData = data.filter(d => d.projected)
  const splitIdx = pastData.length - 1

  const pastPath = pastData.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(i)} ${yPos(d.score)}`).join(' ')
  const futurePath = futureData.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xPos(splitIdx + i)} ${yPos(d.score)}`).join(' ')

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
      {[0, 0.5, 1].map(t => {
        const v = minV + t * (maxV - minV)
        return <g key={t}>
          <line x1={PAD.l} x2={W - PAD.r} y1={yPos(v)} y2={yPos(v)} stroke="#1e2d42" strokeWidth="1" />
          <text x={PAD.l - 6} y={yPos(v) + 4} textAnchor="end" fontSize="10" fill="#7d92b0">{Math.round(v)}</text>
        </g>
      })}
      <line x1={xPos(splitIdx)} x2={xPos(splitIdx)} y1={PAD.t} y2={H - PAD.b} stroke="#7d92b0" strokeWidth="1" strokeDasharray="3 2" />
      <text x={xPos(splitIdx) + 4} y={PAD.t + 10} fontSize="9" fill="#7d92b0">今日</text>
      <path d={pastPath} fill="none" stroke="#60a5fa" strokeWidth="2" />
      <path d={`${pastPath.slice(-1)} ${futurePath}`} fill="none" stroke="#e8002d" strokeWidth="2" strokeDasharray="5 3" />
    </svg>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PredictiveAnalyticsPage() {
  const qc = useQueryClient()
  const [generating, setGenerating] = useState(false)
  const [generateProgress, setGenerateProgress] = useState(0)
  const [generateError, setGenerateError] = useState<string | null>(null)

  // Both queries were previously bound to throwaway names and never read: the
  // model cards rendered from a useState([]) that nothing ever set, so the grid
  // was permanently empty, and the volume chart read a `volume_forecast` key
  // this API has never returned.
  const { data: modelsResp, isLoading: modelsLoading, error: modelsError } =
    useQuery<{ models?: ServerModel[] }>({
      queryKey: ['predictive-models'],
      queryFn: () => apiFetch('/api/v1/admin/predictive/models'),
    })
  const models: PredictionModel[] = (modelsResp?.models ?? []).map(adaptModel)

  const { data: predictionsResp, isLoading: predictionsLoading, error: predictionsError } =
    useQuery<{ predictions?: Prediction[] }>({
      queryKey: ['predictive-predictions'],
      queryFn: () => apiFetch('/api/v1/admin/predictive/predictions'),
    })
  const predictions: Prediction[] = predictionsResp?.predictions ?? []

  // The button posted to /admin/predictive/generate. The route is
  // /admin/predictive/predictions/generate, so every click 404'd — and the
  // handler swallowed it with `catch {}` while a setInterval driven by
  // Math.random() walked a progress bar to 100% and announced 「予測完了」.
  // The path is correct now and a failure is shown rather than animated over.
  const handleGenerate = async () => {
    setGenerating(true)
    setGenerateError(null)
    setGenerateProgress(0)
    const interval = setInterval(() => {
      setGenerateProgress(p => (p >= 90 ? p : p + 10))
    }, 300)
    try {
      await apiFetch('/api/v1/admin/predictive/predictions/generate', { method: 'POST' })
      setGenerateProgress(100)
      await qc.invalidateQueries({ queryKey: ['predictive-predictions'] })
      await qc.invalidateQueries({ queryKey: ['predictive-models'] })
    } catch (e) {
      setGenerateError(e instanceof Error ? e.message : '予測の生成に失敗しました')
      setGenerateProgress(0)
    } finally {
      clearInterval(interval)
      setTimeout(() => { setGenerating(false); setGenerateProgress(0) }, 800)
    }
  }

  const modelIcons = [<TrendingUp key="1" className="w-5 h-5" />, <Shield key="2" className="w-5 h-5" />, <AlertTriangle key="3" className="w-5 h-5" />, <Activity key="4" className="w-5 h-5" />]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <TrendingUp className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">予測的セキュリティ分析</h1>
            <p className="text-xs text-[#7d92b0]">AIモデルによる将来リスク予測</p>
          </div>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors disabled:opacity-60"
        >
          {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
          予測を生成
        </button>
      </div>

      {/* Generate progress */}
      {generating && (
        <div className="bg-[#0d1220] border border-[#e8002d]/30 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm text-white font-medium">予測モデルを実行中...</p>
            <span className="text-xs text-[#e8002d]">{Math.round(generateProgress)}%</span>
          </div>
          <div className="w-full h-2 bg-[#1e2d42] rounded-full overflow-hidden">
            <div
              className="h-full bg-linear-to-r from-[#e8002d] to-red-400 rounded-full transition-all duration-300"
              style={{ width: `${generateProgress}%` }}
            />
          </div>
          <p className="text-xs text-[#7d92b0] mt-1">
            {generateProgress < 50 ? 'データ収集中...' : generateProgress < 100 ? 'モデル推論中...' : '予測完了'}
          </p>
        </div>
      )}

      {generateError && (
        <div className="bg-[#0d1220] border border-red-500/40 rounded-xl p-4">
          <p className="text-sm text-red-300">予測の生成に失敗しました: {generateError}</p>
        </div>
      )}

      {/* Model status cards */}
      {modelsError ? (
        <div className="bg-[#0d1220] border border-red-500/40 rounded-xl p-4">
          <p className="text-sm text-red-300">モデル情報を取得できませんでした</p>
        </div>
      ) : modelsLoading ? (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-sm text-[#7d92b0]">モデル情報を読み込み中...</p>
        </div>
      ) : models.length === 0 ? (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-sm text-[#7d92b0]">利用可能なモデルがありません</p>
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {models.map((m, i) => (
            <div key={m.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-start justify-between mb-3">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${m.status === 'ready' ? 'bg-green-500/10 text-green-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                  {modelIcons[i % modelIcons.length]}
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-sm font-medium ${modelStatusColor[m.status]}`}>
                  {modelStatusLabel[m.status]}
                </span>
              </div>
              <p className="text-sm text-white font-medium mb-0.5">{m.name}</p>
              <p className="text-[11px] text-[#7d92b0] mb-3">{m.description}</p>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-[#7d92b0]">アルゴリズム</p>
                  <p className="text-[13px] font-medium text-white">{m.algorithm}</p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] text-[#3d5068]">最終更新</p>
                  <p className="text-[11px] text-[#7d92b0]">{timeAgo(m.lastTrained)}</p>
                </div>
              </div>
              <div className="mt-2 flex items-center justify-between text-[11px]">
                <span className="text-[#3d5068]">学習サンプル</span>
                <span className="text-[#7d92b0]">{m.trainingSamples.toLocaleString()}</span>
              </div>
              <p className="mt-1 text-[10px] text-[#3d5068]">v{m.version}</p>
            </div>
          ))}
        </div>
      )}

      {/* Predictions */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <p className="text-sm font-medium text-white mb-4">リスク予測</p>
        {predictionsError ? (
          <p className="text-sm text-red-300">予測を取得できませんでした</p>
        ) : predictionsLoading ? (
          <p className="text-sm text-[#7d92b0]">読み込み中...</p>
        ) : predictions.length === 0 ? (
          <p className="text-sm text-[#7d92b0]">予測がありません</p>
        ) : (
          <div className="space-y-3">
            {predictions.map(p => (
              <div key={p.id} className={`border rounded-xl p-4 ${priorityColor[p.severity] ?? 'border-[#1e2d42]'}`}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className={`text-[11px] font-medium px-2 py-0.5 rounded-sm ${priorityBadge[p.severity] ?? 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                      {priorityLabel[p.severity] ?? p.severity}
                    </span>
                    <p className="text-sm text-white font-medium">{p.model_name}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-bold text-white">{Math.round(p.predicted_value * 100)}%</p>
                    <p className="text-[10px] text-[#3d5068]">{p.prediction_horizon} · 信頼度 {Math.round(p.confidence_score * 100)}%</p>
                  </div>
                </div>
                <p className="text-xs text-[#7d92b0] leading-relaxed mb-1.5">{p.recommendation}</p>
                <div className="flex flex-wrap gap-1.5">
                  {p.contributing_factors.map(f => (
                    <span key={f} className="text-[10px] text-[#7d92b0] bg-[#1e2d42] rounded-sm px-2 py-0.5">{f}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Volume Forecast Chart */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-sm font-medium text-white">アラート量予測 (今後30日)</p>
            <p className="text-xs text-[#7d92b0]">信頼区間80% · 赤線=予測, 帯域=上下限</p>
          </div>
          <div className="flex items-center gap-3 text-xs text-[#7d92b0]">
            <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-[#e8002d]" /><span>予測</span></div>
            <div className="flex items-center gap-1.5"><div className="w-4 h-2 bg-[#e8002d]/20 rounded-xs" /><span>信頼区間</span></div>
          </div>
        </div>
        {/* この予測を返すエンドポイントはまだ無い。以前は predictions レスポンスの
            volume_forecast キーを読んでいたが、API はそのキーを返したことがない。 */}
        <VolumeChart data={[]} />
      </div>

      {/* Endpoint breach risk */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <p className="text-sm font-medium text-white mb-4">侵害リスクスコア (上位10エンドポイント)</p>
        <div className="space-y-2.5">
          {([] as EndpointRisk[]).map(ep => (
            <div key={ep.host} className="flex items-center gap-3">
              <p className="text-xs font-mono text-[#e2e8f4] w-36 shrink-0">{ep.host}</p>
              <div className="flex-1 relative">
                <div className="w-full h-5 bg-[#1e2d42] rounded-sm overflow-hidden">
                  <div
                    className={`h-full rounded-sm transition-all duration-500 ${ep.score >= 80 ? 'bg-red-500' : ep.score >= 60 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                    style={{ width: `${ep.score}%` }}
                  />
                </div>
              </div>
              <div className="flex items-center gap-2 w-24 shrink-0">
                <span className={`text-sm font-bold ${ep.score >= 80 ? 'text-red-400' : ep.score >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>
                  {ep.score}
                </span>
                <span className={`text-[10px] ${ep.trend === 'up' ? 'text-red-400' : ep.trend === 'down' ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                  {ep.trend === 'up' ? '↑' : ep.trend === 'down' ? '↓' : '→'}
                </span>
                <span className="text-[10px] text-[#3d5068] truncate">{ep.risk_factors[0]}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Vuln trend */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-sm font-medium text-white">脆弱性露出トレンド (過去30日 + 30日予測)</p>
            <p className="text-xs text-[#7d92b0]">青=実績, 赤点線=予測投影</p>
          </div>
        </div>
        <VulnTrendChart data={[]} />
      </div>

      {/* Recommended actions */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <p className="text-sm font-medium text-white mb-4">AI推奨アクション ({([] as RecommendedAction[]).length}件)</p>
        <div className="space-y-3">
          {([] as RecommendedAction[]).map(a => (
            <div key={a.id} className={`border rounded-xl p-4 ${priorityColor[a.priority]}`}>
              <div className="flex items-start gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[11px] font-medium px-2 py-0.5 rounded-sm ${priorityBadge[a.priority]}`}>{priorityLabel[a.priority]}</span>
                    <p className="text-sm text-white font-medium">{a.title}</p>
                  </div>
                  <p className="text-xs text-[#7d92b0] leading-relaxed mb-1.5">{a.description}</p>
                  <div className="flex items-center gap-3 text-[11px]">
                    <span className="text-[#3d5068]">モデル: <span className="text-[#7d92b0]">{a.model_source}</span></span>
                    <span className="text-[#3d5068]">信頼度: <span className="text-white font-medium">{a.confidence}%</span></span>
                  </div>
                </div>
                <button className="flex items-center gap-1 px-3 py-1.5 text-xs text-white bg-[#e8002d]/80 hover:bg-[#e8002d] rounded-lg transition-colors shrink-0">
                  <ChevronRight className="w-3.5 h-3.5" /> 対応
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom row: Accuracy + Feature Importance */}
      <div className="grid grid-cols-2 gap-4">
        {/* Accuracy chart */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm font-medium text-white">精度追跡 (過去30日)</p>
            <div className="flex items-center gap-3 text-xs text-[#7d92b0]">
              <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-[#e8002d]" style={{ borderTop: '2px dashed #e8002d' }} /><span>予測</span></div>
              <div className="flex items-center gap-1.5"><div className="w-4 h-0.5 bg-blue-400" /><span>実績</span></div>
            </div>
          </div>
          <AccuracyChart data={[]} />
        </div>

        {/* Feature importance */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <p className="text-sm font-medium text-white mb-4">特徴量重要度</p>
          <div className="space-y-2.5">
            {([] as FeatureImportance[]).map(f => (
              <div key={f.feature} className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-0.5">
                    <p className="text-xs text-[#e2e8f4] truncate">{f.feature}</p>
                    <span className="text-[11px] text-[#7d92b0] ml-2 shrink-0">{Math.round(f.importance * 100)}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className="h-full bg-[#e8002d] rounded-full" style={{ width: `${f.importance * 100}%` }} />
                  </div>
                </div>
                <span className="text-[10px] text-[#3d5068] w-20 text-right shrink-0">{f.category}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
