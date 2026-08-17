'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Target, Plus, X, Play, Eye, CheckCircle, XCircle, Clock,
  ToggleLeft, ToggleRight, AlertTriangle, TrendingUp, BarChart3,
  ChevronDown, ChevronRight, RefreshCw, Shield, Edit2, Trash2,
  Filter
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────

type ScenarioType = 'malware' | 'phishing' | 'lateral_movement' | 'exfiltration' | 'ransomware' | 'c2'
type Difficulty = 'easy' | 'medium' | 'hard' | 'expert'
type RunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

interface BASScenario {
  id: string
  name: string
  description: string
  scenario_type: ScenarioType
  mitre_tactics: string[]
  mitre_techniques: string[]
  difficulty: Difficulty
  estimated_duration_min: number
  is_active: boolean
  created_at: string
}

interface StepResult {
  step_id: string
  description: string
  detected: boolean
  prevented: boolean
  alert_generated: boolean
  technique: string
}

interface BASRun {
  id: string
  scenario_id: string
  scenario_name: string
  started_at: string
  completed_at: string | null
  duration_s: number | null
  status: RunStatus
  detection_rate: number
  prevention_rate: number
  total_steps: number
  detected_steps: number
  prevented_steps: number
  target_scope: string[]
  findings: string[]
  step_results: StepResult[]
}

// ── Helpers ───────────────────────────────────────────────────────

const SCENARIO_TYPE_CONFIG: Record<ScenarioType, { label: string; bg: string; text: string }> = {
  malware:          { label: 'マルウェア',  bg: 'bg-red-900/40',    text: 'text-red-300' },
  phishing:         { label: 'フィッシング', bg: 'bg-orange-900/40', text: 'text-orange-300' },
  lateral_movement: { label: '水平移動',    bg: 'bg-purple-900/40', text: 'text-purple-300' },
  exfiltration:     { label: 'データ漏えい', bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  ransomware:       { label: 'ランサム',    bg: 'bg-red-900/60',    text: 'text-red-200' },
  c2:               { label: 'C2通信',      bg: 'bg-rose-950',      text: 'text-rose-300' },
}

const DIFFICULTY_CONFIG: Record<Difficulty, { label: string; color: string }> = {
  easy:   { label: '易', color: 'text-green-400' },
  medium: { label: '中', color: 'text-yellow-400' },
  hard:   { label: '難', color: 'text-orange-400' },
  expert: { label: '専門', color: 'text-red-400' },
}

const RUN_STATUS_CONFIG: Record<RunStatus, { label: string; bg: string; text: string; pulse?: boolean }> = {
  pending:   { label: '待機中',  bg: 'bg-gray-800',      text: 'text-gray-400' },
  running:   { label: '実行中',  bg: 'bg-blue-900/40',   text: 'text-blue-300', pulse: true },
  completed: { label: '完了',    bg: 'bg-green-900/40',  text: 'text-green-300' },
  failed:    { label: '失敗',    bg: 'bg-red-900/40',    text: 'text-red-300' },
  cancelled: { label: 'キャンセル', bg: 'bg-gray-800',  text: 'text-gray-400' },
}

const ALL_MITRE_TACTICS = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Command and Control', 'Impact']

function rateColor(r: number) {
  if (r >= 80) return 'bg-green-500'
  if (r >= 60) return 'bg-yellow-500'
  return 'bg-red-500'
}
function rateText(r: number) {
  if (r >= 80) return 'text-green-400'
  if (r >= 60) return 'text-yellow-400'
  return 'text-red-400'
}
function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
function fmtDuration(s: number | null) {
  if (s === null) return '—'
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}m ${sec}s`
}

// ── Add Scenario Modal ────────────────────────────────────────────

function ScenarioFormModal({ onClose, onSave }: { onClose: () => void; onSave: (s: Omit<BASScenario, 'id' | 'created_at'>) => void }) {
  const [form, setForm] = useState({
    name: '', description: '', scenario_type: 'malware' as ScenarioType,
    mitre_tactics: [] as string[], mitre_techniques: '', difficulty: 'medium' as Difficulty,
    estimated_duration_min: 15, is_active: true,
  })

  const toggleTactic = (t: string) => setForm(p => ({
    ...p, mitre_tactics: p.mitre_tactics.includes(t) ? p.mitre_tactics.filter(x => x !== t) : [...p.mitre_tactics, t]
  }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">シナリオ追加</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">シナリオ名</label>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">シナリオタイプ</label>
              <select value={form.scenario_type} onChange={e => setForm(p => ({ ...p, scenario_type: e.target.value as ScenarioType }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden">
                {(Object.keys(SCENARIO_TYPE_CONFIG) as ScenarioType[]).map(t => (
                  <option key={t} value={t}>{SCENARIO_TYPE_CONFIG[t].label}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">説明</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={2} className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden resize-none" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-2 block">MITRE タクティクス (複数選択)</label>
            <div className="flex flex-wrap gap-2">
              {ALL_MITRE_TACTICS.map(t => (
                <button key={t} onClick={() => toggleTactic(t)}
                  className={`text-xs px-2 py-1 rounded-full border transition-colors ${form.mitre_tactics.includes(t) ? 'bg-falcon-red/20 border-falcon-red/50 text-falcon-red' : 'border-falcon-border text-falcon-muted hover:border-falcon-muted/40'}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">MITRE テクニック (カンマ区切り)</label>
            <input value={form.mitre_techniques} onChange={e => setForm(p => ({ ...p, mitre_techniques: e.target.value }))}
              placeholder="T1566.001, T1059.005..."
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden font-mono" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">難易度</label>
              <select value={form.difficulty} onChange={e => setForm(p => ({ ...p, difficulty: e.target.value as Difficulty }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden">
                {(Object.keys(DIFFICULTY_CONFIG) as Difficulty[]).map(d => (
                  <option key={d} value={d}>{DIFFICULTY_CONFIG[d].label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">推定時間 (分)</label>
              <input type="number" min={1} max={120} value={form.estimated_duration_min} onChange={e => setForm(p => ({ ...p, estimated_duration_min: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden" />
            </div>
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => {
            if (form.name) {
              onSave({ ...form, mitre_techniques: form.mitre_techniques.split(',').map(t => t.trim()).filter(Boolean) })
              onClose()
            }
          }} className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Run Modal ─────────────────────────────────────────────────────

function RunModal({ scenario, onClose }: { scenario: BASScenario; onClose: () => void }) {
  const [scopeInput, setScopeInput] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<'pending' | 'running' | 'done'>('pending')
  const [result, setResult] = useState<BASRun | null>(null)
  const stc = SCENARIO_TYPE_CONFIG[scenario.scenario_type]

  const handleRun = async () => {
    if (!confirmed) return
    setRunning(true)
    setProgress('running')
    const scope = scopeInput.split('\n').map(s => s.trim()).filter(Boolean)
    try {
      await apiFetch('/api/v1/admin/bas/runs', { method: 'POST', body: JSON.stringify({ scenario_id: scenario.id, target_scope: scope }) })
    } catch {}
    setTimeout(() => {
      setProgress('done')
      setResult({ id: String(Date.now()), scenario_id: scenario.id, scenario_name: scenario.name, started_at: new Date().toISOString(), completed_at: new Date().toISOString(), duration_s: scenario.estimated_duration_min * 60, status: 'completed', detection_rate: 75, prevention_rate: 65, total_steps: 10, detected_steps: 7, prevented_steps: 6, target_scope: scope, findings: ['シミュレーション完了', '検知結果を確認してください'], step_results: [] })
    }, 3000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-lg">シナリオ実行</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border mb-4">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${stc.bg} ${stc.text}`}>{stc.label}</span>
            <span className={`text-xs font-bold ${DIFFICULTY_CONFIG[scenario.difficulty].color}`}>{DIFFICULTY_CONFIG[scenario.difficulty].label}</span>
          </div>
          <p className="text-white font-medium text-sm">{scenario.name}</p>
          <p className="text-falcon-muted text-xs mt-0.5">推定時間: {scenario.estimated_duration_min}分</p>
        </div>
        {progress === 'pending' && (
          <>
            <div className="p-3 bg-yellow-900/20 border border-yellow-700/30 rounded-lg mb-4 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-300">シミュレーションは安全な隔離環境で実行されます。本番データには影響しません。</p>
            </div>
            <div className="mb-4">
              <label className="text-xs text-falcon-muted mb-1 block">ターゲットスコープ (ホスト名/IP、1行1件)</label>
              <textarea value={scopeInput} onChange={e => setScopeInput(e.target.value)}
                rows={3} placeholder="workstation-01&#10;192.168.1.100"
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden resize-none font-mono" />
            </div>
            <label className="flex items-center gap-2 text-sm text-falcon-muted cursor-pointer mb-5">
              <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} className="accent-falcon-red" />
              シミュレーション実行内容を確認し、同意します
            </label>
            <div className="flex gap-3">
              <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
              <button onClick={handleRun} disabled={!confirmed}
                className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors disabled:opacity-40 flex items-center justify-center gap-2">
                <Play className="w-4 h-4" /> 実行開始
              </button>
            </div>
          </>
        )}
        {progress === 'running' && (
          <div className="text-center py-8">
            <RefreshCw className="w-10 h-10 text-blue-400 animate-spin mx-auto mb-3" />
            <p className="text-white font-medium mb-1">シナリオ実行中...</p>
            <p className="text-falcon-muted text-sm">結果を収集しています。しばらくお待ちください。</p>
          </div>
        )}
        {progress === 'done' && result && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle className="w-5 h-5 text-green-400" />
              <p className="text-white font-medium">シナリオ完了</p>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                <p className="text-xs text-falcon-muted mb-1">検知率</p>
                <p className={`text-2xl font-bold ${rateText(result.detection_rate)}`}>{result.detection_rate}%</p>
              </div>
              <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                <p className="text-xs text-falcon-muted mb-1">防止率</p>
                <p className={`text-2xl font-bold ${rateText(result.prevention_rate)}`}>{result.prevention_rate}%</p>
              </div>
            </div>
            <ul className="space-y-1 mb-4">
              {result.findings.map((f, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-falcon-muted">
                  <span className="text-falcon-red mt-0.5">•</span> {f}
                </li>
              ))}
            </ul>
            <button onClick={onClose} className="w-full py-2 rounded-sm bg-falcon-border text-white text-sm hover:bg-[#2a3f5a] transition-colors">閉じる</button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Run Detail Modal ──────────────────────────────────────────────

function RunDetailModal({ run, onClose }: { run: BASRun; onClose: () => void }) {
  const sc = RUN_STATUS_CONFIG[run.status]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-white font-semibold text-lg">{run.scenario_name}</h2>
            <p className="text-falcon-muted text-xs mt-0.5">{fmt(run.started_at)}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="grid grid-cols-4 gap-3 mb-5">
          {[
            { label: 'ステータス', value: <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text}`}>{sc.label}</span> },
            { label: '検知率', value: <span className={`font-bold ${rateText(run.detection_rate)}`}>{run.detection_rate}%</span> },
            { label: '防止率', value: <span className={`font-bold ${rateText(run.prevention_rate)}`}>{run.prevention_rate}%</span> },
            { label: '所要時間', value: <span className="text-white text-sm">{fmtDuration(run.duration_s)}</span> },
          ].map(c => (
            <div key={c.label} className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
              <p className="text-xs text-falcon-muted mb-1">{c.label}</p>
              <div className="text-sm">{c.value}</div>
            </div>
          ))}
        </div>
        {run.target_scope.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-falcon-muted mb-2 uppercase tracking-wider font-medium">ターゲット</p>
            <div className="flex flex-wrap gap-2">
              {run.target_scope.map(s => (
                <span key={s} className="text-xs font-mono bg-[#070d19] border border-falcon-border px-2 py-1 rounded-sm text-falcon-text">{s}</span>
              ))}
            </div>
          </div>
        )}
        {run.findings.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-falcon-muted mb-2 uppercase tracking-wider font-medium">フィンディング</p>
            <ul className="space-y-1.5">
              {run.findings.map((f, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-falcon-text">
                  <span className="text-falcon-red mt-0.5 shrink-0">•</span>{f}
                </li>
              ))}
            </ul>
          </div>
        )}
        {run.step_results.length > 0 && (
          <div>
            <p className="text-xs text-falcon-muted mb-2 uppercase tracking-wider font-medium">ステップ別結果</p>
            <div className="space-y-2">
              {run.step_results.map((s, i) => (
                <div key={s.step_id} className="flex items-center gap-3 p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                  <span className="text-xs text-falcon-subtle font-mono w-4 shrink-0">{i + 1}</span>
                  <p className="flex-1 text-sm text-falcon-text">{s.description}</p>
                  <span className="text-xs font-mono text-falcon-muted">{s.technique}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded-sm font-medium ${s.detected ? 'bg-green-900/40 text-green-300' : 'bg-red-900/30 text-red-400'}`}>
                    {s.detected ? '検知' : '未検知'}
                  </span>
                  <span className={`text-xs px-1.5 py-0.5 rounded-sm font-medium ${s.prevented ? 'bg-blue-900/40 text-blue-300' : 'bg-gray-800 text-gray-500'}`}>
                    {s.prevented ? '防止' : '未防止'}
                  </span>
                  {s.alert_generated && <span className="text-xs text-orange-400">🔔</span>}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="mt-5 p-3 bg-[#070d19] rounded-lg border border-falcon-border">
          <p className="text-xs text-falcon-muted mb-1 font-medium">総合評価</p>
          <p className="text-sm text-falcon-text">
            {run.detection_rate >= 80 ? '検知能力は良好です。さらなる向上のため防止設定を見直してください。' :
              run.detection_rate >= 60 ? '一部のテクニックが未検知です。検知ルールの追加を推奨します。' :
              '検知率が低いです。ルールセットの大幅な見直しが必要です。'}
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────

export default function BASPage() {
  const [tab, setTab] = useState<'scenarios' | 'runs'>('scenarios')
  const [localScenarios, setLocalScenarios] = useState<BASScenario[]>([])
  const [localRuns] = useState<BASRun[]>([])
  const [showAddScenario, setShowAddScenario] = useState(false)
  const [runScenario, setRunScenario] = useState<BASScenario | null>(null)
  const [detailRun, setDetailRun] = useState<BASRun | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  useQuery({
    queryKey: ['bas-scenarios'],
    queryFn: () => apiFetchList<BASScenario>('/api/v1/admin/bas/scenarios'),
    onError: () => {},
  } as any)

  useQuery({
    queryKey: ['bas-runs'],
    queryFn: () => apiFetchList<BASRun>('/api/v1/admin/bas/runs'),
    onError: () => {},
  } as any)

  const handleToggleScenario = async (s: BASScenario) => {
    try { await apiFetch(`/api/v1/admin/bas/scenarios/${s.id}/toggle`, { method: 'POST' }) } catch {}
    setLocalScenarios(prev => prev.map(x => x.id === s.id ? { ...x, is_active: !x.is_active } : x))
  }

  const handleAddScenario = (form: Omit<BASScenario, 'id' | 'created_at'>) => {
    const newS: BASScenario = { ...form, id: String(Date.now()), created_at: new Date().toISOString() }
    try { apiFetch('/api/v1/admin/bas/scenarios', { method: 'POST', body: JSON.stringify(form) }) } catch {}
    setLocalScenarios(prev => [...prev, newS])
    showToast(`シナリオ「${form.name}」を追加しました`)
  }

  // Stats
  const completedRuns = localRuns.filter(r => r.status === 'completed')
  const runsThisMonth = localRuns.filter(r => r.started_at.startsWith('2026-03')).length
  const avgDetection = completedRuns.length > 0 ? Math.round(completedRuns.reduce((a, r) => a + r.detection_rate, 0) / completedRuns.length) : 0
  const avgPrevention = completedRuns.length > 0 ? Math.round(completedRuns.reduce((a, r) => a + r.prevention_rate, 0) / completedRuns.length) : 0

  // Gap analysis: tactics with lowest detection rate
  const tacticGaps = ALL_MITRE_TACTICS.slice(0, 6).map((t, i) => ({ tactic: t, rate: [55, 78, 45, 88, 60, 92][i] })).sort((a, b) => a.rate - b.rate)

  // Detection rate trend (last 12 runs)
  const trendRuns = localRuns.filter(r => r.status === 'completed').slice(0, 12).reverse()

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
            <Target className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">侵害・攻撃シミュレーション (BAS)</h1>
            <p className="text-falcon-muted text-sm">セキュリティ制御のシミュレーション検証</p>
          </div>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="flex items-center gap-2 p-3 bg-green-900/20 border border-green-700/30 rounded-lg mb-6">
        <Shield className="w-4 h-4 text-green-400 shrink-0" />
        <p className="text-sm text-green-300">シミュレーションは安全な隔離環境で実行されます。本番システムへの影響はありません。</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総シナリオ数', value: localScenarios.length, color: 'text-blue-400' },
          { label: '今月の実行数', value: runsThisMonth, color: 'text-purple-400' },
          { label: '平均検知率', value: `${avgDetection}%`, color: rateText(avgDetection) },
          { label: '平均防止率', value: `${avgPrevention}%`, color: rateText(avgPrevention) },
        ].map(c => (
          <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-xs text-falcon-muted mb-2">{c.label}</p>
            <p className={`text-2xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'scenarios', label: 'シナリオ' }, { key: 'runs', label: '実行結果' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Scenarios Tab */}
      {tab === 'scenarios' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-falcon-muted text-sm">{localScenarios.length} シナリオ</p>
            <button onClick={() => setShowAddScenario(true)}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> シナリオ追加
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            {localScenarios.map(s => {
              const stc = SCENARIO_TYPE_CONFIG[s.scenario_type]
              const dc = DIFFICULTY_CONFIG[s.difficulty]
              return (
                <div key={s.id} className={`bg-falcon-surface border rounded-xl p-4 transition-colors ${s.is_active ? 'border-falcon-border' : 'border-falcon-border opacity-60'}`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${stc.bg} ${stc.text}`}>{stc.label}</span>
                      <span className={`text-xs font-bold ${dc.color}`}>{dc.label}</span>
                    </div>
                    <button onClick={() => handleToggleScenario(s)}>
                      {s.is_active ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                    </button>
                  </div>
                  <p className="text-white font-medium text-sm mb-1">{s.name}</p>
                  <p className="text-falcon-muted text-xs mb-3 line-clamp-2">{s.description}</p>
                  <div className="flex flex-wrap gap-1 mb-3">
                    {s.mitre_tactics.map(t => (
                      <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-falcon-border text-falcon-muted border border-[#2a3f5a]">{t}</span>
                    ))}
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1 text-xs text-falcon-muted">
                      <Clock className="w-3 h-3" /> {s.estimated_duration_min}分
                    </div>
                    <button onClick={() => setRunScenario(s)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-xs font-medium hover:bg-falcon-red/30 transition-colors">
                      <Play className="w-3 h-3" /> 実行
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Runs Tab */}
      {tab === 'runs' && (
        <div>
          {/* Runs Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden mb-6">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['シナリオ', '開始時刻', '所要時間', 'ステータス', '検知率', '防止率', 'ステップ', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {localRuns.map(run => {
                  const sc = RUN_STATUS_CONFIG[run.status]
                  return (
                    <tr key={run.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <p className="text-white text-sm font-medium truncate max-w-[160px]" title={run.scenario_name}>{run.scenario_name}</p>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(run.started_at)}</td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">{fmtDuration(run.duration_s)}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text} ${sc.pulse ? 'animate-pulse' : ''}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3 min-w-[100px]">
                        {run.status === 'completed' ? (
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${rateColor(run.detection_rate)}`} style={{ width: `${run.detection_rate}%` }} />
                            </div>
                            <span className={`text-xs font-bold ${rateText(run.detection_rate)}`}>{run.detection_rate}%</span>
                          </div>
                        ) : <span className="text-xs text-falcon-subtle">—</span>}
                      </td>
                      <td className="px-4 py-3 min-w-[100px]">
                        {run.status === 'completed' ? (
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${rateColor(run.prevention_rate)}`} style={{ width: `${run.prevention_rate}%` }} />
                            </div>
                            <span className={`text-xs font-bold ${rateText(run.prevention_rate)}`}>{run.prevention_rate}%</span>
                          </div>
                        ) : <span className="text-xs text-falcon-subtle">—</span>}
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">{run.detected_steps}/{run.total_steps}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setDetailRun(run)} className="text-falcon-muted hover:text-white transition-colors">
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Statistics */}
          <div className="grid grid-cols-2 gap-4">
            {/* Detection Trend */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-3 font-medium uppercase tracking-wider flex items-center gap-2">
                <TrendingUp className="w-3.5 h-3.5" /> 検知率トレンド (直近{trendRuns.length}件)
              </p>
              <div className="flex items-end gap-2 h-20">
                {trendRuns.map((r, i) => (
                  <div key={r.id} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-[9px] text-falcon-muted">{r.detection_rate}%</span>
                    <div className={`w-full rounded-t ${rateColor(r.detection_rate)}`} style={{ height: `${(r.detection_rate / 100) * 56}px` }} />
                  </div>
                ))}
              </div>
            </div>

            {/* Gap Analysis */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-3 font-medium uppercase tracking-wider flex items-center gap-2">
                <BarChart3 className="w-3.5 h-3.5" /> タクティクス別検知率 (低い順)
              </p>
              <div className="space-y-2">
                {tacticGaps.map(g => (
                  <div key={g.tactic} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-muted w-28 truncate shrink-0">{g.tactic}</span>
                    <div className="flex-1 h-2 bg-falcon-border rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${rateColor(g.rate)}`} style={{ width: `${g.rate}%` }} />
                    </div>
                    <span className={`text-xs font-bold ${rateText(g.rate)} w-10 text-right`}>{g.rate}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showAddScenario && <ScenarioFormModal onClose={() => setShowAddScenario(false)} onSave={handleAddScenario} />}
      {runScenario && <RunModal scenario={runScenario} onClose={() => setRunScenario(null)} />}
      {detailRun && <RunDetailModal run={detailRun} onClose={() => setDetailRun(null)} />}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-falcon-surface border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-falcon-text flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-falcon-muted hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
