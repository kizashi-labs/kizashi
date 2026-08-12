'use client'

import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  PlayCircle, Plus, Pencil, Trash2, X, Clock, Users,
  CheckCircle, AlertCircle, ChevronDown, ChevronRight,
  TrendingUp, TrendingDown, BarChart2, Award, Target,
  Calendar, User, Zap, BookOpen, Flag, Timer, ArrowRight,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type DrillType = 'tabletop' | 'technical' | 'communication' | 'full_scale'
type DrillStatus = 'draft' | 'scheduled' | 'in_progress' | 'completed'

interface ScenarioInject {
  id: string
  time_offset: number // minutes from start
  label: string
  description: string
  revealed?: boolean
}

interface ScoringCriteria {
  id: string
  category: string
  description: string
  max_points: number
  checked?: boolean
}

interface Drill {
  id: string
  name: string
  drill_type: DrillType
  scenario: string
  scenario_template: string
  status: DrillStatus
  scheduled_at: string
  participants_count: number
  participants: string[]
  facilitator: string
  objectives: string[]
  is_timed: boolean
  duration_minutes: number
  overall_score?: number
  key_findings?: string
  best_performer?: string
  areas_for_improvement?: string[]
  score_breakdown?: Record<string, number>
}

const SCENARIO_INJECTS: ScenarioInject[] = [
  { id: 'inj-1', time_offset: 0, label: 'アラート検知', description: 'SIEMで高深刻度アラートが発生。エンドポイントでの不審な挙動を確認。' },
  { id: 'inj-2', time_offset: 15, label: '横展開の証拠', description: '攻撃者がネットワーク内を横展開している痕跡を発見。' },
  { id: 'inj-3', time_offset: 30, label: 'データ流出の疑い', description: '大量データが外部IPへ転送されていることを確認。' },
  { id: 'inj-4', time_offset: 45, label: 'C2通信の特定', description: 'C2サーバーとの通信を特定。IOCをTIプラットフォームで確認。' },
  { id: 'inj-5', time_offset: 60, label: '封じ込め判断', description: '影響範囲を特定し封じ込め措置を決定する。' },
]

const SCORING_RUBRIC: ScoringCriteria[] = [
  { id: 'sc-1', category: '検知', description: 'アラートを15分以内に確認・分類できたか', max_points: 20 },
  { id: 'sc-2', category: '封じ込め', description: '適切な封じ込め措置を30分以内に実施できたか', max_points: 25 },
  { id: 'sc-3', category: '調査', description: '根本原因の特定と影響範囲の把握ができたか', max_points: 25 },
  { id: 'sc-4', category: 'コミュニケーション', description: 'エスカレーションと関係者への通知が適切だったか', max_points: 15 },
  { id: 'sc-5', category: '復旧', description: '復旧手順を正しく実施できたか', max_points: 15 },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TYPE_BADGE: Record<DrillType, string> = {
  tabletop: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  technical: 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  communication: 'bg-green-500/10 text-green-400 border border-green-500/30',
  full_scale: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
}
const TYPE_LABEL: Record<DrillType, string> = {
  tabletop: '卓上訓練', technical: '技術訓練', communication: 'コミュニケーション', full_scale: '全規模訓練',
}
const STATUS_BADGE: Record<DrillStatus, string> = {
  draft: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
  scheduled: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  in_progress: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 animate-pulse',
  completed: 'bg-green-500/10 text-green-400 border border-green-500/30',
}
const STATUS_LABEL: Record<DrillStatus, string> = {
  draft: '下書き', scheduled: 'スケジュール済み', in_progress: '実施中', completed: '完了',
}

const SCENARIO_TEMPLATES = [
  { value: 'ransomware', label: 'ランサムウェア感染拡大' },
  { value: 'phishing', label: '標的型フィッシングメール' },
  { value: 'insider_threat', label: '内部不正アクセス' },
  { value: 'comm_failure', label: '通信インフラ障害' },
  { value: 'cloud_breach', label: 'クラウドインフラ侵害' },
  { value: 'ddos', label: '大規模DDoS攻撃' },
  { value: 'supply_chain', label: 'サプライチェーン攻撃' },
  { value: 'ai_threat', label: 'AI生成マルウェア' },
  { value: 'custom', label: 'カスタム' },
]

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function scoreColor(score: number): string {
  if (score >= 85) return 'text-green-400'
  if (score >= 70) return 'text-yellow-400'
  return 'text-red-400'
}

// ─── Drill Execution Modal ────────────────────────────────────────────────────

interface ExecutionModalProps {
  drill: Drill
  onClose: () => void
  onComplete: (drillId: string, score: number, breakdown: Record<string, number>) => void
}

function ExecutionModal({ drill, onClose, onComplete }: ExecutionModalProps) {
  const [injects, setInjects] = useState<ScenarioInject[]>(SCENARIO_INJECTS.map(i => ({ ...i, revealed: false })))
  const [rubric, setRubric] = useState<ScoringCriteria[]>(SCORING_RUBRIC.map(c => ({ ...c, checked: false })))
  const [elapsed, setElapsed] = useState(0)
  const [running, setRunning] = useState(false)
  const [responseLog, setResponseLog] = useState<{ time: number; action: string }[]>([])
  const [newAction, setNewAction] = useState('')
  const [expandRubric, setExpandRubric] = useState(false)
  const timerRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    if (running) {
      timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000)
    } else if (timerRef.current) {
      clearInterval(timerRef.current)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [running])

  const revealNextInject = () => {
    const nextIdx = injects.findIndex(i => !i.revealed)
    if (nextIdx !== -1) {
      setInjects(prev => prev.map((i, idx) => idx === nextIdx ? { ...i, revealed: true } : i))
    }
  }

  const addResponseLog = () => {
    if (newAction.trim()) {
      setResponseLog(l => [...l, { time: elapsed, action: newAction.trim() }])
      setNewAction('')
    }
  }

  const totalScore = rubric.filter(c => c.checked).reduce((acc, c) => acc + c.max_points, 0)
  const maxScore = rubric.reduce((acc, c) => acc + c.max_points, 0)

  const formatTime = (secs: number) => `${String(Math.floor(secs / 60)).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-5xl max-h-[95vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42] bg-[#070d19] rounded-t-xl">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <PlayCircle className="w-5 h-5 text-[#e8002d]" />
              <h2 className="text-white font-bold text-lg">{drill.name}</h2>
            </div>
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${TYPE_BADGE[drill.drill_type]}`}>{TYPE_LABEL[drill.drill_type]}</span>
          </div>
          <div className="flex items-center gap-4">
            {/* Timer */}
            <div className="flex items-center gap-2 bg-[#1e2d42] rounded-lg px-4 py-2">
              <Timer className="w-4 h-4 text-[#7d92b0]" />
              <span className="text-white font-mono font-bold text-xl">{formatTime(elapsed)}</span>
              <span className="text-[#7d92b0] text-xs">/ {drill.duration_minutes}分</span>
            </div>
            <button onClick={() => setRunning(r => !r)} className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${running ? 'bg-yellow-500/10 border border-yellow-500/30 text-yellow-400' : 'bg-green-500/10 border border-green-500/30 text-green-400'}`}>
              {running ? '一時停止' : 'タイマー開始'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-0 h-full">
          {/* Left: Scenario Injects */}
          <div className="col-span-1 border-r border-[#1e2d42] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-white font-semibold text-sm">シナリオインジェクト</h3>
              <button onClick={revealNextInject} className="flex items-center gap-1 px-2 py-1 bg-[#e8002d] text-white text-xs rounded hover:bg-[#c0001f] transition-colors">
                <Zap className="w-3 h-3" />次のイベント
              </button>
            </div>
            <div className="space-y-3">
              {injects.map((inject, idx) => (
                <div key={inject.id} className={`p-3 rounded-lg border transition-all ${inject.revealed ? 'border-[#e8002d]/30 bg-[#e8002d]/5' : 'border-[#1e2d42] bg-[#070d19] opacity-50'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs font-mono ${inject.revealed ? 'text-[#e8002d]' : 'text-[#3d5068]'}`}>T+{inject.time_offset}分</span>
                    {inject.revealed && <span className="text-[9px] bg-[#e8002d]/20 text-[#e8002d] px-1 rounded">公開済み</span>}
                  </div>
                  <p className={`text-xs font-medium mb-1 ${inject.revealed ? 'text-white' : 'text-[#3d5068]'}`}>{inject.label}</p>
                  {inject.revealed && <p className="text-[#7d92b0] text-xs">{inject.description}</p>}
                </div>
              ))}
            </div>
          </div>

          {/* Middle: Response Log */}
          <div className="col-span-1 border-r border-[#1e2d42] p-4">
            <h3 className="text-white font-semibold text-sm mb-3">対応ログ</h3>
            <div className="flex gap-2 mb-3">
              <input value={newAction} onChange={e => setNewAction(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') addResponseLog() }} placeholder="対応アクションを記録..." className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:border-[#e8002d]/50" />
              <button onClick={addResponseLog} className="px-2 py-2 bg-[#1e2d42] text-white rounded-lg hover:bg-[#243347] transition-colors">
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {responseLog.length === 0 && <p className="text-[#3d5068] text-xs text-center py-4">対応アクションを記録してください</p>}
              {responseLog.map((log, idx) => (
                <div key={idx} className="flex gap-2 p-2 bg-[#070d19] border border-[#1e2d42] rounded text-xs">
                  <span className="text-[#e8002d] font-mono flex-shrink-0">{formatTime(log.time)}</span>
                  <span className="text-white">{log.action}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Scoring Rubric */}
          <div className="col-span-1 p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-white font-semibold text-sm">採点ルーブリック</h3>
              <span className={`text-lg font-bold ${scoreColor((totalScore / maxScore) * 100)}`}>{totalScore}/{maxScore}</span>
            </div>
            <div className="mb-3 bg-[#070d19] rounded-full h-2">
              <div className="bg-[#e8002d] h-2 rounded-full transition-all duration-300" style={{ width: `${(totalScore / maxScore) * 100}%` }} />
            </div>
            <div className="space-y-2">
              {['検知 (Detection)', '封じ込め (Containment)', 'コミュニケーション (Communication)', 'ドキュメント (Documentation)'].map(cat => (
                <div key={cat}>
                  <p className="text-[#7d92b0] text-xs font-medium mb-1">{cat}</p>
                  {rubric.filter(c => c.category === cat).map(c => (
                    <label key={c.id} className="flex items-start gap-2 p-2 rounded hover:bg-[#070d19] cursor-pointer group">
                      <input type="checkbox" checked={c.checked} onChange={() => setRubric(r => r.map(x => x.id === c.id ? { ...x, checked: !x.checked } : x))} className="mt-0.5 accent-[#e8002d]" />
                      <div className="flex-1 min-w-0">
                        <p className={`text-xs ${c.checked ? 'text-white line-through' : 'text-[#7d92b0]'}`}>{c.description}</p>
                      </div>
                      <span className="text-[#3d5068] text-xs flex-shrink-0">{c.max_points}点</span>
                    </label>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-between items-center p-5 border-t border-[#1e2d42] bg-[#070d19] rounded-b-xl">
          <div className="flex items-center gap-4">
            <div className="text-sm">
              <span className="text-[#7d92b0]">参加者: </span>
              <span className="text-white">{drill.participants.join(', ')}</span>
            </div>
            <div className="text-sm">
              <span className="text-[#7d92b0]">ファシリテーター: </span>
              <span className="text-white">{drill.facilitator}</span>
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] text-sm hover:text-white rounded-lg hover:bg-[#1e2d42] transition-colors">閉じる</button>
            <button onClick={() => {
              const cats = Array.from(new Set(rubric.map(r => r.category)))
              const breakdown: Record<string, number> = {}
              for (const cat of cats) {
                const items = rubric.filter(r => r.category === cat)
                const got = items.filter(i => i.checked).reduce((a, c) => a + c.max_points, 0)
                const max = items.reduce((a, c) => a + c.max_points, 0)
                breakdown[cat] = max ? Math.round((got / max) * 100) : 0
              }
              const scorePct = maxScore ? Math.round((totalScore / maxScore) * 100) : 0
              onComplete(drill.id, scorePct, breakdown)
              onClose()
            }} className="px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors flex items-center gap-2">
              <Flag className="w-4 h-4" />訓練終了
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Create Drill Modal ───────────────────────────────────────────────────────

interface CreateDrillModalProps {
  onClose: () => void
  onSave: (data: Partial<Drill>) => void
}

function CreateDrillModal({ onClose, onSave }: CreateDrillModalProps) {
  const [form, setForm] = useState({
    name: '', drill_type: 'tabletop' as DrillType, scenario_template: 'ransomware',
    scenario: '', scheduled_at: '', facilitator: '',
    participants_input: '', participants: [] as string[],
    objectives_input: '', objectives: [] as string[],
    is_timed: true, duration_minutes: 60,
  })

  const addParticipant = () => {
    if (form.participants_input && !form.participants.includes(form.participants_input)) {
      setForm(f => ({ ...f, participants: [...f.participants, f.participants_input], participants_input: '' }))
    }
  }
  const addObjective = () => {
    if (form.objectives_input) {
      setForm(f => ({ ...f, objectives: [...f.objectives, f.objectives_input], objectives_input: '' }))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">新規訓練作成</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1 rounded hover:bg-[#1e2d42] transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">訓練名 *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="例: Q2 ランサムウェア対応訓練" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">訓練タイプ</label>
              <select value={form.drill_type} onChange={e => setForm(f => ({ ...f, drill_type: e.target.value as DrillType }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(Object.keys(TYPE_LABEL) as DrillType[]).map(t => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">シナリオテンプレート</label>
              <select value={form.scenario_template} onChange={e => setForm(f => ({ ...f, scenario_template: e.target.value, scenario: SCENARIO_TEMPLATES.find(s => s.value === e.target.value)?.label ?? '' }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {SCENARIO_TEMPLATES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">シナリオ説明</label>
            <input value={form.scenario} onChange={e => setForm(f => ({ ...f, scenario: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="シナリオの詳細..." />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">実施予定日時</label>
              <input type="datetime-local" value={form.scheduled_at} onChange={e => setForm(f => ({ ...f, scheduled_at: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">ファシリテーター</label>
              <input value={form.facilitator} onChange={e => setForm(f => ({ ...f, facilitator: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="担当者名" />
            </div>
          </div>
          {/* Participants */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">参加者・グループ</label>
            <div className="flex gap-2 mb-2">
              <input value={form.participants_input} onChange={e => setForm(f => ({ ...f, participants_input: e.target.value }))} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addParticipant() } }} className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="例: SOCチーム" />
              <button onClick={addParticipant} className="px-3 py-2 bg-[#1e2d42] text-white rounded-lg text-sm hover:bg-[#243347] transition-colors">追加</button>
            </div>
            <div className="flex flex-wrap gap-2">
              {form.participants.map(p => (
                <span key={p} className="flex items-center gap-1 px-2 py-1 bg-[#1e2d42] rounded text-xs text-white">
                  {p}<button onClick={() => setForm(f => ({ ...f, participants: f.participants.filter(x => x !== p) }))} className="text-[#7d92b0] hover:text-[#e8002d] ml-1"><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>
          {/* Objectives */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">訓練目標</label>
            <div className="flex gap-2 mb-2">
              <input value={form.objectives_input} onChange={e => setForm(f => ({ ...f, objectives_input: e.target.value }))} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addObjective() } }} className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="例: 感染端末の隔離手順確認" />
              <button onClick={addObjective} className="px-3 py-2 bg-[#1e2d42] text-white rounded-lg text-sm hover:bg-[#243347] transition-colors">追加</button>
            </div>
            <div className="space-y-1">
              {form.objectives.map((o, i) => (
                <div key={i} className="flex items-center gap-2 px-2 py-1 bg-[#070d19] border border-[#1e2d42] rounded text-xs">
                  <span className="text-white flex-1">{o}</span>
                  <button onClick={() => setForm(f => ({ ...f, objectives: f.objectives.filter((_, idx) => idx !== i) }))} className="text-[#7d92b0] hover:text-[#e8002d]"><X className="w-3 h-3" /></button>
                </div>
              ))}
            </div>
          </div>
          {/* Duration */}
          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 text-sm text-[#7d92b0] cursor-pointer">
              <input type="checkbox" checked={form.is_timed} onChange={e => setForm(f => ({ ...f, is_timed: e.target.checked }))} className="accent-[#e8002d]" />
              タイムリミットあり
            </label>
            {form.is_timed && (
              <div className="flex items-center gap-2">
                <input type="number" value={form.duration_minutes} onChange={e => setForm(f => ({ ...f, duration_minutes: Number(e.target.value) }))} min={15} max={480} step={15} className="w-20 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
                <span className="text-[#7d92b0] text-sm">分</span>
              </div>
            )}
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] text-sm hover:text-white rounded-lg hover:bg-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => onSave({ ...form, participants_count: form.participants.length, status: 'scheduled' })} className="px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">作成</button>
        </div>
      </div>
    </div>
  )
}

// ─── Scorecard Detail Modal ───────────────────────────────────────────────────

function ScorecardModal({ drill, onClose }: { drill: Drill; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">{drill.name} — スコアカード詳細</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1 rounded hover:bg-[#1e2d42] transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          {/* Overall */}
          <div className="flex items-center gap-6">
            <div className="text-center">
              <p className={`text-5xl font-bold ${scoreColor(drill.overall_score ?? 0)}`}>{drill.overall_score}%</p>
              <p className="text-[#7d92b0] text-xs mt-1">総合スコア</p>
            </div>
            <div className="flex-1 space-y-2">
              {drill.score_breakdown && Object.entries(drill.score_breakdown).map(([cat, score]) => (
                <div key={cat} className="flex items-center gap-3">
                  <span className="text-[#7d92b0] text-xs w-28 flex-shrink-0">{cat}</span>
                  <div className="flex-1 bg-[#070d19] rounded-full h-2">
                    <div className={`h-2 rounded-full transition-all duration-500 ${score >= 85 ? 'bg-green-500' : score >= 70 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${score}%` }} />
                  </div>
                  <span className={`text-xs w-10 text-right ${scoreColor(score)}`}>{score}%</span>
                </div>
              ))}
            </div>
          </div>
          {/* Details */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-[#7d92b0] text-xs mb-2">主な発見事項</p>
              <p className="text-white text-sm">{drill.key_findings}</p>
            </div>
            <div className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-[#7d92b0] text-xs mb-2">最優秀参加者</p>
              <p className="text-white text-sm flex items-center gap-2"><Award className="w-4 h-4 text-yellow-400" />{drill.best_performer}</p>
            </div>
          </div>
          <div className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg">
            <p className="text-[#7d92b0] text-xs mb-2">改善が必要な領域</p>
            <div className="space-y-1">
              {(drill.areas_for_improvement ?? []).map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <span className="w-2 h-2 rounded-full bg-[#e8002d] flex-shrink-0" />
                  <span className="text-white">{a}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg text-center">
              <p className="text-[#7d92b0] text-xs">参加者数</p>
              <p className="text-white font-bold text-xl mt-1">{drill.participants_count}</p>
            </div>
            <div className="p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg text-center">
              <p className="text-[#7d92b0] text-xs">実施日</p>
              <p className="text-white text-sm mt-1">{formatDate(drill.scheduled_at)}</p>
            </div>
            <div className="p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg text-center">
              <p className="text-[#7d92b0] text-xs">所要時間</p>
              <p className="text-white font-bold text-xl mt-1">{drill.duration_minutes}分</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Trend SVG Chart ──────────────────────────────────────────────────────────

function TrendChart({ drills }: { drills: Drill[] }) {
  const completed = drills.filter(d => d.status === 'completed' && d.overall_score !== undefined)
    .sort((a, b) => new Date(a.scheduled_at).getTime() - new Date(b.scheduled_at).getTime())
    .slice(-8)

  if (completed.length < 2) return null

  const w = 400, h = 120, pad = 20
  const scores = completed.map(d => d.overall_score as number)
  const minScore = Math.min(...scores, 50)
  const maxScore = Math.max(...scores, 100)
  const xStep = (w - pad * 2) / (completed.length - 1)
  const points = scores.map((s, i) => ({
    x: pad + i * xStep,
    y: h - pad - ((s - minScore) / (maxScore - minScore)) * (h - pad * 2),
    score: s,
    label: new Date(completed[i].scheduled_at).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' }),
  }))
  const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <h3 className="text-white font-semibold text-sm mb-3">スコアトレンド (直近8回)</h3>
      <svg width="100%" viewBox={`0 0 ${w} ${h + 20}`} className="overflow-visible">
        {[60, 70, 80, 90, 100].map(y => {
          const cy = h - pad - ((y - minScore) / (maxScore - minScore)) * (h - pad * 2)
          return (
            <g key={y}>
              <line x1={pad} y1={cy} x2={w - pad} y2={cy} stroke="#1e2d42" strokeWidth="1" strokeDasharray="4,4" />
              <text x={pad - 4} y={cy + 4} fill="#7d92b0" fontSize="9" textAnchor="end">{y}</text>
            </g>
          )
        })}
        <path d={pathD} fill="none" stroke="#e8002d" strokeWidth="2" />
        {points.map((p, i) => (
          <g key={i}>
            <circle cx={p.x} cy={p.y} r="4" fill="#e8002d" />
            <text x={p.x} y={h + 14} fill="#7d92b0" fontSize="9" textAnchor="middle">{p.label}</text>
            <text x={p.x} y={p.y - 8} fill="#e2e8f4" fontSize="10" textAnchor="middle">{p.score}</text>
          </g>
        ))}
      </svg>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IncidentDrillsPage() {
  const [activeTab, setActiveTab] = useState<'drills' | 'scorecard'>('drills')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [executingDrill, setExecutingDrill] = useState<Drill | undefined>()
  const [viewingScorecard, setViewingScorecard] = useState<Drill | undefined>()
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const qc = useQueryClient()

  const { data } = useQuery<{ drills: Drill[] }>({
    queryKey: ['incident-drills'],
    queryFn: () => apiFetch<{ drills: Drill[] }>('/api/v1/admin/incident-drills').catch(() => ({ drills: [] })),
  })
  const drills = data?.drills ?? []

  const showToast = (message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3500)
  }

  const createMut = useMutation({
    mutationFn: (d: Partial<Drill>) => apiFetch('/api/v1/admin/incident-drills', { method: 'POST', body: JSON.stringify(d) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['incident-drills'] }); showToast('訓練を作成しました') },
    onError: () => showToast('訓練の作成に失敗しました', 'error'),
  })
  const updateMut = useMutation({
    mutationFn: ({ id, ...body }: { id: string } & Record<string, unknown>) =>
      apiFetch(`/api/v1/admin/incident-drills/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['incident-drills'] }) },
    onError: () => showToast('更新に失敗しました', 'error'),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/incident-drills/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['incident-drills'] }); showToast('訓練を削除しました') },
    onError: () => showToast('削除に失敗しました', 'error'),
  })

  const completedDrills = drills.filter(d => d.status === 'completed')
  const scheduledDrills = drills.filter(d => d.status === 'scheduled')
  const avgScore = completedDrills.length > 0 ? Math.round(completedDrills.reduce((s, d) => s + (d.overall_score ?? 0), 0) / completedDrills.length) : 0
  const totalParticipants = drills.reduce((s, d) => s + d.participants_count, 0)

  const categoryScores: Record<string, number[]> = { '検知': [], '封じ込め': [], 'コミュニケーション': [], 'ドキュメント': [] }
  completedDrills.forEach(d => {
    if (d.score_breakdown) {
      Object.entries(d.score_breakdown).forEach(([cat, score]) => {
        if (categoryScores[cat]) categoryScores[cat].push(score)
      })
    }
  })

  const handleCreateDrill = (data: Partial<Drill>) => {
    createMut.mutate(data)
    setShowCreateModal(false)
  }

  const handleCompleteDrill = (drillId: string, score: number, breakdown: Record<string, number>) => {
    updateMut.mutate({ id: drillId, status: 'completed', overall_score: score, score_breakdown: breakdown },
      { onSuccess: () => showToast('訓練を完了しました') })
  }

  const handleDeleteDrill = (id: string) => {
    deleteMut.mutate(id)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl border text-sm font-medium ${toast.type === 'success' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
          {toast.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
            <PlayCircle className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">インシデント訓練シミュレーション</h1>
            <p className="text-[#7d92b0] text-sm">インシデント対応力強化のための訓練管理</p>
          </div>
        </div>
        <button onClick={() => setShowCreateModal(true)} className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">
          <Plus className="w-4 h-4" />新規訓練作成
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '完了した訓練', value: completedDrills.length, icon: CheckCircle, color: 'text-green-400', suffix: '回' },
          { label: '平均スコア', value: avgScore, icon: Award, color: 'text-yellow-400', suffix: '%' },
          { label: 'トレーニング受講者', value: totalParticipants, icon: Users, color: 'text-blue-400', suffix: '人' },
          { label: '次回予定訓練', value: scheduledDrills.length > 0 ? new Date(scheduledDrills.sort((a, b) => new Date(a.scheduled_at).getTime() - new Date(b.scheduled_at).getTime())[0].scheduled_at).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' }) : '未定', icon: Calendar, color: 'text-purple-400', isDate: true },
        ].map((c, i) => (
          <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-lg bg-[#070d19] flex items-center justify-center flex-shrink-0">
              <c.icon className={`w-5 h-5 ${c.color}`} />
            </div>
            <div>
              <p className="text-[#7d92b0] text-xs">{c.label}</p>
              <p className="text-white font-bold text-2xl">{(c as any).isDate ? c.value : `${c.value}${c.suffix ?? ''}`}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['drills', 'scorecard'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {tab === 'drills' ? '訓練管理' : 'スコアカード'}
          </button>
        ))}
      </div>

      {/* Drills Management Tab */}
      {activeTab === 'drills' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['訓練名', 'タイプ', 'シナリオ', 'ステータス', '予定日時', '参加者', 'ファシリテーター', 'アクション'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {drills.map(d => (
                <tr key={d.id} className="hover:bg-[#0d1826] transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{d.name}</p>
                    {d.overall_score !== undefined && (
                      <p className={`text-xs mt-0.5 ${scoreColor(d.overall_score)}`}>スコア: {d.overall_score}%</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${TYPE_BADGE[d.drill_type]}`}>{TYPE_LABEL[d.drill_type]}</span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm max-w-[180px]">
                    <span className="truncate block">{d.scenario}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_BADGE[d.status]}`}>{STATUS_LABEL[d.status]}</span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{formatDate(d.scheduled_at)}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{d.participants_count}名</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{d.facilitator}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      {d.status === 'scheduled' && (
                        <button onClick={() => setExecutingDrill(d)} className="flex items-center gap-1 px-2 py-1 bg-green-500/10 text-green-400 border border-green-500/30 rounded text-xs hover:bg-green-500/20 transition-colors">
                          <PlayCircle className="w-3 h-3" />開始
                        </button>
                      )}
                      {d.status === 'completed' && (
                        <button onClick={() => setViewingScorecard(d)} className="flex items-center gap-1 px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded text-xs hover:bg-blue-500/20 transition-colors">
                          <Award className="w-3 h-3" />詳細
                        </button>
                      )}
                      <button onClick={() => handleDeleteDrill(d.id)} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Scorecard Tab */}
      {activeTab === 'scorecard' && (
        <div className="space-y-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['訓練名', '実施日', '総合スコア', '主な発見事項', '参加者数', '最優秀', '改善領域', '詳細'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {completedDrills.sort((a, b) => new Date(b.scheduled_at).getTime() - new Date(a.scheduled_at).getTime()).map(d => (
                  <tr key={d.id} className="hover:bg-[#0d1826] transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white text-sm font-medium">{d.name}</p>
                      <span className={`px-1.5 py-0.5 rounded text-xs ${TYPE_BADGE[d.drill_type]}`}>{TYPE_LABEL[d.drill_type]}</span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{formatDate(d.scheduled_at)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xl font-bold ${scoreColor(d.overall_score ?? 0)}`}>{d.overall_score}%</span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[180px]">
                      <span className="line-clamp-2">{d.key_findings}</span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{d.participants_count}名</td>
                    <td className="px-4 py-3 text-white text-sm">
                      <div className="flex items-center gap-1"><Award className="w-3 h-3 text-yellow-400" />{d.best_performer}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="space-y-0.5">
                        {(d.areas_for_improvement ?? []).slice(0, 2).map((a, i) => (
                          <p key={i} className="text-[#7d92b0] text-xs flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d] flex-shrink-0" />{a}
                          </p>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => setViewingScorecard(d)} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Trend Chart + Gap Analysis */}
          <div className="grid grid-cols-2 gap-4">
            <TrendChart drills={drills} />
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="text-white font-semibold text-sm mb-4">カテゴリ別平均スコア</h3>
              <div className="space-y-3">
                {Object.entries(categoryScores).map(([cat, scores]) => {
                  const avg = scores.length > 0 ? Math.round(scores.reduce((s, v) => s + v, 0) / scores.length) : 0
                  return (
                    <div key={cat} className="flex items-center gap-3">
                      <span className="text-[#7d92b0] text-xs w-32 flex-shrink-0">{cat}</span>
                      <div className="flex-1 bg-[#070d19] rounded-full h-2">
                        <div className={`h-2 rounded-full transition-all duration-500 ${avg >= 85 ? 'bg-green-500' : avg >= 70 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${avg}%` }} />
                      </div>
                      <span className={`text-xs w-10 text-right ${scoreColor(avg)}`}>{avg}%</span>
                    </div>
                  )
                })}
              </div>
              <div className="mt-4 pt-4 border-t border-[#1e2d42]">
                <p className="text-[#7d92b0] text-xs mb-2">改善優先領域</p>
                {Object.entries(categoryScores)
                  .map(([cat, scores]) => ({ cat, avg: scores.length > 0 ? Math.round(scores.reduce((s, v) => s + v, 0) / scores.length) : 0 }))
                  .filter(x => x.avg < 75)
                  .map(x => (
                    <div key={x.cat} className="flex items-center gap-2 text-xs mb-1">
                      <AlertCircle className="w-3 h-3 text-[#e8002d]" />
                      <span className="text-white">{x.cat}</span>
                      <span className="text-[#7d92b0]">— 継続的なトレーニングが必要</span>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showCreateModal && <CreateDrillModal onClose={() => setShowCreateModal(false)} onSave={handleCreateDrill} />}
      {executingDrill && <ExecutionModal drill={executingDrill} onClose={() => setExecutingDrill(undefined)} onComplete={handleCompleteDrill} />}
      {viewingScorecard && <ScorecardModal drill={viewingScorecard} onClose={() => setViewingScorecard(undefined)} />}
    </div>
  )
}
