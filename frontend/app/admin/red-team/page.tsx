'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Target, Plus, Pencil, Trash2, X, Loader2, Search,
  CheckCircle, AlertTriangle, Clock, FileText, Download,
  Shield, ChevronRight, Users, Calendar,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type ExerciseType = 'full_red_team' | 'purple_team' | 'tabletop' | 'phishing_sim' | 'physical'
type ExerciseStatus = 'planning' | 'active' | 'completed' | 'paused'
type ExercisePhase = 'reconnaissance' | 'initial_access' | 'lateral_movement' | 'persistence' | 'exfiltration'
type DetectionStatus = 'detected' | 'missed' | 'partially_detected'
type FindingSeverity = 'critical' | 'high' | 'medium' | 'low'
type FindingStatus = 'open' | 'remediated' | 'accepted'

interface Exercise {
  id: string
  name: string
  exercise_type: ExerciseType
  status: ExerciseStatus
  current_phase: ExercisePhase
  start_date: string
  end_date: string
  red_team_lead: string
  blue_team_notified: boolean
  scope: string
  rules_of_engagement: string
  objectives: string[]
  is_blind: boolean
  findings_count: number
  days_running: number
}

interface PhaseInfo {
  phase: ExercisePhase
  date: string | null
  notes: string
}

interface Finding {
  id: string
  exercise_id: string
  exercise_name: string
  finding_id: string
  title: string
  attack_technique: string
  severity: FindingSeverity
  detection_status: DetectionStatus
  dwell_time_hours: number
  remediation: string
  status: FindingStatus
  description: string
  timeline: string
  created_at: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const EXERCISE_TYPE_STYLES: Record<ExerciseType, { label: string; cls: string }> = {
  full_red_team: { label: 'Full Red Team', cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
  purple_team:   { label: 'Purple Team',   cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  tabletop:      { label: 'Tabletop',      cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  phishing_sim:  { label: 'Phishing Sim',  cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  physical:      { label: 'Physical',      cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

const EXERCISE_STATUS_STYLES: Record<ExerciseStatus, { label: string; cls: string }> = {
  planning:  { label: '計画中', cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  active:    { label: '実施中', cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  completed: { label: '完了',   cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  paused:    { label: '一時停止', cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

const PHASE_LABELS: Record<ExercisePhase, string> = {
  reconnaissance:   '偵察',
  initial_access:   '初期侵入',
  lateral_movement: '横断移動',
  persistence:      '永続化',
  exfiltration:     '情報持出',
}

const PHASES: ExercisePhase[] = ['reconnaissance', 'initial_access', 'lateral_movement', 'persistence', 'exfiltration']

const FINDING_SEVERITY_STYLES: Record<FindingSeverity, { label: string; cls: string; color: string }> = {
  critical: { label: 'Critical', cls: 'bg-red-600/20 text-red-400 border-red-600/40',     color: '#e8002d' },
  high:     { label: 'High',     cls: 'bg-orange-500/20 text-orange-400 border-orange-500/40', color: '#f97316' },
  medium:   { label: 'Medium',   cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40', color: '#eab308' },
  low:      { label: 'Low',      cls: 'bg-green-500/20 text-green-400 border-green-500/40',  color: '#22c55e' },
}

const DETECTION_STATUS_STYLES: Record<DetectionStatus, { label: string; cls: string }> = {
  detected:            { label: '検知済み',   cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  missed:              { label: '見逃し',     cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
  partially_detected:  { label: '部分検知',   cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
}

const FINDING_STATUS_STYLES: Record<FindingStatus, { label: string; cls: string }> = {
  open:       { label: '未対応',   cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
  remediated: { label: '対処済み', cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  accepted:   { label: 'リスク受容', cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

const MITRE_TACTICS = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration']

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

// ─── Exercise Create Modal ────────────────────────────────────────────────────

function ExerciseModal({ onClose, onSave, saving }: {
  onClose: () => void; onSave: (d: Partial<Exercise>) => void; saving: boolean
}) {
  const [form, setForm] = useState({
    name: '',
    exercise_type: 'full_red_team' as ExerciseType,
    start_date: '',
    end_date: '',
    scope: '',
    rules_of_engagement: '',
    red_team_lead: '',
    is_blind: true,
    objectives: [''] as string[],
  })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))
  const addObjective = () => setForm(f => ({ ...f, objectives: [...f.objectives, ''] }))
  const removeObjective = (i: number) => setForm(f => ({ ...f, objectives: f.objectives.filter((_, idx) => idx !== i) }))
  const setObjective = (i: number, v: string) => setForm(f => ({ ...f, objectives: f.objectives.map((o, idx) => idx === i ? v : o) }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <h2 className="text-white font-semibold">新規演習作成</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">演習名 *</label>
            <input value={form.name} onChange={e => set('name', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="2026年Q2 フルレッドチーム演習" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">演習タイプ</label>
              <select value={form.exercise_type} onChange={e => set('exercise_type', e.target.value as ExerciseType)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(Object.entries(EXERCISE_TYPE_STYLES) as [ExerciseType, { label: string }][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">レッドチームリード</label>
              <input value={form.red_team_lead} onChange={e => set('red_team_lead', e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                placeholder="氏名 (会社名)" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">開始日</label>
              <input type="date" value={form.start_date} onChange={e => set('start_date', e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">終了日</label>
              <input type="date" value={form.end_date} onChange={e => set('end_date', e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">スコープ</label>
            <textarea value={form.scope} onChange={e => set('scope', e.target.value)} rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="対象システム、ネットワークレンジ、アプリケーション" />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">交戦規定 (Rules of Engagement)</label>
            <textarea value={form.rules_of_engagement} onChange={e => set('rules_of_engagement', e.target.value)} rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="禁止手法、緊急連絡手順など" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs text-falcon-muted">目標</label>
              <button onClick={addObjective} className="text-xs text-falcon-red hover:text-red-300 transition-colors">+ 追加</button>
            </div>
            <div className="space-y-2">
              {form.objectives.map((obj, i) => (
                <div key={i} className="flex gap-2">
                  <input value={obj} onChange={e => setObjective(i, e.target.value)}
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                    placeholder={`目標 ${i + 1}`} />
                  {form.objectives.length > 1 && (
                    <button onClick={() => removeObjective(i)} className="p-2 rounded-lg hover:bg-red-900/30 text-falcon-muted hover:text-red-400 transition-colors">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="is_blind" checked={form.is_blind} onChange={e => set('is_blind', e.target.checked)}
              className="rounded-sm border-falcon-border bg-[#070d19]" />
            <label htmlFor="is_blind" className="text-sm text-falcon-muted">ブラインド演習 (ブルーチームへの事前通知なし)</label>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} disabled={saving || !form.name}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Exercise Slide-over ──────────────────────────────────────────────────────

function ExerciseSlideOver({ exercise, onClose }: { exercise: Exercise; onClose: () => void }) {
  const phaseIndex = PHASES.indexOf(exercise.current_phase)
  const mockPhases: PhaseInfo[] = PHASES.map((p, i) => ({
    phase: p,
    date: i <= phaseIndex ? `2026-03-${String(1 + i * 3).padStart(2, '0')}` : null,
    notes: i <= phaseIndex ? `フェーズ完了。${i === 0 ? 'ターゲットの詳細情報収集' : i === 1 ? '初期足場の確立に成功' : i === 2 ? 'ドメイン内12台に展開' : i === 3 ? '複数の永続化機構を設置' : 'データ抽出シミュレーション完了'}` : '未開始',
  }))

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="bg-falcon-surface border-l border-falcon-border w-full max-w-xl h-full flex flex-col overflow-hidden shadow-2xl"
        onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${EXERCISE_TYPE_STYLES[exercise.exercise_type].cls}`}>
                {EXERCISE_TYPE_STYLES[exercise.exercise_type].label}
              </span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${EXERCISE_STATUS_STYLES[exercise.status].cls}`}>
                {EXERCISE_STATUS_STYLES[exercise.status].label}
              </span>
            </div>
            <h2 className="text-white font-semibold text-base">{exercise.name}</h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white shrink-0"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'リード', value: exercise.red_team_lead },
              { label: '実施日数', value: `${exercise.days_running}日` },
              { label: '開始日', value: exercise.start_date },
              { label: '終了日', value: exercise.end_date },
            ].map(({ label, value }) => (
              <div key={label} className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                <p className="text-xs text-falcon-muted mb-1">{label}</p>
                <p className="text-sm text-white">{value}</p>
              </div>
            ))}
          </div>

          {/* Phase Stepper */}
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-3">フェーズ進捗</p>
            <div className="space-y-3">
              {mockPhases.map((p, i) => {
                const isDone = i < phaseIndex
                const isCurrent = i === phaseIndex
                return (
                  <div key={p.phase} className="flex gap-3">
                    <div className="flex flex-col items-center shrink-0">
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        isDone ? 'bg-green-500 text-white' : isCurrent ? 'bg-falcon-red text-white' : 'bg-[#070d19] border border-falcon-border text-falcon-subtle'
                      }`}>
                        {isDone ? '✓' : i + 1}
                      </div>
                      {i < PHASES.length - 1 && (
                        <div className={`w-0.5 h-6 mt-1 ${isDone ? 'bg-green-500/50' : 'bg-falcon-border'}`} />
                      )}
                    </div>
                    <div className="flex-1 pb-3">
                      <div className="flex items-center gap-2">
                        <p className={`text-sm font-medium ${isDone ? 'text-green-400' : isCurrent ? 'text-falcon-red' : 'text-falcon-subtle'}`}>
                          {PHASE_LABELS[p.phase]}
                        </p>
                        {p.date && <span className="text-xs text-falcon-subtle">{p.date}</span>}
                      </div>
                      {p.date && <p className="text-xs text-falcon-muted mt-0.5">{p.notes}</p>}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Scope */}
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">スコープ</p>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-sm text-falcon-text">{exercise.scope}</div>
          </div>

          {/* Objectives */}
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">目標</p>
            <div className="space-y-1">
              {exercise.objectives.map((obj, i) => (
                <div key={i} className="flex items-start gap-2 text-sm text-falcon-text">
                  <ChevronRight className="w-3.5 h-3.5 text-falcon-red mt-0.5 shrink-0" />
                  <span>{obj}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Rules */}
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">交戦規定</p>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-sm text-falcon-text">{exercise.rules_of_engagement}</div>
          </div>

          {/* Deconfliction */}
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">デコンフリクション (要調整アクティビティ)</p>
            <div className="space-y-2">
              {[
                { time: '03/10 14:00', activity: 'C2ビーコン設置', status: '通知済み', note: 'SOC確認後に実施' },
                { time: '03/13 11:00', activity: 'DCSync操作', status: '未通知', note: 'ブラインドテスト' },
                { time: '03/16 10:00', activity: 'NTLM Relay', status: '未通知', note: 'ブラインドテスト' },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-3 bg-[#070d19] border border-falcon-border rounded-lg p-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-falcon-muted">{item.time}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded-sm ${item.status === '通知済み' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{item.status}</span>
                    </div>
                    <p className="text-sm text-white mt-0.5">{item.activity}</p>
                    <p className="text-xs text-falcon-muted">{item.note}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Finding Detail Modal ─────────────────────────────────────────────────────

function FindingDetailModal({ finding, onClose, onUpdate, updating }: {
  finding: Finding; onClose: () => void; onUpdate: (id: string, status: FindingStatus) => void; updating: boolean
}) {
  const [status, setStatus] = useState<FindingStatus>(finding.status)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-start justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono text-falcon-muted">{finding.finding_id}</span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${FINDING_SEVERITY_STYLES[finding.severity].cls}`}>
                {FINDING_SEVERITY_STYLES[finding.severity].label}
              </span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${DETECTION_STATUS_STYLES[finding.detection_status].cls}`}>
                {DETECTION_STATUS_STYLES[finding.detection_status].label}
              </span>
            </div>
            <h2 className="text-white font-semibold text-base">{finding.title}</h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white shrink-0"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
              <p className="text-xs text-falcon-muted mb-1">MITRE ATT&CK</p>
              <a href={`https://attack.mitre.org/techniques/${finding.attack_technique.replace('.', '/')}`}
                target="_blank" rel="noopener noreferrer"
                className="text-sm font-mono text-blue-400 hover:text-blue-300 transition-colors">
                {finding.attack_technique}
              </a>
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
              <p className="text-xs text-falcon-muted mb-1">滞在時間</p>
              <p className="text-sm text-white">{finding.dwell_time_hours}時間</p>
            </div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">攻撃シナリオ</p>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-sm text-falcon-text leading-relaxed">{finding.description}</div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">タイムライン</p>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-sm font-mono text-green-400">{finding.timeline}</div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">証拠 (モック)</p>
            <div className="grid grid-cols-3 gap-2">
              {['screenshot_001.png', 'memory_dump.bin', 'network_capture.pcap'].map(f => (
                <div key={f} className="bg-[#070d19] border border-falcon-border rounded-lg p-2 flex items-center gap-2 cursor-pointer hover:border-falcon-muted/30 transition-colors">
                  <FileText className="w-3.5 h-3.5 text-falcon-muted shrink-0" />
                  <span className="text-xs text-falcon-muted truncate">{f}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">検知ギャップ分析</p>
            <div className="bg-[#070d19] border border-yellow-500/20 rounded-lg p-3 text-sm text-falcon-text">
              {finding.detection_status === 'missed' && '検知ルールが存在しないか、既存ルールが回避されました。SIEMへのルール追加とEDRの設定見直しが必要です。'}
              {finding.detection_status === 'partially_detected' && 'アラートは発生しましたが、適切に処理されませんでした。トリアージプロセスとSOCアナリストのトレーニング改善が必要です。'}
              {finding.detection_status === 'detected' && '検知が成功しました。しかし対応時間の短縮と自動化の改善余地があります。'}
            </div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">推奨対策</p>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-sm text-falcon-text">{finding.remediation}</div>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted mb-2">ステータス更新</p>
            <select value={status} onChange={e => setStatus(e.target.value as FindingStatus)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              {(Object.entries(FINDING_STATUS_STYLES) as [FindingStatus, { label: string }][]).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">閉じる</button>
          <button onClick={() => onUpdate(finding.id, status)} disabled={updating}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
            {updating && <Loader2 className="w-3.5 h-3.5 animate-spin" />}更新
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Add Finding Modal ────────────────────────────────────────────────────────

function AddFindingModal({ exercises, onClose, onSave, saving }: {
  exercises: Exercise[]; onClose: () => void; onSave: (d: Partial<Finding>) => void; saving: boolean
}) {
  const [form, setForm] = useState({
    exercise_id: exercises[0]?.id ?? '',
    title: '',
    attack_technique: '',
    severity: 'high' as FindingSeverity,
    detection_status: 'missed' as DetectionStatus,
    dwell_time_hours: 0,
    remediation: '',
    description: '',
  })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <h2 className="text-white font-semibold">所見追加</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">演習</label>
            <select value={form.exercise_id} onChange={e => set('exercise_id', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              {exercises.map(ex => <option key={ex.id} value={ex.id}>{ex.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">タイトル *</label>
            <input value={form.title} onChange={e => set('title', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="発見事項のタイトル" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">MITRE ATT&CK ID</label>
              <input value={form.attack_technique} onChange={e => set('attack_technique', e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-falcon-red/50"
                placeholder="T1558.003" />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">重大度</label>
              <select value={form.severity} onChange={e => set('severity', e.target.value as FindingSeverity)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(Object.entries(FINDING_SEVERITY_STYLES) as [FindingSeverity, { label: string }][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">検知状況</label>
              <select value={form.detection_status} onChange={e => set('detection_status', e.target.value as DetectionStatus)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(Object.entries(DETECTION_STATUS_STYLES) as [DetectionStatus, { label: string }][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">滞在時間 (時間)</label>
              <input type="number" value={form.dwell_time_hours} onChange={e => set('dwell_time_hours', parseInt(e.target.value))} min={0}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">説明</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)} rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="攻撃シナリオの詳細説明" />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">推奨修正</label>
            <textarea value={form.remediation} onChange={e => set('remediation', e.target.value)} rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="具体的な改善手順" />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} disabled={saving || !form.title}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function RedTeamPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'exercises' | 'findings'>('exercises')
  const [showExerciseModal, setShowExerciseModal] = useState(false)
  const [showFindingModal, setShowFindingModal] = useState(false)
  const [slideOverExercise, setSlideOverExercise] = useState<Exercise | null>(null)
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null)

  // Filters
  const [findingSearch, setFindingSearch] = useState('')
  const [exerciseFilter, setExerciseFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | 'all'>('all')
  const [detectionFilter, setDetectionFilter] = useState<DetectionStatus | 'all'>('all')

  const { data: exercises = [] } = useQuery<Exercise[]>({
    queryKey: ['red-team-exercises'],
    queryFn: async () => {
      try { return await apiFetchList<Exercise>('/api/v1/admin/red-team/exercises') }
      catch { return [] }
    },
  })

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ['red-team-findings'],
    queryFn: async () => {
      try { return await apiFetchList<Finding>('/api/v1/admin/red-team/findings') }
      catch { return [] }
    },
  })

  const createExerciseMutation = useMutation({
    mutationFn: async (data: Partial<Exercise>) => {
      try { return await apiFetch('/api/v1/admin/red-team/exercises', { method: 'POST', body: JSON.stringify(data) }) }
      catch { return { ...data, id: `ex-${Date.now()}` } }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-exercises'] }); setShowExerciseModal(false) },
  })

  const deleteExerciseMutation = useMutation({
    mutationFn: async (id: string) => {
      try { return await apiFetch(`/api/v1/admin/red-team/exercises/${id}`, { method: 'DELETE' }) }
      catch { return null }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['red-team-exercises'] }),
  })

  const createFindingMutation = useMutation({
    mutationFn: async (data: Partial<Finding>) => {
      try { return await apiFetch('/api/v1/admin/red-team/findings', { method: 'POST', body: JSON.stringify(data) }) }
      catch { return { ...data, id: `f-${Date.now()}` } }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-findings'] }); setShowFindingModal(false) },
  })

  const updateFindingMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: FindingStatus }) => {
      try { return await apiFetch(`/api/v1/admin/red-team/findings/${id}`, { method: 'PUT', body: JSON.stringify({ status }) }) }
      catch { return null }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-findings'] }); setDetailFinding(null) },
  })

  const activeExercise = exercises.find(e => e.status === 'active')
  const totalFindings = findings.length
  const detectedCount = findings.filter(f => f.detection_status === 'detected').length
  const detectionRate = totalFindings > 0 ? Math.round((detectedCount / totalFindings) * 100) : 0
  const avgDwell = findings.length > 0 ? Math.round(findings.reduce((s, f) => s + f.dwell_time_hours, 0) / findings.length) : 0

  const filteredFindings = findings.filter(f => {
    if (findingSearch && !f.title.toLowerCase().includes(findingSearch.toLowerCase()) && !f.attack_technique.toLowerCase().includes(findingSearch.toLowerCase())) return false
    if (exerciseFilter !== 'all' && f.exercise_id !== exerciseFilter) return false
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false
    if (detectionFilter !== 'all' && f.detection_status !== detectionFilter) return false
    return true
  })

  // MITRE Heatmap mock data
  const tacticDetectionMap: Record<string, Record<DetectionStatus, number>> = {}
  MITRE_TACTICS.forEach(t => {
    tacticDetectionMap[t] = { detected: 0, missed: 0, partially_detected: 0 }
  })
  const tacticMapping: Record<string, string> = {
    'T1566': 'Initial Access', 'T1558': 'Credential Access', 'T1550': 'Lateral Movement',
    'T1053': 'Persistence', 'T1071': 'Collection', 'T1003': 'Credential Access',
    'T1059': 'Execution', 'T1557': 'Lateral Movement', 'T1110': 'Credential Access', 'T1556': 'Defense Evasion',
  }
  findings.forEach(f => {
    const prefix = f.attack_technique.split('.')[0]
    const tactic = tacticMapping[prefix]
    if (tactic && tacticDetectionMap[tactic]) {
      tacticDetectionMap[tactic][f.detection_status]++
    }
  })

  const handleGenerateReport = () => {
    const a = document.createElement('a')
    a.href = 'data:application/pdf;base64,JVBERi0xLjQ='
    a.download = `red-team-report-${Date.now()}.pdf`
    a.click()
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/20 border border-falcon-red/30 flex items-center justify-center">
            <Target className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">レッドチーム演習管理</h1>
            <p className="text-sm text-falcon-muted">レッドチーム演習の管理と所見追跡</p>
          </div>
        </div>
        <button onClick={handleGenerateReport}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">
          <Download className="w-4 h-4" />
          レポート生成
        </button>
      </div>

      {/* Active Exercise Summary */}
      {activeExercise && (
        <div className="bg-falcon-surface border border-yellow-500/30 rounded-xl p-4 mb-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse mt-1" />
              <div>
                <p className="text-xs text-yellow-400 font-medium mb-0.5">実施中の演習</p>
                <p className="text-white font-semibold">{activeExercise.name}</p>
              </div>
            </div>
            <div className="flex items-center gap-6 text-sm">
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{activeExercise.days_running}</p>
                <p className="text-xs text-falcon-muted">実施日数</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-falcon-red">{activeExercise.findings_count}</p>
                <p className="text-xs text-falcon-muted">所見数</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-400">{PHASE_LABELS[activeExercise.current_phase]}</p>
                <p className="text-xs text-falcon-muted">現在フェーズ</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{activeExercise.is_blind ? '非通知' : '通知済'}</p>
                <p className="text-xs text-falcon-muted">ブルーチーム</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['exercises', 'findings'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-150 ${
              activeTab === tab ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
            }`}>
            {tab === 'exercises' ? '演習管理' : `所見・報告 (${findings.length})`}
          </button>
        ))}
      </div>

      {/* Exercises Tab */}
      {activeTab === 'exercises' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button onClick={() => setShowExerciseModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors">
              <Plus className="w-4 h-4" />
              新規演習作成
            </button>
          </div>

          <div className="space-y-4">
            {exercises.map(ex => (
              <div key={ex.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 hover:border-falcon-muted/30 transition-all">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${EXERCISE_TYPE_STYLES[ex.exercise_type].cls}`}>
                        {EXERCISE_TYPE_STYLES[ex.exercise_type].label}
                      </span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${EXERCISE_STATUS_STYLES[ex.status].cls}`}>
                        {EXERCISE_STATUS_STYLES[ex.status].label}
                      </span>
                      {ex.blue_team_notified ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border font-medium bg-blue-500/20 text-blue-400 border-blue-500/30">
                          <Shield className="w-2.5 h-2.5" />ブルーチーム通知済
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border font-medium bg-red-500/20 text-red-400 border-red-500/30">
                          ブラインド
                        </span>
                      )}
                    </div>
                    <h3 className="text-base font-semibold text-white mb-1">{ex.name}</h3>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button onClick={() => setSlideOverExercise(ex)}
                      className="px-3 py-1.5 rounded-lg text-xs bg-falcon-border hover:bg-[#2a3a52] text-white transition-colors">
                      詳細
                    </button>
                    <button onClick={() => deleteExerciseMutation.mutate(ex.id)}
                      className="p-1.5 rounded-sm hover:bg-red-900/30 text-falcon-muted hover:text-red-400 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-4 gap-3 mb-3">
                  <div className="flex items-center gap-1.5 text-xs text-falcon-muted">
                    <Users className="w-3.5 h-3.5 shrink-0" />
                    <span className="truncate">{ex.red_team_lead}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-falcon-muted">
                    <Calendar className="w-3.5 h-3.5 shrink-0" />
                    <span>{ex.start_date} 〜 {ex.end_date}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-falcon-muted">
                    <Clock className="w-3.5 h-3.5 shrink-0" />
                    <span>現在: {PHASE_LABELS[ex.current_phase]}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs">
                    <AlertTriangle className="w-3.5 h-3.5 text-falcon-red shrink-0" />
                    <span className="text-white font-semibold">{ex.findings_count}</span>
                    <span className="text-falcon-muted">所見</span>
                  </div>
                </div>

                <p className="text-xs text-falcon-muted line-clamp-1">{ex.scope}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: '検知率', value: `${detectionRate}%`, color: detectionRate >= 70 ? '#22c55e' : detectionRate >= 40 ? '#eab308' : '#e8002d' },
              { label: '見逃し', value: findings.filter(f => f.detection_status === 'missed').length, color: '#e8002d' },
              { label: '平均滞在時間', value: `${avgDwell}h`, color: '#f97316' },
              { label: '対処済み', value: findings.filter(f => f.status === 'remediated').length, color: '#22c55e' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                <p className="text-xs text-falcon-muted mb-1">{label}</p>
                <p className="text-2xl font-bold" style={{ color }}>{value}</p>
              </div>
            ))}
          </div>

          {/* MITRE Heatmap */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-sm font-semibold text-white mb-3">MITRE ATT&CK 検知ヒートマップ (タクティクス別)</p>
            <div className="grid grid-cols-5 gap-2">
              {MITRE_TACTICS.map(tactic => {
                const data = tacticDetectionMap[tactic]
                const total = data.detected + data.missed + data.partially_detected
                const bgColor = total === 0 ? '#070d19' : data.missed > data.detected ? 'rgba(232,0,45,0.15)' : data.partially_detected > 0 ? 'rgba(234,179,8,0.15)' : 'rgba(34,197,94,0.15)'
                const borderColor = total === 0 ? '#1e2d42' : data.missed > data.detected ? 'rgba(232,0,45,0.3)' : data.partially_detected > 0 ? 'rgba(234,179,8,0.3)' : 'rgba(34,197,94,0.3)'
                return (
                  <div key={tactic} className="rounded-lg p-2.5 border" style={{ background: bgColor, borderColor }}>
                    <p className="text-[10px] font-medium text-white leading-tight mb-1">{tactic}</p>
                    {total > 0 && (
                      <div className="flex gap-1 text-[9px]">
                        {data.detected > 0 && <span className="text-green-400">{data.detected}✓</span>}
                        {data.partially_detected > 0 && <span className="text-yellow-400">{data.partially_detected}△</span>}
                        {data.missed > 0 && <span className="text-red-400">{data.missed}✗</span>}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Filters + Table */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-falcon-muted" />
              <input value={findingSearch} onChange={e => setFindingSearch(e.target.value)}
                placeholder="所見を検索..."
                className="w-full bg-falcon-surface border border-falcon-border rounded-lg pl-9 pr-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <select value={exerciseFilter} onChange={e => setExerciseFilter(e.target.value)}
              className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden">
              <option value="all">全演習</option>
              {exercises.map(ex => <option key={ex.id} value={ex.id}>{ex.name}</option>)}
            </select>
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as FindingSeverity | 'all')}
              className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden">
              <option value="all">全重大度</option>
              {(Object.entries(FINDING_SEVERITY_STYLES) as [FindingSeverity, { label: string }][]).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <select value={detectionFilter} onChange={e => setDetectionFilter(e.target.value as DetectionStatus | 'all')}
              className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden">
              <option value="all">全検知状況</option>
              {(Object.entries(DETECTION_STATUS_STYLES) as [DetectionStatus, { label: string }][]).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <button onClick={() => setShowFindingModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors ml-auto">
              <Plus className="w-4 h-4" />
              所見追加
            </button>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['所見ID', 'タイトル', '攻撃手法', '重大度', '検知状況', '滞在時間', 'ステータス', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-sm text-falcon-muted">所見が見つかりません</td></tr>
                ) : filteredFindings.map(f => (
                  <tr key={f.id} className="border-b border-falcon-border/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-falcon-muted">{f.finding_id}</span>
                    </td>
                    <td className="px-4 py-3 max-w-[180px]">
                      <p className="text-sm text-white truncate" title={f.title}>{f.title}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-sm">
                        {f.attack_technique}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${FINDING_SEVERITY_STYLES[f.severity].cls}`}>
                        {FINDING_SEVERITY_STYLES[f.severity].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${DETECTION_STATUS_STYLES[f.detection_status].cls}`}>
                        {DETECTION_STATUS_STYLES[f.detection_status].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-mono font-bold ${f.dwell_time_hours > 24 ? 'text-red-400' : f.dwell_time_hours > 8 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {f.dwell_time_hours}h
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${FINDING_STATUS_STYLES[f.status].cls}`}>
                        {FINDING_STATUS_STYLES[f.status].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => setDetailFinding(f)}
                        className="px-2 py-1 rounded-sm text-xs bg-falcon-border hover:bg-[#2a3a52] text-white transition-colors">
                        詳細
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showExerciseModal && (
        <ExerciseModal
          onClose={() => setShowExerciseModal(false)}
          onSave={data => createExerciseMutation.mutate(data)}
          saving={createExerciseMutation.isPending}
        />
      )}
      {showFindingModal && (
        <AddFindingModal
          exercises={exercises}
          onClose={() => setShowFindingModal(false)}
          onSave={data => createFindingMutation.mutate(data)}
          saving={createFindingMutation.isPending}
        />
      )}
      {detailFinding && (
        <FindingDetailModal
          finding={detailFinding}
          onClose={() => setDetailFinding(null)}
          onUpdate={(id, status) => updateFindingMutation.mutate({ id, status })}
          updating={updateFindingMutation.isPending}
        />
      )}
      {slideOverExercise && (
        <ExerciseSlideOver
          exercise={slideOverExercise}
          onClose={() => setSlideOverExercise(null)}
        />
      )}
    </div>
  )
}
