'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  FlaskConical, Search, Filter, Plus, X, Download, ChevronRight,
  CheckCircle2, XCircle, AlertCircle, Clock, RefreshCw,
  Shield, User, Calendar, FileText, Upload, BarChart3,
  Edit2, Trash2, Play, Eye,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type ControlCategory = 'preventive' | 'detective' | 'corrective' | 'compensating'
type Framework = 'SOC2' | 'ISO27001' | 'NIST' | 'CIS' | 'PCI DSS'
type ControlStatus = 'passing' | 'failing' | 'partial' | 'not_tested'
type TestMethod = 'automated' | 'manual' | 'review'
type TestResult = 'pass' | 'fail' | 'partial'

interface TestHistoryEntry {
  id: string
  date: string
  tester: string
  result: TestResult
  score: number
  notes: string
  evidence_link?: string
}

interface Control {
  id: string
  control_id: string
  name: string
  description: string
  category: ControlCategory
  frameworks: Framework[]
  status: ControlStatus
  last_tested: string | null
  test_method: TestMethod
  score: number
  assigned_to: string
  test_procedure: string[]
  test_history: TestHistoryEntry[]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const CATEGORY_STYLES: Record<ControlCategory, string> = {
  preventive: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  detective: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
  corrective: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  compensating: 'bg-gray-800 text-gray-300 border border-gray-700/40',
}

const CATEGORY_LABELS: Record<ControlCategory, string> = {
  preventive: '予防的',
  detective: '発見的',
  corrective: '是正的',
  compensating: '補完的',
}

const STATUS_STYLES: Record<ControlStatus, string> = {
  passing: 'bg-green-900/40 text-green-400 border border-green-700/40',
  failing: 'bg-falcon-red/20 text-falcon-red border border-falcon-red/30',
  partial: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  not_tested: 'bg-gray-800 text-gray-400 border border-gray-700/40',
}

const STATUS_LABELS: Record<ControlStatus, string> = {
  passing: '合格',
  failing: '不合格',
  partial: '部分的',
  not_tested: '未テスト',
}

const STATUS_ICONS: Record<ControlStatus, React.ElementType> = {
  passing: CheckCircle2,
  failing: XCircle,
  partial: AlertCircle,
  not_tested: Clock,
}

const METHOD_LABELS: Record<TestMethod, string> = {
  automated: '自動',
  manual: '手動',
  review: 'レビュー',
}

const FRAMEWORKS: Framework[] = ['SOC2', 'ISO27001', 'NIST', 'CIS']

// ─── Test Execution Modal ─────────────────────────────────────────────────────

function TestExecutionModal({ control, onClose, onSubmit }: {
  control: Control
  onClose: () => void
  onSubmit: (data: { result: TestResult; score: number; notes: string }) => void
}) {
  const [checkedSteps, setCheckedSteps] = useState<Set<number>>(new Set())
  const [result, setResult] = useState<TestResult>('pass')
  const [score, setScore] = useState(80)
  const [notes, setNotes] = useState('')
  const [evidenceFile, setEvidenceFile] = useState('')

  const toggleStep = (i: number) => {
    setCheckedSteps(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border sticky top-0 bg-falcon-surface">
          <div>
            <h3 className="text-white font-bold">テスト実行</h3>
            <p className="text-falcon-muted text-xs mt-0.5">{control.control_id} — {control.name}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          {/* Procedure checklist */}
          <div>
            <h4 className="text-white font-semibold text-sm mb-3">テスト手順</h4>
            <div className="space-y-2">
              {control.test_procedure.map((step, i) => (
                <label key={i} className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={checkedSteps.has(i)}
                    onChange={() => toggleStep(i)}
                    className="mt-0.5 accent-falcon-red"
                  />
                  <span className={`text-sm transition-colors ${checkedSteps.has(i) ? 'text-falcon-muted line-through' : 'text-falcon-text'}`}>
                    {step}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Evidence upload */}
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">エビデンスファイル（モック）</label>
            <div className="flex items-center gap-2">
              <input
                value={evidenceFile}
                onChange={e => setEvidenceFile(e.target.value)}
                placeholder="ファイル名または参照先..."
                className="flex-1 bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                           focus:outline-hidden focus:border-falcon-red/50"
              />
              <button className="flex items-center gap-1.5 px-3 py-2 bg-falcon-raised border border-falcon-border rounded-sm text-falcon-muted text-sm hover:text-white hover:border-falcon-muted/40 transition-colors">
                <Upload className="w-4 h-4" />
                参照
              </button>
            </div>
          </div>

          {/* Pass/Fail/Partial */}
          <div>
            <label className="text-falcon-muted text-xs mb-2 block">テスト結果</label>
            <div className="flex gap-3">
              {(['pass', 'partial', 'fail'] as TestResult[]).map(r => (
                <label key={r} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="result"
                    value={r}
                    checked={result === r}
                    onChange={() => setResult(r)}
                    className="accent-falcon-red"
                  />
                  <span className={`text-sm font-medium ${
                    r === 'pass' ? 'text-green-400' : r === 'fail' ? 'text-falcon-red' : 'text-yellow-400'
                  }`}>
                    {r === 'pass' ? '合格' : r === 'fail' ? '不合格' : '部分的'}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Score slider */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-falcon-muted text-xs">スコア</label>
              <span className="text-white font-bold text-sm">{score}</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={score}
              onChange={e => setScore(parseInt(e.target.value))}
              className="w-full accent-falcon-red"
            />
            <div className="flex justify-between text-falcon-subtle text-xs mt-1">
              <span>0</span><span>50</span><span>100</span>
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">備考</label>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                         focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="テスト結果の詳細..."
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { onSubmit({ result, score, notes }); onClose() }}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-falcon-red text-white rounded-sm font-medium hover:bg-[#c5001f] transition-colors"
          >
            <Play className="w-4 h-4" />
            結果を提出
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Control Detail Modal ─────────────────────────────────────────────────────

function ControlDetailModal({ control, onClose }: { control: Control; onClose: () => void }) {
  const StatusIcon = STATUS_ICONS[control.status]
  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto">
        <div className="flex items-start justify-between p-5 border-b border-falcon-border">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="text-falcon-muted font-mono text-sm">{control.control_id}</span>
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-medium ${STATUS_STYLES[control.status]}`}>
                {STATUS_LABELS[control.status]}
              </span>
            </div>
            <h3 className="text-white font-bold text-lg">{control.name}</h3>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-6">
          <div>
            <h4 className="text-falcon-muted text-xs mb-1">説明</h4>
            <p className="text-falcon-text text-sm">{control.description}</p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
              <p className="text-falcon-muted text-xs mb-1">カテゴリ</p>
              <span className={`text-xs px-2.5 py-1 rounded-sm font-medium ${CATEGORY_STYLES[control.category]}`}>
                {CATEGORY_LABELS[control.category]}
              </span>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
              <p className="text-falcon-muted text-xs mb-1">テスト方法</p>
              <p className="text-white text-sm font-medium">{METHOD_LABELS[control.test_method]}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
              <p className="text-falcon-muted text-xs mb-1">担当者</p>
              <p className="text-white text-sm">{displayUser(control.assigned_to)}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
              <p className="text-falcon-muted text-xs mb-1">最終テスト</p>
              <p className="text-white text-sm">{control.last_tested ?? '未実施'}</p>
            </div>
          </div>
          <div>
            <h4 className="text-white font-semibold text-sm mb-2">フレームワーク対応</h4>
            <div className="flex flex-wrap gap-2">
              {control.frameworks.map(f => (
                <span key={f} className="text-xs px-2.5 py-1 rounded-sm bg-falcon-raised text-falcon-muted border border-falcon-border font-mono">{f}</span>
              ))}
            </div>
          </div>
          <div>
            <h4 className="text-white font-semibold text-sm mb-2">テスト履歴</h4>
            {control.test_history.length === 0 ? (
              <p className="text-falcon-muted text-sm">テスト履歴なし</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-falcon-border">
                      {['日付', 'テスター', '結果', 'スコア', '備考', 'エビデンス'].map(h => (
                        <th key={h} className="text-left text-falcon-muted text-xs pb-2 pr-3 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-falcon-border">
                    {control.test_history.map(th => (
                      <tr key={th.id}>
                        <td className="py-2 pr-3 text-falcon-muted text-xs whitespace-nowrap">{th.date}</td>
                        <td className="py-2 pr-3 text-falcon-text text-xs whitespace-nowrap">{th.tester}</td>
                        <td className="py-2 pr-3 text-xs">
                          <span className={`px-2 py-0.5 rounded-full font-medium ${
                            th.result === 'pass' ? 'bg-green-900/40 text-green-400' :
                            th.result === 'fail' ? 'bg-falcon-red/20 text-falcon-red' :
                            'bg-yellow-900/40 text-yellow-400'
                          }`}>
                            {th.result === 'pass' ? '合格' : th.result === 'fail' ? '不合格' : '部分的'}
                          </span>
                        </td>
                        <td className="py-2 pr-3 text-white font-medium text-xs">{th.score}</td>
                        <td className="py-2 pr-3 text-falcon-muted text-xs max-w-[160px] truncate">{th.notes}</td>
                        <td className="py-2 text-xs">
                          {th.evidence_link ? (
                            <a href={th.evidence_link} className="text-falcon-red hover:underline text-xs">表示</a>
                          ) : (
                            <span className="text-falcon-subtle">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Add Control Modal ────────────────────────────────────────────────────────

function AddControlModal({ onClose, onSubmit }: {
  onClose: () => void
  onSubmit: (data: Partial<Control>) => void
}) {
  const [form, setForm] = useState({
    control_id: '',
    name: '',
    description: '',
    category: 'preventive' as ControlCategory,
    frameworks: [] as Framework[],
    test_method: 'manual' as TestMethod,
    assigned_to: '',
    test_procedure: '',
  })

  const toggleFramework = (f: Framework) => {
    setForm(prev => ({
      ...prev,
      frameworks: prev.frameworks.includes(f)
        ? prev.frameworks.filter(x => x !== f)
        : [...prev.frameworks, f],
    }))
  }

  const handleSubmit = () => {
    if (!form.control_id.trim() || !form.name.trim()) return
    onSubmit({
      ...form,
      test_procedure: form.test_procedure.split('\n').map(s => s.trim()).filter(Boolean),
      status: 'not_tested',
      last_tested: null,
      score: 0,
      test_history: [],
    })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border sticky top-0 bg-falcon-surface">
          <h3 className="text-white font-bold">コントロール追加</h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">コントロールID *</label>
              <input
                value={form.control_id}
                onChange={e => setForm(p => ({ ...p, control_id: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                placeholder="例: CC-016"
              />
            </div>
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">担当者</label>
              <input
                value={form.assigned_to}
                onChange={e => setForm(p => ({ ...p, assigned_to: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                placeholder="例: 田中 太郎"
              />
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">コントロール名 *</label>
            <input
              value={form.name}
              onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="コントロール名..."
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">カテゴリ</label>
              <select
                value={form.category}
                onChange={e => setForm(p => ({ ...p, category: e.target.value as ControlCategory }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="preventive">予防的</option>
                <option value="detective">発見的</option>
                <option value="corrective">是正的</option>
                <option value="compensating">補完的</option>
              </select>
            </div>
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">テスト方法</label>
              <select
                value={form.test_method}
                onChange={e => setForm(p => ({ ...p, test_method: e.target.value as TestMethod }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="automated">自動</option>
                <option value="manual">手動</option>
                <option value="review">レビュー</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-2 block">フレームワーク（複数選択）</label>
            <div className="flex flex-wrap gap-2">
              {FRAMEWORKS.map(f => (
                <button
                  key={f}
                  onClick={() => toggleFramework(f)}
                  className={`text-xs px-3 py-1.5 rounded font-mono font-medium transition-colors border ${
                    form.frameworks.includes(f)
                      ? 'bg-falcon-red/20 text-falcon-red border-falcon-red/40'
                      : 'bg-falcon-raised text-falcon-muted border-falcon-border'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">テスト手順（1行1ステップ）</label>
            <textarea
              value={form.test_procedure}
              onChange={e => setForm(p => ({ ...p, test_procedure: e.target.value }))}
              rows={4}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="ステップ1&#10;ステップ2&#10;ステップ3"
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">キャンセル</button>
          <button
            onClick={handleSubmit}
            disabled={!form.control_id.trim() || !form.name.trim()}
            className="px-4 py-2 text-sm bg-falcon-red text-white rounded-sm font-medium hover:bg-[#c5001f] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Framework Coverage Section ───────────────────────────────────────────────

function FrameworkCoverage({ controls }: { controls: Control[] }) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5 mb-6">
      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
        <BarChart3 className="w-4 h-4 text-falcon-red" />
        フレームワークカバレッジ
      </h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        {FRAMEWORKS.map(fw => {
          const fwControls = controls.filter(c => c.frameworks.includes(fw))
          const passing = fwControls.filter(c => c.status === 'passing').length
          const pct = fwControls.length > 0 ? Math.round((passing / fwControls.length) * 100) : 0
          return (
            <div key={fw}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-white font-mono font-semibold text-sm">{fw}</span>
                <span className={`text-sm font-bold ${pct >= 80 ? 'text-green-400' : pct >= 60 ? 'text-yellow-400' : 'text-falcon-red'}`}>
                  {pct}%
                </span>
              </div>
              <div className="h-2 bg-falcon-border rounded-full">
                <div
                  className={`h-full rounded-full transition-all ${pct >= 80 ? 'bg-green-500' : pct >= 60 ? 'bg-yellow-500' : 'bg-falcon-red'}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <p className="text-falcon-muted text-xs mt-1">{passing} / {fwControls.length} 合格</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ControlTestingPage() {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [filterCategory, setFilterCategory] = useState<ControlCategory | ''>('')
  const [filterFramework, setFilterFramework] = useState<Framework | ''>('')
  const [filterStatus, setFilterStatus] = useState<ControlStatus | ''>('')
  const [selectedControl, setSelectedControl] = useState<Control | null>(null)
  const [testingControl, setTestingControl] = useState<Control | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)

  const { data: controlsData, isLoading } = useQuery<Control[]>({
    queryKey: ['admin-controls'],
    queryFn: () => apiFetch('/api/v1/admin/controls'),
    staleTime: 60_000,
  })

  const controls = controlsData ?? []

  const testMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: object }) =>
      apiFetch(`/api/v1/admin/controls/${id}/test`, { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-controls'] }),
  })

  const addMutation = useMutation({
    mutationFn: (data: Partial<Control>) =>
      apiFetch('/api/v1/admin/controls', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-controls'] }),
  })

  const filtered = controls.filter(c => {
    if (searchTerm && !c.name.toLowerCase().includes(searchTerm.toLowerCase()) && !c.control_id.toLowerCase().includes(searchTerm.toLowerCase())) return false
    if (filterCategory && c.category !== filterCategory) return false
    if (filterFramework && !c.frameworks.includes(filterFramework as Framework)) return false
    if (filterStatus && c.status !== filterStatus) return false
    return true
  })

  const passingCount = controls.filter(c => c.status === 'passing').length
  const failingCount = controls.filter(c => c.status === 'failing').length
  const passingPct = controls.length > 0 ? Math.round((passingCount / controls.length) * 100) : 0
  const lastTestDate = controls
    .filter(c => c.last_tested)
    .sort((a, b) => (b.last_tested ?? '').localeCompare(a.last_tested ?? ''))
    [0]?.last_tested ?? '—'

  const handleExportCSV = () => {
    const header = 'ID,名前,カテゴリ,フレームワーク,ステータス,スコア,最終テスト,担当者\n'
    const rows = controls.map(c =>
      `${c.control_id},"${c.name}",${CATEGORY_LABELS[c.category]},"${c.frameworks.join('/')}",${STATUS_LABELS[c.status]},${c.score},${c.last_tested ?? ''},${c.assigned_to}`
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `control-test-results-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <FlaskConical className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">セキュリティコントロールテスト</h1>
            <p className="text-falcon-muted text-sm">コントロールの検証・テスト結果管理</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted text-sm hover:text-white hover:border-falcon-muted/40 transition-colors"
          >
            <Download className="w-4 h-4" />
            CSVエクスポート
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white text-sm font-medium hover:bg-[#c5001f] transition-colors"
          >
            <Plus className="w-4 h-4" />
            コントロール追加
          </button>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総コントロール数', value: controls.length, color: 'text-white', icon: Shield },
          { label: '合格率', value: `${passingPct}%`, color: 'text-green-400', icon: CheckCircle2 },
          { label: '不合格', value: failingCount, color: 'text-falcon-red', icon: XCircle },
          { label: '最終テスト', value: lastTestDate, color: 'text-falcon-muted', icon: Calendar },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Icon className={`w-5 h-5 ${color}`} />
              <div>
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-falcon-muted text-xs">{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Framework Coverage */}
      <FrameworkCoverage controls={controls} />

      {/* Filters */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 mb-4">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-muted" />
            <input
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="コントロールIDまたは名前で検索..."
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 pl-9 text-white text-sm
                         focus:outline-hidden focus:border-falcon-red/50 placeholder:text-falcon-subtle"
            />
          </div>
          <select
            value={filterCategory}
            onChange={e => setFilterCategory(e.target.value as ControlCategory | '')}
            className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted focus:outline-hidden focus:border-falcon-red/50"
          >
            <option value="">全カテゴリ</option>
            <option value="preventive">予防的</option>
            <option value="detective">発見的</option>
            <option value="corrective">是正的</option>
            <option value="compensating">補完的</option>
          </select>
          <select
            value={filterFramework}
            onChange={e => setFilterFramework(e.target.value as Framework | '')}
            className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted focus:outline-hidden focus:border-falcon-red/50"
          >
            <option value="">全フレームワーク</option>
            {FRAMEWORKS.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value as ControlStatus | '')}
            className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted focus:outline-hidden focus:border-falcon-red/50"
          >
            <option value="">全ステータス</option>
            <option value="passing">合格</option>
            <option value="failing">不合格</option>
            <option value="partial">部分的</option>
            <option value="not_tested">未テスト</option>
          </select>
          {(searchTerm || filterCategory || filterFramework || filterStatus) && (
            <button
              onClick={() => { setSearchTerm(''); setFilterCategory(''); setFilterFramework(''); setFilterStatus('') }}
              className="flex items-center gap-1 text-sm text-falcon-red hover:text-[#ff3355] transition-colors"
            >
              <X className="w-4 h-4" />
              クリア
            </button>
          )}
        </div>
        <p className="text-falcon-muted text-xs mt-2">{filtered.length} / {controls.length} コントロールを表示</p>
      </div>

      {/* Controls table */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-8 h-8 border-2 border-falcon-red border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-falcon-border">
                <tr>
                  {['ID', 'コントロール名', 'カテゴリ', 'フレームワーク', 'ステータス', '最終テスト', '方法', 'スコア', '担当者', 'アクション'].map(h => (
                    <th key={h} className="text-left text-falcon-muted text-xs px-4 py-3 font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {filtered.map(control => {
                  const StatusIcon = STATUS_ICONS[control.status]
                  return (
                    <tr key={control.id} className="hover:bg-falcon-card transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-falcon-muted font-mono text-xs">{control.control_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white font-medium text-sm">{control.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${CATEGORY_STYLES[control.category]}`}>
                          {CATEGORY_LABELS[control.category]}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {control.frameworks.map(f => (
                            <span key={f} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-falcon-border text-falcon-muted font-mono">{f}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full font-medium w-fit ${STATUS_STYLES[control.status]}`}>
                          <StatusIcon className="w-3 h-3" />
                          {STATUS_LABELS[control.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                        {control.last_tested ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">
                        {METHOD_LABELS[control.test_method]}
                      </td>
                      <td className="px-4 py-3">
                        {control.status === 'not_tested' ? (
                          <span className="text-falcon-subtle text-xs">—</span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-falcon-border rounded-full">
                              <div
                                className={`h-full rounded-full ${control.score >= 80 ? 'bg-green-500' : control.score >= 60 ? 'bg-yellow-500' : 'bg-falcon-red'}`}
                                style={{ width: `${control.score}%` }}
                              />
                            </div>
                            <span className="text-white text-xs font-medium">{control.score}</span>
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                        {displayUser(control.assigned_to)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setTestingControl(control)}
                            title="テスト実行"
                            className="p-1.5 rounded-sm text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 transition-colors"
                          >
                            <Play className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setSelectedControl(control)}
                            title="詳細表示"
                            className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-4 py-12 text-center text-falcon-muted">
                      <FlaskConical className="w-10 h-10 mx-auto mb-2 text-falcon-subtle" />
                      条件に一致するコントロールが見つかりません
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modals */}
      {testingControl && (
        <TestExecutionModal
          control={testingControl}
          onClose={() => setTestingControl(null)}
          onSubmit={data => testMutation.mutate({ id: testingControl.id, data })}
        />
      )}
      {selectedControl && (
        <ControlDetailModal control={selectedControl} onClose={() => setSelectedControl(null)} />
      )}
      {showAddModal && (
        <AddControlModal
          onClose={() => setShowAddModal(false)}
          onSubmit={data => addMutation.mutate(data)}
        />
      )}
    </div>
  )
}
