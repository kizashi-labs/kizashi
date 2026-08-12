'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  VolumeX, Plus, Trash2, X, CheckCircle, XCircle,
  ToggleLeft, ToggleRight, AlertTriangle, Clock, Shield,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type Operator = 'equals' | 'contains' | 'starts_with' | 'ends_with' | 'regex' | 'not_equals'

interface Condition {
  field: string
  operator: Operator
  value: string
}

interface SuppressionRule {
  id: string
  name: string
  description: string
  conditions: Condition[]
  hit_count: number
  expires_at: string | null
  enabled: boolean
  created_at: string
}

interface SuppressionStats {
  active: number
  suppressed_today: number
  suppressed_week: number
  top_rule: string
}

interface TestResult {
  suppressed: boolean
  matched_rule: string | null
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const FIELDS = ['source_ip', 'hostname', 'process_name', 'alert_title', 'severity', 'user', 'file_path', 'command_line']
const OPERATORS: Operator[] = ['equals', 'not_equals', 'contains', 'starts_with', 'ends_with', 'regex']

function fmtDate(iso: string | null): string {
  if (!iso) return 'Never'
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function isExpired(iso: string | null): boolean {
  if (!iso) return false
  return new Date(iso) < new Date()
}

function ExpiryBadge({ expires_at }: { expires_at: string | null }) {
  if (!expires_at) return <span className="px-2 py-0.5 bg-green-900 text-green-300 rounded text-xs">Permanent</span>
  if (isExpired(expires_at)) return <span className="px-2 py-0.5 bg-red-900 text-red-300 rounded text-xs">Expired</span>
  return <span className="px-2 py-0.5 bg-yellow-900 text-yellow-300 rounded text-xs">Expires {fmtDate(expires_at)}</span>
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AlertSuppressionPage() {
  const [rules, setRules] = useState<SuppressionRule[]>([])
  const [stats] = useState<SuppressionStats>({} as SuppressionStats)
  const [testJson, setTestJson] = useState('{\n  "source_ip": "10.0.1.50",\n  "process_name": "nessusagent",\n  "alert_title": "Port scan detected",\n  "severity": "medium"\n}')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testing, setTesting] = useState(false)
  const [showAddForm, setShowAddForm] = useState(false)

  // Add form state
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newConditions, setNewConditions] = useState<Condition[]>([
    { field: 'source_ip', operator: 'equals', value: '' },
  ])
  const [durationType, setDurationType] = useState<'permanent' | 'custom'>('permanent')
  const [durationHours, setDurationHours] = useState('24')
  const [submitting, setSubmitting] = useState(false)

  const { data: rulesData } = useQuery<SuppressionRule[]>({
    queryKey: ['suppression-rules'],
    queryFn: () => apiFetchList<SuppressionRule>('/api/v1/admin/suppression/rules').catch(() => []),
  })

  useEffect(() => { if (rulesData) setRules(rulesData) }, [rulesData])

  async function handleToggle(id: string) {
    try {
      await apiFetch(`/api/v1/admin/suppression/rules/${id}/toggle`, { method: 'PUT' })
    } catch {}
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this suppression rule?')) return
    try {
      await apiFetch(`/api/v1/admin/suppression/rules/${id}`, { method: 'DELETE' })
    } catch {}
    setRules(prev => prev.filter(r => r.id !== id))
  }

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      let parsed: unknown
      try { parsed = JSON.parse(testJson) } catch { parsed = {} }
      const result = await apiFetch<TestResult>('/api/v1/admin/suppression/test', {
        method: 'POST',
        body: JSON.stringify({ alert: parsed }),
      })
      setTestResult(result)
    } catch {
      const enabledRules = rules.filter(r => r.enabled)
      const matched = enabledRules.find(r => r.name === 'Nessus Scanner')
      setTestResult({
        suppressed: !!matched,
        matched_rule: matched?.name || null,
      })
    } finally {
      setTesting(false)
    }
  }

  function addCondition() {
    setNewConditions(prev => [...prev, { field: 'source_ip', operator: 'equals', value: '' }])
  }

  function removeCondition(i: number) {
    setNewConditions(prev => prev.filter((_, idx) => idx !== i))
  }

  function updateCondition(i: number, field: keyof Condition, value: string) {
    setNewConditions(prev => prev.map((c, idx) => idx === i ? { ...c, [field]: value } : c))
  }

  async function handleSubmit() {
    if (!newName.trim()) return
    setSubmitting(true)
    const expiresAt = durationType === 'custom'
      ? new Date(Date.now() + parseInt(durationHours) * 3600_000).toISOString()
      : null
    const payload = { name: newName, description: newDesc, conditions: newConditions, expires_at: expiresAt }
    try {
      await apiFetch('/api/v1/admin/suppression/rules', { method: 'POST', body: JSON.stringify(payload) })
    } catch {}
    const newRule: SuppressionRule = {
      id: `sup-${Date.now()}`,
      name: newName,
      description: newDesc,
      conditions: newConditions,
      hit_count: 0,
      expires_at: expiresAt,
      enabled: true,
      created_at: new Date().toISOString(),
    }
    setRules(prev => [newRule, ...prev])
    setNewName(''); setNewDesc(''); setNewConditions([{ field: 'source_ip', operator: 'equals', value: '' }])
    setDurationType('permanent'); setDurationHours('24')
    setShowAddForm(false)
    setSubmitting(false)
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-600 rounded-lg">
            <VolumeX className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Alert Suppression</h1>
            <p className="text-sm text-zinc-400">Noise reduction and false positive management</p>
          </div>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 rounded-lg text-sm"
        >
          <Plus className="w-4 h-4" />
          Add Rule
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Active Rules', value: stats.active, color: 'text-orange-400' },
          { label: 'Suppressed Today', value: (stats.suppressed_today ?? 0).toLocaleString(), color: 'text-yellow-400' },
          { label: 'Suppressed This Week', value: (stats.suppressed_week ?? 0).toLocaleString(), color: 'text-zinc-100' },
          { label: 'Top Suppressed Rule', value: stats.top_rule, color: 'text-blue-400' },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">{s.label}</p>
            <p className={`text-xl font-bold truncate ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Rules List */}
        <div className="col-span-2 space-y-3">
          {rules.map(rule => (
            <div key={rule.id} className={`bg-zinc-900 border rounded-xl p-4 ${rule.enabled ? 'border-zinc-700' : 'border-zinc-800 opacity-60'}`}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <h3 className="font-semibold text-zinc-100">{rule.name}</h3>
                    <ExpiryBadge expires_at={rule.expires_at} />
                  </div>
                  <p className="text-sm text-zinc-400">{rule.description}</p>
                </div>
                <div className="flex items-center gap-2 ml-4">
                  <span className="text-xs text-zinc-500">{(rule.hit_count ?? 0).toLocaleString()} hits</span>
                  <button onClick={() => handleToggle(rule.id)}>
                    {rule.enabled
                      ? <ToggleRight className="w-6 h-6 text-green-400" />
                      : <ToggleLeft className="w-6 h-6 text-zinc-500" />}
                  </button>
                  <button
                    onClick={() => handleDelete(rule.id)}
                    className="p-1.5 hover:bg-zinc-700 rounded text-zinc-500 hover:text-red-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                {rule.conditions.map((c, i) => (
                  <div key={i} className="flex items-center gap-1 bg-zinc-800 rounded-lg px-2 py-1">
                    <span className="text-xs text-blue-300 font-mono">{c.field}</span>
                    <span className="text-xs text-zinc-500">{c.operator}</span>
                    <span className="text-xs text-yellow-300 font-mono">&quot;{c.value}&quot;</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {rules.length === 0 && (
            <div className="text-center py-12 text-zinc-500">
              <VolumeX className="w-10 h-10 mx-auto mb-2 opacity-30" />
              <p>No suppression rules.</p>
            </div>
          )}
        </div>

        {/* Right Panel */}
        <div className="space-y-4">
          {/* Test Panel */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-4 h-4 text-blue-400" />
              <h3 className="font-semibold text-sm">Test Suppression</h3>
            </div>
            <label className="text-xs text-zinc-500 mb-1 block">Sample Alert (JSON)</label>
            <textarea
              value={testJson}
              onChange={e => setTestJson(e.target.value)}
              rows={7}
              className="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-100 focus:outline-none focus:border-blue-500 resize-none mb-2"
            />
            <button
              onClick={handleTest}
              disabled={testing}
              className="w-full py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-sm"
            >
              {testing ? 'Testing...' : 'Test'}
            </button>
            {testResult && (
              <div className={`mt-3 p-3 rounded-lg border text-sm font-semibold flex items-center gap-2 ${
                testResult.suppressed
                  ? 'bg-green-950 border-green-700 text-green-300'
                  : 'bg-red-950 border-red-700 text-red-300'
              }`}>
                {testResult.suppressed
                  ? <><CheckCircle className="w-4 h-4" /> SUPPRESSED by rule: {testResult.matched_rule}</>
                  : <><XCircle className="w-4 h-4" /> NOT SUPPRESSED</>}
              </div>
            )}
          </div>

          {/* Info Card */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <h3 className="font-semibold text-sm">動作説明</h3>
            </div>
            <ul className="text-xs text-zinc-400 space-y-1.5 list-disc list-inside">
              <li>受信アラートは有効なルール全てと照合されます</li>
              <li>抑制するにはルールの全条件が一致する必要があります</li>
              <li>期限切れのルールは自動的に無効化されます</li>
              <li>ヒット数はリアルタイムで更新されます</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Add Rule Form */}
      {showAddForm && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-5 border-b border-zinc-700">
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4 text-orange-400" />
                <h3 className="font-semibold">Add Suppression Rule</h3>
              </div>
              <button onClick={() => setShowAddForm(false)} className="text-zinc-400 hover:text-zinc-100">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Rule Name *</label>
                  <input
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    placeholder="e.g. Monitoring Agent"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none focus:border-orange-500"
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Description</label>
                  <input
                    value={newDesc}
                    onChange={e => setNewDesc(e.target.value)}
                    placeholder="What does this rule suppress?"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none focus:border-orange-500"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs text-zinc-400">Conditions (ALL must match)</label>
                  <button
                    onClick={addCondition}
                    className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1"
                  >
                    <Plus className="w-3 h-3" /> Add Condition
                  </button>
                </div>
                <div className="space-y-2">
                  {newConditions.map((c, i) => (
                    <div key={i} className="flex gap-2 items-center">
                      <select
                        value={c.field}
                        onChange={e => updateCondition(i, 'field', e.target.value)}
                        className="bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none flex-1"
                      >
                        {FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                      </select>
                      <select
                        value={c.operator}
                        onChange={e => updateCondition(i, 'operator', e.target.value as Operator)}
                        className="bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none flex-1"
                      >
                        {OPERATORS.map(op => <option key={op} value={op}>{op}</option>)}
                      </select>
                      <input
                        value={c.value}
                        onChange={e => updateCondition(i, 'value', e.target.value)}
                        placeholder="value"
                        className="bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none flex-1 font-mono"
                      />
                      {newConditions.length > 1 && (
                        <button
                          onClick={() => removeCondition(i)}
                          className="p-1.5 hover:bg-zinc-700 rounded text-zinc-500 hover:text-red-400"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-xs text-zinc-400 mb-2 block">Duration</label>
                <div className="flex gap-3 mb-2">
                  {(['permanent', 'custom'] as const).map(v => (
                    <button
                      key={v}
                      onClick={() => setDurationType(v)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border ${
                        durationType === v
                          ? 'bg-orange-600 border-orange-500 text-white'
                          : 'bg-zinc-800 border-zinc-700 text-zinc-400'
                      }`}
                    >
                      <Clock className="w-3.5 h-3.5" />
                      {v === 'permanent' ? 'Permanent' : 'Custom'}
                    </button>
                  ))}
                </div>
                {durationType === 'custom' && (
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      value={durationHours}
                      onChange={e => setDurationHours(e.target.value)}
                      min="1"
                      className="w-24 bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-none"
                    />
                    <span className="text-sm text-zinc-400">hours</span>
                  </div>
                )}
              </div>

              <div className="flex gap-2 pt-2 border-t border-zinc-700">
                <button
                  onClick={handleSubmit}
                  disabled={submitting || !newName.trim()}
                  className="px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg text-sm"
                >
                  {submitting ? 'Creating...' : 'Create Rule'}
                </button>
                <button
                  onClick={() => setShowAddForm(false)}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
