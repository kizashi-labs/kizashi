'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  Crosshair, Play, Plus, X, RefreshCw, CheckCircle, Clock,

  AlertTriangle, TrendingUp, Activity, ChevronRight, ShieldCheck, ShieldAlert,

  BarChart2, ChevronDown,

} from 'lucide-react'




// ── Types ──────────────────────────────────────────────────────────────────────



interface SimStats {

  total_runs: number

  completed: number

  running: number

  avg_detection_rate: number

}



interface SimTemplate {

  id: string

  name: string

  category: string

  mitre_tactics: string[]

  techniques_count: number

  enabled: boolean

}



interface SimRun {

  id: string

  name: string

  template_id: string

  status: 'running' | 'completed' | 'failed' | 'pending'

  detections: number

  missed: number

  started_at: string

  duration_seconds?: number

}



interface RunSimPayload {

  template_id: string

  name: string

  target_agents: string[]

}



// ── Helpers ────────────────────────────────────────────────────────────────────



function fmtDateTime(iso?: string): string {

  if (!iso) return '—'

  try {

    return new Date(iso).toLocaleString('en-US', {

      year: 'numeric', month: '2-digit', day: '2-digit',

      hour: '2-digit', minute: '2-digit',

    })

  } catch { return '—' }

}



function fmtDuration(secs?: number): string {

  if (!secs) return '—'

  const m = Math.floor(secs / 60)

  const s = secs % 60

  return m > 0 ? `${m}m ${s}s` : `${s}s`

}



const RUN_STATUS_STYLES: Record<string, string> = {

  running:   'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',

  completed: 'bg-green-900/40 text-green-300 border border-green-700/50',

  failed:    'bg-red-900/40 text-red-300 border border-red-700/50',

  pending:   'bg-falcon-raised text-[#8899aa] border border-falcon-border',

}



// ── Run Detail Panel ──────────────────────────────────────────────────────────



const MITRE_TACTICS = [

  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',

  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',

  'Collection', 'Exfiltration', 'Impact',

]



interface TacticResult {

  tactic: string

  detected: number

  missed: number

  techniques: Array<{ id: string; name: string; detected: boolean }>

}



function buildMockTacticResults(run: SimRun, templates: SimTemplate[]): TacticResult[] {

  const template = templates.find(t => t.id === run.template_id)

  const tactics = template?.mitre_tactics ?? ['Execution', 'Discovery']

  const techCount = template?.techniques_count ?? 5

  const detRate = run.detections / Math.max(1, run.detections + run.missed)



  return tactics.map((tactic, ti) => {

    const tacticTechs = Math.max(1, Math.round(techCount / tactics.length) + (ti % 2 === 0 ? 1 : 0))

    const techniques = Array.from({ length: tacticTechs }, (_, i) => {

      const detected = Math.random() < detRate

      return {

        id: `T${1059 + ti * 10 + i}`,

        name: `${tactic} Technique ${i + 1}`,

        detected,

      }

    })

    return {

      tactic,

      detected: techniques.filter(t => t.detected).length,

      missed: techniques.filter(t => !t.detected).length,

      techniques,

    }

  })

}



function RunDetailPanel({ run, templates, onClose }: {

  run: SimRun

  templates: SimTemplate[]

  onClose: () => void

}) {

  const [expandedTactic, setExpandedTactic] = useState<string | null>(null)

  const total = run.detections + run.missed

  const rate = total > 0 ? Math.round((run.detections / total) * 100) : 0

  const tacticResults = buildMockTacticResults(run, templates)



  const rateColor = rate >= 80 ? '#00c853' : rate >= 60 ? '#ff9800' : '#e8002d'



  return (

    <div className="fixed inset-0 z-50 flex items-start justify-end bg-black/40 backdrop-blur-xs"

         onClick={onClose}>

      <div

        className="h-full w-full max-w-xl bg-falcon-surface border-l border-falcon-border shadow-2xl overflow-y-auto"

        onClick={e => e.stopPropagation()}

      >

        {/* Header */}

        <div className="sticky top-0 bg-falcon-surface border-b border-falcon-border px-6 py-4 flex items-start justify-between z-10">

          <div>

            <h2 className="text-white font-bold text-lg">{run.name}</h2>

            <p className="text-falcon-muted text-sm mt-0.5">{fmtDateTime(run.started_at)}</p>

          </div>

          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors mt-1">

            <X className="w-5 h-5" />

          </button>

        </div>



        <div className="p-6 space-y-6">

          {/* Status + Duration */}

          <div className="flex items-center gap-4">

            <span className={`text-xs px-2.5 py-1 rounded-full capitalize font-medium ${RUN_STATUS_STYLES[run.status]}`}>

              {run.status}

            </span>

            {run.duration_seconds && (

              <span className="text-xs text-falcon-muted">Duration: {fmtDuration(run.duration_seconds)}</span>

            )}

          </div>



          {/* Detection Rate */}

          <div className="bg-falcon-raised rounded-xl p-4">

            <div className="flex items-center justify-between mb-3">

              <div className="flex items-center gap-2">

                <BarChart2 className="w-4 h-4 text-falcon-muted" />

                <span className="text-sm font-medium text-white">Detection Rate</span>

              </div>

              <span className="text-2xl font-bold" style={{ color: rateColor }}>{rate}%</span>

            </div>

            <div className="w-full h-3 bg-falcon-border rounded-full overflow-hidden mb-3">

              <div className="h-full rounded-full transition-all" style={{ width: `${rate}%`, backgroundColor: rateColor }} />

            </div>

            <div className="flex items-center gap-6 text-sm">

              <div className="flex items-center gap-2">

                <ShieldCheck className="w-4 h-4 text-green-400" />

                <span className="text-green-400 font-bold">{run.detections}</span>

                <span className="text-falcon-muted">Detected</span>

              </div>

              <div className="flex items-center gap-2">

                <ShieldAlert className="w-4 h-4 text-red-400" />

                <span className="text-red-400 font-bold">{run.missed}</span>

                <span className="text-falcon-muted">Missed</span>

              </div>

              <div className="ml-auto text-falcon-muted">{total} total techniques</div>

            </div>

          </div>



          {/* MITRE ATT&CK Breakdown */}

          <div>

            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">

              <Crosshair className="w-4 h-4 text-falcon-red" />

              MITRE ATT&CK Technique Breakdown

            </h3>

            <div className="space-y-2">

              {tacticResults.map(tr => {

                const tacticTotal = tr.detected + tr.missed

                const tacticRate = tacticTotal > 0 ? Math.round((tr.detected / tacticTotal) * 100) : 0

                const isExpanded = expandedTactic === tr.tactic

                return (

                  <div key={tr.tactic} className="bg-falcon-raised rounded-lg overflow-hidden">

                    <button

                      onClick={() => setExpandedTactic(isExpanded ? null : tr.tactic)}

                      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-falcon-hover transition-colors"

                    >

                      <div className="flex-1 min-w-0 text-left">

                        <span className="text-sm text-white">{tr.tactic}</span>

                      </div>

                      <div className="flex items-center gap-3 shrink-0">

                        <span className="text-xs text-green-400">{tr.detected} det.</span>

                        <span className="text-xs text-red-400">{tr.missed} miss</span>

                        <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">

                          <div className="h-full rounded-full"

                               style={{ width: `${tacticRate}%`, backgroundColor: tacticRate >= 80 ? '#00c853' : tacticRate >= 50 ? '#ff9800' : '#e8002d' }} />

                        </div>

                        <span className="text-xs text-falcon-muted w-8 text-right">{tacticRate}%</span>

                        {isExpanded

                          ? <ChevronDown className="w-3.5 h-3.5 text-falcon-subtle" />

                          : <ChevronRight className="w-3.5 h-3.5 text-falcon-subtle" />}

                      </div>

                    </button>

                    {isExpanded && (

                      <div className="px-4 pb-3 space-y-1.5 border-t border-falcon-border">

                        {tr.techniques.map(tech => (

                          <div key={tech.id} className="flex items-center gap-3 py-1">

                            {tech.detected

                              ? <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />

                              : <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />}

                            <span className="text-xs font-mono text-falcon-muted">{tech.id}</span>

                            <span className="text-xs text-falcon-text">{tech.name}</span>

                            <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded font-medium ${

                              tech.detected

                                ? 'bg-green-900/40 text-green-400'

                                : 'bg-red-900/40 text-red-400'

                            }`}>

                              {tech.detected ? 'DETECTED' : 'MISSED'}

                            </span>

                          </div>

                        ))}

                      </div>

                    )}

                  </div>

                )

              })}

            </div>

          </div>

        </div>

      </div>

    </div>

  )

}



// ── Stat Card ─────────────────────────────────────────────────────────────────



function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {

  label: string; value: string | number; icon: React.ElementType; color?: string

}) {

  return (

    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-4">

      <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"

           style={{ backgroundColor: `${color}20` }}>

        <Icon className="w-5 h-5" style={{ color }} />

      </div>

      <div>

        <p className="text-falcon-muted text-xs">{label}</p>

        <p className="text-white text-xl font-bold">{value}</p>

      </div>

    </div>

  )

}



// ── Run Simulation Modal ───────────────────────────────────────────────────────



function RunSimModal({ templates, onClose, onRun }: {

  templates: SimTemplate[]

  onClose: () => void

  onRun: (d: RunSimPayload) => void

}) {

  const [form, setForm] = useState<RunSimPayload>({

    template_id: templates[0]?.id ?? '',

    name: '',

    target_agents: [],

  })

  const [agentInput, setAgentInput] = useState('')



  const addAgent = () => {

    const trimmed = agentInput.trim()

    if (trimmed && !form.target_agents.includes(trimmed)) {

      setForm(f => ({ ...f, target_agents: [...f.target_agents, trimmed] }))

      setAgentInput('')

    }

  }



  const removeAgent = (a: string) =>

    setForm(f => ({ ...f, target_agents: f.target_agents.filter(x => x !== a) }))



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">

      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md">

        <div className="flex items-center justify-between p-6 border-b border-falcon-border">

          <h3 className="text-white font-bold text-lg flex items-center gap-2">

            <Play className="w-5 h-5 text-green-400" />

            Run Simulation

          </h3>

          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">

            <X className="w-5 h-5" />

          </button>

        </div>



        <div className="p-6 space-y-4">

          <div>

            <label className="block text-falcon-muted text-xs mb-1.5">Template <span className="text-falcon-red">*</span></label>

            <select

              value={form.template_id}

              onChange={e => setForm(f => ({ ...f, template_id: e.target.value }))}

              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm

                         focus:outline-hidden focus:border-falcon-red/50"

            >

              {templates.filter(t => t.enabled).map(t => (

                <option key={t.id} value={t.id}>{t.name}</option>

              ))}

            </select>

          </div>



          <div>

            <label className="block text-falcon-muted text-xs mb-1.5">Run Name <span className="text-falcon-red">*</span></label>

            <input

              type="text"

              value={form.name}

              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}

              placeholder="e.g. Weekly APT29 Check"

              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm

                         placeholder:text-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"

            />

          </div>



          <div>

            <label className="block text-falcon-muted text-xs mb-1.5">Target Agents</label>

            <div className="flex gap-2 mb-2">

              <input

                type="text"

                value={agentInput}

                onChange={e => setAgentInput(e.target.value)}

                onKeyDown={e => e.key === 'Enter' && addAgent()}

                placeholder="Agent ID (press Enter to add)"

                className="flex-1 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm

                           placeholder:text-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"

              />

              <button onClick={addAgent}

                className="px-3 py-2 bg-falcon-border hover:bg-[#2a3f5c] text-white rounded-lg text-sm transition-colors">

                <Plus className="w-4 h-4" />

              </button>

            </div>

            {form.target_agents.length > 0 && (

              <div className="flex flex-wrap gap-1.5">

                {form.target_agents.map(a => (

                  <span key={a} className="flex items-center gap-1 px-2 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-xs">

                    {a}

                    <button onClick={() => removeAgent(a)} className="hover:text-white transition-colors">

                      <X className="w-3 h-3" />

                    </button>

                  </span>

                ))}

              </div>

            )}

            <p className="text-falcon-subtle text-xs mt-1">Leave empty to run against all agents</p>

          </div>

        </div>



        <div className="flex gap-3 p-6 border-t border-falcon-border">

          <button onClick={onClose}

            className="flex-1 px-4 py-2 border border-falcon-border text-falcon-muted rounded-lg text-sm hover:bg-falcon-hover transition-colors">

            Cancel

          </button>

          <button

            onClick={() => onRun(form)}

            disabled={!form.template_id || !form.name.trim()}

            className="flex-1 px-4 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed

                       text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2">

            <Play className="w-4 h-4" />

            Start Simulation

          </button>

        </div>

      </div>

    </div>

  )

}



// ── Main Page ─────────────────────────────────────────────────────────────────



export default function ThreatSimulationPage() {

  const qc = useQueryClient()

  const [activeTab, setActiveTab] = useState<'templates' | 'runs'>('templates')

  const [showRunModal, setShowRunModal] = useState(false)

  const [selectedRun, setSelectedRun] = useState<SimRun | null>(null)



  const { data: stats = { total_runs: 0, completed: 0, running: 0, avg_detection_rate: 0 } } = useQuery<SimStats>({

    queryKey: ['sim-stats'],

    queryFn: () => apiFetch<SimStats>('/api/v1/admin/threat-simulation/stats').catch(() => ({ total_runs: 0, completed: 0, running: 0, avg_detection_rate: 0 } as SimStats)),

    staleTime: 30_000,

  })



  const { data: templates = [], isLoading: templatesLoading } = useQuery<SimTemplate[]>({

    queryKey: ['sim-templates'],

    queryFn: () => apiFetch<{ templates: SimTemplate[] }>('/api/v1/admin/threat-simulation/templates')

      .then(r => r.templates)

      .catch(() => []),

    staleTime: 60_000,

  })



  const { data: runs = [], isLoading: runsLoading } = useQuery<SimRun[]>({

    queryKey: ['sim-runs'],

    queryFn: () => apiFetch<{ runs: SimRun[] }>('/api/v1/admin/threat-simulation/runs')

      .then(r => r.runs)

      .catch(() => []),

    staleTime: 30_000,

    refetchInterval: 15_000,

  })



  const runMutation = useMutation({

    mutationFn: (data: RunSimPayload) =>

      apiFetch('/api/v1/admin/threat-simulation/runs', { method: 'POST', body: JSON.stringify(data) })

        .catch(() => ({})),

    onSuccess: () => {

      qc.invalidateQueries({ queryKey: ['sim-runs'] })

      qc.invalidateQueries({ queryKey: ['sim-stats'] })

      setShowRunModal(false)

    },

  })



  return (

    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}

      <div className="flex items-center justify-between mb-6">

        <div>

          <h1 className="text-2xl font-bold text-white flex items-center gap-3">

            <Crosshair className="w-7 h-7 text-falcon-red" />

            Breach & Attack Simulation

          </h1>

          <p className="text-falcon-muted text-sm mt-1">Validate security controls with automated attack simulations</p>

        </div>

        <button

          onClick={() => setShowRunModal(true)}

          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"

        >

          <Play className="w-4 h-4" />

          Run Simulation

        </button>

      </div>



      {/* Stats */}

      <div className="grid grid-cols-4 gap-4 mb-6">

        <StatCard label="Total Runs"           value={stats.total_runs}                              icon={Activity}      color="#7d92b0" />

        <StatCard label="Completed"            value={stats.completed}                               icon={CheckCircle}   color="#00c853" />

        <StatCard label="Running"              value={stats.running}                                 icon={Clock}         color="#ff9800" />

        <StatCard label="Avg Detection Rate"   value={`${stats.avg_detection_rate.toFixed(1)}%`}     icon={TrendingUp}    color="#1a6bff" />

      </div>



      {/* Tabs */}

      <div className="flex gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit mb-6">

        {([['templates', 'Simulation Templates'], ['runs', 'Simulation Runs']] as const).map(([key, label]) => (

          <button key={key}

            onClick={() => setActiveTab(key)}

            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${

              activeTab === key ? 'bg-falcon-active text-white' : 'text-falcon-muted hover:text-white'

            }`}>

            {label}

          </button>

        ))}

      </div>



      {/* Templates Tab */}

      {activeTab === 'templates' && (

        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">

          {templatesLoading ? (

            <div className="flex items-center justify-center py-16">

              <RefreshCw className="w-6 h-6 text-falcon-muted animate-spin" />

            </div>

          ) : (

            <table className="w-full">

              <thead>

                <tr className="border-b border-falcon-border">

                  {['Name', 'Category', 'MITRE Tactics', 'Techniques', 'Enabled'].map(h => (

                    <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">{h}</th>

                  ))}

                </tr>

              </thead>

              <tbody>

                {templates.map(t => (

                  <tr key={t.id} className="border-b border-falcon-border/50 hover:bg-falcon-hover/30 transition-colors">

                    <td className="px-4 py-3 text-white text-sm font-medium">{t.name}</td>

                    <td className="px-4 py-3">

                      <span className="text-xs px-2 py-0.5 rounded-sm bg-falcon-border text-falcon-muted">{t.category}</span>

                    </td>

                    <td className="px-4 py-3">

                      <div className="flex flex-wrap gap-1">

                        {t.mitre_tactics.map(tac => (

                          <span key={tac} className="text-xs px-1.5 py-0.5 rounded-sm bg-purple-900/30 text-purple-300 border border-purple-700/30">

                            {tac}

                          </span>

                        ))}

                      </div>

                    </td>

                    <td className="px-4 py-3 text-falcon-muted text-sm">{t.techniques_count}</td>

                    <td className="px-4 py-3">

                      <span className={`text-xs px-2 py-0.5 rounded-full ${t.enabled ? 'bg-green-900/40 text-green-300 border border-green-700/50' : 'bg-falcon-raised text-[#8899aa] border border-falcon-border'}`}>

                        {t.enabled ? 'Enabled' : 'Disabled'}

                      </span>

                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          )}

        </div>

      )}



      {/* Runs Tab */}

      {activeTab === 'runs' && (

        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">

          {runsLoading ? (

            <div className="flex items-center justify-center py-16">

              <RefreshCw className="w-6 h-6 text-falcon-muted animate-spin" />

            </div>

          ) : (

            <table className="w-full">

              <thead>

                <tr className="border-b border-falcon-border">

                  {['Run Name', 'Status', 'Detections', 'Missed', 'Detection Rate', 'Started At', 'Duration'].map(h => (

                    <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">{h}</th>

                  ))}

                </tr>

              </thead>

              <tbody>

                {runs.length === 0 ? (

                  <tr>

                    <td colSpan={7} className="px-4 py-12 text-center text-falcon-muted text-sm">

                      No simulation runs yet

                    </td>

                  </tr>

                ) : runs.map(r => {

                  const total = r.detections + r.missed

                  const rate = total > 0 ? Math.round((r.detections / total) * 100) : 0

                  return (

                    <tr key={r.id}

                        onClick={() => setSelectedRun(r)}

                        className="border-b border-falcon-border/50 hover:bg-falcon-hover/30 transition-colors cursor-pointer">

                      <td className="px-4 py-3 text-white text-sm font-medium">{r.name}</td>

                      <td className="px-4 py-3">

                        <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${RUN_STATUS_STYLES[r.status]}`}>

                          {r.status === 'running' ? (

                            <span className="flex items-center gap-1">

                              <RefreshCw className="w-3 h-3 animate-spin inline" /> Running

                            </span>

                          ) : r.status}

                        </span>

                      </td>

                      <td className="px-4 py-3 text-green-400 text-sm font-medium">{r.detections}</td>

                      <td className="px-4 py-3 text-red-400 text-sm font-medium">{r.missed}</td>

                      <td className="px-4 py-3">

                        <div className="flex items-center gap-2">

                          <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">

                            <div className="h-full rounded-full" style={{

                              width: `${rate}%`,

                              backgroundColor: rate >= 80 ? '#00c853' : rate >= 60 ? '#ff9800' : '#e8002d'

                            }} />

                          </div>

                          <span className="text-falcon-muted text-xs">{rate}%</span>

                        </div>

                      </td>

                      <td className="px-4 py-3 text-falcon-muted text-sm">{fmtDateTime(r.started_at)}</td>

                      <td className="px-4 py-3 text-falcon-muted text-sm">{fmtDuration(r.duration_seconds)}</td>

                    </tr>

                  )

                })}

              </tbody>

            </table>

          )}

        </div>

      )}



      {showRunModal && (

        <RunSimModal

          templates={templates}

          onClose={() => setShowRunModal(false)}

          onRun={data => runMutation.mutate(data)}

        />

      )}



      {selectedRun && (

        <RunDetailPanel

          run={selectedRun}

          templates={templates}

          onClose={() => setSelectedRun(null)}

        />

      )}

    </div>

  )

}

